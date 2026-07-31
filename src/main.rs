mod link;
mod proto;
mod wire;

use anyhow::{bail, Context, Result};
use clap::Parser;
use link::{
    check_port, increase_port, timeout, Link, CONNECT_TIMEOUT, RELAY_PORT, RS_PUB_KEY,
};
use proto::rustshell::*;
use protobuf::Message as ProtoMessage;
use sha2::{Digest, Sha256};
use sodiumoxide::crypto::{box_, secretbox, sign};
use std::io::Write;
use tokio::time;

const APP_NAME: &str = "RustShell";
const VERSION: &str = env!("CARGO_PKG_VERSION");

// ── CLI arguments ──────────────────────────────────────────────────

#[derive(Parser, Debug)]
#[command(
    name = APP_NAME,
    version = VERSION,
    about = concat!("Cross-platform remote shell via RustDesk v", env!("CARGO_PKG_VERSION")),
    after_help = "Environment variables (fallback when CLI arg not set):\n  \
                  RUSTSHELL_ID, RUSTSHELL_SERVER, RUSTSHELL_PORT, RUSTSHELL_KEY, \
                  RUSTSHELL_PASSWORD, RUSTSHELL_QUIT_KEY=(a-z), RUSTSHELL_DEBUG=(1|true), \
                  RUSTSHELL_NEW_SESSION=(1|true), RUSTSHELL_DETACH=(1|true)"
)]
struct Args {
    #[arg(short = 'i', long, default_value = "")] id: String,
    #[arg(short = 's', long, default_value = "")] server: String,
    #[arg(short = 'p', long, default_value = "21116")] port: u16,
    #[arg(short = 'k', long, default_value = "")] key: String,
    #[arg(short = 'w', long, default_value = "")] password: String,
    #[arg(short = 'd', long, default_value = "false")] debug: bool,
    #[arg(short = 'q', long, default_value = "q")] quit_key: char,
    /// Start a fresh terminal session instead of reattaching to the persistent one
    #[arg(short = 'n', long, default_value = "false")] new_session: bool,
    /// Write a plain-text transcript to this path (off unless set)
    #[arg(short = 'l', long, default_value = "")] log_file: String,
    /// Leave the remote shell running on quit instead of closing it
    #[arg(long, default_value = "false")] detach: bool,
    /// Session slot to attach to [default: first one not in use locally]
    #[arg(short = 't', long)] slot: Option<i32>,
    /// Do not reconnect automatically when the connection drops
    #[arg(long, default_value = "false")] no_reconnect: bool,
    /// Draw from a screen model, giving native scrollback and the pager
    #[arg(long, default_value = "false")] render: bool,
    /// 读一次本地剪贴板并报告结果，不连接。用于定位 Ctrl+V 不生效是哪一环。
    #[arg(long, default_value = "false")] clipboard_check: bool,
}

/// Why a session ended — decides whether reconnecting makes sense.
enum SessionEnd {
    /// User pressed the quit key.
    UserQuit,
    /// The remote shell exited.
    RemoteClosed,
    /// The link dropped; the remote session is likely still alive.
    Disconnected,
}

/// Terminal `service_id` used to reattach to a persistent remote session.
///
/// The remote keeps a per-`service_id` session alive with a buffer of prior
/// output, and replays it on reattach (`TerminalOpened.replay_terminal_output`).
/// A random id every run therefore means a brand-new session every run — no
/// scrollback, nothing to replay. Deriving the id from (local host, device id)
/// keeps it stable across runs without needing a state file, while staying
/// distinct per operator machine and per remote device.
fn stable_service_id(device_id: &str) -> String {
    let host = std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .or_else(|_| std::env::var("USER"))
        .or_else(|_| std::env::var("USERNAME"))
        .unwrap_or_default();
    let mut h = Sha256::new();
    h.update(b"rustshell-terminal-v1");
    h.update(host.as_bytes());
    h.update(device_id.as_bytes());
    let digest = h.finalize();
    let mut s = String::from("ts_");
    for b in &digest[..8] {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

/// zstd 压缩。对端按 `compress` 标志决定是否解压，级别随意。
fn zstd_compress(data: &[u8]) -> Vec<u8> {
    // 用 bulk 而不是 encode_all。两者都产出 zstd 帧，但 bulk 事先知道原始
    // 长度、会把它写进帧头；encode_all 是流式的，不写。实测对端解不开后者
    // 的大帧——小的能过，131KB 的过不去，而同样大小不压缩直接发反而没事。
    // 对端解压失败时返回空数据，于是长度对不上被静默丢弃，什么都不会说。
    zstd::bulk::compress(data, 3).unwrap_or_default()
}

/// zstd 解压。解不开就当空数据——一帧坏了不值得断开整个会话。
fn zstd_decompress(data: &[u8]) -> Vec<u8> {
    zstd::decode_all(data).unwrap_or_default()
}

// ── Crypto helpers ─────────────────────────────────────────────────

fn get_pk(pk: &[u8]) -> Option<[u8; 32]> {
    if pk.len() == 32 {
        let mut tmp = [0u8; 32];
        tmp[..].copy_from_slice(pk);
        Some(tmp)
    } else { None }
}

fn get_rs_pk(str_base64: &str) -> Option<sign::PublicKey> {
    use base64::Engine;
    get_pk(&base64::engine::general_purpose::STANDARD.decode(str_base64).ok()?).map(sign::PublicKey)
}

fn decode_id_pk(signed: &[u8], key: &sign::PublicKey) -> Result<(String, [u8; 32])> {
    let raw = sign::verify(signed, key).map_err(|_| anyhow::anyhow!("Signature mismatch"))?;
    let id_pk = IdPk::parse_from_bytes(&raw)?;
    let pk = get_pk(&id_pk.pk).ok_or_else(|| anyhow::anyhow!("Wrong public key length"))?;
    Ok((id_pk.id, pk))
}

fn create_symmetric_key_msg(their_pk_b: [u8; 32]) -> (Vec<u8>, Vec<u8>, secretbox::Key) {
    let their_pk_b = box_::PublicKey(their_pk_b);
    let (our_pk_b, our_sk_b) = box_::gen_keypair();
    let key = secretbox::gen_key();
    let nonce = box_::Nonce([0u8; box_::NONCEBYTES]);
    let sealed_key = box_::seal(&key.0, &nonce, &their_pk_b, &our_sk_b);
    (our_pk_b.0.to_vec(), sealed_key, key)
}

// ── Key event encoding ─────────────────────────────────────────────

use crossterm::event::{KeyCode, KeyModifiers};

fn key_event_to_bytes(code: KeyCode, modifiers: KeyModifiers) -> Vec<u8> {
    let ctrl = modifiers.contains(KeyModifiers::CONTROL);
    let alt = modifiers.contains(KeyModifiers::ALT);
    match code {
        KeyCode::Char(c) => {
            if ctrl {
                let c_lower = c.to_ascii_lowercase();
                if ('a'..='z').contains(&c_lower) { vec![(c_lower as u8) - b'a' + 1] }
                else {
                    match c_lower {
                        '[' => vec![0x1b], ']' => vec![0x1d],
                        '\\' => vec![0x1c], '^' => vec![0x1e],
                        _ => vec![c as u8],
                    }
                }
            } else if alt {
                let mut v = vec![0x1b];
                let mut buf = [0u8; 4];
                let s = c.encode_utf8(&mut buf);
                v.extend_from_slice(s.as_bytes());
                v
            } else {
                let mut buf = [0u8; 4];
                let s = c.encode_utf8(&mut buf);
                s.as_bytes().to_vec()
            }
        }
        KeyCode::Enter => vec![b'\r'],       KeyCode::Backspace => vec![0x7f],
        KeyCode::Tab => vec![b'\t'],          KeyCode::Esc => vec![0x1b],
        KeyCode::Up => vec![0x1b, b'[', b'A'], KeyCode::Down => vec![0x1b, b'[', b'B'],
        KeyCode::Right => vec![0x1b, b'[', b'C'], KeyCode::Left => vec![0x1b, b'[', b'D'],
        KeyCode::Home => vec![0x1b, b'[', b'H'], KeyCode::End => vec![0x1b, b'[', b'F'],
        KeyCode::PageUp => vec![0x1b, b'[', b'5', b'~'], KeyCode::PageDown => vec![0x1b, b'[', b'6', b'~'],
        KeyCode::Delete => vec![0x1b, b'[', b'3', b'~'], KeyCode::Insert => vec![0x1b, b'[', b'2', b'~'],
        KeyCode::F(1) => vec![0x1b, b'O', b'P'], KeyCode::F(2) => vec![0x1b, b'O', b'Q'],
        KeyCode::F(3) => vec![0x1b, b'O', b'R'], KeyCode::F(4) => vec![0x1b, b'O', b'S'],
        KeyCode::F(5) => vec![0x1b, b'[', b'1', b'5', b'~'], KeyCode::F(6) => vec![0x1b, b'[', b'1', b'7', b'~'],
        KeyCode::F(7) => vec![0x1b, b'[', b'1', b'8', b'~'], KeyCode::F(8) => vec![0x1b, b'[', b'1', b'9', b'~'],
        KeyCode::F(9) => vec![0x1b, b'[', b'2', b'0', b'~'], KeyCode::F(10) => vec![0x1b, b'[', b'2', b'1', b'~'],
        KeyCode::F(11) => vec![0x1b, b'[', b'2', b'3', b'~'], KeyCode::F(12) => vec![0x1b, b'[', b'2', b'4', b'~'],
        _ => vec![],
    }
}

// ── Windows console helpers ────────────────────────────────────────

#[cfg(windows)]
mod win_console {
    extern "system" {
        pub fn GetStdHandle(nStdHandle: u32) -> isize;
        pub fn GetConsoleMode(handle: isize, mode: *mut u32) -> i32;
        pub fn SetConsoleMode(handle: isize, mode: u32) -> i32;
        pub fn SetConsoleCP(code_page: u32) -> i32;
        pub fn SetConsoleOutputCP(code_page: u32) -> i32;
    }
    pub const STD_OUTPUT_HANDLE: u32 = (-11i32) as u32;
    pub const ENABLE_VIRTUAL_TERMINAL_PROCESSING: u32 = 0x0004;
    pub const DISABLE_NEWLINE_AUTO_RETURN: u32 = 0x0008;
}

/// Write bytes to stdout.
fn write_stdout(data: &[u8]) {
    // Tests drive the renderer directly and assert on the models; letting
    // control sequences reach the real stdout just shreds the test report.
    if cfg!(test) {
        return;
    }
    let mut stdout = std::io::stdout();
    stdout.write_all(data).ok();
    stdout.flush().ok();
}

// ── Terminal setup ─────────────────────────────────────────────────

struct ConsoleGuard;
impl ConsoleGuard {
    fn enable() -> Result<Self> {
        crossterm::terminal::enable_raw_mode()
            .context("Failed to enable raw mode")?;
        // Without this the local terminal delivers a paste as a burst of
        // individual key events, so we cannot tell pasted text from typing and
        // the remote sees a multi-line paste as line-by-line input.
        crossterm::execute!(std::io::stdout(), crossterm::event::EnableBracketedPaste).ok();
        // On Windows, enable VT100 processing on output.
        // This lets WriteFile (stdout) handle UTF-8 + escape sequences
        // natively, matching Unix terminal behavior.
        #[cfg(windows)]
        unsafe {
            let handle = win_console::GetStdHandle(win_console::STD_OUTPUT_HANDLE);
            let mut mode: u32 = 0;
            if win_console::GetConsoleMode(handle, &mut mode) != 0 {
                win_console::SetConsoleMode(handle, mode
                    | win_console::ENABLE_VIRTUAL_TERMINAL_PROCESSING
                    | win_console::DISABLE_NEWLINE_AUTO_RETURN);
            }
        }
        Ok(Self)
    }
}
impl Drop for ConsoleGuard {
    fn drop(&mut self) {
        crossterm::execute!(std::io::stdout(), crossterm::event::DisableBracketedPaste).ok();
        let _ = crossterm::terminal::disable_raw_mode();
    }
}

/// One thing the input loop needs to act on.
enum Input {
    Key(crossterm::event::KeyEvent),
    /// A whole clipboard paste, delivered in one piece by bracketed paste.
    Paste(String),
}

/// Poll local input (cross-platform, uses crossterm).
///
/// Returns events rather than encoded bytes: the scrollback viewer needs to see
/// modifiers to decide whether a key is for it or for the remote, and a paste
/// has to stay whole rather than being replayed as keystrokes.
fn poll_input() -> Option<Input> {
    use crossterm::event::{self, Event, KeyEventKind};
    if !event::poll(std::time::Duration::from_millis(0)).unwrap_or(false) {
        return None;
    }
    match event::read() {
        Ok(Event::Key(k)) if k.kind != KeyEventKind::Release => Some(Input::Key(k)),
        Ok(Event::Paste(s)) => Some(Input::Paste(s)),
        _ => None,
    }
}

// ── Scrollback viewer ──────────────────────────────────────────────

const SCROLLBACK_LINES: usize = 10_000;

/// Put the local clipboard's image onto the *remote* clipboard.
///
/// A terminal sends nothing at all when the clipboard holds an image — there is
/// no text to paste, so no paste event ever arrives. The transfer therefore has
/// to be started from here rather than driven by the remote app.
///
/// The shape of this message is not a free choice; it was measured against a
/// live remote, and three things are load-bearing:
///
/// * `ImageRgba`, not `ImagePng`. A PNG reaches the Windows clipboard only as
///   the registered "image/png" format and not as CF_DIB, so an app that asks
///   whether the clipboard holds an image is told no. RGBA writes both.
/// * `width` and `height` must be set. They are validated on arrival and a zero
///   is rejected outright, which is silent from this side.
/// * It must be wrapped in `MultiClipboards`. The bare `Clipboard` message did
///   not take effect.
///
/// Byte order passes through unchanged: RGBA in, RGBA out, no swap.
fn clipboard_image_message() -> Result<(Message, usize, u32, u32)> {
    let mut clipboard = arboard::Clipboard::new().context("open the local clipboard")?;
    let image = clipboard.get_image().context("no image on the local clipboard")?;
    build_clipboard_image(&image.bytes, image.width, image.height)
}

/// 把一张 RGBA 图装进剪贴板消息。
///
/// 与读剪贴板分开，是为了让不带剪贴板的机器（比如无头 Linux）也能测这条
/// 消息构造路径——测的必须是同一段代码，否则测了等于没测。
fn build_clipboard_image(bytes: &[u8], w: usize, h: usize) -> Result<(Message, usize, u32, u32)> {
    if w == 0 || h == 0 {
        bail!("clipboard image has no size ({w}x{h})");
    }
    // 一张截图裸 RGBA 就有约 15 MB，超过这个数只可能是搞错了，不值得占用
    // 用户一分钟的链路。
    const MAX_RAW: usize = 128 * 1024 * 1024;
    if bytes.len() > MAX_RAW {
        bail!("clipboard image is {} bytes, too large to send", bytes.len());
    }
    if bytes.len() != w * h * 4 {
        bail!("RGBA length {} does not match {w}x{h}", bytes.len());
    }

    let mut entry = Clipboard::new();
    entry.format = ClipboardFormat::ImageRgba.into();
    entry.width = w as i32;
    entry.height = h as i32;
    // 压缩是可疑环节之一，留一个开关便于二分。
    if std::env::var("RUSTSHELL_CLIP_NOCOMPRESS").is_ok() {
        entry.content = bytes.to_vec().into();
        entry.compress = false;
    } else {
        entry.content = zstd_compress(bytes).into();
        entry.compress = true;
    }
    let sent = entry.content.len();

    let mut clipboards = MultiClipboards::new();
    clipboards.clipboards.push(entry);
    let mut msg = Message::new();
    msg.set_multi_clipboards(clipboards);
    Ok((msg, sent, w as u32, h as u32))
}

/// 合成一张纯色 RGBA，用于在没有剪贴板的机器上测消息构造与发送。
fn synthetic_clipboard_image(spec: &str) -> Result<(Message, usize, u32, u32)> {
    let (w, h) = spec
        .split_once(['x', 'X'])
        .and_then(|(a, b)| Some((a.parse::<usize>().ok()?, b.parse::<usize>().ok()?)))
        .ok_or_else(|| anyhow::anyhow!("expected WxH, got {spec:?}"))?;
    // 用一段不可压缩的图案，否则纯色图压缩后只剩几十字节，测不到大载荷。
    let mut bytes = Vec::with_capacity(w * h * 4);
    let mut state: u32 = 0x1234_5678;
    for _ in 0..(w * h) {
        state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        let b = state.to_le_bytes();
        bytes.extend_from_slice(&[b[0], b[1], b[2], 0xff]);
    }
    build_clipboard_image(&bytes, w, h)
}

/// Spot a repaint that is really a scroll.
///
/// ConPTY does not scroll on behalf of a full-screen app; it moves the cursor
/// and rewrites rows, so no line is ever pushed off the top and nothing *looks*
/// retired. But if the top of the new screen is a run of rows that used to sit
/// lower down on the old screen, the content did move up — by exactly that far.
fn detect_scroll(prev: &[String], cur: &[String]) -> usize {
    let rows = prev.len();
    if rows == 0 || cur.len() != rows {
        return 0;
    }

    // 探测窗口取内容最密集的一段，而不是屏幕最顶上那几行。
    //
    // 这是实测逼出来的：Claude Code 的布局是顶部一片空白填充、对话在中间、
    // 状态栏钉在底部。从顶部取窗口，取到的全是空行，「窗口太空就放弃」的
    // 保护于是把整个检测关掉了——真机上 moved 恒为 0，一行历史都留不下。
    let window = (rows / 5).clamp(3, 6).min(rows);
    let substance = |row: &String| {
        // NUL 是终端填充，算空白；否则一屏 NUL 会被当成有内容。
        !row.chars().all(|c| c.is_whitespace() || c == '\0')
    };
    let score = |slice: &[String]| -> usize {
        let mut seen: Vec<&str> = Vec::new();
        for row in slice.iter().filter(|r| substance(r)) {
            let t = row.trim();
            if !seen.contains(&t) {
                seen.push(t);
            }
        }
        // 只数**不重复**的非空行。重复行（边框、分隔线）到处都能匹配上，
        // 拿它们当锚点会指向错误的位置。
        seen.len()
    };

    // 候选窗口按得分从高到低依次试。只取最高分的那一个不行：得分相同的窗口
    // 很多，而挑中靠近屏幕底部的那个时，它在上一帧里正好落在固定框上，永远
    // 匹配不上——实测就是这样让检测失效的。
    let mut candidates: Vec<usize> = (0..=(rows - window)).collect();
    candidates.sort_by_key(|&i| std::cmp::Reverse(score(&cur[i..i + window])));

    for at in candidates.into_iter().take(8) {
        let probe = &cur[at..at + window];
        if score(probe) < 3 {
            break;
        }
        // 这段内容在上一帧里的位置。当时更靠下，就说明内容整体上移了。
        if let Some(before) = (0..=(rows - window)).find(|&i| &prev[i..i + window] == probe) {
            if before > at {
                return before - at;
            }
            // 位置没动或反而更靠上，这个锚点说明不了滚动，换下一个候选。
        }
    }
    0
}

/// The screen, modelled twice.
///
/// A Windows remote drives ConPTY, which repaints in place with absolute cursor
/// moves instead of pushing lines upward. Passing that stream straight through
/// is why the local terminal's own scrollback stayed empty: nothing ever
/// scrolled, so the wheel and the scrollbar had nothing to show.
///
/// So we stop passing it through. `model` is the authoritative remote screen;
/// `host` mirrors what the local terminal is actually displaying. Each frame we
/// work out how many lines left the top of the screen, scroll the local terminal
/// by that many so they land in its *real* scrollback, then send the minimal
/// diff to bring the viewport into line. Ordinary shell output then scrolls
/// natively, with the wheel.
///
/// That covers the main screen only. A full-screen app — Claude Code, vim —
/// runs in the alternate screen, where a terminal keeps no history at all by
/// design, so there is nowhere native for its output to go. Those lines are
/// archived in `history` and reachable through the built-in pager, which is the
/// same bargain tmux and screen strike with their copy modes.
struct Screen {
    model: vt100::Parser,
    /// What the local terminal is showing. Needed because a diff can only be
    /// computed against the state the receiver is actually in.
    host: vt100::Parser,
    /// Lines that have left the screen, oldest first, formatted for replay.
    history: std::collections::VecDeque<Vec<u8>>,
    /// Last frame's visible rows: plain for spotting a scroll, formatted for
    /// archiving the rows it retired.
    prev_plain: Vec<String>,
    prev_formatted: Vec<Vec<u8>>,
    /// Lines paged back; 0 means the live view.
    offset: usize,
    rows: u16,
    cols: u16,
    /// Alternate-screen state the model was last seen in.
    alt: bool,
    /// A short message parked on the last row, and when it was set.
    ///
    /// Clipboard transfers fail in ways nothing else can report: the local
    /// clipboard may hold no image, and a remote that drops the message says
    /// nothing back. Logging to stderr is not an option — it would write past
    /// the screen model — so status goes through the renderer like everything
    /// else.
    status: Option<(String, std::time::Instant)>,
    /// Bytes straight to the terminal, no modelling.
    passthrough: bool,
    /// vt100 history length as of the last absorb.
    drawn_history: usize,
    /// 自上次渲染以来退役的行，等着被推进宿主终端的滚动缓冲。
    pending: Vec<Vec<u8>>,
}

impl Screen {
    fn new(rows: u16, cols: u16) -> Self {
        Self {
            model: vt100::Parser::new(rows, cols, SCROLLBACK_LINES),
            // The real terminal keeps the main screen's history, and our own
            // buffer keeps the alternate screen's, so this one needs none.
            host: vt100::Parser::new(rows, cols, 0),
            history: std::collections::VecDeque::new(),
            prev_plain: Vec::new(),
            prev_formatted: Vec::new(),
            offset: 0,
            rows,
            cols,
            alt: false,
            status: None,
            passthrough: true,
            drawn_history: 0,
            pending: Vec::new(),
        }
    }

    /// Write to the terminal and keep the host model in step.
    ///
    /// Every byte the terminal receives has to go through here, or the next
    /// diff is computed against a state the terminal is not in and the output
    /// lands in the wrong place.
    fn emit(&mut self, bytes: &[u8]) {
        if bytes.is_empty() {
            return;
        }
        write_stdout(bytes);
        self.host.process(bytes);
    }

    /// Park a message on the last row for a few seconds.
    fn set_status(&mut self, text: impl Into<String>) {
        if self.passthrough {
            let t = text.into();
            write_stdout(format!("
[rustshell] {t}
").as_bytes());
            return;
        }
        self.status = Some((text.into(), std::time::Instant::now()));
    }

    /// The status line, while it is still worth showing.
    fn status_line(&self) -> Option<Vec<u8>> {
        let (text, since) = self.status.as_ref()?;
        if since.elapsed() > std::time::Duration::from_secs(4) {
            return None;
        }
        let width = self.cols as usize;
        let mut text = format!(" {text} ");
        text.truncate(width);
        Some(format!("\x1b[{};1H\x1b[7m{}\x1b[0m", self.rows, text).into_bytes())
    }

    /// Show a local notice, keeping the host model aware of it.
    fn note(&mut self, text: &str) {
        let bytes = text.replace('\n', "\r\n").into_bytes();
        if self.passthrough {
            write_stdout(&bytes);
            return;
        }
        self.emit(&bytes);
    }

    /// 是否在建模渲染。直通模式下很多处理没有意义，甚至有害。
    fn renders(&self) -> bool {
        !self.passthrough
    }

    #[cfg(test)]
    fn history_len(&self) -> usize {
        self.history.len()
    }

    /// How many lines of history vt100 itself holds.
    ///
    /// `set_scrollback` clamps to what actually exists and the clamped value is
    /// readable back, so asking for more than possible reports the real length.
    /// Note this *falls to zero* on entering the alternate screen.
    fn vt_history(&mut self) -> usize {
        self.model.set_scrollback(usize::MAX);
        let len = self.model.screen().scrollback();
        self.model.set_scrollback(0);
        len
    }

    /// The formatted contents of vt100 history line `index`, out of `total`.
    fn vt_history_line(&mut self, total: usize, index: usize) -> Vec<u8> {
        // At scrollback offset s the top visible row is history line total - s.
        self.model.set_scrollback(total - index);
        let mut row = self
            .model
            .screen()
            .rows_formatted(0, self.cols)
            .next()
            .unwrap_or_default();
        self.model.set_scrollback(0);
        // A formatted row leaves its attributes applied; without this they
        // would bleed into the line printed after it.
        row.extend_from_slice(b"\x1b[m");
        row
    }

    fn archive(&mut self, line: Vec<u8>) {
        if self.history.len() >= SCROLLBACK_LINES {
            self.history.pop_front();
        }
        self.history.push_back(line);
    }

    /// Absorb remote output and update the terminal.
    /// 收下字节，先不画。
    ///
    /// ConPTY 会把一屏重绘拆成好几个 Data 帧发过来。收一帧画一帧的话，滚动
    /// 检测会在重绘只完成一半时命中，被推进滚动缓冲的就是画了一半的行——历史
    /// 里于是全是某一行的前缀，看着像是被截断了。
    fn absorb(&mut self, data: &[u8]) {
        if self.passthrough {
            write_stdout(data);
            return;
        }
        let before = self.drawn_history;
        self.model.process(data);
        let after = self.vt_history();
        self.drawn_history = after;

        // 检测与归档必须按帧做，不能等到渲染时刻。
        //
        // 模型逐字节处理了每一个中间状态，但两次渲染之间可能经过几十帧；只在
        // 渲染时刻比较前后快照的话，中间状态就从眼皮底下流走了。实测抓到过一
        // 次刷新之间屏幕从横幅直接跳到第 41 行——跳了 40 行，30 行的屏幕前后
        // 零重叠，那 40 行于是永远找不回来。
        let natural = after.saturating_sub(before);
        let cur_plain: Vec<String> = self.model.screen().rows(0, self.cols).collect();
        let moved = if natural > 0 {
            natural
        } else {
            detect_scroll(&self.prev_plain, &cur_plain)
        };

        if natural > 0 {
            for index in before..after {
                let line = self.vt_history_line(after, index);
                self.pending.push(line);
            }
        } else if moved > 0 {
            let take = moved.min(self.prev_formatted.len());
            let lines: Vec<Vec<u8>> = self.prev_formatted.iter().take(take).cloned().collect();
            self.pending.extend(lines);
        }

        if moved > 0 {
            log::debug!(
                "absorb: natural={natural} moved={moved} pending={} hist={}",
                self.pending.len(),
                self.history.len()
            );
        }

        self.prev_plain = cur_plain;
        self.prev_formatted = self.model.screen().rows_formatted(0, self.cols).collect();
    }

    /// 收下并立刻画出来。等价于 absorb 后紧跟 flush。
    fn feed(&mut self, data: &[u8]) {
        self.absorb(data);
        self.flush();
    }

    /// 把模型当前的状态画到终端上。
    ///
    /// 与 absorb 分开，是为了只在一次重绘完整落地之后才做滚动检测。
    fn flush(&mut self) {
        if self.passthrough {
            return;
        }
        let alt = self.model.screen().alternate_screen();
        let rows = self.rows as usize;

        // absorb 已经按帧检测并攒好了退役的行，这里只管画。
        let retired = std::mem::take(&mut self.pending);
        for line in &retired {
            self.archive(line.clone());
        }

        // 翻页回看时视图冻结，但 offset 从底部往回数，历史一长就得跟着走，
        // 否则同一个 offset 会指向别的内容。
        if self.offset > 0 {
            if !retired.is_empty() {
                self.offset = (self.offset + retired.len()).min(self.history.len());
            }
            return;
        }

        // 备用屏幕不镜像到本地：终端不为它保留滚动缓冲，而 iTerm2 和
        // Terminal.app 在应用处于备用屏幕时会把滚轮发成方向键。整屏切换时
        // 内容会全变，diff 跨不过去，直接重画。
        if alt != self.alt {
            self.alt = alt;
            self.repaint(false);
            return;
        }

        let mut out: Vec<u8> = Vec::with_capacity(4096);
        if !retired.is_empty() {
            // 在最后一行换行是唯一能让终端滚动的办法，而滚动是行进入它自己
            // 滚动缓冲的唯一途径。还在屏幕上的行会带着自己的格式一起上去，
            // 所以只需要滚。
            out.extend_from_slice(format!("\x1b[{};1H", self.rows).as_bytes());
            for _ in 0..retired.len().min(rows) {
                out.extend_from_slice(b"\r\n");
            }
            if retired.len() > rows {
                // 这些从没到过终端，得先写出来再滚走，否则进缓冲是空行。
                for line in &retired[rows..] {
                    out.extend_from_slice(b"\x1b[2K");
                    out.extend_from_slice(line);
                    out.extend_from_slice(b"\r\n");
                }
            }
        }
        self.emit(&out);

        let diff = self.model.screen().contents_diff(self.host.screen());
        self.emit(&diff);

        // 状态行每帧重画，因为远端应用一直在覆盖最后一行。
        if let Some(line) = self.status_line() {
            self.emit(&line);
        } else if self.status.is_some() {
            self.status = None;
            self.repaint(false);
        }
    }

    /// 吸收重连回放。返回 true 表示需要请远端重画一次。
    fn feed_replay(&mut self, data: &[u8]) -> bool {
        // 回放一律先过屏幕模型，直通模式也不例外。
        //
        // 那段字节流是流水账——上次会话最后 8KB 的原始输出，从任意位置切断，
        // 里面有多个历史提示符、跑过又退出的程序的残迹，以及大量假定了某个
        // 屏幕状态的绝对光标定位。原样倒进终端就是一坨；因为远端缓冲内容不变，
        // 每次重连还乱得一模一样。
        //
        // 但它本身就是终端指令序列：让 vt100 跑一遍，得到的就是「这个会话现在
        // 的屏幕」。画那一屏，而不是画流水账，也不是丢掉——丢掉的话，会话里
        // 如果正跑着全屏应用，你会连它的界面都看不到。
        self.model.process(data);
        self.model.set_scrollback(0);
        self.prev_plain = self.model.screen().rows(0, self.cols).collect();
        self.prev_formatted = self.model.screen().rows_formatted(0, self.cols).collect();

        if self.passthrough {
            // 直通模式没有宿主模型，所以这里直接写：先把终端清成已知状态，
            // 再画出重建的这一屏。之后的实时输出接着这个画面往下走。
            let mut out: Vec<u8> = Vec::with_capacity(8192);
            out.extend_from_slice(b"\x1b[?1049l\x1b[?7h\x1b[r\x1b[0m\x1b[H\x1b[2J");
            out.extend_from_slice(&self.model.screen().contents_formatted());
            write_stdout(&out);
            // 重建出来的画面就是当前状态，不需要再请远端重画。
            return false;
        }

        self.repaint(true);
        false
    }

    fn resize(&mut self, rows: u16, cols: u16) {
        if self.passthrough {
            self.rows = rows;
            self.cols = cols;
            return;
        }
        self.model.set_size(rows, cols);
        self.host.set_size(rows, cols);
        self.rows = rows;
        self.cols = cols;
        self.prev_plain = self.model.screen().rows(0, cols).collect();
        self.prev_formatted = self.model.screen().rows_formatted(0, cols).collect();
    }

    fn active(&self) -> bool {
        self.offset > 0
    }

    /// Move the view by `delta` half-screens. Returns true if it moved.
    fn page(&mut self, delta: i32) -> bool {
        if self.passthrough {
            return false;
        }
        let step = std::cmp::max(1, (self.rows / 2) as i64);
        let limit = self.history.len() as i64;
        let target = (self.offset as i64 + delta as i64 * step).clamp(0, limit) as usize;
        if target == self.offset {
            return false;
        }
        self.offset = target;
        true
    }

    fn to_live(&mut self) {
        self.offset = 0;
    }

    /// The rows the pager is showing.
    ///
    /// The archive and the live screen form one continuous buffer; `offset`
    /// windows it. At offset 0 that is just the live screen.
    fn view(&self) -> Vec<Vec<u8>> {
        let live: Vec<Vec<u8>> = self.model.screen().rows_formatted(0, self.cols).collect();
        let rows = self.rows as usize;
        let total = self.history.len() + live.len();
        let start = total.saturating_sub(rows + self.offset);
        (0..rows)
            .map_while(|r| {
                let index = start + r;
                if index >= total {
                    return None;
                }
                Some(if index < self.history.len() {
                    self.history[index].clone()
                } else {
                    // Archived lines already carry a reset; give the live ones
                    // one too, so every row in the view is self-terminating and
                    // attributes cannot bleed into the row below.
                    let mut row = live[index - self.history.len()].clone();
                    row.extend_from_slice(b"\x1b[m");
                    row
                })
            })
            .collect()
    }

    /// Repaint from the model. Used for the pager and after a replay.
    fn render(&mut self) {
        self.repaint(false)
    }

    /// Repaint the whole screen.
    ///
    /// `fresh` is for the point where the terminal may be carrying state we do
    /// not own — a scroll region, a half-applied SGR, or our own connection
    /// logs. The model is authoritative, so that state is cleared first; rather
    /// than erasing what is on screen, it is scrolled away, which keeps it
    /// reachable in the terminal's scrollback.
    fn repaint(&mut self, fresh: bool) {
        if self.passthrough {
            return;
        }
        self.alt = self.model.screen().alternate_screen();
        let mut out: Vec<u8> = Vec::with_capacity(8192);
        if fresh {
            // leave any alternate screen we are somehow in, restore wrap, drop
            // the scroll region, clear SGR
            out.extend_from_slice(b"\x1b[?1049l\x1b[?7h\x1b[r\x1b[0m");
            out.extend_from_slice(format!("\x1b[{};1H", self.rows).as_bytes());
            for _ in 0..self.rows {
                out.extend_from_slice(b"\r\n");
            }
            out.extend_from_slice(b"\x1b[H");
        } else {
            out.extend_from_slice(b"\x1b[H\x1b[2J");
        }

        if self.offset == 0 {
            out.extend_from_slice(&self.model.screen().contents_formatted());
        } else {
            // Paged back: the view spans our archive and the live screen, so it
            // is assembled row by row rather than handed over by vt100.
            for (r, line) in self.view().into_iter().enumerate() {
                out.extend_from_slice(format!("\x1b[{};1H\x1b[2K", r + 1).as_bytes());
                out.extend_from_slice(&line);
            }
            // Park a hint on the last row so it is obvious the view is frozen.
            out.extend_from_slice(
                format!(
                    "\x1b[{};1H\x1b[7m -- SCROLLBACK -{} lines | Shift+PgDn forward, Shift+End live -- \x1b[0m",
                    self.rows, self.offset
                )
                .as_bytes(),
            );
        }
        // A full repaint invalidates whatever the host model held.
        self.host = vt100::Parser::new(self.rows, self.cols, 0);
        if let Some(line) = self.status_line() {
            out.extend_from_slice(&line);
        }
        self.emit(&out);
    }
}

/// Keys the scrollback viewer owns. Shift-modified so they cannot collide with
/// what a full-screen remote app expects to receive.
fn scrollback_key(ev: &crossterm::event::KeyEvent) -> Option<i32> {
    use crossterm::event::{KeyCode, KeyModifiers};
    if !ev.modifiers.contains(KeyModifiers::SHIFT) {
        return None;
    }
    // Positive moves *back* into history, matching how `offset` is counted.
    match ev.code {
        KeyCode::PageUp => Some(1),
        KeyCode::PageDown => Some(-1),
        KeyCode::Home => Some(i32::MAX),
        KeyCode::End => Some(i32::MIN),
        _ => None,
    }
}

// ── Stream helpers ─────────────────────────────────────────────────

async fn recv_raw(conn: &mut Link, step: &str) -> Result<bytes::BytesMut> {
    match conn.next().await {
        Some(Ok(b)) => { log::debug!("[{step}] received {} bytes", b.len()); Ok(b) }
        Some(Err(e)) => bail!("[{step}] stream error: {e}"),
        None => bail!("[{step}] connection closed by peer"),
    }
}

async fn recv_msg(conn: &mut Link, step: &str) -> Result<Message> {
    let bytes = recv_raw(conn, step).await?;
    Message::parse_from_bytes(&bytes)
        .with_context(|| format!("[{step}] failed to parse Message"))
}

async fn recv_rendezvous_msg(conn: &mut Link, step: &str) -> Result<RendezvousMessage> {
    let bytes = recv_raw(conn, step).await?;
    RendezvousMessage::parse_from_bytes(&bytes)
        .with_context(|| format!("[{step}] failed to parse RendezvousMessage"))
}

async fn send_msg(conn: &mut Link, msg: &impl ProtoMessage, step: &str) -> Result<()> {
    timeout(CONNECT_TIMEOUT, conn.send(msg)).await
        .with_context(|| format!("[{step}] timeout sending message"))??;
    log::debug!("[{step}] sent message");
    Ok(())
}

// ── Main ───────────────────────────────────────────────────────────

fn main() {
    // Windows: set console to UTF-8 codepage
    #[cfg(windows)]
    unsafe {
        win_console::SetConsoleCP(65001);
        win_console::SetConsoleOutputCP(65001);
    }

    let mut args = Args::parse();

    // Fill empty fields from RUSTSHELL_* environment variables
    if args.id.is_empty() { args.id = std::env::var("RUSTSHELL_ID").unwrap_or_default(); }
    if args.server.is_empty() { args.server = std::env::var("RUSTSHELL_SERVER").unwrap_or_default(); }
    if args.port == 21116 { if let Ok(v) = std::env::var("RUSTSHELL_PORT") { if let Ok(p) = v.parse() { args.port = p; } } }
    if args.key.is_empty() { args.key = std::env::var("RUSTSHELL_KEY").unwrap_or_default(); }
    if !args.debug { args.debug = std::env::var("RUSTSHELL_DEBUG").map(|v| v == "1" || v.eq_ignore_ascii_case("true")).unwrap_or(false); }
    if args.password.is_empty() { args.password = std::env::var("RUSTSHELL_PASSWORD").unwrap_or_default(); }
    if args.quit_key == 'q' { if let Ok(v) = std::env::var("RUSTSHELL_QUIT_KEY") { if let Some(c) = v.chars().next() { args.quit_key = c; } } }
    if !args.new_session { args.new_session = std::env::var("RUSTSHELL_NEW_SESSION").map(|v| v == "1" || v.eq_ignore_ascii_case("true")).unwrap_or(false); }
    if args.log_file.is_empty() { args.log_file = std::env::var("RUSTSHELL_LOG_FILE").unwrap_or_default(); }
    if !args.detach { args.detach = std::env::var("RUSTSHELL_DETACH").map(|v| v == "1" || v.eq_ignore_ascii_case("true")).unwrap_or(false); }
    if args.slot.is_none() { if let Ok(v) = std::env::var("RUSTSHELL_SLOT") { if let Ok(n) = v.parse() { args.slot = Some(n); } } }
    if !args.render { args.render = std::env::var("RUSTSHELL_RENDER").map(|v| v == "1" || v.eq_ignore_ascii_case("true")).unwrap_or(false); }
    if !args.no_reconnect { args.no_reconnect = std::env::var("RUSTSHELL_NO_RECONNECT").map(|v| v == "1" || v.eq_ignore_ascii_case("true")).unwrap_or(false); }

    if args.clipboard_check {
        match clipboard_image_message() {
            Ok((_, bytes, w, h)) => {
                println!("clipboard: 图片 {w}x{h}，压缩后 {bytes} 字节，可以发送");
            }
            Err(e) => println!("clipboard: 读不到图片 —— {e:#}"),
        }
        return;
    }

    if args.id.is_empty() { eprintln!("Error: --id or RUSTSHELL_ID is required"); std::process::exit(1); }
    if args.server.is_empty() { eprintln!("Error: --server or RUSTSHELL_SERVER is required"); std::process::exit(1); }
    if !args.quit_key.is_ascii_alphabetic() { eprintln!("Error: --quit-key must be an ASCII letter a-z"); std::process::exit(1); }

    let log_level = if args.debug { "debug" } else { "info" };
    env_logger::init_from_env(env_logger::Env::default().filter_or("RUST_LOG", log_level));

    let password = if args.password.is_empty() {
        match rpassword::prompt_password("Enter password: ") {
            Ok(p) => p,
            Err(e) => { eprintln!("Failed to read password: {}", e); std::process::exit(1); }
        }
    } else { args.password };

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all().build().expect("tokio runtime");

    // Opt-in only. Writing a transcript per run by default silently filled the
    // user's home directory with megabytes of logs nobody asked for.
    let log_path: Option<std::path::PathBuf> = if args.log_file.is_empty() {
        None
    } else {
        Some(std::path::PathBuf::from(&args.log_file))
    };

    // Pin the session identity before connecting: the service_id decides which
    // remote session we reattach to, and the slot keeps concurrent windows off
    // each other's terminal. Both must survive reconnects, so they live here
    // rather than inside run().
    let base = stable_service_id(&args.id);
    let slot = TerminalSlot::acquire(&base, args.slot);
    // The remote broadcasts a service's output to every client attached to that
    // service_id, so two windows sharing one service_id see each other's shell
    // even with distinct terminal_ids. Isolation has to happen here: one
    // service_id per slot, stable per slot so each window reattaches to its own.
    let service_id = if args.new_session {
        format!("ts_{}", uuid::Uuid::new_v4())
    } else {
        format!("{}s{}", base, slot.id)
    };
    log::info!(
        "Terminal session: {} (slot {}, {})",
        service_id, slot.id,
        if args.new_session { "new" } else { "reattach if it exists" }
    );

    let mut attempt: u32 = 0;
    loop {
        let outcome = rt.block_on(run(
            args.id.clone(), args.key.clone(), args.server.clone(), args.port,
            password.clone(), args.quit_key, service_id.clone(), &slot,
            log_path.clone(), args.detach, args.render, args.new_session,
        ));
        let _ = crossterm::terminal::disable_raw_mode();

        let should_retry = match &outcome {
            Ok(SessionEnd::UserQuit) => { break; }
            Ok(SessionEnd::RemoteClosed) => { break; }
            Ok(SessionEnd::Disconnected) => true,
            Err(e) => {
                eprintln!("\r\nError: {:#}", e);
                // A failure before the first successful session is usually a
                // bad address or password — retrying would just repeat it.
                attempt > 0
            }
        };

        if !should_retry || args.no_reconnect {
            if matches!(outcome, Err(_)) { std::process::exit(1); }
            break;
        }

        attempt += 1;
        // 2s, 4s, 8s ... capped at 30s.
        let delay = std::cmp::min(2u64.saturating_pow(attempt.min(5)), 30);
        eprintln!("\r\nConnection lost. Reconnecting in {}s (attempt {})...", delay, attempt);
        std::thread::sleep(std::time::Duration::from_secs(delay));
    }
}

async fn run(
    device_id: String, licence_key: String,
    server: String, port: u16, password: String,
    quit_key: char, service_id: String, slot: &TerminalSlot,
    log_path: Option<std::path::PathBuf>, detach: bool, render: bool, new_session: bool,
) -> Result<SessionEnd> {
    let rendezvous_addr = format!("{}:{}", server, port);
    log::info!("Connecting to rendezvous server {}...", rendezvous_addr);

    // Phase 1: Connect to rendezvous server
    let mut socket = Link::connect(&rendezvous_addr.clone(), CONNECT_TIMEOUT).await
        .with_context(|| format!("Failed to connect to {}", rendezvous_addr))?;
    log::info!("TCP connected to rendezvous server");

    let key_str: &str = if licence_key.is_empty() { RS_PUB_KEY } else { &licence_key };
    attempt_secure_tcp(&mut socket, key_str).await?;

    // Send PunchHoleRequest
    let mut msg_out = RendezvousMessage::new();
    msg_out.set_punch_hole_request(PunchHoleRequest {
        id: device_id.clone(), licence_key: licence_key.clone(),
        conn_type: ConnType::TERMINAL.into(),
        nat_type: NatType::SYMMETRIC.into(), force_relay: false,
        version: VERSION.to_owned(), ..Default::default()
    });
    log::info!("Requesting connection to device {}...", device_id);
    send_msg(&mut socket, &msg_out, "punch_hole_request").await?;

    // Wait for response
    let rmsg = recv_rendezvous_msg(&mut socket, "wait_rendezvous_response").await?;
    let (peer_pk_from_server, relay_server, relay_uuid, try_direct) = match rmsg.union {
        Some(rendezvous_message::Union::PunchHoleResponse(ph)) => {
            if let Some(addr) = link::decode_peer_addr(&ph.socket_addr) {
                let relay = if ph.relay_server.is_empty() {
                    increase_port(&rendezvous_addr, 1)
                } else { check_port(ph.relay_server.clone(), RELAY_PORT) };
                log::info!("Peer address: {} (local: {}), relay fallback: {}", addr, ph.is_local(), relay);
                (ph.pk.to_vec(), relay, String::new(), Some(addr))
            } else {
                use punch_hole_response::Failure;
                let reason = match ph.failure.enum_value() {
                    Ok(Failure::ID_NOT_EXIST) => "ID does not exist",
                    Ok(Failure::OFFLINE) => "Remote device is offline",
                    Ok(Failure::LICENSE_MISMATCH) => "Key mismatch",
                    Ok(Failure::LICENSE_OVERUSE) => "Key overuse",
                    _ => &ph.other_failure,
                };
                bail!("Connection refused: {}", reason);
            }
        }
        Some(rendezvous_message::Union::RelayResponse(rr)) => {
            let relay = if rr.relay_server.is_empty() {
                increase_port(&rendezvous_addr, 1)
            } else { check_port(rr.relay_server, RELAY_PORT) };
            log::info!("Relay assigned: {} (uuid: {})", relay, rr.uuid);
            let pk = match rr.union {
                Some(relay_response::Union::Pk(pk)) => pk.to_vec(),
                _ => Vec::new(),
            };
            (pk, relay, rr.uuid, None)
        }
        other => bail!("Unexpected response: {:?}", other.map(|_| "unknown")),
    };

    // Phase 2: Connect — try direct first, fall back to relay
    let mut conn = if let Some(addr) = try_direct {
        let direct_addr = format!("{}:{}", addr.ip(), addr.port());
        log::info!("Trying direct connection to {}...", direct_addr);
        match Link::connect(&direct_addr, CONNECT_TIMEOUT).await {
            Ok(c) => {
                log::info!("Direct connection established");
                c
            }
            Err(e) => {
                log::info!("Direct failed ({}), falling back to relay {}", e, relay_server);
                let mut c = Link::connect(&relay_server.clone(), CONNECT_TIMEOUT).await
                    .with_context(|| format!("Failed to connect to relay {}", relay_server))?;
                // Send RequestRelay for relay
                let mut msg_out = RendezvousMessage::new();
                msg_out.set_request_relay(RequestRelay {
                    id: device_id.clone(), uuid: relay_uuid,
                    licence_key: licence_key.clone(),
                    conn_type: ConnType::TERMINAL.into(), ..Default::default()
                });
                send_msg(&mut c, &msg_out, "request_relay").await?;
                c
            }
        }
    } else {
        log::info!("Connecting via relay server {}...", relay_server);
        let mut c = Link::connect(&relay_server.clone(), CONNECT_TIMEOUT).await
            .with_context(|| format!("Failed to connect to relay {}", relay_server))?;
        let mut msg_out = RendezvousMessage::new();
        msg_out.set_request_relay(RequestRelay {
            id: device_id.clone(), uuid: relay_uuid,
            licence_key: licence_key.clone(),
            conn_type: ConnType::TERMINAL.into(), ..Default::default()
        });
        send_msg(&mut c, &msg_out, "request_relay").await?;
        c
    };

    // Phase 3: E2E key exchange
    let rs_pk = get_rs_pk(key_str).context("Invalid rendezvous server key")?;
    let peer_sign_pk = if !peer_pk_from_server.is_empty() {
        let (vouched_id, pk) = decode_id_pk(&peer_pk_from_server, &rs_pk)
            .context("Failed to verify peer key from rendezvous")?;
        log::debug!("Peer key vouched: {}", vouched_id);
        Some(sign::PublicKey(pk))
    } else { None };

    let msg_in = recv_msg(&mut conn, "wait_signed_id").await?;
    let signed_id = match msg_in.union {
        Some(message::Union::SignedId(si)) => si,
        other => bail!("Expected SignedId, got: {:?}", other.map(|_| "other")),
    };
    let peer_sign_pk = peer_sign_pk
        .ok_or_else(|| anyhow::anyhow!("No peer public key from rendezvous server"))?;
    let (peer_id, their_pk) = decode_id_pk(&signed_id.id, &peer_sign_pk)?;
    log::info!("Peer identity verified: {}", peer_id);

    let (av, sv, enc_key) = create_symmetric_key_msg(their_pk);
    let mut pk_msg = Message::new();
    pk_msg.set_public_key(PublicKey { asymmetric_value: av.into(), symmetric_value: sv.into(), ..Default::default() });
    send_msg(&mut conn, &pk_msg, "public_key").await?;
    conn.set_key(enc_key);
    log::info!("End-to-end encryption established");

    // Phase 4: Password authentication
    let msg_in = recv_msg(&mut conn, "wait_hash").await?;
    let hash = match msg_in.union {
        Some(message::Union::Hash(h)) => h,
        _ => bail!("Expected Hash challenge"),
    };
    let mut h1 = Sha256::new();
    h1.update(password.as_bytes()); h1.update(hash.salt.as_bytes());
    let mut h2 = Sha256::new();
    h2.update(&h1.finalize()[..]); h2.update(hash.challenge.as_bytes());
    let pw_response: Vec<u8> = h2.finalize()[..].into();

    // Phase 5: Login with Terminal
    let mut lr = LoginRequest::new();
    lr.username = device_id.clone(); lr.password = pw_response.into();
    lr.my_id = format!("RustShell-{}", std::process::id());
    lr.version = VERSION.to_owned();
    lr.my_platform = std::env::consts::OS.to_owned();
    // Without this the remote tears the whole service down as soon as we
    // disconnect (`if !is_persistent { remove_service() }`), so there is nothing
    // left to reattach to and no buffered output to replay. rustshell never sent
    // an OptionMessage at all, which is why sessions never survived.
    let mut opt = OptionMessage::new();
    opt.terminal_persistent = option_message::BoolOption::Yes.into();
    lr.option = protobuf::MessageField::some(opt);

    let mut terminal = Terminal::new();
    // Reattach to the persistent session so the remote replays its buffered
    // output; the caller owns this id so it survives reconnects.
    terminal.service_id = service_id;
    lr.set_terminal(terminal);
    let mut lr_msg = Message::new();
    lr_msg.set_login_request(lr);
    send_msg(&mut conn, &lr_msg, "login_request").await?;
    log::info!("Login request sent");

    let bytes = recv_raw(&mut conn, "wait_login_response").await?;
    log::debug!("Login response raw bytes ({}): {:02x?}", bytes.len(), bytes.as_ref());
    // Some server versions send LoginResponse directly (not wrapped in Message).
    // Try Message first, then fall back to raw LoginResponse.
    let lr = match Message::parse_from_bytes(&bytes) {
        Ok(m) => match m.union {
            Some(message::Union::LoginResponse(lr)) => lr,
            Some(message::Union::TerminalResponse(_)) => {
                log::debug!("Early terminal response, proceeding");
                LoginResponse::new()
            }
            _ => LoginResponse::parse_from_bytes(&bytes).unwrap_or_default(),
        },
        Err(_) => LoginResponse::parse_from_bytes(&bytes).unwrap_or_default(),
    };
    let mut remote_platform = String::new();
    match lr.union {
        Some(login_response::Union::Error(err)) if !err.is_empty() => bail!("Login failed: {}", err),
        Some(login_response::Union::PeerInfo(pi)) => {
            log::info!("Connected to {} ({} {})", pi.hostname, pi.platform, pi.version);
            remote_platform = pi.platform;
        }
        _ => {
            log::debug!("Login accepted (no peer info, empty response)");
            log::warn!("Server did not provide platform info — terminal access may be unsupported on this host");
        }
    }

    // Phase 6: Terminal I/O
    terminal_io_loop(&mut conn, &remote_platform, quit_key, render, new_session, slot, log_path, detach).await
}

// ── secure_tcp ─────────────────────────────────────────────────────

async fn attempt_secure_tcp(conn: &mut Link, key: &str) -> Result<()> {
    let rs_pk = match get_rs_pk(key) {
        Some(pk) => pk,
        None => { log::debug!("No valid key, skipping secure_tcp"); return Ok(()); }
    };
    match timeout(3000, conn.next()).await {
        Ok(Some(Ok(bytes))) => {
            let rmsg = match RendezvousMessage::parse_from_bytes(&bytes) {
                Ok(m) => m, Err(_) => { log::debug!("Non-protobuf, skipping"); return Ok(()); }
            };
            let ex = match rmsg.union {
                Some(rendezvous_message::Union::KeyExchange(ex)) => ex,
                _ => { log::debug!("No KeyExchange, proceeding"); return Ok(()); }
            };
            if ex.keys.len() != 1 { log::warn!("Invalid KeyExchange"); return Ok(()); }
            let their_pk_b = match sign::verify(&ex.keys[0], &rs_pk) {
                Ok(pk) => pk, Err(_) => { log::warn!("Sig verify failed"); return Ok(()); }
            };
            let their_pk = match get_pk(&their_pk_b) {
                Some(pk) => pk, None => { log::warn!("Invalid pk len"); return Ok(()); }
            };
            let (av, sv, enc) = create_symmetric_key_msg(their_pk);
            let mut mo = RendezvousMessage::new();
            mo.set_key_exchange(KeyExchange { keys: vec![av.into(), sv.into()], ..Default::default() });
            send_msg(conn, &mo, "key_exchange_response").await?;
            conn.set_key(enc);
            log::info!("Secure channel with rendezvous server");
        }
        Ok(Some(Err(e))) => { log::warn!("Stream err: {e}"); }
        Ok(None) => bail!("Rendezvous server closed connection"),
        Err(_) => { log::debug!("No KeyExchange (timeout), proceeding"); }
    }
    Ok(())
}

// ── Session transcript ─────────────────────────────────────────────

/// The remote only replays 8 KB of scrollback on reattach
/// (`DEFAULT_RECONNECT_BUFFER_BYTES` in RustDesk's terminal_service), and a
/// remote that redraws the screen in place never pushes anything into the local
/// terminal's scrollback at all. So keep our own copy of everything we display.
///
/// Escape sequences are stripped, because a raw capture of a screen-redrawing
/// remote is unreadable in a pager — the point of this file is to be greppable.
struct SessionLog {
    file: std::fs::File,
    state: EscState,
}

enum EscState {
    Normal,
    /// Saw ESC, waiting to find out what kind of sequence this is.
    Esc,
    /// Inside CSI (`ESC [`) — ends at a byte in 0x40..=0x7E.
    Csi,
    /// Inside OSC (`ESC ]`) — ends at BEL, or at ST (`ESC \`).
    Osc,
    /// Saw ESC while inside OSC; a following `\` terminates the string.
    OscEsc,
    /// Two-byte sequence (charset selection etc.) — drop the next byte.
    SkipOne,
}

impl SessionLog {
    fn create(path: &std::path::Path) -> Result<Self> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)
                .with_context(|| format!("Failed to create log directory {}", dir.display()))?;
        }
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .with_context(|| format!("Failed to open log file {}", path.display()))?;
        Ok(Self { file, state: EscState::Normal })
    }

    /// Append `data` with escape sequences removed.
    fn append(&mut self, data: &[u8]) {
        let out = strip_escapes(&mut self.state, data);
        if !out.is_empty() {
            // A failed write must not take down the session — the transcript is
            // a convenience, not the point of the connection.
            if let Err(e) = self.file.write_all(&out) {
                log::debug!("Session log write failed: {}", e);
            }
            let _ = self.file.flush();
        }
    }
}

/// Remove terminal escape sequences, keeping readable text plus `\n` and `\t`.
/// `state` carries over between calls because a sequence can be split across
/// two Data frames.
fn strip_escapes(state: &mut EscState, data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len());
    for &b in data {
        match state {
            EscState::Normal => match b {
                0x1b => *state = EscState::Esc,
                // \r\n arrives from the PTY; keep the \n and drop the \r so the
                // file has plain Unix line endings. A lone \r is a redraw-in-place
                // (progress bars) and is dropped too.
                b'\r' | 0x7f => {}
                b'\n' | b'\t' => out.push(b),
                _ if b >= 0x20 => out.push(b),
                _ => {}
            },
            EscState::Esc => match b {
                b'[' => *state = EscState::Csi,
                b']' => *state = EscState::Osc,
                b'(' | b')' | b'*' | b'+' | b'#' => *state = EscState::SkipOne,
                _ => *state = EscState::Normal,
            },
            EscState::Csi => {
                if (0x40..=0x7e).contains(&b) {
                    // ConPTY breaks lines by moving the cursor rather than
                    // emitting \n, so dropping every CSI would run separate
                    // lines together. Cursor-down (B) and cursor-next-line (E)
                    // are line breaks as far as a transcript is concerned.
                    if b == b'B' || b == b'E' {
                        out.push(b'\n');
                    }
                    *state = EscState::Normal;
                }
            }
            EscState::Osc => match b {
                0x07 => *state = EscState::Normal,
                0x1b => *state = EscState::OscEsc,
                _ => {}
            },
            EscState::OscEsc => {
                *state = if b == b'\\' { EscState::Normal } else { EscState::Osc };
            }
            EscState::SkipOne => *state = EscState::Normal,
        }
    }
    out
}

#[cfg(test)]
mod render_tests {
    use super::*;

    // Written as numbers on purpose: these tests are about exact control
    // bytes, and an escape that silently loses its CR would test nothing.
    const ESC: u8 = 27;
    const CR: u8 = 13;
    const LF: u8 = 10;
    const BRACKET: u8 = 91;

    fn line(text: &str) -> Vec<u8> {
        let mut v = text.as_bytes().to_vec();
        v.push(CR);
        v.push(LF);
        v
    }

    fn csi(body: &str) -> Vec<u8> {
        let mut v = vec![ESC, BRACKET];
        v.extend_from_slice(body.as_bytes());
        v
    }

    /// The invariant the renderer lives or dies by: after any frame, what we
    /// told the terminal to display must equal what the model says is on
    /// screen. If these drift, output lands in the wrong place — which is what
    /// "the screen is a mess" looks like from the outside.
    fn assert_in_sync(s: &Screen, case: &str) {
        assert_eq!(
            s.model.screen().contents(),
            s.host.screen().contents(),
            "host diverged from model: {case}"
        );
    }

    fn screen() -> Screen {
        let mut s = Screen::new(10, 40);
        // These exercise the renderer, which is off by default.
        s.passthrough = false;
        s
    }

    #[test]
    fn plain_output_stays_in_sync() {
        let mut s = screen();
        s.feed(&line("hello"));
        s.feed(&line("world"));
        assert_in_sync(&s, "plain");
        assert!(s.model.screen().contents().contains("hello"));
    }

    #[test]
    fn scrolling_retires_lines_into_history() {
        let mut s = screen();
        for i in 0..30 {
            s.feed(&line(&format!("line{i}")));
        }
        assert_in_sync(&s, "scrolled");
        // 30 lines through a 10-row screen: the trailing newline leaves the
        // cursor on a fresh row, so 21 have been pushed off the top.
        assert_eq!(s.history_len(), 21);
        assert!(s.model.screen().contents().contains("line29"));
    }

    #[test]
    fn burst_larger_than_the_screen_stays_in_sync() {
        // The case a naive implementation gets wrong: one frame retires more
        // lines than the screen ever held, so most never reached the terminal
        // and cannot simply be scrolled into its scrollback.
        let mut s = screen();
        let mut burst = Vec::new();
        for i in 0..100 {
            burst.extend(line(&format!("burst{i}")));
        }
        s.feed(&burst);
        assert_in_sync(&s, "burst");
        assert_eq!(s.history_len(), 91);
    }

    #[test]
    fn conpty_style_absolute_repaint_stays_in_sync() {
        // ConPTY does not scroll; it positions the cursor and overwrites.
        let mut s = screen();
        let mut frame = csi("2J");
        frame.extend(csi("1;1H"));
        frame.extend_from_slice(b"first");
        frame.extend(csi("2;1H"));
        frame.extend_from_slice(b"second");
        s.feed(&frame);
        assert_in_sync(&s, "repaint 1");

        let mut frame = csi("1;1H");
        frame.extend_from_slice(b"third");
        frame.extend(csi("2;1H"));
        frame.extend_from_slice(b"fourth");
        s.feed(&frame);
        assert_in_sync(&s, "repaint 2");

        let contents = s.model.screen().contents();
        assert!(contents.contains("third"), "{contents}");
        assert!(!contents.contains("first"), "{contents}");
    }

    #[test]
    fn colour_attributes_do_not_bleed_between_retired_lines() {
        // Big enough to force the explicit write-out path, with one coloured
        // line in the middle whose attributes must not leak onto the next.
        let mut s = screen();
        let mut burst = Vec::new();
        for i in 0..40 {
            if i == 5 {
                burst.extend(csi("31m"));
                burst.extend_from_slice(b"red");
                burst.extend(csi("m"));
                burst.push(CR);
                burst.push(LF);
            } else {
                burst.extend(line(&format!("plain{i}")));
            }
        }
        s.feed(&burst);
        assert_in_sync(&s, "colour burst");
    }

    #[test]
    fn replay_does_not_echo_raw_bytes() {
        // The remote replay is the tail of a byte stream cut at an arbitrary
        // offset, so it opens partway through an escape sequence.
        let mut s = screen();
        let mut chunk = b"31mtail of a cut sequence".to_vec();
        chunk.push(CR);
        chunk.push(LF);
        chunk.extend(line("second line"));
        s.feed_replay(&chunk);
        assert_in_sync(&s, "replay");
    }

    #[test]
    fn paging_back_freezes_the_view_then_returns_live() {
        let mut s = screen();
        for i in 0..40 {
            s.feed(&line(&format!("row{i}")));
        }
        assert!(s.page(1), "should page back");
        assert!(s.active());
        let frozen = s.view();

        // Output arriving while paged back must not slide the frozen view. The
        // offset counts back from the live bottom, so it has to grow with the
        // history to stay pointed at the same lines.
        s.feed(&line("newest"));
        assert_eq!(s.view(), frozen, "view moved while paged back");

        s.to_live();
        assert!(!s.active());
        assert!(s.model.screen().contents().contains("newest"));
    }

    #[test]
    fn paging_offset_never_exceeds_real_history() {
        let mut s = screen();
        for i in 0..15 {
            s.feed(&line(&format!("x{i}")));
        }
        let history = s.history_len();
        // Jumping to the oldest line must land on the real limit, not park at
        // some huge number that makes paging forward look dead.
        s.page(SCROLLBACK_LINES as i32);
        assert_eq!(s.offset, history);
        assert!(!s.page(1), "already at the oldest line");
        assert!(s.page(-1), "should page forward");
    }

    #[test]
    fn resize_keeps_both_models_together() {
        let mut s = screen();
        s.feed(&line("before resize"));
        s.resize(20, 60);
        s.feed(&line("after resize"));
        assert_in_sync(&s, "resized");
        assert_eq!(s.model.screen().size(), (20, 60));
    }
    /// Enter the alternate screen, the way a full-screen app does.
    fn enter_alt() -> Vec<u8> {
        csi("?1049h")
    }

    fn leave_alt() -> Vec<u8> {
        csi("?1049l")
    }

    /// Repaint a whole screen in place with absolute cursor moves, which is
    /// what ConPTY does for a full-screen app instead of scrolling.
    fn repaint_rows(rows: &[&str]) -> Vec<u8> {
        let mut out = csi("2J");
        for (i, text) in rows.iter().enumerate() {
            out.extend(csi(&format!("{};1H", i + 1)));
            out.extend_from_slice(text.as_bytes());
        }
        out
    }

    #[test]
    fn entering_the_alternate_screen_does_not_underflow() {
        // vt100 throws its history away on entering the alternate screen, so
        // the length falls. Subtracting without care wraps around and asks the
        // terminal to scroll billions of lines.
        let mut s = screen();
        for i in 0..30 {
            s.feed(&line(&format!("main{i}")));
        }
        let before = s.history_len();
        assert!(before > 0);
        s.feed(&enter_alt());
        assert!(
            s.history_len() >= before && s.history_len() < before + 100,
            "history went haywire: {} -> {}",
            before,
            s.history_len()
        );
        assert_in_sync(&s, "entered alt screen");
    }

    #[test]
    fn alternate_screen_content_is_archived_when_it_scrolls() {
        // The Claude Code case: a full-screen app whose output moves up the
        // screen by absolute repaint. The terminal keeps no history for the
        // alternate screen, so the archive is the only place it can live.
        let mut s = screen();
        s.feed(&enter_alt());
        let first: Vec<String> = (0..10).map(|i| format!("chat{i}")).collect();
        let refs: Vec<&str> = first.iter().map(|x| x.as_str()).collect();
        s.feed(&repaint_rows(&refs));
        let before = s.history_len();

        // Same screen shifted up by 3: rows 3..10 carry over, 3 new at the end.
        let second: Vec<String> = (3..13).map(|i| format!("chat{i}")).collect();
        let refs: Vec<&str> = second.iter().map(|x| x.as_str()).collect();
        s.feed(&repaint_rows(&refs));

        assert_eq!(s.history_len(), before + 3, "scroll by repaint not detected");
        let archived: Vec<String> = s
            .history
            .iter()
            .map(|l| String::from_utf8_lossy(l).to_string())
            .collect();
        let joined = archived.join("|");
        for m in ["chat0", "chat1", "chat2"] {
            assert!(joined.contains(m), "{m} missing from archive: {joined}");
        }
        assert_in_sync(&s, "alt screen scrolled");
    }

    #[test]
    fn paging_reaches_alternate_screen_history() {
        // What the user actually does: scroll back while the full-screen app
        // is still running and expect to see what went past.
        let mut s = screen();
        s.feed(&enter_alt());
        for step in 0..12 {
            let rows: Vec<String> = (step..step + 10).map(|i| format!("out{i}")).collect();
            let refs: Vec<&str> = rows.iter().map(|x| x.as_str()).collect();
            s.feed(&repaint_rows(&refs));
        }
        assert!(s.history_len() >= 10, "archive too small: {}", s.history_len());
        assert!(s.page(1), "should page back into the archive");
        assert!(s.active());
        s.to_live();
    }

    #[test]
    fn a_static_screen_is_not_mistaken_for_a_scroll() {
        let mut s = screen();
        s.feed(&enter_alt());
        let rows = ["alpha", "beta", "gamma", "delta"];
        s.feed(&repaint_rows(&rows));
        let before = s.history_len();
        // Same content again: a redraw, not a scroll.
        s.feed(&repaint_rows(&rows));
        assert_eq!(s.history_len(), before, "redraw counted as a scroll");
    }

    #[test]
    fn a_blank_heavy_screen_is_not_mistaken_for_a_scroll() {
        let mut s = screen();
        s.feed(&enter_alt());
        s.feed(&repaint_rows(&["", "", "", "only one line"]));
        let before = s.history_len();
        s.feed(&repaint_rows(&["", "", "", "", "different"]));
        assert_eq!(before, s.history_len(), "matched on blank rows");
    }

    #[test]
    fn leaving_the_alternate_screen_restores_the_main_one() {
        let mut s = screen();
        s.feed(&line("before the app"));
        s.feed(&enter_alt());
        s.feed(&repaint_rows(&["app row 1", "app row 2"]));
        assert!(s.model.screen().alternate_screen());
        s.feed(&leave_alt());
        assert!(!s.model.screen().alternate_screen());
        assert!(s.model.screen().contents().contains("before the app"));
        assert_in_sync(&s, "left alt screen");
    }

    #[test]
    fn detect_scroll_finds_the_shift() {
        let prev: Vec<String> = (0..10).map(|i| format!("row{i}")).collect();
        let cur: Vec<String> = (4..14).map(|i| format!("row{i}")).collect();
        assert_eq!(detect_scroll(&prev, &cur), 4);
    }

    /// Claude Code's shape: blank padding at the top, the conversation in the
    /// middle, a fixed box pinned to the bottom.
    fn tui_screen(first_line: usize) -> Vec<String> {
        let mut rows: Vec<String> = Vec::new();
        for _ in 0..6 {
            rows.push(String::new());
        }
        for i in first_line..first_line + 16 {
            rows.push(format!("  conversation line {i}"));
        }
        rows.push("─────────────────────────".into());
        rows.push("> ".into());
        rows.push("  bypass permissions on (shift+tab to cycle)".into());
        rows.push(String::new());
        rows
    }

    #[test]
    fn a_scroll_is_found_when_the_top_of_the_screen_is_blank() {
        // The case that made the detector useless in practice: probing the top
        // rows finds only padding, so the "too empty to trust" guard fired and
        // detection never ran at all. Real sessions logged moved=0 forever.
        let prev = tui_screen(1);
        let cur = tui_screen(4);
        assert_eq!(prev.len(), cur.len());
        assert!(prev[..6].iter().all(|r| r.trim().is_empty()), "top must be blank");
        assert_eq!(detect_scroll(&prev, &cur), 3);
    }

    #[test]
    fn nul_padding_counts_as_blank() {
        // A terminal pads with NUL, which is not whitespace; without treating it
        // as blank, a screen of padding looks like content.
        let mut prev = tui_screen(1);
        let mut cur = tui_screen(2);
        for rows in [&mut prev, &mut cur] {
            for i in 0..6 {
                rows[i] = "\0\0\0\0".into();
            }
        }
        assert_eq!(detect_scroll(&prev, &cur), 1);
    }

    #[test]
    fn repeated_chrome_does_not_anchor_the_search() {
        // Borders and separators repeat all over a TUI. Anchoring on them points
        // at the wrong place, so the probe is scored on distinct rows only.
        let mut prev: Vec<String> = vec!["────".into(); 20];
        let mut cur: Vec<String> = vec!["────".into(); 20];
        prev[10] = "unique alpha".into();
        prev[11] = "unique beta".into();
        prev[12] = "unique gamma".into();
        cur[8] = "unique alpha".into();
        cur[9] = "unique beta".into();
        cur[10] = "unique gamma".into();
        assert_eq!(detect_scroll(&prev, &cur), 2);
    }

    #[test]
    fn a_screen_that_did_not_move_reports_nothing() {
        let screen = tui_screen(1);
        assert_eq!(detect_scroll(&screen, &screen), 0);
    }

    #[test]
    fn content_moving_down_is_not_a_scroll() {
        // Only upward movement retires lines. Downward means the app redrew
        // lower, and nothing left the screen.
        let prev = tui_screen(4);
        let cur = tui_screen(1);
        assert_eq!(detect_scroll(&prev, &cur), 0);
    }

    #[test]
    fn detect_scroll_reports_nothing_for_an_unrelated_screen() {
        let prev: Vec<String> = (0..10).map(|i| format!("row{i}")).collect();
        let cur: Vec<String> = (0..10).map(|i| format!("totally different {i}")).collect();
        assert_eq!(detect_scroll(&prev, &cur), 0);
    }
    #[test]
    fn crossing_into_and_out_of_the_alternate_screen_keeps_the_archive() {
        // The sequence that produced a shredded display: shell output, a
        // full-screen app, then back to the shell.
        let mut s = screen();
        for i in 0..20 {
            s.feed(&line(&format!("shell{i}")));
        }
        let before_alt = s.history_len();
        assert!(before_alt > 0);

        s.feed(&enter_alt());
        assert_in_sync(&s, "entered");
        for step in 0..8 {
            let rows: Vec<String> = (step..step + 10).map(|i| format!("app{i}")).collect();
            let refs: Vec<&str> = rows.iter().map(|x| x.as_str()).collect();
            s.feed(&repaint_rows(&refs));
        }
        let during_alt = s.history_len();
        assert!(during_alt > before_alt, "alt screen output was not archived");

        s.feed(&leave_alt());
        assert_in_sync(&s, "left");
        // Nothing archived may be lost by crossing back.
        assert!(s.history_len() >= during_alt, "archive shrank on leaving the alternate screen");
        // And the shell is back.
        assert!(s.model.screen().contents().contains("shell19"));

        // Both sides of the crossing must still be reachable.
        let archived: String = s
            .history
            .iter()
            .map(|l| String::from_utf8_lossy(l).to_string())
            .collect::<Vec<_>>()
            .join("|");
        assert!(archived.contains("shell0"), "shell history lost");
        assert!(archived.contains("app0"), "app history lost");
    }

    #[test]
    fn a_forced_repaint_leaves_the_models_agreeing() {
        // What Shift+F5 does. It has to be safe in either screen and at any
        // scrollback position.
        let mut s = screen();
        for i in 0..30 {
            s.feed(&line(&format!("row{i}")));
        }
        s.page(1);
        s.to_live();
        s.repaint(true);
        assert_in_sync(&s, "forced repaint, main screen");

        s.feed(&enter_alt());
        s.feed(&repaint_rows(&["app top", "app middle", "app bottom"]));
        s.repaint(true);
        assert_in_sync(&s, "forced repaint, alternate screen");
    }
}



#[cfg(test)]
mod transcript_tests {
    use super::{strip_escapes, EscState};

    fn strip(chunks: &[&[u8]]) -> String {
        let mut st = EscState::Normal;
        let mut out = Vec::new();
        for c in chunks {
            out.extend(strip_escapes(&mut st, c));
        }
        String::from_utf8(out).expect("valid utf-8")
    }

    #[test]
    fn plain_text_passes_through() {
        assert_eq!(strip(&[b"hello world\n"]), "hello world\n");
    }

    #[test]
    fn crlf_becomes_lf() {
        assert_eq!(strip(&[b"a\r\nb\r\n"]), "a\nb\n");
    }

    #[test]
    fn csi_colour_sequences_are_removed() {
        assert_eq!(strip(&[b"\x1b[31mred\x1b[0m\n"]), "red\n");
    }

    #[test]
    fn osc_title_is_removed_for_both_terminators() {
        assert_eq!(strip(&[b"\x1b]0;my title\x07text"]), "text");
        assert_eq!(strip(&[b"\x1b]0;my title\x1b\\text"]), "text");
    }

    /// What a ConPTY remote actually sends: home the cursor, clear, repaint.
    /// None of the positioning should reach the transcript.
    fn conpty_repaint() {
        assert_eq!(strip(&[b"\x1b[H\x1b[2J\x1b[3JC:\\> dir\n"]), "C:\\> dir\n");
    }

    #[test]
    fn conpty_repaint_is_stripped() {
        conpty_repaint();
    }

    /// A sequence split across two Data frames must not leak its tail.
    #[test]
    fn sequence_split_across_chunks() {
        assert_eq!(strip(&[b"before\x1b[3", b"1mafter"]), "beforeafter");
        assert_eq!(strip(&[b"x\x1b", b"]0;t\x07y"]), "xy");
    }

    #[test]
    fn utf8_multibyte_survives() {
        assert_eq!(strip(&["中文\n".as_bytes()]), "中文\n");
    }

    #[test]
    fn charset_selection_drops_exactly_one_byte() {
        assert_eq!(strip(&[b"\x1b(Bkeep"]), "keep");
    }
}

// ── Terminal slot allocation ───────────────────────────────────────

/// How long a slot lock may go un-refreshed before another process claims it.
const SLOT_STALE_SECS: u64 = 90;
const MAX_SLOTS: i32 = 64;

/// The remote indexes sessions by `(service_id, terminal_id)`. With a stable
/// service_id, every concurrent client that also hardcodes `terminal_id = 0`
/// lands on the *same* remote terminal — so a second window would hijack the
/// first one's shell.
///
/// Each process therefore claims a distinct `terminal_id` by creating a lock
/// file, and keeps it stable across restarts so a relaunched window reattaches
/// to its own session rather than someone else's. The lock is refreshed while
/// the session runs; one left behind by a crash goes stale and is reclaimed.
struct TerminalSlot {
    id: i32,
    lock: Option<std::path::PathBuf>,
}

impl TerminalSlot {
    fn acquire(service_id: &str, explicit: Option<i32>) -> Self {
        if let Some(id) = explicit {
            return Self { id, lock: None };
        }
        let dir = match lock_dir() {
            Some(d) => d,
            // Without a home directory we cannot coordinate; fall back to the
            // old behaviour rather than refusing to connect.
            None => return Self { id: 0, lock: None },
        };
        if std::fs::create_dir_all(&dir).is_err() {
            return Self { id: 0, lock: None };
        }
        for id in 0..MAX_SLOTS {
            let path = dir.join(format!("{}-{}.lock", service_id, id));
            if claim_lock(&path) {
                log::debug!("Claimed terminal slot {} ({})", id, path.display());
                return Self { id, lock: Some(path) };
            }
        }
        log::warn!("All {} terminal slots busy; falling back to slot 0", MAX_SLOTS);
        Self { id: 0, lock: None }
    }

    /// Keep the lock from going stale while this session is alive.
    fn refresh(&self) {
        if let Some(p) = &self.lock {
            let _ = std::fs::write(p, std::process::id().to_string());
        }
    }
}

impl Drop for TerminalSlot {
    fn drop(&mut self) {
        if let Some(p) = &self.lock {
            let _ = std::fs::remove_file(p);
        }
    }
}

/// Slot locks are scratch state, not user data — keep them out of $HOME.
fn lock_dir() -> Option<std::path::PathBuf> {
    let mut p = std::env::temp_dir();
    p.push("rustshell-locks");
    Some(p)
}

/// True if we now own `path`. Takes over a lock whose holder stopped
/// refreshing it (crash, kill -9) rather than leaking the slot forever.
fn claim_lock(path: &std::path::Path) -> bool {
    match std::fs::OpenOptions::new().write(true).create_new(true).open(path) {
        Ok(mut f) => {
            let _ = f.write_all(std::process::id().to_string().as_bytes());
            true
        }
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            let stale = std::fs::metadata(path)
                .and_then(|m| m.modified())
                .and_then(|t| t.elapsed().map_err(|_| std::io::Error::other("clock skew")))
                .map(|age| age.as_secs() > SLOT_STALE_SECS)
                .unwrap_or(false);
            if stale && std::fs::remove_file(path).is_ok() {
                log::debug!("Reclaimed stale lock {}", path.display());
                return claim_lock(path);
            }
            false
        }
        Err(_) => false,
    }
}

// ── Terminal I/O loop ──────────────────────────────────────────────

async fn terminal_io_loop(
    conn: &mut Link, remote_platform: &str, quit_key: char, render: bool, new_session: bool,
    slot: &TerminalSlot, log_path: Option<std::path::PathBuf>, detach: bool,
) -> Result<SessionEnd> {
    let mut session_log = match log_path {
        Some(p) => match SessionLog::create(&p) {
            Ok(l) => { log::info!("Session transcript: {}", p.display()); Some(l) }
            // Losing the transcript is not worth refusing the connection over.
            Err(e) => { log::warn!("Session transcript disabled: {:#}", e); None }
        },
        None => None,
    };
    let _guard = ConsoleGuard::enable()?;
    let (cols, rows) = crossterm::terminal::size().context("Failed to get terminal size")?;
    // Isolation comes from the per-slot service_id, so every session uses the
    // service's default terminal.
    let terminal_id: i32 = 0;

    {
        let mut action = TerminalAction::new();
        action.set_open(OpenTerminal { terminal_id, rows: rows as u32, cols: cols as u32, ..Default::default() });
        let mut msg = Message::new();
        msg.set_terminal_action(action);
        send_msg(conn, &msg, "open_terminal").await?;
    }
    log::debug!("OpenTerminal sent ({}x{}), waiting for shell...", cols, rows);

    let mut screen = Screen::new(rows, cols);
    screen.passthrough = !render;
    let mut input_timer = time::interval(std::time::Duration::from_millis(20));
    let mut keepalive = time::interval(std::time::Duration::from_secs(15));
    let mut terminal_opened = false;
    let mut locale_injected = false;
    let mut expect_replay = false;
    let mut first_frame = true;
    // 第一批未画出数据的时刻，以及最近一批的时刻。
    let mut pending_since: Option<std::time::Instant> = None;
    let mut last_data = std::time::Instant::now();
    // 静默这么久就认为一次重绘的分片已经到齐了。
    const SETTLE: std::time::Duration = std::time::Duration::from_millis(12);
    // 但输出不停的时候永远等不到静默，所以再给一个强制上限，否则屏幕会冻住。
    const MAX_HOLD: std::time::Duration = std::time::Duration::from_millis(60);
    let mut last_cols = cols;
    let mut last_rows = rows;

    loop {
        tokio::select! {
            _ = keepalive.tick() => {
                if terminal_opened {
                    // Relays and NATs drop idle TCP connections, which is what
                    // made sessions die on their own. Keep the link warm and
                    // treat a failed send as the link being gone, rather than
                    // silently ignoring it and waiting forever for data.
                    if let Err(e) = conn.send(&Message::new()).await {
                        log::info!("Keepalive failed ({}), connection lost", e);
                        return Ok(SessionEnd::Disconnected);
                    }
                    // Prove to other local instances that this slot is still ours.
                    slot.refresh();
                }
            }

            res = conn.next() => {
                let bytes = match res {
                    Some(Ok(b)) => b,
                    // Both mean the transport died, not that the remote shell
                    // exited — the session on the far side is probably still
                    // there, so this is reconnectable.
                    Some(Err(e)) => { log::info!("Stream error: {}", e); return Ok(SessionEnd::Disconnected); }
                    None => { log::info!("Connection closed by peer"); return Ok(SessionEnd::Disconnected); }
                };
                let msg_in = match Message::parse_from_bytes(&bytes) {
                    Ok(m) => m, Err(e) => { log::error!("Parse: {} (raw: {:02x?})", e, bytes.as_ref()); continue; }
                };
                match msg_in.union {
                    Some(message::Union::TerminalResponse(resp)) => {
                        use terminal_response::Union;
                        match resp.union {
                            Some(Union::Opened(o)) => {
                                terminal_opened = o.success;
                                if !o.success { bail!("Terminal open failed: {}", o.message); }
                                log::info!("Shell started (pid: {})", o.pid);
                                // Say this before anything is drawn. Written into
                                // a live screen it lands at whatever cursor
                                // position the remote app left behind and
                                // corrupts the display; here the first frame's
                                // repaint scrolls it into the terminal's own
                                // scrollback, where it stays readable.
                                if let Ok(spec) = std::env::var("RUSTSHELL_CLIP_TEST") {
                                    // spec 为 real 时读真实剪贴板，否则按 WxH 合成。
                                    let built = if spec == "real" {
                                        clipboard_image_message()
                                    } else {
                                        synthetic_clipboard_image(&spec)
                                    };
                                    match built {
                                        Ok((m, bytes, w, h)) => {
                                            log::info!("cliptest: sending {w}x{h}, {bytes} bytes on the wire");
                                            match conn.send(&m).await {
                                                Ok(()) => log::info!("cliptest: sent"),
                                                Err(e) => log::error!("cliptest: send failed: {e}"),
                                            }
                                        }
                                        Err(e) => log::error!("cliptest: {e:#}"),
                                    }
                                }
                                if !locale_injected {
                                    locale_injected = true;
                                    let hint = if remote_platform.eq_ignore_ascii_case("Windows") {
                                        "\n  | Tip: If CJK chars display incorrectly, run:\n  |   cmd /c \"chcp 65001 >nul 2>&1\"\n"
                                    } else {
                                        "\n  | Tip: If CJK chars display incorrectly, run:\n  |   export LANG=en_US.UTF-8 LC_ALL=en_US.UTF-8\n"
                                    };
                                    screen.note(hint);
                                }
                                if !o.service_id.is_empty() {
                                    log::info!("Remote session id: {}", o.service_id);
                                }
                                if !o.persistent_sessions.is_empty() {
                                    log::info!("Persistent sessions on remote: {:?}", o.persistent_sessions);
                                }
                                // The remote signals that the next Data frame is a
                                // replay of this session's buffered output — i.e. the
                                // scrollback from before we (re)attached.
                                if o.replay_terminal_output {
                                    log::info!("Replaying buffered output from previous session...");
                                    expect_replay = true;
                                }
                            }
                            Some(Union::Data(data)) => {
                                let output = if data.compressed {
                                    zstd_decompress(&data.data)
                                } else { data.data.to_vec() };
                                // The very first frame also gets the replay
                                // treatment: it is the point where the terminal
                                // still carries our connection logs, and the
                                // renderer needs a screen it knows the state of.
                                // 接回会话时，第一帧一律当回放，不管远端有没有
                                // 置 replay_terminal_output。
                                //
                                // 实测这台远端会发回放却不置标志位。信了标志位
                                // 的结果是：那段旧会话的流水被原样写进终端，而且
                                // 因为缓冲内容不变，每次重连都乱得一模一样。
                                //
                                // 全新会话（-n）不能这么做——那一帧是 shell 的
                                // 初始输出，丢了就真没了。
                                let treat_as_replay = expect_replay
                                    || (first_frame && (!new_session || screen.renders()));
                                if treat_as_replay {
                                    expect_replay = false;
                                    first_frame = false;
                                    if screen.feed_replay(&output) {
                                        // Ctrl+L 是「重画」的通用约定，shell
                                        // 和全屏应用都认。比发回车安全——回车
                                        // 会被当成一次输入提交。
                                        let mut a = TerminalAction::new();
                                        a.set_data(TerminalData {
                                            terminal_id,
                                            data: vec![0x0c].into(),
                                            compressed: false,
                                            ..Default::default()
                                        });
                                        let mut m = Message::new();
                                        m.set_terminal_action(a);
                                        conn.send(&m).await.ok();
                                    }
                                } else {
                                    first_frame = false;
                                    // 只吸收，不画。画的时机由下面的定时器在
                                    // 字节流静下来之后决定——半张重绘不能拿去
                                    // 做滚动检测。
                                    screen.absorb(&output);
                                    last_data = std::time::Instant::now();
                                    pending_since.get_or_insert(last_data);
                                }
                                if let Some(l) = session_log.as_mut() { l.append(&output); }
                            }
                            Some(Union::Closed(c)) => {
                                log::info!("Terminal closed (exit code: {})", c.exit_code);
                                return Ok(SessionEnd::RemoteClosed);
                            }
                            Some(Union::Error(e)) => bail!("Terminal error: {}", e.message),
                            _ => { log::debug!("TerminalResponse with empty union"); }
                        }
                    }
                    Some(message::Union::Hash(_)) => {}
                    other => { log::debug!("Unhandled message type: {:?}", other.map(|_| ())); }
                }
            }

            _ = input_timer.tick() => {
                if let Some(since) = pending_since {
                    if last_data.elapsed() >= SETTLE || since.elapsed() >= MAX_HOLD {
                        screen.flush();
                        pending_since = None;
                    }
                }

                if let Ok((nc, nr)) = crossterm::terminal::size() {
                    if (nc != last_cols || nr != last_rows) && terminal_opened {
                        log::debug!("Resize: {}x{}", nc, nr);
                        screen.resize(nr, nc);
                        let mut a = TerminalAction::new();
                        a.set_resize(ResizeTerminal { terminal_id, rows: nr as u32, cols: nc as u32, ..Default::default() });
                        let mut m = Message::new(); m.set_terminal_action(a);
                        conn.send(&m).await.ok();
                        last_cols = nc; last_rows = nr;
                    }
                }
                let mut typed: Vec<u8> = Vec::new();
                while let Some(input) = poll_input() {
                    let ev = match input {
                        Input::Key(k) => k,
                        Input::Paste(text) => {
                            if !terminal_opened { continue; }
                            if screen.active() { screen.to_live(); screen.render(); }
                            // Hand the remote a paste, not keystrokes. Apps that
                            // asked for bracketed paste (Claude Code, vim, most
                            // shells) use the markers to take the text
                            // literally — without them a multi-line paste runs
                            // line by line and indentation logic mangles it.
                            // Terminals send CR for line breaks inside a paste.
                            let body = text.replace("\r\n", "\r").replace('\n', "\r");
                            let mut payload = Vec::with_capacity(body.len() + 12);
                            payload.extend_from_slice(b"\x1b[200~");
                            payload.extend_from_slice(body.as_bytes());
                            payload.extend_from_slice(b"\x1b[201~");
                            let mut a = TerminalAction::new();
                            a.set_data(TerminalData { terminal_id, data: payload.into(), compressed: false, ..Default::default() });
                            let mut m = Message::new(); m.set_terminal_action(a);
                            conn.send(&m).await.ok();
                            continue;
                        }
                    };
                    // Insurance. The screen is drawn from a model of what the
                    // terminal is showing, and that model can only be wrong if
                    // something wrote to the terminal behind its back. There is
                    // no way to read a terminal back to find out, so give the
                    // user one key that throws the model's idea of the screen
                    // away and paints it again from scratch.
                    if ev.code == KeyCode::F(5) && ev.modifiers.contains(KeyModifiers::SHIFT) {
                        screen.to_live();
                        screen.repaint(true);
                        continue;
                    }
                    // Scrollback navigation is handled locally and never
                    // reaches the remote.
                    if let Some(delta) = scrollback_key(&ev) {
                        let changed = match delta {
                            i32::MAX => screen.page(SCROLLBACK_LINES as i32),
                            i32::MIN => { let was = screen.active(); screen.to_live(); was }
                            d => screen.page(d),
                        };
                        if changed { screen.render(); }
                        continue;
                    }
                    // Any other key resumes the live view, like a pager would.
                    if screen.active() {
                        screen.to_live();
                        screen.render();
                    }

                    // Ctrl+V is the key an app on the far side reads an image
                    // with, and it is the only chance we get: an image-only
                    // clipboard produces no local paste event, so the image has
                    // to be on the remote clipboard *before* the keystroke
                    // arrives. Text pastes are unaffected — they come through
                    // bracketed paste, and Ctrl+V still goes through either way.
                    if matches!(ev.code, KeyCode::Char(c) if c.eq_ignore_ascii_case(&'v'))
                        && ev.modifiers.contains(KeyModifiers::CONTROL)
                        && terminal_opened
                    {
                        // 诊断用：让 Ctrl+V 走合成图，把「会话进行中发送」这个
                        // 变量单独隔离出来测。
                        let built = match std::env::var("RUSTSHELL_CLIP_TEST") {
                            Ok(spec) => synthetic_clipboard_image(&spec),
                            Err(_) => clipboard_image_message(),
                        };
                        match built {
                            Ok((m, bytes, w, h)) => {
                                log::debug!("clipboard image {w}x{h}, {bytes} bytes compressed");
                                if let Err(e) = conn.send(&m).await {
                                    screen.set_status(format!("clipboard: send failed: {e}"));
                                } else {
                                    screen.set_status(format!(
                                        "clipboard: sent {w}x{h} image, {} KB — if nothing appears, the remote is RustDesk 1.4.9+ and drops it",
                                        bytes / 1024
                                    ));
                                    // The remote applies the clipboard on its own
                                    // thread, so the keystroke has to lag behind
                                    // it or the app reads the old clipboard.
                                    time::sleep(std::time::Duration::from_millis(200)).await;
                                }
                            }
                            // Say so rather than doing nothing. "Ctrl+V did not
                            // work" has several possible causes and the user
                            // cannot tell them apart from silence — a file
                            // copied in Finder puts a path on the clipboard,
                            // not an image, and reads the same as a failure.
                            Err(e) => screen.set_status(format!("clipboard: {e:#}")),
                        }
                    }

                    let data = key_event_to_bytes(ev.code, ev.modifiers);
                    if data.is_empty() { continue; }
                    let quit_byte = (quit_key.to_ascii_lowercase() as u8) - b'a' + 1;
                    if data == [quit_byte] {
                        // Close by default. Detaching leaks on the remote: its
                        // connection sockets pile up in CLOSE_WAIT and the
                        // service thread keeps polling, until RustDesk burns a
                        // core and drops off the rendezvous server entirely
                        // ("remote device is offline"). An explicit CloseTerminal
                        // is the path the server cleans up properly.
                        if terminal_opened && !typed.is_empty() {
                            let mut a = TerminalAction::new();
                            a.set_data(TerminalData {
                                terminal_id,
                                data: std::mem::take(&mut typed).into(),
                                compressed: false,
                                ..Default::default()
                            });
                            let mut m = Message::new();
                            m.set_terminal_action(a);
                            conn.send(&m).await.ok();
                        }
                        if detach {
                            log::info!("Detaching (Ctrl+{}), remote session left running", quit_key.to_ascii_uppercase());
                        } else {
                            log::info!("Closing terminal (Ctrl+{})...", quit_key.to_ascii_uppercase());
                            if terminal_opened {
                                let mut a = TerminalAction::new();
                                a.set_close(CloseTerminal { terminal_id, ..Default::default() });
                                let mut m = Message::new(); m.set_terminal_action(a);
                                conn.send(&m).await.ok();
                            }
                        }
                        return Ok(SessionEnd::UserQuit);
                    }
                    // 攒起来，本轮结束一次发完。一个按键一条消息的话，打字
                    // 快一点就是几十条消息背靠背挤过中继——实测会丢字，表现
                    // 为「敲不进去」。
                    typed.extend_from_slice(&data);
                }

                if terminal_opened && !typed.is_empty() {
                    let mut a = TerminalAction::new();
                    a.set_data(TerminalData {
                        terminal_id,
                        data: std::mem::take(&mut typed).into(),
                        compressed: false,
                        ..Default::default()
                    });
                    let mut m = Message::new();
                    m.set_terminal_action(a);
                    conn.send(&m).await.ok();
                }
            }
        }
    }
    #[allow(unreachable_code)]
    Ok(SessionEnd::Disconnected)
}
