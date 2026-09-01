mod link;
mod proto;
mod wire;

use anyhow::{bail, Context, Result};
use clap::Parser;
use link::{
    check_port, increase_port, timeout, Link, LinkWriter, CONNECT_TIMEOUT, RELAY_PORT, RS_PUB_KEY,
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
                  RUSTSHELL_NEW_SESSION=(1|true), RUSTSHELL_DETACH=(1|true), \
                  RUSTSHELL_NO_REMOTE_CLOSE=(1|true)"
)]
struct Args {
    #[arg(short = 'i', long, default_value = "")]
    id: String,
    #[arg(short = 's', long, default_value = "")]
    server: String,
    #[arg(short = 'p', long, default_value = "21116")]
    port: u16,
    #[arg(short = 'k', long, default_value = "")]
    key: String,
    #[arg(short = 'w', long, default_value = "")]
    password: String,
    #[arg(short = 'd', long, default_value = "false")]
    debug: bool,
    #[arg(short = 'q', long, default_value = "q")]
    quit_key: char,
    /// Start a fresh terminal session instead of reattaching to the persistent one
    #[arg(short = 'n', long, default_value = "false")]
    new_session: bool,
    /// Write a plain-text transcript to this path (off unless set)
    #[arg(short = 'l', long, default_value = "")]
    log_file: String,
    /// Leave the remote shell running on quit instead of closing it
    #[arg(long, default_value = "false")]
    detach: bool,
    /// Session slot to attach to [default: first one not in use locally]
    #[arg(short = 't', long)]
    slot: Option<i32>,
    /// Do not reconnect automatically when the connection drops
    #[arg(long, default_value = "false")]
    no_reconnect: bool,
    /// Draw from a screen model, giving native scrollback and the pager
    #[arg(long, default_value = "false")]
    render: bool,
    /// 读一次本地剪贴板并报告结果，不连接。用于定位 Ctrl+V 不生效是哪一环。
    #[arg(long, default_value = "false")]
    clipboard_check: bool,
    /// 退出时一律不要求远端销毁会话（远端 helper 卡住时，销毁会拖死整个 RustDesk 服务）
    #[arg(long, default_value = "false")]
    no_remote_close: bool,
}

/// Why a session ended — decides whether reconnecting makes sense.
enum SessionEnd {
    /// User pressed the quit key.
    UserQuit,
    /// The remote shell exited.
    RemoteClosed,
    /// The link dropped; reconnect using the configured persistence policy.
    Disconnected,
}

/// Stable terminal `service_id` used to isolate local slots.
///
/// A disconnected session can reattach to this ID and replay buffered output,
/// while distinct local slots remain isolated from each other.
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

/// 每个本地槽位只对应一个可重新寻址的远端服务。
fn slot_service_id(base: &str, slot: i32) -> String {
    format!("{}s{}", base, slot)
}

/// A fresh session must not touch the previous service at all. RustDesk 1.4.6
/// can wedge while closing a stale Windows helper; sending Close then Open to
/// that service leaves Open queued forever. A new service ID bypasses the
/// poisoned mutex while remaining stable for reconnects in this process.
fn fresh_service_id(base: &str, slot: i32) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let mut h = Sha256::new();
    h.update(b"rustshell-fresh-service-v1");
    h.update(base.as_bytes());
    h.update(slot.to_le_bytes());
    h.update(std::process::id().to_le_bytes());
    h.update(now.to_le_bytes());
    let digest = h.finalize();
    let mut id = slot_service_id(base, slot);
    id.push('n');
    for byte in &digest[..8] {
        id.push_str(&format!("{:02x}", byte));
    }
    id
}

/// 远端持久终端已经被旧连接卡住时，OpenTerminal 会一直等不到回应。
/// 这种错误只能通过换一个 service_id 绕开，不应对同一个坏服务无限重试。
fn is_terminal_open_timeout(error: &anyhow::Error) -> bool {
    error
        .to_string()
        .contains("Timed out waiting for the remote shell")
}

/// vt100 和远端 PTY 都不接受 0 尺寸；宽高至少为 2，避免宽字符路径做 `cols - 2`
/// 时下溢，也避开 vt100 0.15 在单行网格滚屏时的无效行索引。
fn normalize_terminal_size(cols: u16, rows: u16) -> (u16, u16) {
    (cols.max(2), rows.max(2))
}

#[cfg(test)]
mod session_lifecycle_tests {
    use super::*;

    #[test]
    fn slot_service_id_is_stable() {
        assert_eq!(slot_service_id("ts_base", 7), "ts_bases7");
        assert_eq!(slot_service_id("ts_base", 7), slot_service_id("ts_base", 7));
    }

    #[test]
    fn new_session_bypasses_the_stable_service() {
        let stable = slot_service_id("ts_base", 7);
        let fresh = fresh_service_id("ts_base", 7);
        assert_ne!(fresh, stable);
        assert!(fresh.starts_with("ts_bases7n"));
    }

    #[test]
    fn terminal_open_timeout_is_detected_for_service_recovery() {
        let error = anyhow::anyhow!(
            "Timed out waiting for the remote shell; the target RustDesk terminal service may be stuck"
        );
        assert!(is_terminal_open_timeout(&error));
        assert!(!is_terminal_open_timeout(&anyhow::anyhow!("login failed")));
    }

    #[test]
    fn rendered_notice_is_safe_for_a_zero_sized_test_pty() {
        let mut screen = Screen::new(0, 0);
        screen.passthrough = false;
        screen.note("\n  | Tip:\n  |   command\n");
    }

    #[test]
    fn unusable_terminal_dimensions_are_clamped() {
        assert_eq!(normalize_terminal_size(0, 0), (2, 2));
        assert_eq!(normalize_terminal_size(1, 20), (2, 20));
        assert_eq!(normalize_terminal_size(120, 40), (120, 40));
    }

    #[test]
    fn full_stdout_queue_never_blocks_the_event_loop() {
        let (tx, _rx) = std::sync::mpsc::sync_channel(1);
        assert!(try_queue_stdout(&tx, b"first"));
        assert!(!try_queue_stdout(&tx, b"dropped"));
    }

    #[test]
    fn input_reader_filters_release_but_keeps_press_and_paste() {
        use crossterm::event::{Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};

        let press = Event::Key(KeyEvent::new(KeyCode::Char('x'), KeyModifiers::NONE));
        assert!(matches!(input_from_event(press), Some(Input::Key(_))));

        let release = Event::Key(KeyEvent::new_with_kind(
            KeyCode::Char('x'),
            KeyModifiers::NONE,
            KeyEventKind::Release,
        ));
        assert!(input_from_event(release).is_none());

        assert!(matches!(
            input_from_event(Event::Paste("hello".to_owned())),
            Some(Input::Paste(text)) if text == "hello"
        ));

        // 尺寸变化过去被丢在这里，于是只能靠每 20 毫秒问一次控制台去发现。
        assert!(
            matches!(
                input_from_event(Event::Resize(120, 40)),
                Some(Input::Resize(120, 40))
            ),
            "Resize 必须收下，否则又要退回轮询控制台"
        );
    }

    /// 看门狗本身也得被验一次。
    ///
    /// 它的全部价值在于「下次卡死时一定留下现场」。如果它悄悄不响，代价是又浪费
    /// 一整轮复现——所以这里真的把它跑起来，真的制造一次停顿，再确认文件落了地。
    #[test]
    fn the_watchdog_names_the_phase_it_got_stuck_in() {
        use std::sync::atomic::Ordering;

        let path = stall::report_path();
        let _ = std::fs::remove_file(&path);
        stall::spawn_watchdog();

        // 停在一个非空闲相位上并且不再心跳,正是卡死的样子。
        stall::enter(stall::ABSORB);
        std::thread::sleep(std::time::Duration::from_secs(4));

        let report = std::fs::read_to_string(&path).unwrap_or_default();
        // 让它闭嘴,免得后面的测试一直被它写文件。
        stall::PHASE.store(stall::IDLE, Ordering::Relaxed);

        assert!(
            report.contains("absorb"),
            "看门狗没有指认卡住的相位，取证文件内容：{report:?}"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn graceful_disconnect_uses_rustdesk_close_reason() {
        let encoded = close_connection_message().write_to_bytes().unwrap();
        let decoded = Message::parse_from_bytes(&encoded).unwrap();
        assert!(matches!(
            decoded.union,
            Some(message::Union::Misc(Misc {
                union: Some(misc::Union::CloseReason(reason)),
                ..
            })) if reason.is_empty()
        ));
    }

    #[test]
    fn keepalive_is_a_real_rustdesk_liveness_probe() {
        let encoded = keepalive_message(42).write_to_bytes().unwrap();
        assert!(!encoded.is_empty());
        let decoded = Message::parse_from_bytes(&encoded).unwrap();
        assert!(matches!(
            decoded.union,
            Some(message::Union::TestDelay(TestDelay {
                time: 42,
                from_client: true,
                ..
            }))
        ));
    }

    #[test]
    fn a_quiet_link_may_still_be_asked_to_close_the_session() {
        assert!(may_close_remote(false, None));
        assert!(may_close_remote(
            false,
            Some(std::time::Duration::from_millis(200))
        ));
    }

    #[test]
    fn a_link_that_stopped_answering_probes_is_never_asked_to_close() {
        // 这一发打在忙/卡住的 Windows helper 上会把整个 RustDesk 服务锁死，
        // 设备直接离线。宁可把 persistent shell 留在远端。
        assert!(!may_close_remote(false, Some(PROBE_STALE)));
        assert!(!may_close_remote(
            false,
            Some(std::time::Duration::from_secs(60))
        ));
    }

    #[test]
    fn opting_out_wins_over_a_healthy_link() {
        assert!(!may_close_remote(true, None));
        assert!(!may_close_remote(
            true,
            Some(std::time::Duration::from_millis(1))
        ));
    }

    #[test]
    fn controlled_side_liveness_probe_is_echoed_unchanged() {
        let probe = TestDelay {
            time: 123_456,
            from_client: false,
            last_delay: 17,
            target_bitrate: 2_000_000,
            ..Default::default()
        };
        let encoded = echo_test_delay(probe).write_to_bytes().unwrap();
        let decoded = Message::parse_from_bytes(&encoded).unwrap();
        assert!(matches!(
            decoded.union,
            Some(message::Union::TestDelay(TestDelay {
                time: 123_456,
                from_client: false,
                last_delay: 17,
                target_bitrate: 2_000_000,
                ..
            }))
        ));
    }
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
    } else {
        None
    }
}

fn get_rs_pk(str_base64: &str) -> Option<sign::PublicKey> {
    use base64::Engine;
    get_pk(
        &base64::engine::general_purpose::STANDARD
            .decode(str_base64)
            .ok()?,
    )
    .map(sign::PublicKey)
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
                if ('a'..='z').contains(&c_lower) {
                    vec![(c_lower as u8) - b'a' + 1]
                } else {
                    match c_lower {
                        '[' => vec![0x1b],
                        ']' => vec![0x1d],
                        '\\' => vec![0x1c],
                        '^' => vec![0x1e],
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
        KeyCode::Enter => vec![b'\r'],
        KeyCode::Backspace => vec![0x7f],
        KeyCode::Tab => vec![b'\t'],
        KeyCode::Esc => vec![0x1b],
        KeyCode::Up => vec![0x1b, b'[', b'A'],
        KeyCode::Down => vec![0x1b, b'[', b'B'],
        KeyCode::Right => vec![0x1b, b'[', b'C'],
        KeyCode::Left => vec![0x1b, b'[', b'D'],
        KeyCode::Home => vec![0x1b, b'[', b'H'],
        KeyCode::End => vec![0x1b, b'[', b'F'],
        KeyCode::PageUp => vec![0x1b, b'[', b'5', b'~'],
        KeyCode::PageDown => vec![0x1b, b'[', b'6', b'~'],
        KeyCode::Delete => vec![0x1b, b'[', b'3', b'~'],
        KeyCode::Insert => vec![0x1b, b'[', b'2', b'~'],
        KeyCode::F(1) => vec![0x1b, b'O', b'P'],
        KeyCode::F(2) => vec![0x1b, b'O', b'Q'],
        KeyCode::F(3) => vec![0x1b, b'O', b'R'],
        KeyCode::F(4) => vec![0x1b, b'O', b'S'],
        KeyCode::F(5) => vec![0x1b, b'[', b'1', b'5', b'~'],
        KeyCode::F(6) => vec![0x1b, b'[', b'1', b'7', b'~'],
        KeyCode::F(7) => vec![0x1b, b'[', b'1', b'8', b'~'],
        KeyCode::F(8) => vec![0x1b, b'[', b'1', b'9', b'~'],
        KeyCode::F(9) => vec![0x1b, b'[', b'2', b'0', b'~'],
        KeyCode::F(10) => vec![0x1b, b'[', b'2', b'1', b'~'],
        KeyCode::F(11) => vec![0x1b, b'[', b'2', b'3', b'~'],
        KeyCode::F(12) => vec![0x1b, b'[', b'2', b'4', b'~'],
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

// ── 卡死取证 ───────────────────────────────────────────────────────

/// 卡死时屏幕已经不动了,日志也未必写得出去,所以停顿只能由一个不参与任何锁的
/// 独立线程发现,并写进文件。
///
/// 这一套存在的理由:这个卡死改了几轮都没改对,每一轮都是靠读代码猜。猜错的成本
/// 是一整轮返工,而现场其实什么都没留下——屏幕不动、日志停在半路,分不清是收不
/// 到帧、画不出来,还是卡在某个同步系统调用里。有了相位标记,下一次复现就能直接
/// 指认,不用再猜。
mod stall {
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

    /// 主循环每走一步就加一,看门狗靠它判断有没有在动。
    pub static BEAT: AtomicU64 = AtomicU64::new(0);
    /// 主循环当前所处的相位,取值是 PHASES 的下标。
    pub static PHASE: AtomicUsize = AtomicUsize::new(0);
    /// stdout 线程同样一套,用来区分「主循环卡住」和「控制台写不动」。
    pub static OUT_BEAT: AtomicU64 = AtomicU64::new(0);
    pub static OUT_PHASE: AtomicUsize = AtomicUsize::new(0);
    /// 因为队列满被丢掉的帧数,以及还排在队列里的字节数。
    pub static DROPPED: AtomicU64 = AtomicU64::new(0);
    pub static QUEUED_BYTES: AtomicU64 = AtomicU64::new(0);

    pub const PHASES: &[&str] = &[
        "启动",
        "select 等待(正常空闲)",
        "absorb 吸收远端字节",
        "flush 渲染一帧",
        "repaint 整屏重画",
        "feed_replay 处理回放",
        "crossterm::terminal::size() 查询控制台尺寸",
        "读本地剪贴板(arboard)",
        "剪贴板发送后的固定等待",
        "处理本地按键",
        "关闭连接：停止写任务",
        "退出：恢复本地终端模式",
        "退出：关闭 tokio 运行时",
    ];
    pub const IDLE: usize = 1;
    pub const ABSORB: usize = 2;
    pub const FLUSH: usize = 3;
    pub const REPAINT: usize = 4;
    pub const REPLAY: usize = 5;
    pub const SIZE_QUERY: usize = 6;
    pub const CLIPBOARD: usize = 7;
    pub const CLIP_WAIT: usize = 8;
    pub const INPUT: usize = 9;
    pub const CLOSING: usize = 10;
    pub const EXIT_CONSOLE: usize = 11;
    pub const EXIT_RUNTIME: usize = 12;

    pub const OUT_PHASES: &[&str] = &["空闲", "写控制台(write_all)", "冲刷控制台(flush)"];
    pub const OUT_IDLE: usize = 0;
    pub const OUT_WRITE: usize = 1;
    pub const OUT_FLUSH: usize = 2;

    /// 进入一个相位。只有一次 relaxed store,放在热路径上也不心疼。
    pub fn enter(phase: usize) {
        PHASE.store(phase, Ordering::Relaxed);
        BEAT.fetch_add(1, Ordering::Relaxed);
    }

    pub fn out_enter(phase: usize) {
        OUT_PHASE.store(phase, Ordering::Relaxed);
        OUT_BEAT.fetch_add(1, Ordering::Relaxed);
    }

    fn name(table: &[&str], index: usize) -> String {
        table
            .get(index)
            .map(|s| (*s).to_owned())
            .unwrap_or_else(|| format!("未知({index})"))
    }

    /// 停顿超过这个时长就认为卡死了。正常一帧几毫秒,空闲时相位是「select 等待」
    /// 且心跳照常在动,所以不会误报。
    const STALL: std::time::Duration = std::time::Duration::from_secs(3);

    pub fn report_path() -> std::path::PathBuf {
        std::env::temp_dir().join(format!("rustshell-stall-{}.log", std::process::id()))
    }

    /// 起看门狗。它不碰终端、不碰任何业务锁,只读原子量和写文件。
    pub fn spawn_watchdog() {
        let path = report_path();
        std::thread::Builder::new()
            .name("rustshell-watchdog".to_owned())
            .spawn(move || {
                use std::io::Write;
                let mut last = (0_u64, 0_u64);
                let mut moved_at = std::time::Instant::now();
                let mut reported_at: Option<std::time::Instant> = None;
                loop {
                    std::thread::sleep(std::time::Duration::from_millis(500));
                    let now = (BEAT.load(Ordering::Relaxed), OUT_BEAT.load(Ordering::Relaxed));
                    let phase = PHASE.load(Ordering::Relaxed);
                    // 两种「不动」是正常的:一是主循环停在 select 上等事件,二是
                    // 会话还没开始——连接和握手本来就可能慢到十几秒,那段时间相位
                    // 一直是「启动」,不该报。
                    let idle = phase == IDLE || phase == 0;
                    if now != last || idle {
                        last = now;
                        moved_at = std::time::Instant::now();
                        reported_at = None;
                        continue;
                    }
                    let stuck = moved_at.elapsed();
                    if stuck < STALL {
                        continue;
                    }
                    // 卡住期间每 5 秒记一次,既能看出是持续卡还是偶发顿。
                    if reported_at.is_some_and(|t| {
                        t.elapsed() < std::time::Duration::from_secs(5)
                    }) {
                        continue;
                    }
                    let first = reported_at.is_none();
                    reported_at = Some(std::time::Instant::now());
                    let line = format!(
                        "[{:?} 无进展] 主循环相位={} | stdout 线程相位={} | 已丢帧={} | 队列积压={} 字节\n",
                        stuck,
                        name(PHASES, phase),
                        name(OUT_PHASES, OUT_PHASE.load(Ordering::Relaxed)),
                        DROPPED.load(Ordering::Relaxed),
                        QUEUED_BYTES.load(Ordering::Relaxed),
                    );
                    // 屏幕多半已经死了,所以写文件;stderr 也写一份,重定向到文件时更省事。
                    if let Ok(mut f) = std::fs::OpenOptions::new()
                        .create(true)
                        .append(true)
                        .open(&path)
                    {
                        let _ = f.write_all(line.as_bytes());
                    }
                    // 屏幕这时多半已经不动了，但万一还能显示，第一条要告诉用户
                    // 取证文件在哪。用 \r\n 是因为终端处于原始模式。
                    if first {
                        eprint!("\r\n[rustshell 卡死取证] 详情写入 {}\r\n", path.display());
                    }
                    eprint!("\r\n[rustshell 卡死取证] {line}");
                }
            })
            .expect("start stall watchdog");
    }
}

enum StdoutCommand {
    Write(Vec<u8>),
    Flush(std::sync::mpsc::SyncSender<()>),
}

fn stdout_sender() -> &'static std::sync::mpsc::SyncSender<StdoutCommand> {
    static SENDER: std::sync::OnceLock<std::sync::mpsc::SyncSender<StdoutCommand>> =
        std::sync::OnceLock::new();
    SENDER.get_or_init(|| {
        // 四秒左右的完整帧余量。队列满时宁可丢一帧并在下一帧整屏重画，也不能让
        // stdout 反压堵住网络与输入循环，否则连 Ctrl+Q 都读不到。
        let (tx, rx) = std::sync::mpsc::sync_channel::<StdoutCommand>(64);
        std::thread::Builder::new()
            .name("rustshell-stdout".to_owned())
            .spawn(move || {
                while let Ok(command) = rx.recv() {
                    let mut stdout = std::io::stdout();
                    match command {
                        StdoutCommand::Write(data) => {
                            // 写控制台是同步系统调用,在 Windows 上还要抢控制台
                            // 锁。它卡住时整个窗口就不动了,所以单独标一个相位。
                            stall::out_enter(stall::OUT_WRITE);
                            stdout.write_all(&data).ok();
                            stall::out_enter(stall::OUT_FLUSH);
                            stdout.flush().ok();
                            stall::QUEUED_BYTES
                                .fetch_sub(data.len() as u64, std::sync::atomic::Ordering::Relaxed);
                            stall::out_enter(stall::OUT_IDLE);
                        }
                        StdoutCommand::Flush(done) => {
                            stall::out_enter(stall::OUT_FLUSH);
                            stdout.flush().ok();
                            done.try_send(()).ok();
                            stall::out_enter(stall::OUT_IDLE);
                        }
                    }
                }
            })
            .expect("start stdout worker");
        tx
    })
}

/// 把字节交给独立 stdout 线程；返回 false 表示本帧因本地终端反压被丢弃。
///
/// 丢帧过去是完全静默的。屏幕停住时分不清是没收到数据还是收到了画不出去,而这
/// 两者的修法完全相反——所以丢一帧必须留下痕迹。
fn try_queue_stdout(sender: &std::sync::mpsc::SyncSender<StdoutCommand>, data: &[u8]) -> bool {
    use std::sync::atomic::Ordering;
    let n = data.len() as u64;
    match sender.try_send(StdoutCommand::Write(data.to_vec())) {
        Ok(()) => {
            stall::QUEUED_BYTES.fetch_add(n, Ordering::Relaxed);
            true
        }
        Err(_) => {
            let dropped = stall::DROPPED.fetch_add(1, Ordering::Relaxed) + 1;
            // 刷屏时丢帧会连成一片,全记下来只会把日志淹掉;按 2 的幂记一次,
            // 既能看出「开始丢了」也能看出量级。
            if dropped.is_power_of_two() {
                log::warn!(
                    "本地终端跟不上：已丢弃 {dropped} 帧输出（队列积压 {} 字节）",
                    stall::QUEUED_BYTES.load(Ordering::Relaxed)
                );
            }
            false
        }
    }
}

fn write_stdout(data: &[u8]) -> bool {
    // Tests drive the renderer directly and assert on the models; letting
    // control sequences reach the real stdout just shreds the test report.
    if cfg!(test) {
        return true;
    }
    try_queue_stdout(stdout_sender(), data)
}

/// 尽力等 stdout 队列落地，但绝不让退出再次被堵死。
fn flush_stdout() {
    if cfg!(test) {
        return;
    }
    let (tx, rx) = std::sync::mpsc::sync_channel(1);
    if stdout_sender().try_send(StdoutCommand::Flush(tx)).is_ok() {
        let _ = rx.recv_timeout(std::time::Duration::from_millis(250));
    }
}

// ── Terminal setup ─────────────────────────────────────────────────

struct ConsoleGuard;
impl ConsoleGuard {
    fn enable() -> Result<Self> {
        crossterm::terminal::enable_raw_mode().context("Failed to enable raw mode")?;
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
                win_console::SetConsoleMode(
                    handle,
                    mode | win_console::ENABLE_VIRTUAL_TERMINAL_PROCESSING
                        | win_console::DISABLE_NEWLINE_AUTO_RETURN,
                );
            }
        }
        Ok(Self)
    }
}
impl Drop for ConsoleGuard {
    fn drop(&mut self) {
        // 先恢复输入模式。stdout 线程若正在被终端反压，直接 execute 会在这里再次
        // 卡住；控制序列也走非阻塞队列，并只做有上限的等待。
        let _ = crossterm::terminal::disable_raw_mode();
        write_stdout(b"\x1b[?2004l");
        flush_stdout();
    }
}

/// One thing the input loop needs to act on.
enum Input {
    Key(crossterm::event::KeyEvent),
    /// A whole clipboard paste, delivered in one piece by bracketed paste.
    Paste(String),
    /// 终端改了尺寸，(cols, rows)。
    Resize(u16, u16),
}

type InputResult = std::result::Result<Input, String>;

/// Keep the blocking terminal reader outside Tokio and outside reconnects.
///
/// `event::read()` cannot be cancelled reliably on every terminal. The reader
/// thread is therefore process-scoped and deliberately detached: dropping the
/// receiver makes future sends fail, and a blocked read can never hold up
/// Ctrl+Q, a process signal, network handling, or process shutdown.
fn spawn_input_reader() -> tokio::sync::mpsc::UnboundedReceiver<InputResult> {
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
    std::thread::Builder::new()
        .name("rustshell-input".to_owned())
        .spawn(move || loop {
            match crossterm::event::read() {
                Ok(event) => {
                    if let Some(input) = input_from_event(event) {
                        if tx.send(Ok(input)).is_err() {
                            break;
                        }
                    }
                }
                Err(error) => {
                    let _ = tx.send(Err(error.to_string()));
                    break;
                }
            }
        })
        .expect("start terminal input reader");
    rx
}

/// 只把业务关心的终端事件放进发送队列。
///
/// Resize 过去在这里被丢掉，改尺寸靠主循环每 20 毫秒调一次
/// `crossterm::terminal::size()` 去发现。那个调用在 Windows 上要打开 CONOUT$
/// 并取控制台锁，而 stdout 线程正拿着同一把锁往控制台里灌字节——刷屏时每秒五十
/// 次去抢它，纯属自找。终端本来就会把尺寸变化当成事件送过来，收下即可。
fn input_from_event(event: crossterm::event::Event) -> Option<Input> {
    use crossterm::event::{Event, KeyEventKind};
    match event {
        Event::Key(key) if key.kind != KeyEventKind::Release => Some(Input::Key(key)),
        Event::Paste(text) => Some(Input::Paste(text)),
        Event::Resize(cols, rows) => Some(Input::Resize(cols, rows)),
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
    let image = clipboard
        .get_image()
        .context("no image on the local clipboard")?;
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
        bail!(
            "clipboard image is {} bytes, too large to send",
            bytes.len()
        );
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
    /// stdout 队列曾丢帧；下一次渲染必须整屏重画，不能继续基于旧 host 做 diff。
    output_dirty: bool,
    /// vt100 history length as of the last absorb.
    drawn_history: usize,
    /// 上一次 absorb 看到的备用屏幕状态。
    ///
    /// 与 `alt` 分开：那个由 flush/repaint 维护，按帧走；这个要按分片走，因为
    /// 判断历史长度的跳变是不是「换了块画布」必须在同一次 absorb 里完成。
    absorb_alt: bool,
    /// 自上次渲染以来退役的行，等着被推进宿主终端的滚动缓冲。
    pending: Vec<Vec<u8>>,
    /// 本帧内 vt100 自己增长出来的历史行数。
    ///
    /// 它精确且与分片无关，所以照旧按分片累计；启发式检测则要等整帧落地。
    natural_in_frame: usize,
}

impl Screen {
    fn new(rows: u16, cols: u16) -> Self {
        let (cols, rows) = normalize_terminal_size(cols, rows);
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
            output_dirty: false,
            drawn_history: 0,
            absorb_alt: false,
            pending: Vec::new(),
            natural_in_frame: 0,
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
        if write_stdout(bytes) {
            self.host.process(bytes);
        } else {
            self.output_dirty = true;
        }
    }

    /// 把字节攒进本帧的输出缓冲，并让 host 模型立刻跟上。
    ///
    /// 与 `emit` 的区别只在于不马上写出去。host 必须在这里就更新,因为同一帧
    /// 里后面算 diff 要拿它当基准——基准慢一步,diff 就画错位置。
    fn stage(&mut self, frame: &mut Vec<u8>, bytes: &[u8]) {
        if bytes.is_empty() {
            return;
        }
        self.host.process(bytes);
        frame.extend_from_slice(bytes);
    }

    /// Park a message on the last row for a few seconds.
    fn set_status(&mut self, text: impl Into<String>) {
        if self.passthrough {
            let t = text.into();
            write_stdout(
                format!(
                    "
[rustshell] {t}
"
                )
                .as_bytes(),
            );
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
        // 切成不超过一屏字节数的小片喂进去。
        //
        // vt100 只能透过「一屏那么大的窗口」回看历史:它把可见行拼成
        // `scrollback[len-off..] ++ rows[..rows-off]`,off 一旦超过屏幕行数,
        // 后半段的减法就下溢——debug 构建当场 panic,release 构建靠回绕侥幸
        // 得出对的结果。而一次 process 能一口气把几百行顶出屏幕,off 就是这么
        // 超出去的:远端一帧里塞进比一屏还多的行,正是刷屏的全屏应用的常态。
        //
        // 一个字节最多让行号前进一格,所以每片给不超过 rows 个字节,就保证每
        // 片新增的历史行数不超过一屏,取历史行时的 off 永远落在 vt100 撑得住
        // 的范围内。vt100 是流式解析器,从任意字节处切开都不影响解析结果。
        let step = (self.rows as usize).max(1);
        for chunk in data.chunks(step) {
            self.absorb_chunk(chunk);
        }
        // 启发式检测不在这里做——见 detect_retired。
    }

    /// 吸收一片保证不会顶出超过一屏内容的字节。
    fn absorb_chunk(&mut self, data: &[u8]) {
        let before = self.drawn_history;
        self.model.process(data);

        // 备用屏幕是另一块不带回滚的画布,进出它会把历史长度整个换掉:进去时
        // 归零,出来时主屏那份又整体回来。把这个跳变当成「新增了这么多历史」
        // 的话,离开备用屏幕的一瞬间会把整份主屏历史(上限一万行)重新归档一
        // 遍,再由 flush 逐行写进终端——冻屏好几秒,回滚里还平白多出一整份重
        // 复。全屏应用退出时必然撞上。它不是滚动,重新对一次基准即可。
        let alt = self.model.screen().alternate_screen();
        if alt != self.absorb_alt {
            self.absorb_alt = alt;
            self.drawn_history = self.vt_history();
            return;
        }

        let after = self.vt_history();
        self.drawn_history = after;

        // vt100 自己长出来的历史是精确的，而且与分片无关：这些行确实被推出了
        // 屏幕。照旧按分片归档。
        let natural = after.saturating_sub(before);
        if natural > 0 {
            for index in before..after {
                let line = self.vt_history_line(after, index);
                self.pending.push(line);
            }
            self.natural_in_frame += natural;
            log::debug!(
                "absorb: natural={natural} pending={} hist={}",
                self.pending.len(),
                self.history.len()
            );
        }
    }

    /// 整帧落地之后再判断有没有发生「重绘式滚动」。
    ///
    /// 这件事**不能**按网络分片做。一次重绘会被切成好几块，中间态是「新行盖在
    /// 上面、旧行还留在下面」的混合屏——它照样能锚上，于是把没退役的行也归了
    /// 档，并把基准推到这张半成品；下一块补完后又检测出一次位移，同一批行被归
    /// 档两次。归档的行会被滚进终端缓冲、diff 又把它们画回屏幕，回滚里于是出现
    /// 重复的块。实测在 10 行屏上按字节遍历切分点，能稳定复现出退役 6 行而不是
    /// 3 行。
    ///
    /// 所以检测只在帧边界跑，和渲染共用同一个静默判定。原先把它放在分片里，是
    /// 为了不漏掉两次渲染之间的中间态；那个顾虑由上面的 natural 兜住——真正把
    /// 行顶出屏幕的滚动都会体现为 vt100 的历史增长，与分片无关。
    fn detect_retired(&mut self) {
        let cur_plain: Vec<String> = self.model.screen().rows(0, self.cols).collect();
        if self.natural_in_frame == 0 {
            let moved = detect_scroll(&self.prev_plain, &cur_plain);
            if moved > 0 {
                let take = moved.min(self.prev_formatted.len());
                let lines: Vec<Vec<u8>> = self.prev_formatted.iter().take(take).cloned().collect();
                self.pending.extend(lines);
                log::debug!(
                    "frame: moved={moved} pending={} hist={}",
                    self.pending.len(),
                    self.history.len()
                );
            }
        }
        self.natural_in_frame = 0;
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
        // 到这里这一帧才算完整，检测放在这里做。
        self.detect_retired();

        let alt = self.model.screen().alternate_screen();
        let rows = self.rows as usize;

        // 退役的行已经攒好，这里只管画。
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
        if self.output_dirty {
            self.repaint(false);
            return;
        }

        // 一帧只写一次。原先退役滚动、diff、状态行各写一次、各 flush 一次,
        // 三趟系统调用;Windows 控制台上这个往返不便宜,而且中间态会闪。
        let mut frame: Vec<u8> = Vec::with_capacity(4096);
        let mut out: Vec<u8> = Vec::with_capacity(1024);
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
        self.stage(&mut frame, &out);

        let diff = self.model.screen().contents_diff(self.host.screen());
        self.stage(&mut frame, &diff);

        // 状态行每帧重画，因为远端应用一直在覆盖最后一行。
        let status = self.status_line();
        if let Some(line) = &status {
            self.stage(&mut frame, line);
        }
        if !write_stdout(&frame) {
            // stage 已经按“成功写出”推进了 host；丢帧后必须废弃这个基准。
            self.host = vt100::Parser::new(self.rows, self.cols, 0);
            self.output_dirty = true;
        }

        // 状态行刚过期：屏幕上还留着它，只能整屏重画抹掉。
        if status.is_none() && self.status.is_some() {
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

    /// 返回 true 表示需要请远端重画一次。
    fn resize(&mut self, rows: u16, cols: u16) -> bool {
        let (cols, rows) = normalize_terminal_size(cols, rows);
        if self.passthrough {
            self.rows = rows;
            self.cols = cols;
            // 直通模式没有模型可以重画，只能把本地清成已知状态再让远端自己
            // 重来。终端刚按自己的规则回流过一遍，留在屏幕上的是错位的旧内容，
            // 不清掉的话远端没覆盖到的地方会一直花着。用 2J 而不是 3J——
            // 滚动缓冲是直通模式下唯一的历史，不能连它一起清了。
            write_stdout(b"\x1b[H\x1b[2J");
            return true;
        }
        self.model.set_size(rows, cols);
        self.host.set_size(rows, cols);
        // 改尺寸会让 vt100 重排网格，历史长度跟着跳。那个跳变不是滚动,拿旧
        // 基准去减会凭空归档一大批行,和进出备用屏幕是同一类问题。
        self.drawn_history = self.vt_history();
        self.rows = rows;
        self.cols = cols;
        self.prev_plain = self.model.screen().rows(0, cols).collect();
        self.prev_formatted = self.model.screen().rows_formatted(0, cols).collect();
        // 尺寸变了必须整屏重画，不能接着 diff。
        //
        // 真实终端在被拉伸时会按自己的规则回流——换行的长行是重排还是截断、
        // 光标下方的内容留不留——`vt100::set_size` 复现不出同一套结果。于是
        // host 模型和终端实际显示分叉，而 diff 是对着 host 算的，之后每一帧
        // 都画在错位的基准上，屏幕就花了。理由和备用屏幕切换那里一样：跨不
        // 过去的状态变更，就别 diff。
        self.repaint(false);
        // 本地已经按模型画好了，不必劳烦远端。
        false
    }

    /// 上一次写没能交出去，屏幕上留着的是旧内容。
    ///
    /// 这个状态过去只能等下一帧远端数据来推动。可是刷屏卡住时最后一帧往往正好
    /// 是被丢掉的那一帧，而应用画完就安静了——于是屏幕永远停在半张画面上,
    /// 看着和死了一样，其实链路好好的。要自己爬回来。
    fn needs_repaint(&self) -> bool {
        !self.passthrough && self.output_dirty
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
        if write_stdout(&out) {
            self.host.process(&out);
            self.output_dirty = false;
        } else {
            self.output_dirty = true;
        }
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
    const RECEIVE_TIMEOUT_MS: u64 = 15_000;
    match timeout(RECEIVE_TIMEOUT_MS, conn.next())
        .await
        .with_context(|| format!("Timed out during {step}"))?
    {
        Some(Ok(b)) => {
            log::debug!("[{step}] received {} bytes", b.len());
            Ok(b)
        }
        Some(Err(e)) => bail!("[{step}] stream error: {e}"),
        None => bail!("[{step}] connection closed by peer"),
    }
}

async fn recv_msg(conn: &mut Link, step: &str) -> Result<Message> {
    let bytes = recv_raw(conn, step).await?;
    Message::parse_from_bytes(&bytes).with_context(|| format!("[{step}] failed to parse Message"))
}

async fn recv_rendezvous_msg(conn: &mut Link, step: &str) -> Result<RendezvousMessage> {
    let bytes = recv_raw(conn, step).await?;
    RendezvousMessage::parse_from_bytes(&bytes)
        .with_context(|| format!("[{step}] failed to parse RendezvousMessage"))
}

async fn send_msg(conn: &mut Link, msg: &impl ProtoMessage, step: &str) -> Result<()> {
    timeout(CONNECT_TIMEOUT, conn.send(msg))
        .await
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
    if args.id.is_empty() {
        args.id = std::env::var("RUSTSHELL_ID").unwrap_or_default();
    }
    if args.server.is_empty() {
        args.server = std::env::var("RUSTSHELL_SERVER").unwrap_or_default();
    }
    if args.port == 21116 {
        if let Ok(v) = std::env::var("RUSTSHELL_PORT") {
            if let Ok(p) = v.parse() {
                args.port = p;
            }
        }
    }
    if args.key.is_empty() {
        args.key = std::env::var("RUSTSHELL_KEY").unwrap_or_default();
    }
    if !args.debug {
        args.debug = std::env::var("RUSTSHELL_DEBUG")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);
    }
    if args.password.is_empty() {
        args.password = std::env::var("RUSTSHELL_PASSWORD").unwrap_or_default();
    }
    if args.quit_key == 'q' {
        if let Ok(v) = std::env::var("RUSTSHELL_QUIT_KEY") {
            if let Some(c) = v.chars().next() {
                args.quit_key = c;
            }
        }
    }
    if !args.new_session {
        args.new_session = std::env::var("RUSTSHELL_NEW_SESSION")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);
    }
    if args.log_file.is_empty() {
        args.log_file = std::env::var("RUSTSHELL_LOG_FILE").unwrap_or_default();
    }
    if !args.detach {
        args.detach = std::env::var("RUSTSHELL_DETACH")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);
    }
    if args.slot.is_none() {
        if let Ok(v) = std::env::var("RUSTSHELL_SLOT") {
            if let Ok(n) = v.parse() {
                args.slot = Some(n);
            }
        }
    }
    if !args.render {
        args.render = std::env::var("RUSTSHELL_RENDER")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);
    }
    if !args.no_reconnect {
        args.no_reconnect = std::env::var("RUSTSHELL_NO_RECONNECT")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);
    }
    if !args.no_remote_close {
        args.no_remote_close = std::env::var("RUSTSHELL_NO_REMOTE_CLOSE")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);
    }

    if args.clipboard_check {
        match clipboard_image_message() {
            Ok((_, bytes, w, h)) => {
                println!("clipboard: 图片 {w}x{h}，压缩后 {bytes} 字节，可以发送");
            }
            Err(e) => println!("clipboard: 读不到图片 —— {e:#}"),
        }
        return;
    }

    if args.id.is_empty() {
        eprintln!("Error: --id or RUSTSHELL_ID is required");
        std::process::exit(1);
    }
    if args.server.is_empty() {
        eprintln!("Error: --server or RUSTSHELL_SERVER is required");
        std::process::exit(1);
    }
    if !args.quit_key.is_ascii_alphabetic() {
        eprintln!("Error: --quit-key must be an ASCII letter a-z");
        std::process::exit(1);
    }

    let log_level = if args.debug { "debug" } else { "info" };
    // Raw terminal mode disables the usual LF -> CRLF translation. Without an
    // explicit carriage return, any log emitted while the session is active
    // starts at the previous cursor column and corrupts the rendered screen.
    let mut logger =
        env_logger::Builder::from_env(env_logger::Env::default().filter_or("RUST_LOG", log_level));
    logger.format_suffix("\r\n").init();

    let password = if args.password.is_empty() {
        match rpassword::prompt_password("Enter password: ") {
            Ok(p) => p,
            Err(e) => {
                eprintln!("Failed to read password: {}", e);
                std::process::exit(1);
            }
        }
    } else {
        args.password
    };

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");

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
    let mut service_id = if args.new_session {
        fresh_service_id(&base, slot.id)
    } else {
        slot_service_id(&base, slot.id)
    };
    log::info!(
        "Terminal session: {} (slot {}, {})",
        service_id,
        slot.id,
        if args.new_session {
            "new"
        } else {
            "reattach if it exists"
        }
    );

    let mut attempt: u32 = 0;
    let mut failed = false;
    let mut fresh_fallback_used = false;
    let mut fresh_open = args.new_session;
    let _console_guard = match ConsoleGuard::enable() {
        Ok(guard) => guard,
        Err(error) => {
            eprintln!("Error: {error:#}");
            std::process::exit(1);
        }
    };
    let mut input_events = spawn_input_reader();
    // 卡死过好几轮都没定位到,靠的都是读代码猜。这个线程不参与任何锁,停顿超过
    // 三秒就把当时的相位写进文件,下次复现直接看它。
    stall::spawn_watchdog();
    // 记 info 而不是 debug：不带 -d 的日志也要能一眼看出跑的是带取证的版本。
    log::info!("卡死取证文件: {}", stall::report_path().display());
    loop {
        // 网络连接和服务端握手期间没有本地阻塞调用，不能沿用上一次收尾时的相位，
        // 否则重连等待超过三秒会被看门狗误报成卡死在 CloseTerminal。
        stall::enter(stall::IDLE);
        let outcome = rt.block_on(run(
            args.id.clone(),
            args.key.clone(),
            args.server.clone(),
            args.port,
            password.clone(),
            args.quit_key,
            service_id.clone(),
            &slot,
            log_path.clone(),
            args.detach,
            args.render,
            fresh_open,
            args.no_remote_close,
            &mut input_events,
        ));
        // A reconnect always targets the same persistent service and replays
        // its buffered output. Only the first --new-session open is fresh.
        fresh_open = false;

        // 同一个持久 service 被旧连接卡住时，登录仍会成功，但 OpenTerminal 永远
        // 没有回应。只在第一次遇到这个明确症状时切换新 service，避免后续重连不断
        // 创建新会话；新 service 后续仍保持稳定，断线可以继续接回。
        let switched_to_fresh =
            !fresh_fallback_used && matches!(&outcome, Err(error) if is_terminal_open_timeout(error));
        if switched_to_fresh {
            fresh_fallback_used = true;
            service_id = fresh_service_id(&base, slot.id);
            fresh_open = true;
            log::warn!(
                "持久终端打开超时，将切换到新的 service_id 绕过远端卡住的 terminal service"
            );
        }

        let should_retry = match &outcome {
            Ok(SessionEnd::UserQuit) => {
                break;
            }
            Ok(SessionEnd::RemoteClosed) => {
                break;
            }
            Ok(SessionEnd::Disconnected) => true,
            Err(e) => {
                eprintln!("\r\nError: {:#}", e);
                // A failure before the first successful session is usually a
                // bad address or password — retrying would just repeat it.
                // terminal open 超时只允许一次 service_id 恢复尝试。新的 service
                // 也超时，说明远端 terminal service 已经整体失去响应；继续重连只会
                // 在远端堆积更多卡住的连接，最后把 RustDesk 服务拖死。
                if switched_to_fresh {
                    true
                } else if fresh_fallback_used && is_terminal_open_timeout(e) {
                    log::error!("新的 service_id 仍无法打开远端终端，停止自动重连；请先恢复远端 RustDesk 服务");
                    false
                } else {
                    attempt > 0
                }
            }
        };

        if !should_retry || args.no_reconnect {
            // 这里过去直接 process::exit(1)。那会跳过所有析构，包括把终端从
            // raw mode 放回去的那个——连不上服务器之后，用户的 shell 就不回显
            // 了，得自己 `reset`。改成记下来，走完统一的收尾再带着退出码走。
            failed = matches!(outcome, Err(_));
            break;
        }

        attempt += 1;
        // 2s, 4s, 8s ... capped at 30s.
        let delay = std::cmp::min(2u64.saturating_pow(attempt.min(5)), 30);
        eprintln!(
            "\r\nConnection lost. Reconnecting in {}s (attempt {})...",
            delay, attempt
        );
        // 退避睡眠不是主循环卡死，清掉 CLOSING 相位，避免看门狗把正常等待记成故障。
        stall::enter(stall::IDLE);
        std::thread::sleep(std::time::Duration::from_secs(delay));
    }

    // 退出路径上的每一步都要有上限，而且要能在日志里认出来。
    //
    // 现场记录过一次：SIGTERM 的处理日志已经打出来了，进程却再也没退，只能补一
    // 刀。会话循环里的收尾本来就步步有超时，剩下没有上限的就是这两步——恢复终端
    // 模式要等 stdout 线程，而 drop 运行时会一直等到所有工作线程停妥。链路已经
    // 废掉时，这两处都可能永远等下去。
    log::info!("会话结束，正在恢复本地终端...");
    stall::enter(stall::EXIT_CONSOLE);
    drop(_console_guard);

    log::info!("正在关闭运行时...");
    stall::enter(stall::EXIT_RUNTIME);
    // 用带上限的关闭代替隐式 drop。到点仍没停妥的任务被就地丢下——此刻已经没有
    // 任何东西依赖它们，而「退不出去」比「少收一个尾」严重得多。
    rt.shutdown_timeout(std::time::Duration::from_secs(2));
    log::info!("已退出");
    if failed {
        std::process::exit(1);
    }
}

async fn run(
    device_id: String,
    licence_key: String,
    server: String,
    port: u16,
    password: String,
    quit_key: char,
    service_id: String,
    slot: &TerminalSlot,
    log_path: Option<std::path::PathBuf>,
    detach: bool,
    render: bool,
    fresh_open: bool,
    no_remote_close: bool,
    input_events: &mut tokio::sync::mpsc::UnboundedReceiver<InputResult>,
) -> Result<SessionEnd> {
    let rendezvous_addr = format!("{}:{}", server, port);
    log::info!("Connecting to rendezvous server {}...", rendezvous_addr);

    // Phase 1: Connect to rendezvous server
    let mut socket = Link::connect(&rendezvous_addr.clone(), CONNECT_TIMEOUT)
        .await
        .with_context(|| format!("Failed to connect to {}", rendezvous_addr))?;
    log::info!("TCP connected to rendezvous server");

    let key_str: &str = if licence_key.is_empty() {
        RS_PUB_KEY
    } else {
        &licence_key
    };
    attempt_secure_tcp(&mut socket, key_str).await?;

    // Send PunchHoleRequest
    let mut msg_out = RendezvousMessage::new();
    msg_out.set_punch_hole_request(PunchHoleRequest {
        id: device_id.clone(),
        licence_key: licence_key.clone(),
        conn_type: ConnType::TERMINAL.into(),
        nat_type: NatType::SYMMETRIC.into(),
        force_relay: false,
        version: VERSION.to_owned(),
        ..Default::default()
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
                } else {
                    check_port(ph.relay_server.clone(), RELAY_PORT)
                };
                log::info!(
                    "Peer address: {} (local: {}), relay fallback: {}",
                    addr,
                    ph.is_local(),
                    relay
                );
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
            } else {
                check_port(rr.relay_server, RELAY_PORT)
            };
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
                log::info!(
                    "Direct failed ({}), falling back to relay {}",
                    e,
                    relay_server
                );
                let mut c = Link::connect(&relay_server.clone(), CONNECT_TIMEOUT)
                    .await
                    .with_context(|| format!("Failed to connect to relay {}", relay_server))?;
                // Send RequestRelay for relay
                let mut msg_out = RendezvousMessage::new();
                msg_out.set_request_relay(RequestRelay {
                    id: device_id.clone(),
                    uuid: relay_uuid,
                    licence_key: licence_key.clone(),
                    conn_type: ConnType::TERMINAL.into(),
                    ..Default::default()
                });
                send_msg(&mut c, &msg_out, "request_relay").await?;
                c
            }
        }
    } else {
        log::info!("Connecting via relay server {}...", relay_server);
        let mut c = Link::connect(&relay_server.clone(), CONNECT_TIMEOUT)
            .await
            .with_context(|| format!("Failed to connect to relay {}", relay_server))?;
        let mut msg_out = RendezvousMessage::new();
        msg_out.set_request_relay(RequestRelay {
            id: device_id.clone(),
            uuid: relay_uuid,
            licence_key: licence_key.clone(),
            conn_type: ConnType::TERMINAL.into(),
            ..Default::default()
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
    } else {
        None
    };

    let msg_in = recv_msg(&mut conn, "wait_signed_id").await?;
    let signed_id = match msg_in.union {
        Some(message::Union::SignedId(si)) => si,
        other => bail!("Expected SignedId, got: {:?}", other.map(|_| "other")),
    };
    let peer_sign_pk =
        peer_sign_pk.ok_or_else(|| anyhow::anyhow!("No peer public key from rendezvous server"))?;
    let (peer_id, their_pk) = decode_id_pk(&signed_id.id, &peer_sign_pk)?;
    log::info!("Peer identity verified: {}", peer_id);

    let (av, sv, enc_key) = create_symmetric_key_msg(their_pk);
    let mut pk_msg = Message::new();
    pk_msg.set_public_key(PublicKey {
        asymmetric_value: av.into(),
        symmetric_value: sv.into(),
        ..Default::default()
    });
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
    h1.update(password.as_bytes());
    h1.update(hash.salt.as_bytes());
    let mut h2 = Sha256::new();
    h2.update(&h1.finalize()[..]);
    h2.update(hash.challenge.as_bytes());
    let pw_response: Vec<u8> = h2.finalize()[..].into();

    // Phase 5: Login with Terminal
    let mut lr = LoginRequest::new();
    lr.username = device_id.clone();
    lr.password = pw_response.into();
    lr.my_id = format!("RustShell-{}", std::process::id());
    lr.version = VERSION.to_owned();
    lr.my_platform = std::env::consts::OS.to_owned();
    // Keep the service persistent even for ordinary sessions. RustDesk 1.4.6
    // removes non-persistent services synchronously on disconnect while holding
    // its global terminal registry lock. If Windows helper teardown blocks,
    // every later terminal Open hangs until the RustDesk service is restarted.
    // Normal Ctrl+Q still sends CloseTerminal; persistence only makes abnormal
    // disconnects recoverable instead of poisoning the whole terminal service.
    let mut opt = OptionMessage::new();
    opt.terminal_persistent = option_message::BoolOption::Yes.into();
    lr.option = protobuf::MessageField::some(opt);

    let mut terminal = Terminal::new();
    // The stable ID isolates slots and lets a disconnected session reattach.
    terminal.service_id = service_id;
    lr.set_terminal(terminal);
    let mut lr_msg = Message::new();
    lr_msg.set_login_request(lr);
    send_msg(&mut conn, &lr_msg, "login_request").await?;
    log::info!("Login request sent");

    let bytes = recv_raw(&mut conn, "wait_login_response").await?;
    log::debug!(
        "Login response raw bytes ({}): {:02x?}",
        bytes.len(),
        bytes.as_ref()
    );
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
        Some(login_response::Union::Error(err)) if !err.is_empty() => {
            bail!("Login failed: {}", err)
        }
        Some(login_response::Union::PeerInfo(pi)) => {
            log::info!(
                "Connected to {} ({} {})",
                pi.hostname,
                pi.platform,
                pi.version
            );
            remote_platform = pi.platform;
        }
        _ => {
            log::debug!("Login accepted (no peer info, empty response)");
            log::info!("Login accepted (peer omitted optional platform metadata)");
        }
    }

    // Phase 6: Terminal I/O
    terminal_io_loop(
        conn,
        &remote_platform,
        quit_key,
        render,
        fresh_open,
        slot,
        log_path,
        detach,
        no_remote_close,
        input_events,
    )
    .await
}

// ── secure_tcp ─────────────────────────────────────────────────────

async fn attempt_secure_tcp(conn: &mut Link, key: &str) -> Result<()> {
    let rs_pk = match get_rs_pk(key) {
        Some(pk) => pk,
        None => {
            log::debug!("No valid key, skipping secure_tcp");
            return Ok(());
        }
    };
    match timeout(3000, conn.next()).await {
        Ok(Some(Ok(bytes))) => {
            let rmsg = match RendezvousMessage::parse_from_bytes(&bytes) {
                Ok(m) => m,
                Err(_) => {
                    log::debug!("Non-protobuf, skipping");
                    return Ok(());
                }
            };
            let ex = match rmsg.union {
                Some(rendezvous_message::Union::KeyExchange(ex)) => ex,
                _ => {
                    log::debug!("No KeyExchange, proceeding");
                    return Ok(());
                }
            };
            if ex.keys.len() != 1 {
                log::warn!("Invalid KeyExchange");
                return Ok(());
            }
            let their_pk_b = match sign::verify(&ex.keys[0], &rs_pk) {
                Ok(pk) => pk,
                Err(_) => {
                    log::warn!("Sig verify failed");
                    return Ok(());
                }
            };
            let their_pk = match get_pk(&their_pk_b) {
                Some(pk) => pk,
                None => {
                    log::warn!("Invalid pk len");
                    return Ok(());
                }
            };
            let (av, sv, enc) = create_symmetric_key_msg(their_pk);
            let mut mo = RendezvousMessage::new();
            mo.set_key_exchange(KeyExchange {
                keys: vec![av.into(), sv.into()],
                ..Default::default()
            });
            send_msg(conn, &mo, "key_exchange_response").await?;
            conn.set_key(enc);
            log::info!("Secure channel with rendezvous server");
        }
        Ok(Some(Err(e))) => {
            log::warn!("Stream err: {e}");
        }
        Ok(None) => bail!("Rendezvous server closed connection"),
        Err(_) => {
            log::debug!("No KeyExchange (timeout), proceeding");
        }
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
        Ok(Self {
            file,
            state: EscState::Normal,
        })
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
                *state = if b == b'\\' {
                    EscState::Normal
                } else {
                    EscState::Osc
                };
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
    fn zero_sized_screen_does_not_panic() {
        let s = Screen::new(0, 0);
        assert_eq!((s.cols, s.rows), (2, 2));
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
        //
        // 也是 absorb 分片喂的理由:vt100 只能透过一屏那么大的窗口回看历史,一
        // 口气顶出去 91 行再去取,它自己的减法就下溢——debug 构建当场 panic。
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
        assert!(!s.resize(20, 60), "the renderer repaints locally");
        s.feed(&line("after resize"));
        assert_in_sync(&s, "resized");
        assert_eq!(s.model.screen().size(), (20, 60));
    }

    #[test]
    fn resize_repaints_instead_of_trusting_the_host_model() {
        // A real terminal reflows on resize by its own rules, which vt100's
        // set_size does not reproduce, so after a resize the host model no
        // longer describes what is on screen. Simulate that divergence and
        // check the resize repaints rather than diffing against a stale
        // baseline — otherwise every later frame is drawn at the wrong offset
        // and the display turns to noise.
        let mut s = screen();
        s.feed(&line("before resize"));

        // Whatever the terminal actually did with the old contents, it is not
        // what our host model thinks.
        s.host
            .process(b"\x1b[H\x1b[2Jreflowed differently by the terminal");
        assert_ne!(
            s.model.screen().contents(),
            s.host.screen().contents(),
            "test setup should have diverged the models"
        );

        s.resize(20, 60);
        assert_in_sync(&s, "resize must resync the host model");
    }

    #[test]
    fn passthrough_resize_asks_the_remote_to_redraw() {
        // With no screen model there is nothing to repaint from, so the only way
        // to clear the terminal's own reflow mess is to have the remote draw the
        // screen again.
        let mut s = screen();
        s.passthrough = true;
        assert!(s.resize(20, 60), "passthrough must request a remote redraw");
        assert_eq!((s.rows, s.cols), (20, 60));
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

        assert_eq!(
            s.history_len(),
            before + 3,
            "scroll by repaint not detected"
        );
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

    /// ConPTY's actual shape: no clear, just walk the cursor and overwrite each
    /// row. A half-delivered frame therefore leaves new rows above stale ones,
    /// not blank space — which is what detection has to survive.
    fn overwrite_rows(rows: &[&str]) -> Vec<u8> {
        let mut out = Vec::new();
        for (i, text) in rows.iter().enumerate() {
            out.extend(csi(&format!("{};1H", i + 1)));
            out.extend(csi("2K"));
            out.extend_from_slice(text.as_bytes());
        }
        out
    }

    #[test]
    fn a_conpty_repaint_retires_the_same_lines_at_every_split_point() {
        // absorb runs per network read, so detection sees whatever half of a
        // frame happened to arrive. The retired count must not depend on where
        // the reads fall — if it does, lines that never left get scrolled into
        // the terminal and then drawn back, and the same block lands in the
        // scrollback twice.
        let old: Vec<String> = (0..10).map(|i| format!("chat{i}")).collect();
        let new: Vec<String> = (3..13).map(|i| format!("chat{i}")).collect();
        let old_refs: Vec<&str> = old.iter().map(|x| x.as_str()).collect();
        let new_refs: Vec<&str> = new.iter().map(|x| x.as_str()).collect();
        let bytes = overwrite_rows(&new_refs);

        for cut in 0..=bytes.len() {
            let mut s = screen();
            s.feed(&enter_alt());
            s.feed(&overwrite_rows(&old_refs));
            let before = s.history_len();

            s.absorb(&bytes[..cut]);
            s.absorb(&bytes[cut..]);
            s.flush();

            assert_eq!(
                s.history_len(),
                before + 3,
                "split at byte {cut} retired {} lines instead of 3",
                s.history_len() - before
            );
        }
    }

    #[test]
    fn a_repaint_split_across_chunks_retires_the_same_lines_as_a_whole_one() {
        // The network hands a repaint over in pieces, and absorb runs on every
        // piece. Detection therefore gets to compare a half-drawn screen against
        // a whole one — and a half-drawn screen can still anchor somewhere,
        // which retires lines that never left. They get scrolled into the
        // terminal and then drawn back on screen, so the same block ends up
        // twice in the scrollback.
        let mut s = screen();
        s.feed(&enter_alt());
        let first: Vec<String> = (0..10).map(|i| format!("chat{i}")).collect();
        let refs: Vec<&str> = first.iter().map(|x| x.as_str()).collect();
        s.feed(&repaint_rows(&refs));
        let before = s.history_len();

        let second: Vec<String> = (3..13).map(|i| format!("chat{i}")).collect();
        let refs: Vec<&str> = second.iter().map(|x| x.as_str()).collect();
        let bytes = repaint_rows(&refs);

        // Same repaint as the whole-chunk test above, only delivered in two
        // reads. The answer must not depend on where the split lands.
        let cut = bytes.len() / 2;
        s.absorb(&bytes[..cut]);
        s.absorb(&bytes[cut..]);
        s.flush();

        assert_eq!(
            s.history_len(),
            before + 3,
            "split repaint retired a different number of lines than the whole one"
        );
        assert_in_sync(&s, "split repaint");
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
        assert!(
            s.history_len() >= 10,
            "archive too small: {}",
            s.history_len()
        );
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
        assert!(
            prev[..6].iter().all(|r| r.trim().is_empty()),
            "top must be blank"
        );
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
        assert!(
            during_alt > before_alt,
            "alt screen output was not archived"
        );

        s.feed(&leave_alt());
        assert_in_sync(&s, "left");
        // Nothing archived may be lost by crossing back.
        assert!(
            s.history_len() >= during_alt,
            "archive shrank on leaving the alternate screen"
        );
        // 也不能凭空多出来。见下面那条专门的测试。
        assert!(
            s.history_len() <= during_alt + s.rows as usize,
            "leaving the alternate screen re-archived history: {} -> {}",
            during_alt,
            s.history_len()
        );
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
    fn leaving_the_alternate_screen_does_not_re_archive_the_main_one() {
        // 备用屏幕是另一块不带回滚的画布:进去时 vt100 的历史长度归零,出来时
        // 主屏那份整体回来。把这个跳变当成「新增了这么多历史」的话,全屏应用
        // 一退出就会把整份主屏历史(上限一万行)重新归档一遍,再由 flush 逐行
        // 写进终端——冻屏好几秒,回滚里还平白多出一整份重复。
        //
        // codex、vim 这类应用全程待在备用屏幕里,退出时必然撞上这一下。
        let mut s = screen();
        for i in 0..60 {
            s.feed(&line(&format!("shell{i}")));
        }
        let main_history = s.history_len();
        assert!(
            main_history >= 40,
            "主屏历史太少，测不出问题: {main_history}"
        );

        s.feed(&enter_alt());
        s.feed(&repaint_rows(&["app row"]));
        let before_leave = s.history_len();

        s.feed(&leave_alt());
        assert_eq!(
            s.history_len(),
            before_leave,
            "离开备用屏幕把整份主屏历史又归档了一遍"
        );
        assert_in_sync(&s, "left the alternate screen");
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

    /// 本地终端反压丢掉一帧之后，屏幕必须能自己爬回来。
    ///
    /// 过去只有下一帧远端数据才会触发重画。可是最后一帧被丢掉、远端随即安静下来
    /// 正是刷屏结束时的常态——屏幕于是永远停在半张画面上，看着像死了，其实链路
    /// 一直好好的。
    #[test]
    fn a_dropped_frame_repaints_without_waiting_for_the_remote() {
        let mut s = screen();
        s.feed(&line("before"));
        assert!(!s.needs_repaint(), "正常一帧不该要求重画");

        // 队列满时 emit/flush 走的就是这条路。
        s.output_dirty = true;
        assert!(s.needs_repaint(), "丢过帧就必须自己要求重画");

        // 不喂任何新数据，只重画一次，状态就该恢复。
        s.render();
        assert!(!s.needs_repaint(), "重画成功之后不该再挂着脏标记");
        assert_in_sync(&s, "repaint after a dropped frame");
    }

    /// 直通模式没有屏幕模型，重画无从谈起，不能让主循环空转在这上面。
    #[test]
    fn passthrough_never_asks_for_a_repaint() {
        let mut s = Screen::new(10, 40);
        s.output_dirty = true;
        assert!(!s.needs_repaint());
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
                return Self {
                    id,
                    lock: Some(path),
                };
            }
        }
        log::warn!(
            "All {} terminal slots busy; falling back to slot 0",
            MAX_SLOTS
        );
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
    match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
    {
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

/// 待发消息队列的长度。
///
/// 出站流量是按键、改尺寸和保活,都是几十字节的小消息。攒到这个数还没写出去,
/// 只可能是链路已经不动了,而不是一时拥塞。
const OUTBOUND_QUEUE: usize = 256;

/// 单次发送慢过这个数就记一笔,用来事后判断是哪一端在堵。
const SLOW_SEND: std::time::Duration = std::time::Duration::from_secs(1);

/// 一帧画得慢过这个数就记一笔——本地渲染或控制台成了瓶颈的信号。
const SLOW_FLUSH: std::time::Duration = std::time::Duration::from_millis(50);

/// 这么久没收到帧就记一笔。远端或链路不动了的信号。
const QUIET_WARN: std::time::Duration = std::time::Duration::from_secs(5);

/// 一条消息允许花多久写上线。
///
/// 按键之类的小消息给固定预算就够;剪贴板图片能有好几 MB,慢一点的中继上本来
/// 就要几十秒,拿同一把尺子量会把好好的连接判死。所以按大小追加预算,底线约
/// 64 KB/s。
fn send_budget(msg: &Message) -> u64 {
    let bytes = msg.compute_size();
    CONNECT_TIMEOUT + bytes / 64
}

/// 独占发半边的写任务。
///
/// 存在的理由是它必须和读**分开跑**。收发共用一个 `&mut Link` 时,一次写阻塞
/// 会连带把读也停掉;而对端阻塞在写上、正等着我们读,于是两边各等各的,谁也不
/// 动。原先循环里 12 处发送一个超时都没有,连「发不出去就判定掉线重连」的保活
/// 自己都卡在同一个环上,所以这个死锁一旦成立就是永久的:没有输出、没有回显、
/// 也不会重连——正是「跑一阵子整个窗口全死」的样子。
///
/// 拆开之后读永远在跑,远端的写能排空、随即恢复读,堵住的这一边自己就通了。
async fn writer_loop(mut writer: LinkWriter, mut rx: tokio::sync::mpsc::Receiver<Message>) {
    while let Some(msg) = rx.recv().await {
        let started = std::time::Instant::now();
        match timeout(send_budget(&msg), writer.send(&msg)).await {
            Ok(Ok(())) => {
                if started.elapsed() >= SLOW_SEND {
                    log::debug!("writer: send took {:?}", started.elapsed());
                }
            }
            Ok(Err(e)) => {
                log::info!("Send failed ({e}), connection lost");
                return;
            }
            // 超时的 send 是在 flush 中途被丢掉的,写缓冲里可能留着半条帧。所以
            // 只能结束——这一半连同整条连接随即被丢弃重连,不存在带着脏缓冲接
            // 着用的情况。
            Err(_) => {
                log::info!("Send timed out, link is wedged");
                return;
            }
        }
    }
}

/// 正常关闭时，等待写任务把队列里的关闭帧冲上线。
///
/// 这个等待只用于远端已经确认终端关闭的健康路径；异常断线必须直接调用
/// `abort_writer`，不能让协议收尾帧再次触发远端 terminal service 的同步锁。
async fn drain_writer(
    tx: tokio::sync::mpsc::Sender<Message>,
    mut task: tokio::task::JoinHandle<()>,
) {
    // 关掉发送端，写任务收完队列里剩下的就会自己结束。
    drop(tx);
    if timeout(500, &mut task).await.is_err() {
        // 正常关闭只允许等待很短时间，避免收尾路径被网络写阻塞。
        log::debug!("writer 未能及时排空，取消剩余写任务");
        task.abort();
        if timeout(500, task).await.is_err() {
            log::debug!("writer 未响应取消，交由运行时回收");
        }
    }
}

async fn abort_writer(tx: tokio::sync::mpsc::Sender<Message>, task: tokio::task::JoinHandle<()>) {
    // 异常断线不能再排任何协议帧，否则远端可能进入同步收尾路径。
    drop(tx);
    task.abort();
    let _ = timeout(500, task).await;
}

/// 构造明确用户退出时使用的 RustDesk 连接关闭帧。
fn close_connection_message() -> Message {
    let mut misc = Misc::new();
    misc.set_close_reason(String::new());
    let mut msg = Message::new();
    msg.set_misc(misc);
    msg
}

/// Build a protocol-level liveness probe. RustDesk ignores empty protobuf
/// messages, so a zero-field `Message` does not keep the terminal service
/// alive and gives us no way to tell a wedged peer from a quiet shell.
fn keepalive_message(nonce: i64) -> Message {
    let mut delay = TestDelay::new();
    delay.time = nonce;
    delay.from_client = true;
    let mut msg = Message::new();
    msg.set_test_delay(delay);
    msg
}

fn echo_test_delay(delay: TestDelay) -> Message {
    let mut msg = Message::new();
    msg.set_test_delay(delay);
    msg
}

async fn finish_connection(
    tx: tokio::sync::mpsc::Sender<Message>,
    writer_task: tokio::task::JoinHandle<()>,
) {
    stall::enter(stall::CLOSING);
    // 读写错误、探活超时和进程退出都属于异常断线。此时远端可能正卡在
    // terminal service 的锁里，不能再发送 CloseReason 触发它的同步收尾。
    abort_writer(tx, writer_task).await;
    // 收尾完成后可能马上进入重连退避或下一轮握手；这些阶段没有本地阻塞，
    // 不应继续沿用 CLOSING 让看门狗误报。
    stall::enter(stall::IDLE);
}

async fn finish_connection_gracefully(
    tx: tokio::sync::mpsc::Sender<Message>,
    writer_task: tokio::task::JoinHandle<()>,
) {
    stall::enter(stall::CLOSING);
    // 只有远端已经确认终端关闭时才走这个路径，避免把 CloseReason 发到
    // 一个已经失去响应的 terminal service。
    if tx.try_send(close_connection_message()).is_ok() {
        drain_writer(tx, writer_task).await;
    } else {
        abort_writer(tx, writer_task).await;
    }
    stall::enter(stall::IDLE);
}

fn open_terminal_message(terminal_id: i32, rows: u16, cols: u16) -> Message {
    let mut action = TerminalAction::new();
    action.set_open(OpenTerminal {
        terminal_id,
        rows: rows as u32,
        cols: cols as u32,
        ..Default::default()
    });
    let mut msg = Message::new();
    msg.set_terminal_action(action);
    msg
}

/// 保活探测超过这么久还没回执，就认为这条链路已经不健康了。
///
/// 探测每 5 秒发一次，正常回执在一个 RTT 内。3 秒仍未回来说明远端至少已经腾不出
/// 手来处理协议消息。
const PROBE_STALE: std::time::Duration = std::time::Duration::from_secs(3);

/// 此刻能不能要求远端销毁这个终端会话。
///
/// `CloseTerminal` 在 RustDesk 1.4.6 的 Windows 端会同步停掉 helper，而且是**持着
/// 全局终端注册表锁**做的。helper 正忙或已经卡住时（远端刷屏、跑 codex 之类），这
/// 一发会把整个 RustDesk 服务拖死：设备直接显示离线，只能重启 RustDesk 服务才能
/// 恢复。
///
/// 不发的代价小得多：会话本来就声明了 persistent，shell 留在远端，下次同槽位连回
/// 去接的还是它——槽位的 service_id 是稳定的，所以也不会越积越多。
fn may_close_remote(opted_out: bool, unacked_probe: Option<std::time::Duration>) -> bool {
    if opted_out {
        return false;
    }
    !matches!(unacked_probe, Some(waited) if waited >= PROBE_STALE)
}

fn close_terminal_message(terminal_id: i32) -> Message {
    let mut action = TerminalAction::new();
    action.set_close(CloseTerminal {
        terminal_id,
        ..Default::default()
    });
    let mut msg = Message::new();
    msg.set_terminal_action(action);
    msg
}

#[cfg(unix)]
async fn shutdown_signal() -> std::io::Result<()> {
    use tokio::signal::unix::{signal, SignalKind};

    let mut hangup = signal(SignalKind::hangup())?;
    let mut terminate = signal(SignalKind::terminate())?;
    tokio::select! {
        _ = hangup.recv() => {}
        _ = terminate.recv() => {}
    }
    Ok(())
}

#[cfg(not(unix))]
async fn shutdown_signal() -> std::io::Result<()> {
    std::future::pending::<()>().await;
    Ok(())
}

async fn terminal_io_loop(
    mut conn: Link,
    remote_platform: &str,
    quit_key: char,
    render: bool,
    fresh_open: bool,
    slot: &TerminalSlot,
    log_path: Option<std::path::PathBuf>,
    detach: bool,
    no_remote_close: bool,
    input_events: &mut tokio::sync::mpsc::UnboundedReceiver<InputResult>,
) -> Result<SessionEnd> {
    let mut session_log = match log_path {
        Some(p) => match SessionLog::create(&p) {
            Ok(l) => {
                log::info!("Session transcript: {}", p.display());
                Some(l)
            }
            // Losing the transcript is not worth refusing the connection over.
            Err(e) => {
                log::warn!("Session transcript disabled: {:#}", e);
                None
            }
        },
        None => None,
    };
    let (cols, rows) = crossterm::terminal::size().context("Failed to get terminal size")?;
    let (cols, rows) = normalize_terminal_size(cols, rows);
    // Isolation comes from the per-slot service_id, so every session uses the
    // service's default terminal.
    let terminal_id: i32 = 0;

    timeout(
        3_000,
        conn.send(&open_terminal_message(terminal_id, rows, cols)),
    )
    .await
    .context("timeout sending terminal open")??;
    log::debug!(
        "OpenTerminal sent ({}x{}), waiting for shell...",
        cols,
        rows
    );

    let (mut reader, writer) = conn.split();
    let (tx, rx) = tokio::sync::mpsc::channel::<Message>(OUTBOUND_QUEUE);
    let writer_task = tokio::spawn(writer_loop(writer, rx));
    let shutdown = shutdown_signal();
    tokio::pin!(shutdown);

    let mut screen = Screen::new(rows, cols);
    screen.passthrough = !render;
    let mut pending_input = std::collections::VecDeque::<Input>::new();
    let mut input_timer = time::interval(std::time::Duration::from_millis(20));
    let mut keepalive = time::interval(std::time::Duration::from_secs(5));
    keepalive.set_missed_tick_behavior(time::MissedTickBehavior::Skip);
    let mut keepalive_nonce = 0_i64;
    let mut pending_keepalive: Option<(i64, time::Instant)> = None;
    let open_timeout = time::sleep(std::time::Duration::from_secs(12));
    tokio::pin!(open_timeout);
    let mut terminal_opened = false;
    let mut quitting = false;
    let close_timeout = time::sleep(std::time::Duration::from_secs(86_400));
    tokio::pin!(close_timeout);
    let mut locale_injected = false;
    let mut expect_replay = false;
    let mut first_frame = true;
    // 第一批未画出数据的时刻，以及最近一批的时刻。
    let mut pending_since: Option<std::time::Instant> = None;
    let mut last_data = std::time::Instant::now();
    // 一段静默只提醒一次，否则日志会被刷屏。
    let mut quiet_logged = false;
    // 最近一次把真实输入送出去的时刻，以及「敲了没回音」最近一次报告的时刻。
    let mut last_input_at: Option<std::time::Instant> = None;
    let mut quiet_reported_at: Option<std::time::Instant> = None;
    // 一直没回音时每隔这么久再记一笔，好让日志的时间戳能画出整段静默。
    const QUIET_REPEAT: std::time::Duration = std::time::Duration::from_secs(30);
    // 静默这么久就认为一次重绘的分片已经到齐了。
    const SETTLE: std::time::Duration = std::time::Duration::from_millis(12);
    // 但输出不停的时候永远等不到静默，所以再给一个强制上限，否则屏幕会冻住。
    const MAX_HOLD: std::time::Duration = std::time::Duration::from_millis(60);
    let mut last_cols = cols;
    let mut last_rows = rows;
    // 待处理的新尺寸。终端事件和兜底轮询都往这里放，主循环只认最后一个。
    let mut resize_target: Option<(u16, u16)> = None;
    let mut last_size_poll = std::time::Instant::now();
    let mut last_repaint_try = std::time::Instant::now();

    /// 把消息交给写任务。
    ///
    /// 关键在于它**不等**:排进队列就返回,于是发送再也不会挡住这一轮 select,
    /// `reader.next()` 始终有机会被 poll,读永不停。队列满说明写任务已经很久没
    /// 动过了,队列关了说明它已经死了——两种都是链路废了,判掉线让 main 重连,
    /// 而不是像原先那样永远挂在一次 send 上。
    macro_rules! send_out {
        ($msg:expr) => {
            if let Err(e) = tx.try_send($msg) {
                log::info!("Outbound send dropped ({e}), connection lost");
                finish_connection(tx, writer_task).await;
                return Ok(SessionEnd::Disconnected);
            }
        };
    }

    loop {
        // 这里之后就是等事件了。看门狗据此把「正常空闲」和「卡在某个调用里」
        // 分开——相位停在这里不算卡，停在别处才算。
        stall::enter(stall::IDLE);
        tokio::select! {
            // 本地控制必须先于持续就绪的远端输出。尤其在远端刷屏时，随机公平
            // 仍可能让 reader 连续获胜；一旦已有本地输入则完全暂停 reader，
            // 强制下一次 20ms tick 先发送按键或处理 Ctrl+Q。
            biased;

            _ = &mut open_timeout, if !terminal_opened => {
                log::error!("Remote terminal did not open within 12 seconds");
                finish_connection(tx, writer_task).await;
                bail!("Timed out waiting for the remote shell; the target RustDesk terminal service may be stuck");
            }

            _ = &mut close_timeout, if quitting => {
                log::debug!("Remote did not confirm terminal close within 2 seconds");
                finish_connection(tx, writer_task).await;
                return Ok(SessionEnd::UserQuit);
            }

            event = input_events.recv(), if !quitting => {
                match event {
                    Some(Ok(input)) => pending_input.push_back(input),
                    // 本地输入没了（窗口被关掉、终端被回收）不是「用户要求拆会话」，
                    // 而是「这边出事了」——恰恰是最不该去踩远端那把全局锁的时刻。
                    // 一律按 detach 处理：只做连接级关闭握手，远端 shell 留着，下次
                    // 同槽位连回去还是它。
                    Some(Err(e)) => {
                        log::info!("Local input stream failed: {e}; leaving the remote session in place");
                        finish_connection(tx, writer_task).await;
                        return Ok(SessionEnd::UserQuit);
                    }
                    None => {
                        log::info!("Local input stream closed; leaving the remote session in place");
                        finish_connection(tx, writer_task).await;
                        return Ok(SessionEnd::UserQuit);
                    }
                }
            }

            signal = &mut shutdown, if !quitting => {
                signal.context("Failed to register shutdown signals")?;
                // SIGHUP/SIGTERM 同理：进程被外力终止（关窗口、kill、被卡死之后
                // 补刀）时不去销毁远端会话。现场那次离线正是走的这条路——客户端
                // 卡在 codex 的输出里被强退，这一发 CloseTerminal 打到一个正忙的
                // Windows helper 上，把整个 RustDesk 服务锁死了。
                log::info!("Process signal received; leaving the remote session in place");
                finish_connection(tx, writer_task).await;
                return Ok(SessionEnd::UserQuit);
            }

            _ = keepalive.tick(), if !quitting => {
                if terminal_opened {
                    if let Some((nonce, sent_at)) = pending_keepalive {
                        if sent_at.elapsed() >= std::time::Duration::from_secs(15) {
                            log::warn!("RustDesk liveness probe {nonce} was not acknowledged within 15 seconds");
                            finish_connection(tx, writer_task).await;
                            return Ok(SessionEnd::Disconnected);
                        }
                    } else {
                        keepalive_nonce = keepalive_nonce.wrapping_add(1);
                        send_out!(keepalive_message(keepalive_nonce));
                        pending_keepalive = Some((keepalive_nonce, time::Instant::now()));
                    }
                    // Prove to other local instances that this slot is still ours.
                    slot.refresh();
                }
            }

            res = reader.next(), if pending_input.is_empty() || quitting => {
                let bytes = match res {
                    Some(Ok(b)) => b,
                    // Both mean the transport died, not that the remote shell
                    // exited — the session on the far side is probably still
                    // there, so this is reconnectable.
                    Some(Err(e)) => {
                        log::info!("Stream error: {}", e);
                        // 读半边先断开时也要关闭写半边。否则 writer task 会继续持有
                        // relay socket，下一轮重连期间旧连接仍可能占住远端 terminal。
                        finish_connection(tx, writer_task).await;
                        return Ok(if quitting { SessionEnd::UserQuit } else { SessionEnd::Disconnected });
                    }
                    None => {
                        log::info!("Connection closed by peer");
                        finish_connection(tx, writer_task).await;
                        return Ok(if quitting { SessionEnd::UserQuit } else { SessionEnd::Disconnected });
                    }
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
                                if !o.success {
                                    let message = o.message.clone();
                                    finish_connection(tx, writer_task).await;
                                    bail!("Terminal open failed: {}", message);
                                }
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
                                            match tx.try_send(m) {
                                                Ok(()) => log::info!("cliptest: queued"),
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
                                    || (first_frame && (!fresh_open || screen.renders()));
                                if treat_as_replay {
                                    expect_replay = false;
                                    first_frame = false;
                                    stall::enter(stall::REPLAY);
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
                                        send_out!(m);
                                    }
                                } else {
                                    first_frame = false;
                                    // 只吸收，不画。画的时机由下面的定时器在
                                    // 字节流静下来之后决定——半张重绘不能拿去
                                    // 做滚动检测。
                                    stall::enter(stall::ABSORB);
                                    screen.absorb(&output);
                                    last_data = std::time::Instant::now();
                                    quiet_logged = false;
                                    pending_since.get_or_insert(last_data);
                                }
                                if let Some(l) = session_log.as_mut() { l.append(&output); }
                            }
                            Some(Union::Closed(c)) => {
                                log::info!("Terminal closed (exit code: {})", c.exit_code);
                                if quitting {
                                    finish_connection_gracefully(tx, writer_task).await;
                                    return Ok(SessionEnd::UserQuit);
                                }
                                // shell 自己退出了，顺手把服务端那条空壳记录也销毁，
                                // 否则下次不带 -n 重连正好接回它——拿到上次退出前那
                                // 一屏，之后再无输出。
                                //
                                // 但同样要过健康检查：远端刚报完 shell 退出不代表它
                                // 腾得出手做销毁，而销毁是持全局锁同步停 helper 的。
                                let close_remote = terminal_opened
                                    && may_close_remote(
                                        no_remote_close,
                                        pending_keepalive.map(|(_, sent_at)| sent_at.elapsed()),
                                    );
                                if close_remote {
                                    tx.try_send(close_terminal_message(terminal_id)).ok();
                                    finish_connection_gracefully(tx, writer_task).await;
                                } else {
                                    finish_connection(tx, writer_task).await;
                                }
                                return Ok(SessionEnd::RemoteClosed);
                            }
                            Some(Union::Error(e)) => {
                                let message = e.message.clone();
                                finish_connection(tx, writer_task).await;
                                bail!("Terminal error: {}", message);
                            }
                            _ => { log::debug!("TerminalResponse with empty union"); }
                        }
                    }
                    Some(message::Union::TestDelay(delay)) => {
                        if delay.from_client {
                            if matches!(pending_keepalive, Some((nonce, _)) if nonce == delay.time) {
                                pending_keepalive = None;
                            }
                        } else {
                            // RustDesk sends this connection-level probe once and
                            // waits for the same message before scheduling another.
                            // Failing to echo it leaves an idle terminal connection
                            // in a permanently half-probed state.
                            send_out!(echo_test_delay(delay));
                        }
                    }
                    Some(message::Union::Hash(_)) => {}
                    other => { log::debug!("Unhandled message type: {:?}", other.map(|_| ())); }
                }
            }

            _ = input_timer.tick(), if !quitting => {
                // 写任务死了就等于链路断了。靠下一次发送去发现的话，空闲时要
                // 等到 15 秒后的保活才知道；这里 20 毫秒就能察觉。
                if writer_task.is_finished() {
                    log::info!("Writer task ended, connection lost");
                    finish_connection(tx, writer_task).await;
                    return Ok(if quitting { SessionEnd::UserQuit } else { SessionEnd::Disconnected });
                }

                if let Some(since) = pending_since {
                    if last_data.elapsed() >= SETTLE || since.elapsed() >= MAX_HOLD {
                        let started = std::time::Instant::now();
                        stall::enter(stall::FLUSH);
                        screen.flush();
                        if started.elapsed() >= SLOW_FLUSH {
                            log::debug!("flush took {:?}", started.elapsed());
                        }
                        pending_since = None;
                    }
                }

                // 丢过帧就一直重试整屏重画，直到本地终端喘过气来。间隔放宽到
                // 200 毫秒：队列还满着的时候每 20 毫秒重造一屏纯属白烧 CPU，
                // 而且只会让本来就堵着的队列更堵。
                if screen.needs_repaint()
                    && last_repaint_try.elapsed() >= std::time::Duration::from_millis(200)
                {
                    last_repaint_try = std::time::Instant::now();
                    stall::enter(stall::REPAINT);
                    screen.render();
                }

                // 卡死时日志的最后一行要能指认是哪一环:收不到帧了(远端或链路
                // 堵了),还是收得到但画不出来(本地慢了)。
                if terminal_opened && last_data.elapsed() >= QUIET_WARN && !quiet_logged {
                    quiet_logged = true;
                    log::debug!("no frame received for {:?}", last_data.elapsed());
                }

                // 「敲了却一个字节都不回来」是个和空闲截然不同的状态。
                //
                // 单纯的「远端很久没输出」不能报——停在提示符上的 shell 本来就
                // 该是安静的。但我们刚发过输入、之后一个字节都没回来，那就只有
                // 两种可能：远端的终端服务不动了，或者链路只是看着还活着。这两
                // 者都不是本地渲染的锅，日志必须把这句话说出来，否则下次又要从
                // 头猜一遍。
                if terminal_opened {
                    if let Some(sent) = last_input_at {
                        // 写成 match 而不是 is_none_or：后者要 Rust 1.82，
                        // 而 Cargo.toml 声明的 MSRV 是 1.75。
                        let due = match quiet_reported_at {
                            None => true,
                            Some(t) => t.elapsed() >= QUIET_REPEAT,
                        };
                        if sent > last_data && sent.elapsed() >= QUIET_WARN && due {
                            quiet_reported_at = Some(std::time::Instant::now());
                            log::warn!(
                                "已向远端发送输入 {:?}，期间没有收到任何输出；保活{}。这段静默在远端或链路，不是本地渲染。",
                                sent.elapsed(),
                                if pending_keepalive.is_some() {
                                    "未收到回包"
                                } else {
                                    "正常"
                                }
                            );
                        }
                    }
                }

                // 尺寸以终端送来的 Resize 事件为准。轮询只作兜底，两秒一次——
                // 万一某个终端不报事件，功能仍在，但不再是刷屏时的锁竞争来源。
                if resize_target.is_none()
                    && last_size_poll.elapsed() >= std::time::Duration::from_secs(2)
                {
                    last_size_poll = std::time::Instant::now();
                    stall::enter(stall::SIZE_QUERY);
                    if let Ok((nc, nr)) = crossterm::terminal::size() {
                        if (nc, nr) != (last_cols, last_rows) {
                            resize_target = Some((nc, nr));
                        }
                    }
                }

                // 拖拽窗口会连着报很多次尺寸。逐次处理等于逐次整屏重画，
                // 这里只认最后一个。
                if let Some((nc, nr)) = resize_target.take() {
                    let (nc, nr) = normalize_terminal_size(nc, nr);
                    if (nc != last_cols || nr != last_rows) && terminal_opened {
                        log::debug!("Resize: {}x{}", nc, nr);
                        stall::enter(stall::REPAINT);
                        let ask_redraw = screen.resize(nr, nc);
                        let mut a = TerminalAction::new();
                        a.set_resize(ResizeTerminal { terminal_id, rows: nr as u32, cols: nc as u32, ..Default::default() });
                        let mut m = Message::new(); m.set_terminal_action(a);
                        send_out!(m);
                        if ask_redraw {
                            // 先让远端知道新尺寸，再请它按新尺寸重画。
                            let mut a = TerminalAction::new();
                            a.set_data(TerminalData {
                                terminal_id,
                                data: vec![0x0c].into(),
                                compressed: false,
                                ..Default::default()
                            });
                            let mut m = Message::new(); m.set_terminal_action(a);
                            send_out!(m);
                        }
                        last_cols = nc; last_rows = nr;
                    }
                }
                let mut typed: Vec<u8> = Vec::new();
                stall::enter(stall::INPUT);
                while let Some(input) = pending_input.pop_front() {
                    let ev = match input {
                        Input::Key(k) => k,
                        Input::Resize(c, r) => { resize_target = Some((c, r)); continue; }
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
                            log::debug!("Input: queueing {} pasted bytes", body.len());
                            last_input_at = Some(std::time::Instant::now());
                            send_out!(m);
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
                        // arboard 读剪贴板是阻塞的 Win32 调用，别的进程占着剪贴板
                        // 时它要等。卡在这里的话网络读和保活会一起停，所以单独标
                        // 一个相位，好把它和渲染卡死区分开。
                        stall::enter(stall::CLIPBOARD);
                        let built = match std::env::var("RUSTSHELL_CLIP_TEST") {
                            Ok(spec) => synthetic_clipboard_image(&spec),
                            Err(_) => clipboard_image_message(),
                        };
                        stall::enter(stall::INPUT);
                        match built {
                            Ok((m, bytes, w, h)) => {
                                log::debug!("clipboard image {w}x{h}, {bytes} bytes compressed");
                                // 剪贴板发不出去不值得断开会话，只报一声。
                                if let Err(e) = tx.try_send(m) {
                                    screen.set_status(format!("clipboard: send failed: {e}"));
                                } else {
                                    screen.set_status(format!(
                                        "clipboard: sent {w}x{h} image, {} KB — if nothing appears, the remote is RustDesk 1.4.9+ and drops it",
                                        bytes / 1024
                                    ));
                                    // The remote applies the clipboard on its own
                                    // thread, so the keystroke has to lag behind
                                    // it or the app reads the old clipboard.
                                    stall::enter(stall::CLIP_WAIT);
                                    time::sleep(std::time::Duration::from_millis(200)).await;
                                    stall::enter(stall::INPUT);
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
                        // 默认关闭远端 shell；`--detach` 只释放本地连接，保留持久会话。
                        // 正常关闭要等远端确认后才发送连接级收尾帧。
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
                            tx.try_send(m).ok();
                        }
                        // 只有这一条路径是用户明确说「拆掉它」，也只有这一条还会
                        // 发 CloseTerminal——而且要先确认链路还在应答保活。
                        let may_close = may_close_remote(
                            no_remote_close,
                            pending_keepalive.map(|(_, sent_at)| sent_at.elapsed()),
                        );
                        if detach {
                            log::info!("Detaching (Ctrl+{}), remote session left running", quit_key.to_ascii_uppercase());
                            finish_connection(tx, writer_task).await;
                            return Ok(SessionEnd::UserQuit);
                        } else if !may_close {
                            log::warn!(
                                "Quitting without closing the remote terminal: the link is not answering liveness probes. \
                                 The shell stays on the remote; reconnect to the same slot to get it back."
                            );
                            finish_connection(tx, writer_task).await;
                            return Ok(SessionEnd::UserQuit);
                        } else {
                            log::info!("Closing terminal (Ctrl+{})...", quit_key.to_ascii_uppercase());
                            // Opened 尚未返回时也要排队关闭，防止快速关窗留下持久 shell。
                            tx.try_send(close_terminal_message(terminal_id)).ok();
                            quitting = true;
                            close_timeout.as_mut().reset(time::Instant::now() + std::time::Duration::from_secs(2));
                        }
                        pending_input.clear();
                        break;
                    }
                    // 攒起来，本轮结束一次发完。一个按键一条消息的话，打字
                    // 快一点就是几十条消息背靠背挤过中继——实测会丢字，表现
                    // 为「敲不进去」。
                    typed.extend_from_slice(&data);
                }

                if terminal_opened && !typed.is_empty() {
                    log::debug!("Input: queueing {} typed bytes", typed.len());
                    last_input_at = Some(std::time::Instant::now());
                    let mut a = TerminalAction::new();
                    a.set_data(TerminalData {
                        terminal_id,
                        data: std::mem::take(&mut typed).into(),
                        compressed: false,
                        ..Default::default()
                    });
                    let mut m = Message::new();
                    m.set_terminal_action(a);
                    send_out!(m);
                }
            }
        }
    }
    #[allow(unreachable_code)]
    Ok(SessionEnd::Disconnected)
}
