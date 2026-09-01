# RustShell

[中文文档](README_zh.md)

Cross-platform remote shell client. Connects to any device running RustDesk
and opens a remote terminal session via the RustDesk relay infrastructure.

Works on **Windows**, **macOS**, and **Linux**.

## Quick Start

```bash
# Build
cargo build --release

# Connect to a remote device
./target/release/rustshell \
  --id <DEVICE_ID> \
  --server <RENDEZVOUS_SERVER> \
  --key <LICENCE_KEY> \
  --password <DEVICE_PASSWORD>
```

## Usage

```
rustshell [OPTIONS] --id <ID> --server <SERVER>

Options:
  -i, --id <ID>              Remote device ID (required)
  -s, --server <SERVER>      Rendezvous server host:port or IP (required)
  -p, --port <PORT>          Rendezvous server port [default: 21116]
  -k, --key <KEY>            Licence key [default: built-in public key]
  -w, --password <PASSWORD>  Device password (omit for interactive prompt)
  -q, --quit-key <CHAR>      Quit key letter for Ctrl+key combo [default: q]
  -n, --new-session          Start a fresh terminal session instead of reattaching
  -t, --slot <SLOT>          Session slot [default: first one not in use locally]
  -l, --log-file <PATH>      Write a plain-text transcript here (off unless set)
      --detach               Leave the remote shell running on quit
      --no-remote-close      Never destroy the remote session, on any exit
      --no-reconnect         Do not reconnect automatically when the link drops
  -d, --debug                Enable debug logging
  -h, --help                 Print help
```

### Session lifetime

Sessions advertise `terminal_persistent` so an abrupt disconnect remains
reattachable. This avoids a RustDesk 1.4.6 bug: its non-persistent disconnect
path tears down the Windows helper while holding the global terminal registry
lock, and a stuck helper then prevents every later shell from opening. On an
unexpected disconnect, rustshell drops the TCP connection without sending a
connection-level `close_reason`; this avoids entering the server's synchronous
close path while the terminal helper is already stuck. An explicit Ctrl+Q on a
healthy link still sends the close handshake after the terminal confirms it.

**Destroying the remote session (`CloseTerminal`) happens in exactly one case:
the user pressed Ctrl+Q and the link is still answering liveness probes.**
Destruction takes that same global lock, so when the helper is busy (a remote
that is repainting hard, `codex` and friends) or already stuck, this one message
wedges the whole RustDesk service — the device goes offline and only a RustDesk
service restart brings it back. Forced exits — closing the local window,
`SIGHUP`/`SIGTERM`, a broken input stream — therefore never destroy the remote
session; they only close the connection. Ctrl+Q degrades to the same behaviour,
with a warning, when a liveness probe has gone unanswered for three seconds. The
session is persistent, so the remote shell stays and the next connection to the
same slot reattaches to it. `--no-remote-close` disables destruction entirely
(equivalent to `--detach` on every exit).

`--new-session` uses a brand-new service ID instead of closing the previous
service first. This is deliberate: RustDesk 1.4.6 can block forever while
closing a stale Windows helper, which would prevent the following Open from
running.

Each concurrent window takes its own *slot*, and a slot maps to its own remote
session. This matters: the remote broadcasts a session's output to every client
attached to it, so two windows sharing one session would see each other's typing.
Slots are claimed through lock files in the OS temp directory; a lock left
behind by a killed process is reclaimed after 90 seconds. Use `--slot N` to
attach to a specific one.

### Scrollback

A Windows remote drives ConPTY, which paints with absolute cursor moves instead
of pushing lines upward. Passing that stream through verbatim leaves your local
terminal's own scrollback permanently empty: nothing ever scrolls, so the wheel
and the scrollbar have nothing to show, and anything a full-screen app (Claude
Code, vim, …) draws over is gone.

So the client does not pass it through. It parses the stream into a screen model
with 10 000 lines of history, and each frame it scrolls your terminal by exactly
the number of lines the remote pushed off the top, so those lines land in the
terminal's *real* scrollback. **Scrolling then works natively — mouse wheel,
scrollbar, your terminal's own search.** How far back you can go is your
terminal's history limit, not ours.

A full-screen app — **Claude Code**, vim, less — runs in the *alternate screen*
on the remote, and a terminal keeps no history for the alternate screen by
design. So the client **does not put your terminal into it**: the app is drawn on
the main screen, and the lines it scrolls past go into the terminal's real
scrollback like anything else, where the wheel reaches them.

That choice matters. Mirroring the alternate screen locally loses both halves of
this — there is no scrollback to show, and iTerm2 and Terminal.app send **arrow
keys** for the wheel while an app is in the alternate screen, so scrolling starts
walking the remote app's input history instead. The cost is that whatever was on
screen before the app started is overwritten rather than saved and restored; it
is still in the scrollback, which is the trade worth making.

The client spots the scroll by watching the content move, because ConPTY repaints
rather than scrolling and never signals that anything was pushed off. There is
also a 10 000-line archive of its own, and a pager for terminals with little or
no history:

| Key | Action |
|-----|--------|
| Shift+PageUp | Back half a screen |
| Shift+PageDown | Forward half a screen |
| Shift+Home | Oldest line kept |
| Shift+End | Back to live |

While paged back, the last row shows how far back you are, and new output is
recorded without disturbing the view. Any other key returns to live. The
bindings are Shift-modified so plain PageUp/PageDown still reach the remote
application untouched.

Because the screen is rendered from the model rather than forwarded, anything
the model does not understand is dropped rather than passed along — inline
images (sixel, iTerm2) and OSC 8 hyperlinks do not survive.

### Copy and paste

Paste works as a paste: the client turns on bracketed paste locally and forwards
the text in one piece wrapped in `ESC[200~`/`ESC[201~`, so an app on the far side
takes it literally instead of seeing it typed character by character. Without
that, a multi-line paste runs line by line as it arrives and editors re-indent
every line.

Copying is your terminal's own selection — the client never enables mouse
reporting, so selection, Cmd/Ctrl+C and the scrollbar keep working normally.

**Images paste with Ctrl+V.** An app like Claude Code reads images from the
clipboard of the machine it runs on — the remote — so the image has to get there
first. A terminal sends nothing at all when the clipboard holds an image, so
there is no paste event to forward; instead Ctrl+V makes the client read your
local clipboard, put the image on the *remote* clipboard, and then let the
keystroke through so the app picks it up.

> Requires the remote to be running **RustDesk 1.4.8 or earlier**. 1.4.9
> (2026-07-06) added a check that silently discards clipboard messages from a
> terminal-only session, so on a newer remote the image will not arrive and
> nothing will say so. Text paste is unaffected — it goes through the terminal,
> not the clipboard.

### Session transcript

The remote only replays a limited amount of scrollback on reattach, and a Windows
remote (ConPTY) redraws the screen in place rather than pushing lines up — so
your local terminal's scrollback stays empty no matter what the client does. The
client can also write a plain-text transcript, with escape sequences stripped so
it can be read in a pager or grepped. It is off unless `--log-file` is given.

> The transcript records everything the terminal showed, including commands you
> typed and any secrets that appeared in output.

## Environment Variables

All CLI arguments can also be set via environment variables (prefixed with `RUSTSHELL_`).
CLI arguments take precedence when both are provided.

| Variable | CLI flag | Description |
|----------|----------|-------------|
| `RUSTSHELL_ID` | `--id` | Remote device ID |
| `RUSTSHELL_SERVER` | `--server` | Rendezvous server address |
| `RUSTSHELL_PORT` | `--port` | Rendezvous server port |
| `RUSTSHELL_KEY` | `--key` | Licence key |
| `RUSTSHELL_PASSWORD` | `--password` | Device password |
| `RUSTSHELL_QUIT_KEY` | `--quit-key` | Quit key letter (a-z) |
| `RUSTSHELL_NEW_SESSION` | `--new-session` | Set to `1` or `true` |
| `RUSTSHELL_SLOT` | `--slot` | Session slot number |
| `RUSTSHELL_LOG_FILE` | `--log-file` | Transcript path |
| `RUSTSHELL_DETACH` | `--detach` | Set to `1` or `true` |
| `RUSTSHELL_NO_REMOTE_CLOSE` | `--no-remote-close` | Set to `1` or `true` |
| `RUSTSHELL_NO_RECONNECT` | `--no-reconnect` | Set to `1` or `true` |
| `RUSTSHELL_DEBUG` | `--debug` | Set to `1` or `true` |

```bash
# All configuration via environment variables
export RUSTSHELL_ID=123456789
export RUSTSHELL_SERVER=myserver.example.com
export RUSTSHELL_KEY="MyKeyBase64..."
export RUSTSHELL_PASSWORD="mypassword"
rustshell

# Override specific values with CLI flags
RUSTSHELL_ID=123456789 RUSTSHELL_SERVER=myserver.example.com \
  rustshell -k "MyKey..." -w mypassword
```

## Examples

```bash
# Self-hosted server with custom key
rustshell -i 123456789 -s myserver.example.com -k "MyKeyBase64..." -w mypassword

# Custom port
rustshell -i 123456789 -s 192.168.1.100 -p 61116 -k "MyKey..." -w mypassword

# Interactive password prompt (more secure)
rustshell -i 123456789 -s myserver.example.com -k "MyKey..."

# Debug mode for troubleshooting
rustshell -i 123456789 -s myserver.example.com -k "MyKey..." -w mypassword -d
```

## How It Works

```
rustshell                         RustDesk infrastructure              Remote device
    │                                    │                                  │
    ├── TCP connect ──────────────────► rendezvous server (:21116)          │
    │   PunchHoleRequest{id, key}        │                                  │
    │   ◄── PunchHoleResponse ──────────┤                                  │
    │   {peer_addr, relay_fallback}      │                                  │
    │                                    │                                  │
    ├── direct TCP ────────────────(try)──┼────────────────────────────►   │
    │   (fallback on failure)                                 │             │
    │   ─── relay TCP ────────────────► relay (:21117)       │             │
    │       RequestRelay{id, uuid}      │                     │             │
    │                                    ├── bridge ────────►│             │
    │                                    │                                    │
    │   ◄══ E2E encrypted channel ═══════════════════════════════════════   │
    │   ◄── SignedId ───────────────────────────────────────────────────   │
    │   ──── PublicKey (NaCl key exchange) ───────────────────────────►   │
    │   ◄── Hash challenge ────────────────────────────────────────────   │
    │   ──── LoginRequest{terminal} ──────────────────────────────────►   │
    │   ◄══ Terminal I/O (stdin/stdout) ═══════════════════════════════   │
    │                                                                      │
    ▼                                                                      ▼
local terminal                                                     remote shell
(raw mode)                                                   (bash/zsh/PowerShell)
```

1. **Rendezvous**: Connects to the ID server, requests connection to target device
2. **Relay**: ID server assigns a relay server; both sides connect to it
3. **Key exchange**: NaCl-based E2E encryption (Curve25519 + XSalsa20-Poly1305)
4. **Authentication**: SHA-256 challenge-response with the device password
5. **Terminal**: Opens a PTY on the remote, enters raw mode locally, bi-directional I/O

## Requirements

- Rust 1.75+
- A running [RustDesk server](https://github.com/rustdesk/rustdesk-server) (hbbs + hbbr)
- RustDesk running on the target device with terminal access enabled

## Keyboard Shortcuts

| Key | Action |
|-----|--------|
| Ctrl+Q | Close the remote shell and exit (letter set by `--quit-key`) |
| Ctrl+V | Send the local clipboard image to the remote, then paste |
| Shift+F5 | Redraw the screen from scratch |
| Ctrl+C | Sent to remote (stop remote processes) |
| Ctrl+D | Sent to remote (send EOF) |

Shift+F5 exists because the screen is drawn from a model of what your terminal
is showing. If anything writes to the terminal behind that model's back the two
drift apart and the display comes out in fragments; a terminal cannot be read
back to detect this, so the recovery is manual.

## Troubleshooting

**Connection closed immediately:**
- Verify the remote device ID is correct and the device is online
- Check that the rendezvous server address and port are correct
- Ensure the licence key matches the server configuration

**Chinese/CJK characters display as garbled text:**
- The remote shell's locale may not be set to UTF-8
- RustShell prints a hint with the appropriate fix command after connecting
- macOS/Linux: copy and run `export LANG=en_US.UTF-8 LC_ALL=en_US.UTF-8`
- Windows: copy and run `chcp 65001`

**Connection hangs after typing `exit` on Windows remote:**
- This is a [known bug](https://github.com/rustdesk/rustdesk/blob/caadd72ab2db8cc66e3d237e3e1cb60edbab7bc5/src/server/terminal_service.rs#L1267-L1270) in the RustDesk server: Windows ConPTY does not signal EOF when the shell exits, so the server never detects the session has ended
- **Workaround**: use Ctrl+Q instead of typing `exit`. It sends `CloseTerminal`, waits for confirmation, then performs RustDesk's connection close handshake
- This issue only affects Windows remotes; macOS and Linux remotes work correctly with `exit`

**Connection drops after idle:**
- RustDesk `TestDelay` probes are echoed, and the client sends its own acknowledged probe every 5 seconds. A missing acknowledgement for 15 seconds is treated as a dropped connection
- If the link drops, the client reattaches to the persistent shell with backoff. Pass `--no-reconnect` to turn reconnection off
- Check the relay server's timeout configuration

## License

Licensed under either of [Apache-2.0](LICENSE-APACHE) or [MIT](LICENSE-MIT), at
your option.

That covers the code in this repository. It does not extend to `hbb_common`,
which this program links and which declares no license of its own — see
[NOTICE.md](NOTICE.md) before redistributing binaries.
