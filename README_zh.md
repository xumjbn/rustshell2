# RustShell

[English](README.md)

跨平台远程 Shell 客户端。通过 RustDesk 中继基础设施连接任意运行
RustDesk 的设备，并打开远程终端会话。

支持 **Windows**、**macOS**、**Linux**。

## 快速开始

```bash
# 编译
cargo build --release

# 连接远程设备
./target/release/rustshell \
  --id <设备ID> \
  --server <中继服务器地址> \
  --key <许可证密钥> \
  --password <设备密码>
```

## 用法

```
rustshell [OPTIONS] --id <ID> --server <SERVER>

选项:
  -i, --id <ID>              远程设备 ID
  -s, --server <SERVER>      ID 服务器地址 (host:port 或 IP)
  -p, --port <PORT>          ID 服务器端口 [默认: 21116]
  -k, --key <KEY>            许可证密钥 [默认: 内置公钥]
  -w, --password <PASSWORD>  设备密码 (留空则交互式输入)
  -q, --quit-key <CHAR>      退出组合键字母 [默认: q]
  -n, --new-session          开启全新会话，不重连已有会话
  -t, --slot <SLOT>          会话槽位 [默认: 本地第一个空闲槽位]
  -l, --log-file <PATH>      把纯文本会话记录写到此路径（不指定则不写）
      --detach               退出时保留远端 shell 继续运行
      --no-remote-close      任何退出都不销毁远端会话（远端 helper 卡住时销毁会拖死 RustDesk）
      --no-reconnect         断线后不自动重连
  -d, --debug                启用调试日志
  -h, --help                 打印帮助
```

### 会话生命周期

会话始终声明 `terminal_persistent`，异常断线后可以接回。这是在规避 RustDesk 1.4.6 的服务端
缺陷：非持久连接断开时，它会持有全局终端注册表锁并同步销毁 Windows helper；helper 一旦卡住，
后续所有 shell 都无法打开。异常断线时客户端直接释放 TCP 连接，不再发送连接级 `close_reason`，
避免远端 helper 已卡住时再次进入服务端同步收尾路径。只有链路健康且用户按 Ctrl+Q 明确关闭时，
才会在终端确认关闭后发送连接收尾帧。

**销毁远端会话（`CloseTerminal`）只在一种情况下发生：用户按 Ctrl+Q，而且链路仍在应答保活探测。**
同一把全局锁在销毁时也会被持有，helper 正忙（远端刷屏、跑 codex 之类）或已经卡住时，这一发会把
整个 RustDesk 服务拖死——设备直接显示离线，只能重启 RustDesk 服务才能恢复。因此关掉本地窗口、
`SIGHUP`/`SIGTERM`、输入流断开这些**被迫退出**一律不再销毁远端会话，只做连接级关闭；保活探测三秒
没有回执时 Ctrl+Q 也会降级成同样的行为并给出警告。会话是持久的，远端 shell 留着，下次连回同一槽位
接的还是它。`--no-remote-close` 可以彻底关掉销毁（等价于每次退出都 `--detach`）。

`--new-session` 会直接使用全新的 service ID，不再先关闭旧 service。这是刻意绕开 RustDesk 1.4.6
的缺陷：它可能永远阻塞在旧 Windows helper 的关闭过程中，导致后续 Open 根本得不到执行。

每个并发窗口占用一个**槽位**，一个槽位对应一个独立的远端会话。这一点很关键：远端会把
某个会话的输出广播给所有连到它的客户端，所以两个窗口共用一个会话就会互相看到对方的输入。
槽位通过系统临时目录下的锁文件分配（不写 `$HOME`）；进程被强杀留下的锁在 90 秒后可被回收。
用 `--slot N` 指定连到某个槽位。

### 回滚历史

Windows 远端走 ConPTY，它用绝对光标定位在原地重绘，而不是把行往上顶。把这样的字节流
原样透传，本地终端自己的滚动缓冲就**永远是空的**：什么都没滚动过，滚轮和滚动条自然
没内容可显示，全屏应用（Claude Code、vim 等）覆盖掉的内容也就没了。

所以客户端不再透传。它把字节流解析成一个带 10000 行历史的屏幕模型，并且每一帧都按远端
真正挤出屏幕顶部的行数，把本地终端滚动同样多行——这些行于是进入终端**真实的**滚动缓冲。
**滚动因此原生可用：鼠标滚轮、滚动条、终端自带的搜索都能用。**能回溯多远取决于你终端的
历史行数上限，而不是本程序。

全屏应用——**Claude Code**、vim、less——在远端跑在*备用屏幕*里，而终端按设计
根本不为备用屏幕保留历史。所以客户端**不把本地终端切进备用屏幕**：应用就画在主屏幕上，
它滚过去的行照样进入终端真实的滚动缓冲，滚轮因此同样能翻到它们。

这一点很关键：把本地终端切进备用屏幕会同时弄丢两件事——滚动缓冲没了内容可显，
而且 iTerm2 和 Terminal.app 在应用处于备用屏幕时会把**滚轮发送成方向键**，于是滚动变成了
翻远端应用的输入历史。代价是应用启动前屏幕上的内容会被覆盖而不是保存后恢复——
但它仍在滚动缓冲里，这笔交易值得做。

由于 ConPTY 是原地重绘、从不告知有行被挤出，客户端靠**观察内容整体上移**来识别滚动。
另有一个 10000 行的自有归档，给历史很少或没有历史的终端兜底：

| 按键 | 操作 |
|------|------|
| Shift+PageUp | 向后翻半屏 |
| Shift+PageDown | 向前翻半屏 |
| Shift+Home | 跳到保留的最早一行 |
| Shift+End | 回到实时视图 |

翻页时最后一行会显示当前回退了多少行，期间新输出会被记录但不会推动视图。按任意其他键
即回到实时视图。全部用 Shift 组合，是为了让不带 Shift 的 PageUp/PageDown 原样透传给远端应用。

由于屏幕是从模型渲染而非转发，模型不认识的东西会被丢弃而不是原样传下去——行内图片
（sixel、iTerm2）和 OSC 8 超链接无法保留。

### 复制粘贴

粘贴现在是**当作粘贴**处理的：客户端在本地开启 bracketed paste，把整段文本用
`ESC[200~`/`ESC[201~` 包起来一次性发过去，远端应用因此按字面接收，而不是看成你一个字符
一个字符敲进去的。没有这一层的话，多行粘贴会边到边执行，编辑器还会对每一行重新缩进。

复制用的是**终端自己的选区**——客户端从不开启鼠标上报，所以框选、Cmd/Ctrl+C
和滚动条都照常工作。

**图片用 Ctrl+V 粘贴。** Claude Code 这类应用是从**它自己所在机器**的剪贴板读图片，也就是
远端，所以图片得先过去。而剪贴板里放的是图片时，终端什么都不会发——没有粘贴事件可转发；
因此 Ctrl+V 会让客户端读取你本地的剪贴板、把图片放到**远端**剪贴板，然后再把这个按键放行，
让远端应用自己取。

> 要求远端跑的是 **RustDesk 1.4.8 或更早**。1.4.9（2026-07-06）加了一道检查，会把终端类型
> 连接发来的剪贴板消息**静默丢弃**，所以更新的远端上图片到不了，而且不会有任何提示。
> 文本粘贴不受影响——它走终端，不走剪贴板。

### 会话记录

远端重连时只回放有限的历史，而 Windows 远端（ConPTY）是在原地重绘屏幕、不把行往上推——
所以无论客户端怎么改，本地终端的滚动缓冲都是空的。客户端也可以写一份纯文本记录，
剥掉转义序列，可以直接用分页器看或 grep。**默认不写**，只有指定 `--log-file` 才启用。

> 记录文件包含终端显示过的一切，包括你输入的命令和输出中出现的任何密钥。

## 环境变量

所有 CLI 参数也可通过环境变量设置（前缀 `RUSTSHELL_`）。
CLI 参数优先级高于环境变量。

| 变量 | CLI 参数 | 说明 |
|------|----------|------|
| `RUSTSHELL_ID` | `--id` | 远程设备 ID |
| `RUSTSHELL_SERVER` | `--server` | ID 服务器地址 |
| `RUSTSHELL_PORT` | `--port` | ID 服务器端口 |
| `RUSTSHELL_KEY` | `--key` | 许可证密钥 |
| `RUSTSHELL_PASSWORD` | `--password` | 设备密码 |
| `RUSTSHELL_QUIT_KEY` | `--quit-key` | 退出快捷键字母 (a-z) |
| `RUSTSHELL_NEW_SESSION` | `--new-session` | 设为 `1` 或 `true` |
| `RUSTSHELL_SLOT` | `--slot` | 会话槽位编号 |
| `RUSTSHELL_LOG_FILE` | `--log-file` | 会话记录路径 |
| `RUSTSHELL_DETACH` | `--detach` | 设为 `1` 或 `true` |
| `RUSTSHELL_NO_REMOTE_CLOSE` | `--no-remote-close` | 设为 `1` 或 `true` |
| `RUSTSHELL_NO_RECONNECT` | `--no-reconnect` | 设为 `1` 或 `true` |
| `RUSTSHELL_DEBUG` | `--debug` | 设为 `1` 或 `true` |

```bash
# 全部通过环境变量配置
export RUSTSHELL_ID=123456789
export RUSTSHELL_SERVER=myserver.example.com
export RUSTSHELL_KEY="MyKeyBase64..."
export RUSTSHELL_PASSWORD="mypassword"
rustshell

# 环境变量 + CLI 参数覆盖
RUSTSHELL_ID=123456789 RUSTSHELL_SERVER=myserver.example.com \
  rustshell -k "MyKey..." -w mypassword
```

## 示例

```bash
# 自建服务器 + 自定义密钥
rustshell -i 123456789 -s myserver.example.com -k "MyKeyBase64..." -w mypassword

# 自定义端口
rustshell -i 123456789 -s 192.168.1.100 -p 61116 -k "MyKey..." -w mypassword

# 交互式密码输入（更安全，密码不出现在命令行）
rustshell -i 123456789 -s myserver.example.com -k "MyKey..."

# 调试模式
rustshell -i 123456789 -s myserver.example.com -k "MyKey..." -w mypassword -d
```

## 工作原理

```
rustshell                         RustDesk 基础设施                 远程设备
    │                                    │                            │
    ├── TCP 连接 ────────────────────► ID 服务器 (:21116)              │
    │   PunchHoleRequest{id, key}        │                            │
    │   ◄── PunchHoleResponse ──────────┤                            │
    │   {peer_addr, relay_fallback}      │                            │
    │                                    │                            │
    ├── 直连 TCP ────────────────(尝试)──┼────────────────────────►   │
    │   (失败则降级)                                    │             │
    │   ─── 中继 TCP ────────────────► 中继 (:21117)    │             │
    │       RequestRelay{id, uuid}      │               │             │
    │                                    ├── 桥接 ─────►│             │
    │                                    │                            │
    │   ◄══ 端到端加密通道 ════════════════════════════════════════   │
    │   ◄── SignedId ────────────────────────────────────────────    │
    │   ──── PublicKey (NaCl 密钥交换) ─────────────────────────►    │
    │   ◄── Hash 质询 ──────────────────────────────────────────    │
    │   ──── LoginRequest{terminal} ────────────────────────────►    │
    │   ◄══ 终端 I/O (stdin/stdout) ══════════════════════════════   │
    │                                                                 │
    ▼                                                                 ▼
 本地终端                                                         远程 Shell
 (raw mode)                                                  (bash/zsh/sh)
```

1. **信令**：连接 ID 服务器，请求连接到目标设备
2. **中继**：ID 服务器分配中继服务器；双方连接到中继
3. **密钥交换**：基于 NaCl 的端到端加密 (Curve25519 + XSalsa20-Poly1305)
4. **认证**：SHA-256 质询-响应，使用设备密码
5. **终端**：在远端打开 PTY，本地进入 raw 模式，双向 I/O

## 环境要求

- Rust 1.75+
- 运行中的 [RustDesk 服务端](https://github.com/rustdesk/rustdesk-server) (hbbs + hbbr)
- 目标设备上运行 RustDesk，且已开启终端访问权限

## 快捷键

| 按键 | 操作 |
|------|------|
| Ctrl+Q | 关闭远端 shell 并退出（字母可通过 `--quit-key` 自定义） |
| Ctrl+V | 把本地剪贴板里的图片送到远端，然后粘贴 |
| Shift+F5 | 从头重绘屏幕 |
| Ctrl+C | 发送到远端（可终止远端进程） |
| Ctrl+D | 发送到远端（发送 EOF） |

Shift+F5 之所以存在：屏幕是根据「你的终端正在显示什么」的模型画出来的。一旦有东西
绕过这个模型直接写终端，两者就会失去同步，画面会碎成一片片；而终端无法被读回来，
所以没法自动发现，恢复只能靠手动。

## 故障排除

**连接立即断开：**
- 确认远程设备 ID 正确且设备在线
- 检查 ID 服务器地址和端口是否正确
- 确认许可证密钥与服务器配置一致

**中文/CJK 字符显示为乱码：**
- 远端 Shell 的 locale 可能未设置为 UTF-8
- RustShell 连接后会打印相应的修复命令提示
- macOS/Linux：复制并执行 `export LANG=en_US.UTF-8 LC_ALL=en_US.UTF-8`
- Windows：复制并执行 `chcp 65001`

**Windows 远端输入 `exit` 后连接挂起：**
- 这是 RustDesk 服务端的[已知 bug](https://github.com/rustdesk/rustdesk/blob/caadd72ab2db8cc66e3d237e3e1cb60edbab7bc5/src/server/terminal_service.rs#L1267-L1270)：Windows ConPTY 在子进程退出时不发送 EOF 信号，导致服务端无法检测到会话已结束
- **变通方案**：用 Ctrl+Q 替代 `exit`。它会发送 `CloseTerminal`、等待确认，再完成 RustDesk 连接关闭握手
- 此问题仅影响 Windows 远端；macOS 和 Linux 远端使用 `exit` 正常工作

**空闲时连接断开：**
- 客户端会回显 RustDesk 原生 `TestDelay` 探测，并每 5 秒发送一次需要确认的主动探测；连续 15 秒收不到确认就按断线处理
- 万一真的断开，默认会按退避策略接回持久会话；不想重连就加 `--no-reconnect`
- 检查中继服务器的超时配置

## 许可证

采用 [Apache-2.0](LICENSE-APACHE) 或 [MIT](LICENSE-MIT) 双许可，任选其一。

这只覆盖本仓库的代码，不延伸到本程序链接的 `hbb_common`——它自己没有声明任何许可。
分发二进制之前请先看 [NOTICE.md](NOTICE.md)。
