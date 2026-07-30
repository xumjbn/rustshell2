# TODO: OS Login 支持

## 背景

当远端 Windows 机器尚未登录（锁屏/未登录用户）时，RustDesk 服务运行在 SYSTEM 账号下，没有可用的用户会话 token。服务端的 `fill_terminal_user_token` 会检测到 `is_prelogin()` 为 true 并拒绝终端连接。唯一的例外是：客户端在 `LoginRequest.os_login` 字段中提供有效的 Windows 管理员账号密码，服务端通过 `LogonUserW` 验证后允许以 SYSTEM 身份启动 shell。

## 改动范围

约 15 行代码，三处改动：

### 1. CLI 参数（Args struct）

新增两个参数：

```rust
/// Windows-only: OS username for pre-login or elevated terminal
#[arg(long, default_value = "", help = "Windows OS username (optional)")]
os_user: String,

/// Windows-only: OS password for pre-login or elevated terminal
#[arg(long, default_value = "", help = "Windows OS password (optional)")]
os_pass: String,
```

环境变量回退：`RUSTSHELL_OS_USER`、`RUSTSHELL_OS_PASS`

### 2. 填充 LoginRequest.os_login

在构造 `LoginRequest` 时（`run()` 函数中），增加：

```rust
if !os_user.is_empty() {
    lr.os_login = Some(OSLogin {
        username: os_user.clone(),
        password: os_pass.clone(),
        ..Default::default()
    }).into();
}
```

### 3. 更新 CLI help 和 README

在 `after_help` 中添加 `RUSTSHELL_OS_USER, RUSTSHELL_OS_PASS`，README 中补充说明 Windows pre-login 场景。

## 设计决策

### os_pass 不参与 RustDesk 密码哈希

- `--password`（`RUSTSHELL_PASSWORD`）→ RustDesk 设备密码，走 SHA-256(HASH + salt + challenge) 质询流程
- `--os-pass`（`RUSTSHELL_OS_PASS`）→ Windows 登录密码，**明文**放入 `LoginRequest.os_login.password` 字段

原因：服务端需要明文密码调用 `LogonUserW` 进行 Windows 凭据验证。RustDesk 的 E2E 加密通道保证了传输安全性。

### 平台限制

`os_login` 仅在 Windows 远端生效。macOS/Linux 的 RustDesk 服务以当前桌面用户身份运行，不存在 SYSTEM/用户分层问题，不需要 os_login。

| 场景 | 是否需要 os_login |
|------|------------------|
| 远端 Windows，服务已安装，用户已登录 | 不需要（服务可获取登录用户 token） |
| 远端 Windows，服务已安装，用户未登录（锁屏） | **需要 os_login** |
| 远端 Windows，便携版（未安装服务） | 不需要（进程以当前用户运行） |
| 远端 macOS / Linux | 不需要 |

### 安全考量

- `os_pass` 通过命令行参数或环境变量传入，可能暴露在进程列表或 shell 历史中
- 建议优先使用环境变量，避免密码直接出现在命令行
- 传输过程有 NaCl 端到端加密保护

## 使用示例

```bash
# 连接一台尚未登录的 Windows 机器
RustShell \
  -i 123456789 \
  -s server.example.com \
  -w <RustDesk设备密码> \
  --os-user Administrator \
  --os-pass <Windows管理员密码>

# 使用环境变量（更安全，密码不出现在命令行）
export RUSTSHELL_OS_USER=Administrator
export RUSTSHELL_OS_PASS=<Windows管理员密码>
RustShell -i 123456789 -s server.example.com -w <设备密码>
```

## 待确认

1. 是否只支持管理员账号（当前服务端要求 os_login 的账号必须是 Administrators 组成员，否则拒绝）
2. 是否需要同时支持 `--admin` 标志（强制以 SYSTEM 身份而非当前登录用户身份运行 shell）
3. `os_login` 是否同时用于管理员终端提升场景（用户已登录但需要 admin 权限）
