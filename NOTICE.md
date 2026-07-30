# 许可

本仓库的代码采用以下任一许可，由你选择：

* Apache License, Version 2.0（[LICENSE-APACHE](LICENSE-APACHE)）
* MIT（[LICENSE-MIT](LICENSE-MIT)）

## 依赖

本程序不再依赖 `hbb_common`。协议定义（`proto/rustshell.proto`）、
线格式与加密（`src/wire.rs`）、连接层（`src/link.rs`）均为本项目
自己实现。

字段号、分帧规则、nonce 推导方式必须与对端一致，否则无法互通；
这些是互操作性所要求的**接口事实**，不是从上游复制的实现。
消息名和字段名不出现在 protobuf 线格式里。

其余依赖均为宽松许可（MIT 或 Apache-2.0），包括 protobuf、tokio、
tokio-util、sodiumoxide、zstd、crossterm、vt100、arboard、clap。

本程序与 RustDesk 服务端通信，但不包含其任何代码。
