//! 由 proto/rustshell.proto 生成的消息类型。
//!
//! 生成代码里的内层属性在 build.rs 里被去掉了（include! 进 mod 之后位置不
//! 合法），所以那些警告改在这里统一压。

#[allow(
    clippy::all,
    unused_imports,
    unused_results,
    non_snake_case,
    non_camel_case_types,
    non_upper_case_globals,
    dead_code
)]
pub mod rustshell {
    include!(concat!(env!("OUT_DIR"), "/rustshell.rs"));
}
