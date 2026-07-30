//! 从 proto/rustshell.proto 生成消息类型。

fn main() {
    let out = std::env::var("OUT_DIR").expect("OUT_DIR");
    protobuf_codegen::Codegen::new()
        .pure()
        .out_dir(&out)
        .inputs(["proto/rustshell.proto"])
        .include("proto")
        .customize(
            protobuf_codegen::Customize::default()
                // bytes 字段生成 Bytes 而不是 Vec<u8>：终端输出一帧可能几十 KB，
                // 一路传下去不该每次都复制一遍。
                .tokio_bytes(true),
        )
        .run_from_script();

    // 生成的文件开头带一堆内层属性（`#![allow(..)]`）和 `//!` 文档注释。
    // 内层属性只能出现在文件或块的最开头，而我们是用 include! 把它塞进一个
    // mod 里的，位置对不上，编译直接报错。去掉它们即可——那些 allow 是给
    // 生成代码自己压警告用的，这里改成在 mod 上统一压。
    let generated = std::path::Path::new(&out).join("rustshell.rs");
    if let Ok(text) = std::fs::read_to_string(&generated) {
        let cleaned: String = text
            .lines()
            .filter(|l| {
                let l = l.trim_start();
                !l.starts_with("#!") && !l.starts_with("//!")
            })
            .collect::<Vec<_>>()
            .join("\n");
        std::fs::write(&generated, cleaned).expect("rewrite generated proto");
    }

    println!("cargo:rerun-if-changed=proto/rustshell.proto");
}
