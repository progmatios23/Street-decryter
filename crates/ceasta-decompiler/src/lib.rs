//! Lightweight F5-style decompiler — CFG + pattern lifting to C-like pseudocode.

mod emit;
mod lift;
mod protos;

pub use protos::{known_prototype, ProtoParam, Prototype};

use ceasta_analysis::{build_cfg, Analysis, Function};
use ceasta_binary::Binary;
use emit::emit_function;
use lift::lift_function;

/// Decompile one function to C-like pseudocode.
pub fn decompile_function(bin: &Binary, func: &Function) -> String {
    let mut an = Analysis::default();
    an.functions.push(func.clone());
    let Some(cfg) = build_cfg(bin, &an, func.start) else {
        return format!(
            "// no cfg for {}\nvoid {}() {{\n}}\n",
            func.name,
            sanitize(&func.name)
        );
    };
    let stmts = lift_function(bin, func, &cfg);
    emit_function(func, &stmts)
}

fn sanitize(name: &str) -> String {
    name.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ceasta_binary::{Arch, Format, Segment, PERM_R, PERM_X};

    fn text_bin(bytes: &[u8]) -> Binary {
        let mut bin = Binary::empty("t.bin", Format::Raw, Arch::X64);
        bin.base = 0x1000;
        bin.has_entry = true;
        bin.entry = 0x1000;
        bin.segments.push(Segment {
            name: ".text".into(),
            start: 0x1000,
            end: 0x1000 + bytes.len() as u64,
            perms: PERM_R | PERM_X,
            file_off: 0,
            file_size: bytes.len() as u64,
            data: bytes.to_vec(),
        });
        bin
    }

    #[test]
    fn decompiles_simple_mov_ret() {
        let bin = text_bin(&[0xb8, 0x01, 0x00, 0x00, 0x00, 0xc3]);
        let func = Function {
            start: 0x1000,
            end: 0x1006,
            insns: 2,
            name: "sub_1000".into(),
            thunk: false,
            thunk_target: 0,
        };
        let code = decompile_function(&bin, &func);
        assert!(code.contains('{'), "{code}");
        assert!(code.contains('}'), "{code}");
        assert!(code.contains("eax") || code.contains("return"), "{code}");
    }

    #[test]
    fn decompiles_jcc_if() {
        let bin = text_bin(&[
            0x83, 0xf8, 0x00, // cmp eax, 0
            0x75, 0x05, // jne +5
            0xb8, 0x01, 0x00, 0x00, 0x00, // mov eax, 1
            0xc3, // ret
            0xb8, 0x02, 0x00, 0x00, 0x00, // mov eax, 2
            0xc3, // ret
        ]);
        let func = Function {
            start: 0x1000,
            end: 0x1011,
            insns: 6,
            name: "branchy".into(),
            thunk: false,
            thunk_target: 0,
        };
        let code = decompile_function(&bin, &func);
        assert!(code.contains("if"), "{code}");
        assert!(code.contains("eax"), "{code}");
    }
}
