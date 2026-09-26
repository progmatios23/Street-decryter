//! Decompiler scaffold — returns a readable listing-backed stub until the full F5 port lands.

use ceasta_analysis::Function;
use ceasta_binary::Binary;
use ceasta_disasm::decode_at;

pub fn decompile_function(bin: &Binary, func: &Function) -> String {
    let mut out = format!("// rust decompiler scaffold — {}\n", func.name);
    out.push_str(&format!("void {}() {{\n", sanitize(&func.name)));
    let mut addr = func.start;
    let mut n = 0;
    while addr < func.end && n < 64 {
        match decode_at(bin, addr) {
            Ok(insn) => {
                out.push_str(&format!("    // {addr:X}: {}\n", insn.text));
                addr += u64::from(insn.size);
                n += 1;
            }
            Err(_) => break,
        }
    }
    out.push_str("}\n");
    out
}

fn sanitize(name: &str) -> String {
    name.chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '_' { c } else { '_' })
        .collect()
}
