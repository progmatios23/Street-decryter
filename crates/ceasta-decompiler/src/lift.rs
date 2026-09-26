//! Instruction → C-like statement lifting.

use ceasta_analysis::{Cfg, EdgeKind, Function};
use ceasta_binary::Binary;
use ceasta_disasm::{decode_at, Flow, Insn};
use crate::protos::known_prototype;

#[derive(Clone, Debug)]
pub enum Stmt {
    Label(String),
    Line(String),
    If {
        cond: String,
        then_goto: String,
        else_goto: Option<String>,
    },
    Goto(String),
    Ret(Option<String>),
}

pub fn lift_function(bin: &Binary, func: &Function, cfg: &Cfg) -> Vec<Stmt> {
    let mut out = Vec::new();
    let mut last_cmp: Option<(String, String)> = None;
    let mut last_test: Option<String> = None;

    for (i, blk) in cfg.blocks.iter().enumerate() {
        out.push(Stmt::Label(format!("loc_{:X}", blk.start)));
        for &a in &blk.insn_addrs {
            let Ok(insn) = decode_at(bin, a) else {
                continue;
            };
            let is_last = Some(&a) == blk.insn_addrs.last();
            let m = insn.mnemonic.to_ascii_lowercase();

            // Track cmp/test for condition recovery.
            if m == "cmp" {
                let ops = split_ops(&insn.operands);
                if ops.len() >= 2 {
                    last_cmp = Some((tidy(&ops[0]), tidy(&ops[1])));
                    last_test = None;
                }
            } else if m == "test" {
                let ops = split_ops(&insn.operands);
                if ops.len() >= 2 {
                    if ops[0] == ops[1] {
                        last_test = Some(tidy(&ops[0]));
                        last_cmp = None;
                    } else {
                        last_cmp = Some((
                            format!("({} & {})", tidy(&ops[0]), tidy(&ops[1])),
                            "0".into(),
                        ));
                        last_test = None;
                    }
                }
            }

            if is_last {
                match insn.flow {
                    Flow::Cond => {
                        let cond = cond_from_jcc(&m, &last_cmp, &last_test);
                        let taken = blk
                            .succ
                            .iter()
                            .find(|e| e.kind == EdgeKind::Taken)
                            .map(|e| format!("loc_{:X}", cfg.blocks[e.to as usize].start));
                        let not_taken = blk
                            .succ
                            .iter()
                            .find(|e| e.kind == EdgeKind::NotTaken)
                            .map(|e| format!("loc_{:X}", cfg.blocks[e.to as usize].start));
                        if let Some(t) = taken {
                            out.push(Stmt::If {
                                cond,
                                then_goto: t,
                                else_goto: not_taken,
                            });
                        }
                        continue;
                    }
                    Flow::Jump => {
                        if let Some(t) = insn.target {
                            if t >= func.start && t < func.end {
                                out.push(Stmt::Goto(format!("loc_{t:X}")));
                            } else {
                                out.push(Stmt::Line(format!("goto 0x{t:X}; // outside")));
                            }
                        } else {
                            out.push(Stmt::Line(format!("jmp {};", insn.operands)));
                        }
                        continue;
                    }
                    Flow::Ret => {
                        let ret = if bin.is64() { "rax" } else { "eax" };
                        out.push(Stmt::Ret(Some(ret.into())));
                        continue;
                    }
                    Flow::Stop => {
                        out.push(Stmt::Line("__debugbreak();".into()));
                        continue;
                    }
                    _ => {}
                }
            }
            let line = insn_to_c(bin, &insn);
            if !line.is_empty() {
                out.push(Stmt::Line(line));
            }
        }
        // fallthrough
        if let Some(e) = blk.succ.iter().find(|e| e.kind == EdgeKind::Next) {
            let dest = cfg.blocks[e.to as usize].start;
            if e.to as usize != i + 1 {
                out.push(Stmt::Goto(format!("loc_{dest:X}")));
            }
        }
    }
    out
}

pub fn insn_to_c(bin: &Binary, insn: &Insn) -> String {
    let m = insn.mnemonic.to_ascii_lowercase();
    let ops = split_ops(&insn.operands);
    match m.as_str() {
        "nop" | "endbr64" | "endbr32" | "pause" => String::new(),
        "int" | "int3" | "ud2" => "__debugbreak();".into(),
        "ret" | "retn" => String::new(), // handled as CFG Ret
        "leave" => "/* leave */".into(),
        "push" => {
            if let Some(a) = ops.first() {
                format!("push({});", tidy(a))
            } else {
                format!("{};", insn.text)
            }
        }
        "pop" => {
            if let Some(a) = ops.first() {
                format!("{} = pop();", tidy(a))
            } else {
                format!("{};", insn.text)
            }
        }
        "call" => {
            let target = ops.first().map(|s| s.as_str()).unwrap_or("?");
            let name = resolve_call_name(bin, insn, target);
            if let Some(p) = known_prototype(&name) {
                let args: Vec<String> = p
                    .params
                    .iter()
                    .enumerate()
                    .map(|(i, par)| {
                        if !par.name.is_empty() {
                            par.name.clone()
                        } else {
                            format!("arg{i}")
                        }
                    })
                    .collect();
                if p.ret == "void" {
                    format!("{}({});", p.name, args.join(", "))
                } else {
                    format!("rax = {}({});", p.name, args.join(", "))
                }
            } else {
                format!("{name}();")
            }
        }
        "mov" | "movzx" | "movsx" | "movsxd" | "lea" => {
            if ops.len() >= 2 {
                format!("{} = {};", tidy(&ops[0]), tidy(&ops[1]))
            } else {
                format!("{};", insn.text)
            }
        }
        "add" | "sub" | "xor" | "and" | "or" | "shl" | "shr" | "sar" | "rol" | "ror" => {
            let op = match m.as_str() {
                "add" => "+",
                "sub" => "-",
                "xor" => "^",
                "and" => "&",
                "or" => "|",
                "shl" => "<<",
                "shr" | "sar" => ">>",
                "rol" => "<<<",
                "ror" => ">>>",
                _ => "?",
            };
            if ops.len() >= 2 {
                if m == "xor" && ops[0] == ops[1] {
                    format!("{} = 0;", tidy(&ops[0]))
                } else {
                    format!("{a} = {a} {op} {};", tidy(&ops[1]), a = tidy(&ops[0]))
                }
            } else {
                format!("{};", insn.text)
            }
        }
        "inc" => format!("{a} = {a} + 1;", a = tidy(ops.first().map(|s| s.as_str()).unwrap_or("r"))),
        "dec" => format!("{a} = {a} - 1;", a = tidy(ops.first().map(|s| s.as_str()).unwrap_or("r"))),
        "cmp" | "test" => {
            if ops.len() >= 2 {
                format!("/* {m} {}, {} */", tidy(&ops[0]), tidy(&ops[1]))
            } else {
                format!("/* {} */", insn.text)
            }
        }
        "jmp" => String::new(), // handled as CFG
        m if m.starts_with('j') => String::new(),
        _ => format!("/* {} */", insn.text),
    }
}

fn cond_from_jcc(
    m: &str,
    last_cmp: &Option<(String, String)>,
    last_test: &Option<String>,
) -> String {
    let cmp = |op: &str| -> String {
        if let Some((a, b)) = last_cmp {
            format!("{a} {op} {b}")
        } else if let Some(t) = last_test {
            format!("{t} {op} 0")
        } else {
            format!("flags {op} 0")
        }
    };
    match m {
        "je" | "jz" => {
            if let Some(t) = last_test {
                format!("{t} == 0")
            } else {
                cmp("==")
            }
        }
        "jne" | "jnz" => {
            if let Some(t) = last_test {
                format!("{t} != 0")
            } else {
                cmp("!=")
            }
        }
        "ja" | "jnbe" | "jg" | "jnle" => cmp(">"),
        "jae" | "jnb" | "jnc" | "jge" | "jnl" => cmp(">="),
        "jb" | "jnae" | "jc" | "jl" | "jnge" => cmp("<"),
        "jbe" | "jna" | "jle" | "jng" => cmp("<="),
        "js" => {
            if let Some(t) = last_test {
                format!("{t} < 0")
            } else if let Some((a, _)) = last_cmp {
                format!("{a} < 0")
            } else {
                "SF".into()
            }
        }
        "jns" => {
            if let Some(t) = last_test {
                format!("{t} >= 0")
            } else if let Some((a, _)) = last_cmp {
                format!("{a} >= 0")
            } else {
                "!SF".into()
            }
        }
        "jo" => "OF".into(),
        "jno" => "!OF".into(),
        "jp" | "jpe" => "PF".into(),
        "jnp" | "jpo" => "!PF".into(),
        _ => format!("cond_{m}"),
    }
}

fn split_ops(operands: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut depth = 0i32;
    for c in operands.chars() {
        match c {
            '[' => {
                depth += 1;
                cur.push(c);
            }
            ']' => {
                depth -= 1;
                cur.push(c);
            }
            ',' if depth == 0 => {
                let t = cur.trim().to_string();
                if !t.is_empty() {
                    out.push(t);
                }
                cur.clear();
            }
            _ => cur.push(c),
        }
    }
    let t = cur.trim().to_string();
    if !t.is_empty() {
        out.push(t);
    }
    out
}

fn tidy(s: &str) -> String {
    let s = s.trim();
    if let Some(inner) = s.strip_prefix('[').and_then(|x| x.strip_suffix(']')) {
        format!("*({})", inner.trim())
    } else {
        s.to_string()
    }
}

fn resolve_call_name(bin: &Binary, insn: &Insn, raw: &str) -> String {
    if let Some(t) = insn.target {
        if let Some(imp) = bin.imports.iter().find(|i| i.slot == t) {
            return imp.name.clone();
        }
        if let Some(exp) = bin.exports.iter().find(|e| e.addr == t) {
            return exp.name.clone();
        }
        // thunk: jmp [rip+…] often one insn at t
        if let Ok(th) = decode_at(bin, t) {
            if th.mnemonic.eq_ignore_ascii_case("jmp") {
                if let Some(m) = th.mem {
                    if let Some(imp) = bin.imports.iter().find(|i| i.slot == m) {
                        return imp.name.clone();
                    }
                }
            }
        }
        return format!("sub_{t:X}");
    }
    let cleaned = raw
        .trim()
        .trim_start_matches("qword ptr ")
        .trim_start_matches("dword ptr ")
        .trim_matches(|c| c == '[' || c == ']');
    if cleaned.chars().all(|c| c.is_ascii_hexdigit()) {
        format!("sub_{cleaned}")
    } else {
        cleaned.replace([' ', '+'], "_")
    }
}
