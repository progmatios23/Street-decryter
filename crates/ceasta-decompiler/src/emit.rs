//! Emit lifted statements as C-like text with braces and if/else.

use crate::lift::Stmt;
use crate::protos::known_prototype;
use ceasta_analysis::Function;

pub fn emit_function(func: &Function, stmts: &[Stmt]) -> String {
    let mut out = String::new();
    let name = sanitize(&func.name);
    if let Some(p) = known_prototype(&func.name) {
        let mut proto = p.clone();
        proto.name = name.clone();
        out.push_str(&proto.format());
        out.push('\n');
    } else {
        out.push_str(&format!("void {name}()\n"));
    }
    out.push_str("{\n");

    let mut needed: std::collections::HashSet<String> = std::collections::HashSet::new();
    for s in stmts {
        match s {
            Stmt::Goto(l) => {
                needed.insert(l.clone());
            }
            Stmt::If {
                then_goto,
                else_goto,
                ..
            } => {
                needed.insert(then_goto.clone());
                if let Some(e) = else_goto {
                    needed.insert(e.clone());
                }
            }
            _ => {}
        }
    }

    for s in stmts {
        match s {
            Stmt::Label(l) => {
                if needed.contains(l) {
                    out.push_str(l);
                    out.push_str(":\n");
                }
            }
            Stmt::Line(t) => {
                out.push_str("    ");
                out.push_str(t);
                out.push('\n');
            }
            Stmt::If {
                cond,
                then_goto,
                else_goto,
            } => {
                out.push_str(&format!("    if ({cond}) {{\n"));
                out.push_str(&format!("        goto {then_goto};\n"));
                if let Some(e) = else_goto {
                    out.push_str("    } else {\n");
                    out.push_str(&format!("        goto {e};\n"));
                    out.push_str("    }\n");
                } else {
                    out.push_str("    }\n");
                }
            }
            Stmt::Goto(l) => {
                out.push_str(&format!("    goto {l};\n"));
            }
            Stmt::Ret(v) => {
                if let Some(v) = v {
                    out.push_str(&format!("    return {v};\n"));
                } else {
                    out.push_str("    return;\n");
                }
            }
        }
    }
    out.push_str("}\n");
    out
}

fn sanitize(name: &str) -> String {
    let s: String = name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    if s.is_empty() || s.as_bytes()[0].is_ascii_digit() {
        format!("fn_{s}")
    } else {
        s
    }
}
