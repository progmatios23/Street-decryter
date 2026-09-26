//! Pseudocode / decompile view (F5-style).

use crate::{AppState, CenterTab, DialogKind};
use egui::{Color32, FontFamily, FontId, RichText, ScrollArea};

pub fn draw(ui: &mut egui::Ui, state: &mut AppState) {
    let (title, code, func_start, proto_hint) = {
        let Some(db) = state.db.as_ref() else {
            ui.centered_and_justified(|ui| {
                ui.label("Open a binary to decompile.");
            });
            return;
        };
        let Some(func) = db.func_at(state.selected_addr) else {
            ui.centered_and_justified(|ui| {
                ui.label("Place the cursor inside a function and press F5 / open Pseudocode.");
            });
            return;
        };
        let name = {
            let n = db.name_at(func.start);
            if n.is_empty() {
                func.name.clone()
            } else {
                n
            }
        };
        let proto = ceasta_decompiler::known_prototype(&name)
            .map(|p| p.format())
            .unwrap_or_else(|| format!("void {name}()"));
        let title = format!(
            "{}  {}  ({:X}h, {} insns)",
            db.fmt_addr(func.start),
            proto,
            func.end.saturating_sub(func.start),
            func.insns
        );
        let code = ceasta_decompiler::decompile_function(&db.bin, func);
        let hint = ceasta_decompiler::known_prototype(&name).map(|p| {
            format!(
                "// known prototype: {} {}({}){}",
                p.ret,
                p.name,
                p.params
                    .iter()
                    .map(|x| format!("{} {}", x.ty, x.name))
                    .collect::<Vec<_>>()
                    .join(", "),
                if p.variadic { ", ..." } else { "" }
            )
        });
        (title, code, func.start, hint)
    };

    crate::theme::section_header(ui, &state.colors, "Pseudocode", &title);

    let mut do_copy = false;
    ui.horizontal(|ui| {
        if ui.button("Refresh").clicked() {
            state.listing_dirty = true;
        }
        if ui.button("Listing").clicked() {
            state.center_tab = CenterTab::Listing;
        }
        if ui.button("Graph").clicked() {
            state.center_tab = CenterTab::Graph;
        }
        if ui.button("Rename…").clicked() {
            state.open_dialog(DialogKind::Rename);
        }
        if ui.button("Comment…").clicked() {
            state.selected_addr = func_start;
            state.open_dialog(DialogKind::Comment);
        }
        if ui.button("Copy").clicked() {
            do_copy = true;
        }
    });
    if do_copy {
        state.clipboard = code.clone();
        ui.ctx().copy_text(code.clone());
        state.log_info("copied pseudocode");
    }
    ui.add_space(4.0);

    let colors = state.colors.clone();
    let mono = FontId::new(state.fonts.mono, FontFamily::Monospace);

    ScrollArea::both()
        .id_salt("pseudo_scroll")
        .auto_shrink([false, false])
        .show(ui, |ui| {
            ui.set_min_width(ui.available_width());
            for (i, line) in code.lines().enumerate() {
                paint_line(ui, i + 1, line, &colors, &mono);
            }
            if code.is_empty() {
                ui.weak("(empty decompilation)");
            }
        });

    if let Some(hint) = proto_hint {
        ui.separator();
        ui.label(
            RichText::new(hint)
                .small()
                .color(state.colors.auto_comment),
        );
    }

    ui.separator();
    ui.label(
        RichText::new(format!("Function comment @ {func_start:X}"))
            .small()
            .color(state.colors.muted),
    );
    let mut note = state
        .db
        .as_ref()
        .and_then(|d| d.comments.get(&func_start).cloned())
        .unwrap_or_default();
    if ui
        .add(
            egui::TextEdit::multiline(&mut note)
                .desired_rows(2)
                .desired_width(f32::INFINITY)
                .hint_text("function comment / notes"),
        )
        .changed()
    {
        state.set_comment(func_start, note);
    }
}

fn paint_line(
    ui: &mut egui::Ui,
    line_no: usize,
    line: &str,
    colors: &crate::ListingColors,
    mono: &FontId,
) {
    ui.horizontal(|ui| {
        ui.label(
            RichText::new(format!("{line_no:4} "))
                .font(mono.clone())
                .color(colors.muted),
        );

        let trimmed = line.trim_start();
        if trimmed.starts_with("//") || trimmed.starts_with("/*") {
            ui.label(RichText::new(line).font(mono.clone()).color(colors.comment));
            return;
        }

        let mut rest = line;
        while !rest.is_empty() {
            if rest.starts_with('"') {
                if let Some(end) = find_string_end(rest) {
                    let (s, next) = rest.split_at(end);
                    ui.label(RichText::new(s).font(mono.clone()).color(colors.string));
                    rest = next;
                    continue;
                }
            }
            if rest.starts_with('\'') {
                if let Some(end) = find_char_end(rest) {
                    let (s, next) = rest.split_at(end);
                    ui.label(RichText::new(s).font(mono.clone()).color(colors.string));
                    rest = next;
                    continue;
                }
            }
            let ch = rest.chars().next().unwrap();
            if ch.is_ascii_whitespace() {
                let n = rest.chars().take_while(|c| c.is_ascii_whitespace()).count();
                let (s, next) = rest.split_at(n);
                ui.label(RichText::new(s).font(mono.clone()));
                rest = next;
                continue;
            }
            if ch.is_ascii_digit() {
                let n = number_len(rest);
                let (s, next) = rest.split_at(n);
                ui.label(RichText::new(s).font(mono.clone()).color(colors.number));
                rest = next;
                continue;
            }
            if is_ident_start(ch) {
                let n = ident_len(rest);
                let (s, next) = rest.split_at(n);
                ui.label(
                    RichText::new(s)
                        .font(mono.clone())
                        .color(classify_ident(s, colors)),
                );
                rest = next;
                continue;
            }
            let (s, next) = rest.split_at(ch.len_utf8());
            ui.label(RichText::new(s).font(mono.clone()).color(colors.punct));
            rest = next;
        }
    });
}

fn find_string_end(s: &str) -> Option<usize> {
    let bytes = s.as_bytes();
    if bytes.first() != Some(&b'"') {
        return None;
    }
    let mut i = 1;
    while i < bytes.len() {
        if bytes[i] == b'\\' {
            i += 2;
            continue;
        }
        if bytes[i] == b'"' {
            return Some(i + 1);
        }
        i += 1;
    }
    Some(s.len())
}

fn find_char_end(s: &str) -> Option<usize> {
    let bytes = s.as_bytes();
    if bytes.first() != Some(&b'\'') {
        return None;
    }
    let mut i = 1;
    while i < bytes.len() {
        if bytes[i] == b'\\' {
            i += 2;
            continue;
        }
        if bytes[i] == b'\'' {
            return Some(i + 1);
        }
        i += 1;
    }
    Some(s.len())
}

fn number_len(s: &str) -> usize {
    let bytes = s.as_bytes();
    if bytes.starts_with(b"0x") || bytes.starts_with(b"0X") {
        let mut n = 2;
        while n < bytes.len() && bytes[n].is_ascii_hexdigit() {
            n += 1;
        }
        return n;
    }
    let mut n = 0;
    while n < bytes.len() && (bytes[n].is_ascii_digit() || bytes[n] == b'_') {
        n += 1;
    }
    while n < bytes.len() && matches!(bytes[n] as char, 'u' | 'U' | 'l' | 'L') {
        n += 1;
    }
    n.max(1)
}

fn is_ident_start(c: char) -> bool {
    c.is_ascii_alphabetic() || c == '_'
}

fn ident_len(s: &str) -> usize {
    s.chars()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
        .map(|c| c.len_utf8())
        .sum()
}

fn classify_ident(s: &str, colors: &crate::ListingColors) -> Color32 {
    const KW: &[&str] = &[
        "if", "else", "while", "for", "do", "switch", "case", "default", "break", "continue",
        "return", "goto", "sizeof", "typedef", "struct", "union", "enum", "const", "static",
        "extern", "volatile", "register", "inline", "true", "false", "nullptr", "NULL",
    ];
    const TYPES: &[&str] = &[
        "void", "char", "short", "int", "long", "float", "double", "signed", "unsigned", "bool",
        "uint8_t", "uint16_t", "uint32_t", "uint64_t", "int8_t", "int16_t", "int32_t", "int64_t",
        "size_t", "ssize_t", "uintptr_t", "intptr_t", "BYTE", "WORD", "DWORD", "QWORD", "BOOL",
        "HANDLE", "HWND", "LPCSTR", "LPWSTR", "PVOID",
    ];
    if KW.contains(&s) {
        colors.kw
    } else if TYPES.contains(&s) {
        colors.ctype
    } else {
        colors.text
    }
}
