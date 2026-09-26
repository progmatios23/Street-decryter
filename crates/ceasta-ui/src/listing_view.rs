//! Listing view — IDA-style disassembly listing for the current function / neighborhood.

use crate::{AppState, CenterTab, DialogKind};
use ceasta_disasm::{decode_at, Flow, Insn};
use egui::{RichText, ScrollArea, Sense};

#[derive(Clone)]
struct Row {
    addr: u64,
    bytes: String,
    text: String,
    mnemonic: String,
    flow: Flow,
    label: Option<String>,
    comment: Option<String>,
    auto_comment: Option<String>,
    is_func: bool,
    has_bp: bool,
    is_header: bool,
}

pub fn draw(ui: &mut egui::Ui, state: &mut AppState) {
    if state.db.is_none() {
        draw_welcome(ui, state);
        return;
    }

    let (is64, range_start, range_end, title, seg_banner, func_banner) = {
        let db = state.db.as_ref().unwrap();
        let is64 = db.bin.is64();
        let func = db.func_at(state.selected_addr);
        let (range_start, range_end, title, func_banner) = if let Some(f) = func {
            let name = {
                let n = db.name_at(f.start);
                if n.is_empty() {
                    f.name.clone()
                } else {
                    n
                }
            };
            let banner = format!(
                "; {}  ({:X} bytes, {} insns{})",
                name,
                f.end.saturating_sub(f.start),
                f.insns,
                if f.thunk { ", thunk" } else { "" }
            );
            (
                f.start,
                f.end.min(f.start + 0x4000),
                format!(
                    "{}  {}–{}  {} insn",
                    name,
                    db.fmt_addr(f.start),
                    db.fmt_addr(f.end),
                    f.insns
                ),
                Some(banner),
            )
        } else {
            let start = state.selected_addr.saturating_sub(0x40);
            let end = state.selected_addr.saturating_add(0x120);
            (
                start,
                end,
                format!("@ {} (no function)", db.fmt_addr(state.selected_addr)),
                None,
            )
        };
        let seg_banner = db.bin.seg_at(range_start).map(|seg| {
            format!(
                "; segment {}  [{:X} - {:X}]",
                seg.name, seg.start, seg.end
            )
        });
        (is64, range_start, range_end, title, seg_banner, func_banner)
    };

    crate::theme::section_header(ui, &state.colors, "Listing", &title);

    let mut rows = Vec::new();
    if let Some(b) = func_banner {
        rows.push(header_row(range_start, b));
    }
    if let Some(b) = seg_banner {
        rows.push(header_row(range_start, b));
    }
    rows.extend(build_rows(state, range_start, range_end));

    let pc = state.dbg.pc().unwrap_or(0);
    let scroll_to = state.scroll_to_addr.take();

    let mut jump_to: Option<u64> = None;
    let mut rename_at: Option<u64> = None;
    let mut comment_at: Option<u64> = None;
    let mut bp_at: Option<u64> = None;
    let mut follow = false;
    let mut xrefs_at: Option<u64> = None;
    let mut graph = false;
    let mut pseudo = false;
    let mut copy_line: Option<String> = None;
    let mut show_hex: Option<u64> = None;

    ScrollArea::both()
        .id_salt("listing_scroll")
        .auto_shrink([false, false])
        .show(ui, |ui| {
            ui.set_min_width(ui.available_width());
            for row in &rows {
                if let Some(want) = scroll_to {
                    if row.addr == want && !row.is_header {
                        ui.scroll_to_cursor(Some(egui::Align::Center));
                    }
                }
                let selected = row.addr == state.selected_addr && !row.is_header;
                let is_pc = pc != 0 && row.addr == pc && !row.is_header;
                let bg = if is_pc {
                    state.colors.row_pc
                } else if selected {
                    state.colors.row_selected
                } else if row.is_header {
                    state.colors.header_bg
                } else {
                    egui::Color32::TRANSPARENT
                };

                let mono = state.fonts.mono_id();
                let (rect, resp) = ui.allocate_exact_size(
                    egui::vec2(ui.available_width(), mono.size + 4.0),
                    Sense::click(),
                );
                if bg.a() > 0 {
                    ui.painter().rect_filled(rect, 0.0, bg);
                }

                let mut x = rect.left() + 4.0;
                if row.has_bp {
                    ui.painter().circle_filled(
                        egui::pos2(x + 4.0, rect.center().y),
                        4.0,
                        state.colors.bp,
                    );
                }
                if is_pc {
                    let pts = [
                        egui::pos2(x + 14.0, rect.center().y),
                        egui::pos2(x + 6.0, rect.center().y - 5.0),
                        egui::pos2(x + 6.0, rect.center().y + 5.0),
                    ];
                    ui.painter().add(egui::Shape::convex_polygon(
                        pts.to_vec(),
                        state.colors.pc_arrow,
                        egui::Stroke::NONE,
                    ));
                }
                x += 22.0;

                let addr_s = crate::theme::hex_addr(row.addr, is64);
                ui.painter().text(
                    egui::pos2(x, rect.center().y),
                    egui::Align2::LEFT_CENTER,
                    &addr_s,
                    mono.clone(),
                    state.colors.addr,
                );
                x += mono.size * if is64 { 10.5 } else { 6.0 };

                if state.show_bytes && !row.is_header && !row.bytes.is_empty() {
                    ui.painter().text(
                        egui::pos2(x, rect.center().y),
                        egui::Align2::LEFT_CENTER,
                        &row.bytes,
                        egui::FontId::new(mono.size - 1.0, egui::FontFamily::Monospace),
                        state.colors.bytes,
                    );
                }
                x += if state.show_bytes {
                    mono.size * 14.0
                } else {
                    8.0
                };

                if let Some(label) = &row.label {
                    ui.painter().text(
                        egui::pos2(x, rect.center().y),
                        egui::Align2::LEFT_CENTER,
                        &format!("{label}:"),
                        mono.clone(),
                        state.colors.label,
                    );
                    x += mono.size * (label.len() as f32 * 0.62 + 2.0);
                }

                let text_color = if row.is_header {
                    state.colors.segment
                } else if row.is_func {
                    state.colors.func
                } else {
                    state.colors.style_for_mnemonic(&row.mnemonic, row.flow)
                };
                ui.painter().text(
                    egui::pos2(x, rect.center().y),
                    egui::Align2::LEFT_CENTER,
                    &row.text,
                    mono.clone(),
                    text_color,
                );
                x += mono.size * (row.text.len() as f32 * 0.60 + 2.0).min(52.0);

                if let Some(c) = &row.comment {
                    ui.painter().text(
                        egui::pos2(x, rect.center().y),
                        egui::Align2::LEFT_CENTER,
                        &format!("; {c}"),
                        mono.clone(),
                        state.colors.comment,
                    );
                } else if let Some(c) = &row.auto_comment {
                    ui.painter().text(
                        egui::pos2(x, rect.center().y),
                        egui::Align2::LEFT_CENTER,
                        &format!("; {c}"),
                        mono.clone(),
                        state.colors.auto_comment,
                    );
                }

                if resp.clicked() && !row.is_header {
                    jump_to = Some(row.addr);
                }
                if resp.double_clicked() && !row.is_header {
                    jump_to = Some(row.addr);
                    follow = true;
                }
                resp.context_menu(|ui| {
                    if row.is_header {
                        return;
                    }
                    if ui.button("Follow  (Enter)").clicked() {
                        jump_to = Some(row.addr);
                        follow = true;
                        ui.close_menu();
                    }
                    if ui.button("Rename…  (N)").clicked() {
                        rename_at = Some(row.addr);
                        ui.close_menu();
                    }
                    if ui.button("Comment…  (;)").clicked() {
                        comment_at = Some(row.addr);
                        ui.close_menu();
                    }
                    if ui.button("References…  (X)").clicked() {
                        xrefs_at = Some(row.addr);
                        ui.close_menu();
                    }
                    ui.separator();
                    if ui.button("Toggle breakpoint  (F2)").clicked() {
                        bp_at = Some(row.addr);
                        ui.close_menu();
                    }
                    if ui.button("Run to here  (F4)").clicked() {
                        jump_to = Some(row.addr);
                        state.selected_addr = row.addr;
                        state.dbg_run_to_cursor();
                        ui.close_menu();
                    }
                    ui.separator();
                    if ui.button("Copy address").clicked() {
                        ui.ctx()
                            .copy_text(crate::theme::hex_addr(row.addr, is64));
                        ui.close_menu();
                    }
                    if ui.button("Copy line").clicked() {
                        copy_line = Some(format!(
                            "{}  {}{}",
                            crate::theme::hex_compact(row.addr),
                            row.text,
                            row.comment
                                .as_ref()
                                .map(|c| format!("  ; {c}"))
                                .unwrap_or_default()
                        ));
                        ui.close_menu();
                    }
                    if ui.button("Show in hex").clicked() {
                        show_hex = Some(row.addr);
                        ui.close_menu();
                    }
                    if ui.button("Show graph").clicked() {
                        jump_to = Some(row.addr);
                        graph = true;
                        ui.close_menu();
                    }
                    if ui.button("Decompile (F5)").clicked() {
                        jump_to = Some(row.addr);
                        pseudo = true;
                        ui.close_menu();
                    }
                });
            }
            if rows.iter().all(|r| r.is_header) {
                ui.weak("(no instructions in range)");
            }
        });

    if let Some(a) = jump_to {
        if a != state.selected_addr {
            state.jump(a);
        } else {
            state.selected_addr = a;
        }
    }
    if follow {
        state.follow_operand();
    }
    if let Some(a) = rename_at {
        state.selected_addr = a;
        state.open_dialog(DialogKind::Rename);
    }
    if let Some(a) = comment_at {
        state.selected_addr = a;
        state.open_dialog(DialogKind::Comment);
    }
    if let Some(a) = bp_at {
        state.toggle_breakpoint(a);
    }
    if let Some(a) = xrefs_at {
        state.selected_addr = a;
        state.open_dialog(DialogKind::Xrefs);
    }
    if graph {
        state.center_tab = CenterTab::Graph;
    }
    if pseudo {
        state.center_tab = CenterTab::Pseudo;
    }
    if let Some(line) = copy_line {
        state.clipboard = line.clone();
        ui.ctx().copy_text(line);
    }
    if let Some(a) = show_hex {
        state.hex_addr = a;
        state.right_tab = crate::RightTab::Hex;
        state.show_right = true;
    }
}

fn draw_welcome(ui: &mut egui::Ui, state: &mut AppState) {
    ui.vertical_centered(|ui| {
        ui.add_space(ui.available_height() * 0.15);
        ui.label(
            RichText::new("ceasta")
                .size(state.fonts.title)
                .color(state.colors.func),
        );
        ui.label(
            RichText::new("disassembler, decompiler and debugger for windows and linux binaries")
                .color(state.colors.addr),
        );
        ui.add_space(16.0);
        ui.horizontal(|ui| {
            if ui.button("Open a file…").clicked() {
                state.request_open_file = true;
            }
            if ui.button("Open as raw code…").clicked() {
                state.open_dialog(DialogKind::OpenRaw);
            }
        });
        ui.add_space(8.0);
        ui.label(
            RichText::new("or pass a path on the command line:  ceasta <file>")
                .small()
                .color(state.colors.nop),
        );
        if !state.recent.is_empty() {
            ui.add_space(16.0);
            ui.label(RichText::new("recent files").color(state.colors.addr));
            let mut pick = None;
            for r in &state.recent {
                if ui.selectable_label(false, r.display().to_string()).clicked() {
                    pick = Some(r.clone());
                }
            }
            if let Some(p) = pick {
                if let Err(e) = state.load_file(&p) {
                    state.log_error(format!("{e:#}"));
                }
            }
        }
    });
}

fn header_row(addr: u64, text: String) -> Row {
    Row {
        addr,
        bytes: String::new(),
        text,
        mnemonic: String::new(),
        flow: Flow::Normal,
        label: None,
        comment: None,
        auto_comment: None,
        is_func: false,
        has_bp: false,
        is_header: true,
    }
}

fn build_rows(state: &AppState, start: u64, end: u64) -> Vec<Row> {
    let Some(db) = state.db.as_ref() else {
        return Vec::new();
    };
    let mut rows = Vec::new();
    let mut addr = start;
    let mut n = 0usize;
    while addr < end && n < 1200 {
        let flags = db.analysis.flags_at(addr);
        if flags & ceasta_analysis::FL_STR != 0 {
            let text = db
                .analysis
                .string_at(addr)
                .map(|s| format!("db '{}'", escape_str(&s.text, 64)))
                .unwrap_or_else(|| "db ? ; string".into());
            let size = db.analysis.item_size(addr).max(1);
            rows.push(Row {
                addr,
                bytes: String::new(),
                text,
                mnemonic: "db".into(),
                flow: Flow::Normal,
                label: nonempty(db.name_at(addr)),
                comment: db.comments.get(&addr).cloned(),
                auto_comment: None,
                is_func: flags & ceasta_analysis::FL_FUNC != 0,
                has_bp: db.breakpoints.contains(&addr),
                is_header: false,
            });
            addr += u64::from(size);
            n += 1;
            continue;
        }

        match decode_at(&db.bin, addr) {
            Ok(insn) => {
                let label = {
                    let name = db.name_at(insn.addr);
                    if !name.is_empty() {
                        Some(name)
                    } else if db.func_at(insn.addr).map(|f| f.start) == Some(insn.addr) {
                        Some(format!("sub_{:X}", insn.addr))
                    } else {
                        None
                    }
                };
                let auto = auto_comment_for(db, &insn);
                rows.push(Row {
                    addr: insn.addr,
                    bytes: format_bytes(&insn),
                    text: insn.text.clone(),
                    mnemonic: insn.mnemonic.clone(),
                    flow: insn.flow,
                    label,
                    comment: db.comments.get(&insn.addr).cloned(),
                    auto_comment: nonempty(auto),
                    is_func: db.func_at(insn.addr).map(|f| f.start) == Some(insn.addr),
                    has_bp: db.breakpoints.contains(&insn.addr),
                    is_header: false,
                });
                addr = insn.next();
            }
            Err(_) => {
                if let Some(b) = db.bin.read_u8(addr) {
                    rows.push(Row {
                        addr,
                        bytes: crate::theme::hex_byte(b),
                        text: format!("db {b:02X}h"),
                        mnemonic: "db".into(),
                        flow: Flow::Normal,
                        label: nonempty(db.name_at(addr)),
                        comment: db.comments.get(&addr).cloned(),
                        auto_comment: None,
                        is_func: false,
                        has_bp: db.breakpoints.contains(&addr),
                        is_header: false,
                    });
                }
                addr = addr.saturating_add(1);
            }
        }
        n += 1;
    }
    rows
}

fn auto_comment_for(db: &ceasta_db::Database, insn: &Insn) -> String {
    if let Some(t) = insn.target {
        let loc = db.location(t);
        return match insn.flow {
            Flow::Call => format!("call {loc}"),
            Flow::Jump | Flow::Cond => format!("→ {loc}"),
            _ => loc,
        };
    }
    if let Some(m) = insn.mem {
        if let Some(s) = db.analysis.string_at(m) {
            return format!("\"{}\"", escape_str(&s.text, 40));
        }
        let loc = db.location(m);
        if loc != format!("{m:X}") {
            return loc;
        }
    }
    if insn.flow == Flow::Call {
        if let Some(t) = insn.target {
            if let Some(&idx) = db.analysis.thunk_import.get(&t) {
                if let Some(imp) = db.bin.imports.get(idx as usize) {
                    return format!("{}!{}", imp.lib, imp.name);
                }
            }
        }
    }
    String::new()
}

fn escape_str(s: &str, max: usize) -> String {
    let mut out = String::new();
    for (i, ch) in s.chars().enumerate() {
        if i >= max {
            out.push('…');
            break;
        }
        match ch {
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\'' => out.push_str("\\'"),
            c if c.is_control() => out.push('.'),
            c => out.push(c),
        }
    }
    out
}

fn format_bytes(insn: &Insn) -> String {
    let mut s = String::new();
    for i in 0..insn.size as usize {
        if i > 0 {
            s.push(' ');
        }
        s.push_str(&crate::theme::hex_byte(insn.bytes[i]));
        if i >= 7 {
            s.push('…');
            break;
        }
    }
    s
}

fn nonempty(s: String) -> Option<String> {
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}
