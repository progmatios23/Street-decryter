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
    is_func: bool,
    has_bp: bool,
}

pub fn draw(ui: &mut egui::Ui, state: &mut AppState) {
    let Some(db) = state.db.as_ref() else {
        ui.centered_and_justified(|ui| {
            ui.label("Open a binary to view the listing (File → Open…).");
        });
        return;
    };

    let is64 = db.bin.is64();
    let func = db.func_at(state.selected_addr);
    let (range_start, range_end, title) = if let Some(f) = func {
        let name = {
            let n = db.name_at(f.start);
            if n.is_empty() {
                f.name.clone()
            } else {
                n
            }
        };
        (
            f.start,
            f.end,
            format!(
                "{}  {}–{}  {} insn",
                name,
                db.fmt_addr(f.start),
                db.fmt_addr(f.end),
                f.insns
            ),
        )
    } else {
        let start = state.selected_addr.saturating_sub(0x40);
        let end = state.selected_addr.saturating_add(0x120);
        (
            start,
            end,
            format!("@ {} (no function)", db.fmt_addr(state.selected_addr)),
        )
    };

    crate::theme::section_header(ui, &state.colors, "Listing", &title);

    let rows = build_rows(state, range_start, range_end);
    let pc = state.dbg.pc().unwrap_or(0);
    let scroll_to = state.scroll_to_addr.take();

    let mut jump_to: Option<u64> = None;
    let mut rename_at: Option<u64> = None;
    let mut comment_at: Option<u64> = None;
    let mut bp_at: Option<u64> = None;
    let mut follow: bool = false;
    let mut xrefs_at: Option<u64> = None;
    let mut graph = false;
    let mut pseudo = false;

    ScrollArea::both()
        .id_salt("listing_scroll")
        .auto_shrink([false, false])
        .show(ui, |ui| {
            ui.set_min_width(ui.available_width());
            for row in &rows {
                let selected = row.addr == state.selected_addr;
                let is_pc = pc != 0 && row.addr == pc;
                let bg = if is_pc {
                    state.colors.row_pc
                } else if selected {
                    state.colors.row_selected
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

                // left band
                let band = if row.has_bp {
                    state.colors.bp
                } else if row.is_func {
                    state.colors.band_func
                } else {
                    state.colors.band_code
                };
                let band_rect = egui::Rect::from_min_size(
                    rect.left_top(),
                    egui::vec2(4.0, rect.height()),
                );
                ui.painter().rect_filled(band_rect, 0.0, band);

                let mut x = rect.left() + 10.0;
                let y = rect.center().y;
                let painter = ui.painter();

                if row.has_bp {
                    painter.text(
                        egui::pos2(x, y),
                        egui::Align2::LEFT_CENTER,
                        "●",
                        mono.clone(),
                        state.colors.bp,
                    );
                }
                x += 14.0;

                if is_pc {
                    painter.text(
                        egui::pos2(x, y),
                        egui::Align2::LEFT_CENTER,
                        "►",
                        mono.clone(),
                        state.colors.pc_arrow,
                    );
                }
                x += 14.0;

                let addr_s = crate::theme::hex_addr(row.addr, is64);
                let addr_galley = painter.layout_no_wrap(
                    addr_s,
                    mono.clone(),
                    state.colors.addr,
                );
                painter.galley(egui::pos2(x, y - addr_galley.size().y * 0.5), addr_galley, state.colors.addr);
                x += if is64 { 140.0 } else { 80.0 };

                if state.show_bytes {
                    let bytes_galley = painter.layout_no_wrap(
                        row.bytes.clone(),
                        mono.clone(),
                        state.colors.bytes,
                    );
                    painter.galley(
                        egui::pos2(x, y - bytes_galley.size().y * 0.5),
                        bytes_galley,
                        state.colors.bytes,
                    );
                    x += 120.0;
                }

                if let Some(label) = &row.label {
                    let g = painter.layout_no_wrap(
                        format!("{label}:"),
                        mono.clone(),
                        state.colors.label,
                    );
                    painter.galley(egui::pos2(x, y - g.size().y * 0.5), g, state.colors.label);
                    x += 8.0 + mono.size * 0.6 * (label.len() as f32 + 1.0);
                }

                let insn_color = state
                    .colors
                    .style_for_mnemonic(&row.mnemonic, row.flow);
                let text_g = painter.layout_no_wrap(row.text.clone(), mono.clone(), insn_color);
                painter.galley(egui::pos2(x, y - text_g.size().y * 0.5), text_g, insn_color);
                x += 8.0 + mono.size * 0.55 * row.text.len().min(48) as f32;

                if let Some(c) = &row.comment {
                    let g = painter.layout_no_wrap(
                        format!("; {c}"),
                        mono.clone(),
                        state.colors.comment,
                    );
                    painter.galley(egui::pos2(x, y - g.size().y * 0.5), g, state.colors.comment);
                }

                if scroll_to == Some(row.addr) {
                    resp.scroll_to_me(Some(egui::Align::Center));
                }

                if resp.clicked() {
                    jump_to = Some(row.addr);
                }
                if resp.double_clicked() {
                    follow = true;
                    jump_to = Some(row.addr);
                }

                resp.context_menu(|ui| {
                    if ui.button("Follow / enter").clicked() {
                        follow = true;
                        jump_to = Some(row.addr);
                        ui.close_menu();
                    }
                    if ui.button("Rename…").clicked() {
                        rename_at = Some(row.addr);
                        ui.close_menu();
                    }
                    if ui.button("Comment…").clicked() {
                        comment_at = Some(row.addr);
                        ui.close_menu();
                    }
                    if ui.button("Toggle breakpoint").clicked() {
                        bp_at = Some(row.addr);
                        ui.close_menu();
                    }
                    if ui.button("Xrefs…").clicked() {
                        xrefs_at = Some(row.addr);
                        ui.close_menu();
                    }
                    ui.separator();
                    if ui.button("Graph view").clicked() {
                        graph = true;
                        jump_to = Some(row.addr);
                        ui.close_menu();
                    }
                    if ui.button("Decompile").clicked() {
                        pseudo = true;
                        jump_to = Some(row.addr);
                        ui.close_menu();
                    }
                    if ui.button("Copy address").clicked() {
                        let t = format!("{:X}", row.addr);
                        state.clipboard = t.clone();
                        ui.ctx().copy_text(t);
                        ui.close_menu();
                    }
                });

                // hover highlight
                if resp.hovered() && !selected && !is_pc {
                    ui.painter()
                        .rect_filled(rect, 0.0, state.colors.row_hover.gamma_multiply(0.35));
                }
            }

            if rows.is_empty() {
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
}

fn build_rows(state: &AppState, start: u64, end: u64) -> Vec<Row> {
    let Some(db) = state.db.as_ref() else {
        return Vec::new();
    };
    let mut rows = Vec::new();
    let mut addr = start;
    let mut n = 0usize;
    while addr < end && n < 800 {
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
                let comment = db.comments.get(&insn.addr).cloned();
                let is_func = db.func_at(insn.addr).map(|f| f.start) == Some(insn.addr);
                rows.push(Row {
                    addr: insn.addr,
                    bytes: format_bytes(&insn),
                    text: insn.text.clone(),
                    mnemonic: insn.mnemonic.clone(),
                    flow: insn.flow,
                    label,
                    comment,
                    is_func,
                    has_bp: db.breakpoints.contains(&insn.addr),
                });
                addr = insn.next();
            }
            Err(_) => {
                // show a db byte
                if let Some(b) = db.bin.read_u8(addr) {
                    rows.push(Row {
                        addr,
                        bytes: crate::theme::hex_byte(b),
                        text: format!("db {:02X}h", b),
                        mnemonic: "db".into(),
                        flow: Flow::Normal,
                        label: db.name_at(addr).into_option(),
                        comment: db.comments.get(&addr).cloned(),
                        is_func: false,
                        has_bp: db.breakpoints.contains(&addr),
                    });
                }
                addr = addr.saturating_add(1);
            }
        }
        n += 1;
    }
    rows
}

fn format_bytes(insn: &Insn) -> String {
    let mut s = String::new();
    for i in 0..insn.size as usize {
        if i > 0 {
            s.push(' ');
        }
        s.push_str(&crate::theme::hex_byte(insn.bytes[i]));
    }
    s
}

trait IntoOption {
    fn into_option(self) -> Option<String>;
}

impl IntoOption for String {
    fn into_option(self) -> Option<String> {
        if self.is_empty() {
            None
        } else {
            Some(self)
        }
    }
}
