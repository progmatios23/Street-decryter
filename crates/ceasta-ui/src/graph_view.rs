//! Graph view — CFG blocks for the function under the cursor.

use crate::{AppState, CenterTab, DialogKind};
use ceasta_analysis::{build_cfg, Cfg, EdgeKind};
use ceasta_disasm::decode_at;
use egui::{Pos2, Rect, RichText, Sense, Vec2};

pub fn draw(ui: &mut egui::Ui, state: &mut AppState) {
    // Collect everything we need up front so we don't hold a borrow on AppState.
    let prepared = {
        let Some(db) = state.db.as_ref() else {
            ui.centered_and_justified(|ui| {
                ui.label("Open a binary to view the graph.");
            });
            return;
        };
        let Some(func) = db.func_at(state.selected_addr) else {
            ui.centered_and_justified(|ui| {
                ui.label("No function at the current address — jump to a function first.");
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
        let cfg = build_cfg(&db.bin, &db.analysis, func.start);
        let detail = match &cfg {
            Some(c) => format!(
                "{} · {} blocks{}",
                name,
                c.blocks.len(),
                if c.truncated { " (truncated)" } else { "" }
            ),
            None => format!("{name} · no CFG"),
        };
        let is64 = db.bin.is64();
        // Pre-render instruction text so we don't need Binary later.
        let block_lines: Vec<Vec<(u64, String)>> = cfg
            .as_ref()
            .map(|c| {
                c.blocks
                    .iter()
                    .map(|blk| {
                        blk.insn_addrs
                            .iter()
                            .take(24)
                            .map(|&a| {
                                let line = match decode_at(&db.bin, a) {
                                    Ok(insn) => insn.text,
                                    Err(_) => format!("db @ {a:X}"),
                                };
                                (a, trunc(&line, 28))
                            })
                            .collect()
                    })
                    .collect()
            })
            .unwrap_or_default();
        let block_extra: Vec<usize> = cfg
            .as_ref()
            .map(|c| {
                c.blocks
                    .iter()
                    .map(|b| b.insn_addrs.len().saturating_sub(24))
                    .collect()
            })
            .unwrap_or_default();
        Prepared {
            cfg,
            detail,
            is64,
            block_lines,
            block_extra,
        }
    };

    let colors = state.colors.clone();
    crate::theme::section_header(ui, &colors, "Graph", &prepared.detail);

    ui.horizontal(|ui| {
        if ui.button("Listing").clicked() {
            state.center_tab = CenterTab::Listing;
        }
        if ui.button("Decompile").clicked() {
            state.center_tab = CenterTab::Pseudo;
        }
        if ui.button("Rename…").clicked() {
            state.open_dialog(DialogKind::Rename);
        }
        if ui.button("Xrefs…").clicked() {
            state.open_dialog(DialogKind::Xrefs);
        }
    });
    ui.add_space(4.0);

    let Some(cfg) = prepared.cfg else {
        ui.weak("Could not build CFG for this function.");
        return;
    };

    draw_cfg(
        ui,
        state,
        &cfg,
        prepared.is64,
        &prepared.block_lines,
        &prepared.block_extra,
    );
}

struct Prepared {
    cfg: Option<Cfg>,
    detail: String,
    is64: bool,
    block_lines: Vec<Vec<(u64, String)>>,
    block_extra: Vec<usize>,
}

fn draw_cfg(
    ui: &mut egui::Ui,
    state: &mut AppState,
    cfg: &Cfg,
    is64: bool,
    block_lines: &[Vec<(u64, String)>],
    block_extra: &[usize],
) {
    let mut jump_to: Option<u64> = None;
    let block_w = 220.0_f32;
    let row_h = 16.0_f32;
    let gap_x = 40.0_f32;
    let gap_y = 28.0_f32;
    let cols = ((cfg.blocks.len() as f32).sqrt().ceil() as usize).max(1);

    let mut heights: Vec<f32> = Vec::with_capacity(cfg.blocks.len());
    for blk in &cfg.blocks {
        let lines = blk.insn_addrs.len().min(24).max(1) as f32 + 1.5;
        heights.push(lines * row_h + 8.0);
    }

    let mut positions: Vec<Pos2> = vec![Pos2::ZERO; cfg.blocks.len()];
    let mut col_y = vec![8.0_f32; cols];
    for (i, h) in heights.iter().enumerate() {
        let col = i % cols;
        positions[i] = Pos2::new(8.0 + col as f32 * (block_w + gap_x), col_y[col]);
        col_y[col] += *h + gap_y;
    }

    let content_w = cols as f32 * (block_w + gap_x) + 16.0;
    let content_h = col_y.iter().copied().fold(0.0_f32, f32::max) + 16.0;

    // Also render a text CFG summary above the canvas.
    ui.collapsing("Text CFG", |ui| {
        ui.monospace(render_ascii_cfg(cfg, state.selected_addr));
    });

    egui::ScrollArea::both()
        .id_salt("graph_scroll")
        .auto_shrink([false, false])
        .show(ui, |ui| {
            let (resp, painter) =
                ui.allocate_painter(Vec2::new(content_w, content_h), Sense::hover());
            let origin = resp.rect.min;

            for (i, blk) in cfg.blocks.iter().enumerate() {
                let from = positions[i] + origin.to_vec2() + Vec2::new(block_w * 0.5, heights[i]);
                for e in &blk.succ {
                    let Some(&to_pos) = positions.get(e.to as usize) else {
                        continue;
                    };
                    let to = to_pos + origin.to_vec2() + Vec2::new(block_w * 0.5, 0.0);
                    let color = match e.kind {
                        EdgeKind::Taken | EdgeKind::Jump | EdgeKind::Table => state.colors.jump,
                        EdgeKind::NotTaken => state.colors.ret,
                        EdgeKind::Next => state.colors.muted,
                    };
                    painter.line_segment([from, to], egui::Stroke::new(1.5, color));
                }
            }

            for (i, blk) in cfg.blocks.iter().enumerate() {
                let pos = positions[i] + origin.to_vec2();
                let rect = Rect::from_min_size(pos, Vec2::new(block_w, heights[i]));
                let selected = state.selected_addr >= blk.start && state.selected_addr < blk.end;
                let fill = if selected {
                    state.colors.row_selected
                } else {
                    state.colors.panel_bg
                };
                painter.rect(
                    rect,
                    3.0,
                    fill,
                    egui::Stroke::new(1.0, state.colors.header_bg),
                    egui::StrokeKind::Inside,
                );

                let header = format!("bb_{}  {}", i, crate::theme::hex_addr(blk.start, is64));
                painter.text(
                    rect.left_top() + Vec2::new(6.0, 4.0),
                    egui::Align2::LEFT_TOP,
                    header,
                    state.fonts.mono_id(),
                    state.colors.header_text,
                );

                let mut y = 20.0_f32;
                if let Some(lines) = block_lines.get(i) {
                    for &(a, ref line) in lines {
                        let color = if a == state.selected_addr {
                            state.colors.pc_arrow
                        } else {
                            state.colors.text
                        };
                        painter.text(
                            rect.left_top() + Vec2::new(6.0, y),
                            egui::Align2::LEFT_TOP,
                            line,
                            state.fonts.mono_id(),
                            color,
                        );
                        y += row_h;
                    }
                }
                if block_extra.get(i).copied().unwrap_or(0) > 0 {
                    painter.text(
                        rect.left_top() + Vec2::new(6.0, y),
                        egui::Align2::LEFT_TOP,
                        "…",
                        state.fonts.mono_id(),
                        state.colors.muted,
                    );
                }

                let id = ui.id().with(("gblk", i));
                let block_resp = ui.interact(rect, id, Sense::click());
                if block_resp.clicked() {
                    jump_to = Some(blk.start);
                }
                block_resp.context_menu(|ui| {
                    if ui.button("Jump to block").clicked() {
                        jump_to = Some(blk.start);
                        ui.close_menu();
                    }
                    if ui.button("Listing").clicked() {
                        jump_to = Some(blk.start);
                        state.center_tab = CenterTab::Listing;
                        ui.close_menu();
                    }
                });
            }
        });

    ui.label(
        RichText::new("Edges: cyan = taken/jump · red = not-taken · gray = fallthrough")
            .small()
            .color(state.colors.muted),
    );

    if let Some(a) = jump_to {
        state.jump(a);
    }
}

fn render_ascii_cfg(cfg: &Cfg, selected: u64) -> String {
    let mut out = String::new();
    for (i, b) in cfg.blocks.iter().enumerate() {
        let mark = if selected >= b.start && selected < b.end {
            ">"
        } else {
            " "
        };
        out.push_str(&format!("{mark}[{i:02}] {:X}..{:X}", b.start, b.end));
        if !b.succ.is_empty() {
            out.push_str("  ");
            for (si, e) in b.succ.iter().enumerate() {
                if si > 0 {
                    out.push(' ');
                }
                out.push_str(&format!("{}->{}", e.kind.as_str(), e.to));
            }
        }
        out.push('\n');
    }
    out
}

fn trunc(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let t: String = s.chars().take(max.saturating_sub(1)).collect();
        format!("{t}…")
    }
}
