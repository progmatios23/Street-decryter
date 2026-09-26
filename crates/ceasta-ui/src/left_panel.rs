//! Left panel — functions list with filter, plus imports / exports / strings / segments tabs.

use crate::{AppState, DialogKind, LeftTab};
use egui::{RichText, Sense};

#[derive(Clone)]
struct FuncRow {
    addr: u64,
    size: u64,
    name: String,
}

pub fn draw(ui: &mut egui::Ui, state: &mut AppState) {
    crate::theme::section_header(
        ui,
        &state.colors,
        "Browser",
        state
            .db
            .as_ref()
            .map(|d| format!("{} funcs", d.analysis.functions.len()))
            .unwrap_or_default()
            .as_str(),
    );

    ui.horizontal_wrapped(|ui| {
        for t in LeftTab::all() {
            if ui
                .selectable_label(state.left_tab == *t, t.as_str())
                .clicked()
            {
                state.left_tab = *t;
            }
        }
    });
    ui.add_space(2.0);

    let Some(_) = state.db.as_ref() else {
        ui.weak("(no file loaded)");
        ui.label("Open a binary from File → Open… or drop one on the window.");
        return;
    };

    match state.left_tab {
        LeftTab::Functions => draw_functions(ui, state),
        LeftTab::Imports => draw_imports(ui, state),
        LeftTab::Exports => draw_exports(ui, state),
        LeftTab::Strings => draw_strings(ui, state),
        LeftTab::Segments => draw_segments(ui, state),
    }
}

fn draw_functions(ui: &mut egui::Ui, state: &mut AppState) {
    ui.horizontal(|ui| {
        ui.label("Filter");
        ui.add(
            egui::TextEdit::singleline(&mut state.func_filter)
                .desired_width(f32::INFINITY)
                .hint_text("name or address"),
        );
    });

    let rows = build_func_rows(state);
    let cur = state
        .db
        .as_ref()
        .and_then(|d| d.func_at(state.selected_addr))
        .map(|f| f.start);

    ui.label(
        RichText::new(format!("{} shown", rows.len()))
            .small()
            .color(state.colors.muted),
    );

    let mut jump_to: Option<u64> = None;
    let mut rename_at: Option<u64> = None;
    let mut xrefs_at: Option<u64> = None;
    let mut bp_at: Option<u64> = None;
    let mut graph_at: Option<u64> = None;
    let mut copy_name: Option<String> = None;

    egui::ScrollArea::vertical()
        .auto_shrink([false, false])
        .show(ui, |ui| {
            egui::Grid::new("func_grid")
                .num_columns(3)
                .striped(true)
                .min_col_width(40.0)
                .show(ui, |ui| {
                    ui.strong("Name");
                    ui.strong("Address");
                    ui.strong("Size");
                    ui.end_row();

                    for (i, row) in rows.iter().enumerate() {
                        let selected = cur == Some(row.addr);
                        let name_resp = ui.selectable_label(selected, &row.name);
                        if name_resp.clicked() {
                            jump_to = Some(row.addr);
                        }
                        name_resp.context_menu(|ui| {
                            if ui.button("Jump to").clicked() {
                                jump_to = Some(row.addr);
                                ui.close_menu();
                            }
                            if ui.button("Rename…").clicked() {
                                rename_at = Some(row.addr);
                                ui.close_menu();
                            }
                            if ui.button("References…").clicked() {
                                xrefs_at = Some(row.addr);
                                ui.close_menu();
                            }
                            if ui.button("Show graph").clicked() {
                                graph_at = Some(row.addr);
                                ui.close_menu();
                            }
                            if ui.button("Toggle breakpoint").clicked() {
                                bp_at = Some(row.addr);
                                ui.close_menu();
                            }
                            if ui.button("Copy name").clicked() {
                                copy_name = Some(row.name.clone());
                                ui.close_menu();
                            }
                        });
                        ui.label(
                            RichText::new(crate::theme::hex_compact(row.addr))
                                .monospace()
                                .color(state.colors.addr),
                        );
                        ui.label(
                            RichText::new(format!("{:X}", row.size))
                                .monospace()
                                .color(state.colors.muted),
                        );
                        ui.end_row();
                        let _ = i;
                    }
                });
        });

    if let Some(a) = jump_to {
        state.jump(a);
    }
    if let Some(a) = rename_at {
        state.selected_addr = a;
        state.open_dialog(DialogKind::Rename);
    }
    if let Some(a) = xrefs_at {
        state.selected_addr = a;
        state.open_dialog(DialogKind::Xrefs);
    }
    if let Some(a) = bp_at {
        state.toggle_breakpoint(a);
    }
    if let Some(a) = graph_at {
        state.jump(a);
        state.center_tab = crate::CenterTab::Graph;
    }
    if let Some(n) = copy_name {
        state.clipboard = n.clone();
        ui.ctx().copy_text(n);
    }
}

fn build_func_rows(state: &AppState) -> Vec<FuncRow> {
    let Some(db) = state.db.as_ref() else {
        return Vec::new();
    };
    let filter = state.func_filter.trim().to_ascii_lowercase();
    let want_hex = u64::from_str_radix(filter.trim_start_matches("0x"), 16).ok();
    let mut rows: Vec<FuncRow> = db
        .analysis
        .functions
        .iter()
        .filter_map(|f| {
            let name = {
                let n = db.name_at(f.start);
                if n.is_empty() {
                    f.name.clone()
                } else {
                    n
                }
            };
            if !filter.is_empty() {
                let name_l = name.to_ascii_lowercase();
                let addr_s = format!("{:x}", f.start);
                let ok = name_l.contains(&filter)
                    || addr_s.contains(&filter)
                    || want_hex == Some(f.start);
                if !ok {
                    return None;
                }
            }
            Some(FuncRow {
                addr: f.start,
                size: f.end.saturating_sub(f.start),
                name,
            })
        })
        .collect();
    rows.sort_by(|a, b| a.addr.cmp(&b.addr));
    rows
}

fn draw_imports(ui: &mut egui::Ui, state: &mut AppState) {
    ui.horizontal(|ui| {
        ui.label("Filter");
        ui.add(
            egui::TextEdit::singleline(&mut state.import_filter)
                .desired_width(f32::INFINITY)
                .hint_text("name or library"),
        );
    });
    let filter = state.import_filter.trim().to_ascii_lowercase();
    let mut jump: Option<u64> = None;
    let entries: Vec<(u64, String, String)> = state
        .db
        .as_ref()
        .map(|db| {
            db.bin
                .imports
                .iter()
                .filter(|e| {
                    filter.is_empty()
                        || e.name.to_ascii_lowercase().contains(&filter)
                        || e.lib.to_ascii_lowercase().contains(&filter)
                })
                .map(|e| (e.slot, format!("{}!{}", e.lib, e.name), e.lib.clone()))
                .collect()
        })
        .unwrap_or_default();

    ui.label(
        RichText::new(format!("{} imports", entries.len()))
            .small()
            .color(state.colors.muted),
    );
    egui::ScrollArea::vertical()
        .auto_shrink([false, false])
        .show(ui, |ui| {
            for (i, (addr, label, lib)) in entries.iter().enumerate() {
                ui.horizontal(|ui| {
                    let r = ui.add(
                        egui::Label::new(
                            RichText::new(crate::theme::hex_compact(*addr))
                                .monospace()
                                .color(state.colors.addr),
                        )
                        .sense(Sense::click()),
                    );
                    if r.clicked() {
                        jump = Some(*addr);
                    }
                    if ui
                        .selectable_label(false, RichText::new(label).color(state.colors.label))
                        .clicked()
                    {
                        jump = Some(*addr);
                    }
                    ui.label(RichText::new(lib).small().color(state.colors.muted));
                });
                let _ = i;
            }
        });
    if let Some(a) = jump {
        state.jump(a);
    }
}

fn draw_exports(ui: &mut egui::Ui, state: &mut AppState) {
    ui.horizontal(|ui| {
        ui.label("Filter");
        ui.add(
            egui::TextEdit::singleline(&mut state.export_filter)
                .desired_width(f32::INFINITY)
                .hint_text("export name"),
        );
    });
    let filter = state.export_filter.trim().to_ascii_lowercase();
    let mut jump: Option<u64> = None;
    let entries: Vec<(u64, String, String)> = state
        .db
        .as_ref()
        .map(|db| {
            db.bin
                .exports
                .iter()
                .filter(|e| {
                    filter.is_empty()
                        || e.name.to_ascii_lowercase().contains(&filter)
                        || e.forward.to_ascii_lowercase().contains(&filter)
                })
                .map(|e| {
                    (
                        e.addr,
                        e.name.clone(),
                        if e.forward.is_empty() {
                            String::new()
                        } else {
                            format!("→ {}", e.forward)
                        },
                    )
                })
                .collect()
        })
        .unwrap_or_default();

    ui.label(
        RichText::new(format!("{} exports", entries.len()))
            .small()
            .color(state.colors.muted),
    );
    egui::ScrollArea::vertical()
        .auto_shrink([false, false])
        .show(ui, |ui| {
            for (addr, name, fwd) in &entries {
                ui.horizontal(|ui| {
                    if ui
                        .selectable_label(
                            false,
                            RichText::new(crate::theme::hex_compact(*addr))
                                .monospace()
                                .color(state.colors.addr),
                        )
                        .clicked()
                    {
                        jump = Some(*addr);
                    }
                    if ui.selectable_label(false, name).clicked() {
                        jump = Some(*addr);
                    }
                    if !fwd.is_empty() {
                        ui.label(RichText::new(fwd).small().color(state.colors.muted));
                    }
                });
            }
        });
    if let Some(a) = jump {
        state.jump(a);
    }
}

fn draw_strings(ui: &mut egui::Ui, state: &mut AppState) {
    ui.horizontal(|ui| {
        ui.label("Filter");
        ui.add(
            egui::TextEdit::singleline(&mut state.string_filter)
                .desired_width(f32::INFINITY)
                .hint_text("substring"),
        );
    });
    let filter = state.string_filter.trim().to_ascii_lowercase();
    let mut jump: Option<u64> = None;
    let entries: Vec<(u64, String, bool)> = state
        .db
        .as_ref()
        .map(|db| {
            db.analysis
                .strings
                .iter()
                .filter(|s| filter.is_empty() || s.text.to_ascii_lowercase().contains(&filter))
                .take(5000)
                .map(|s| (s.addr, escape_preview(&s.text, 80), s.wide))
                .collect()
        })
        .unwrap_or_default();

    ui.label(
        RichText::new(format!("{} strings", entries.len()))
            .small()
            .color(state.colors.muted),
    );
    egui::ScrollArea::vertical()
        .auto_shrink([false, false])
        .show(ui, |ui| {
            for (addr, text, wide) in &entries {
                ui.horizontal(|ui| {
                    if ui
                        .selectable_label(
                            state.selected_addr == *addr,
                            RichText::new(crate::theme::hex_compact(*addr))
                                .monospace()
                                .color(state.colors.addr),
                        )
                        .clicked()
                    {
                        jump = Some(*addr);
                    }
                    let prefix = if *wide { "L" } else { "" };
                    if ui
                        .selectable_label(
                            false,
                            RichText::new(format!("{prefix}\"{text}\""))
                                .color(state.colors.string),
                        )
                        .clicked()
                    {
                        jump = Some(*addr);
                    }
                });
            }
        });
    if let Some(a) = jump {
        state.jump(a);
    }
}

fn draw_segments(ui: &mut egui::Ui, state: &mut AppState) {
    let mut jump: Option<u64> = None;
    let segs: Vec<(String, u64, u64, String)> = state
        .db
        .as_ref()
        .map(|db| {
            db.bin
                .segments
                .iter()
                .map(|s| {
                    let perms = format!(
                        "{}{}{}",
                        if s.perms & ceasta_binary::PERM_R != 0 {
                            "r"
                        } else {
                            "-"
                        },
                        if s.perms & ceasta_binary::PERM_W != 0 {
                            "w"
                        } else {
                            "-"
                        },
                        if s.exec() { "x" } else { "-" }
                    );
                    (s.name.clone(), s.start, s.end, perms)
                })
                .collect()
        })
        .unwrap_or_default();

    egui::ScrollArea::vertical()
        .auto_shrink([false, false])
        .show(ui, |ui| {
            egui::Grid::new("seg_grid")
                .num_columns(4)
                .striped(true)
                .show(ui, |ui| {
                    ui.strong("Name");
                    ui.strong("Start");
                    ui.strong("End");
                    ui.strong("Perm");
                    ui.end_row();
                    for (name, start, end, perms) in &segs {
                        if ui.selectable_label(false, name).clicked() {
                            jump = Some(*start);
                        }
                        ui.label(
                            RichText::new(crate::theme::hex_compact(*start))
                                .monospace()
                                .color(state.colors.addr),
                        );
                        ui.label(
                            RichText::new(crate::theme::hex_compact(*end))
                                .monospace()
                                .color(state.colors.muted),
                        );
                        ui.label(RichText::new(perms).monospace());
                        ui.end_row();
                    }
                });
        });
    if let Some(a) = jump {
        state.jump(a);
    }
}

fn escape_preview(s: &str, max: usize) -> String {
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
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if c.is_control() => out.push_str(&format!("\\x{:02x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}
