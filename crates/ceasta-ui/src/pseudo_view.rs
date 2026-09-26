//! Pseudocode / decompile view (F5-style).

use crate::{AppState, CenterTab, DialogKind};
use egui::{RichText, ScrollArea};

pub fn draw(ui: &mut egui::Ui, state: &mut AppState) {
    let (title, code, func_start, fmt_start) = {
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
        let title = format!("{}  {}", db.fmt_addr(func.start), proto);
        let code = ceasta_decompiler::decompile_function(&db.bin, func);
        (title, code, func.start, db.fmt_addr(func.start))
    };
    let _ = fmt_start;

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

    ScrollArea::both()
        .id_salt("pseudo_scroll")
        .auto_shrink([false, false])
        .show(ui, |ui| {
            ui.set_min_width(ui.available_width());
            for (i, line) in code.lines().enumerate() {
                let trimmed = line.trim_start();
                let color = if trimmed.starts_with("//") {
                    state.colors.comment
                } else if starts_kw(trimmed) {
                    state.colors.kw
                } else {
                    state.colors.text
                };
                ui.horizontal(|ui| {
                    ui.label(
                        RichText::new(format!("{:4} ", i + 1))
                            .monospace()
                            .color(state.colors.muted),
                    );
                    ui.label(RichText::new(line).monospace().color(color));
                });
            }
            if code.is_empty() {
                ui.weak("(empty decompilation)");
            }
        });

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

fn starts_kw(s: &str) -> bool {
    s.starts_with("if")
        || s.starts_with("else")
        || s.starts_with("while")
        || s.starts_with("return")
        || s.starts_with("goto")
        || s.starts_with("void")
        || s.starts_with("int")
        || s.starts_with("uint")
        || s.starts_with("for")
}
