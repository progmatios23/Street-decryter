//! Bottom panel — output log + Lua / command console.

use crate::{AppState, LogLevel};
use egui::{RichText, ScrollArea};

pub fn draw(ui: &mut egui::Ui, state: &mut AppState) {
    crate::theme::section_header(
        ui,
        &state.colors,
        "Output",
        &format!("{} lines", state.log.len()),
    );

    let input_h = ui.spacing().interact_size.y + 8.0;
    let log_h = (ui.available_height() - input_h).max(40.0);

    // ---- log ----
    let mut clear = false;
    let mut copy_all = false;

    ScrollArea::vertical()
        .id_salt("output_log")
        .auto_shrink([false, false])
        .stick_to_bottom(state.log_to_bottom)
        .max_height(log_h)
        .show(ui, |ui| {
            ui.set_min_width(ui.available_width());
            for line in &state.log {
                let color = state.colors.log_color(line.level);
                ui.label(RichText::new(&line.text).monospace().color(color));
            }
            if state.log_to_bottom {
                ui.scroll_to_cursor(Some(egui::Align::BOTTOM));
            }
        });
    state.log_to_bottom = false;

    ui.ctx().input(|i| {
        // right-click handled via context menu on the area
        let _ = i;
    });
    ui.menu_button("Log actions", |ui| {
        if ui.button("Copy all").clicked() {
            copy_all = true;
            ui.close_menu();
        }
        if ui.button("Clear").clicked() {
            clear = true;
            ui.close_menu();
        }
        if ui.button("Scroll to bottom").clicked() {
            state.log_to_bottom = true;
            ui.close_menu();
        }
    });

    if clear {
        state.log.clear();
    }
    if copy_all {
        let all: String = state
            .log
            .iter()
            .map(|l| l.text.as_str())
            .collect::<Vec<_>>()
            .join("\n");
        state.clipboard = all.clone();
        ui.ctx().copy_text(all);
        state.log_info("copied log");
    }

    // ---- console ----
    ui.horizontal(|ui| {
        ui.label(
            RichText::new("Lua>")
                .monospace()
                .color(state.colors.log_echo),
        );
        let te = egui::TextEdit::singleline(&mut state.console)
            .desired_width(ui.available_width() - 70.0)
            .hint_text("help | jump <addr> | name <addr> <n> | bp <addr> | ceasta.version")
            .font(egui::TextStyle::Monospace);
        let resp = ui.add(te);
        if state.focus_console {
            resp.request_focus();
            state.focus_console = false;
        }

        // history with up/down when focused
        if resp.has_focus() {
            let (up, down) = ui.ctx().input(|i| {
                (
                    i.key_pressed(egui::Key::ArrowUp),
                    i.key_pressed(egui::Key::ArrowDown),
                )
            });
            if up && !state.console_history.is_empty() {
                let n = state.console_history.len() as isize;
                state.history_pos = if state.history_pos < 0 {
                    n - 1
                } else {
                    (state.history_pos - 1).max(0)
                };
                if let Some(line) = state.console_history.get(state.history_pos as usize) {
                    state.console = line.clone();
                }
            }
            if down && state.history_pos >= 0 {
                let n = state.console_history.len() as isize;
                state.history_pos += 1;
                if state.history_pos >= n {
                    state.history_pos = -1;
                    state.console.clear();
                } else if let Some(line) = state.console_history.get(state.history_pos as usize) {
                    state.console = line.clone();
                }
            }
        }

        let enter = resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
        let clicked = ui.button("Run").clicked();
        if enter || clicked {
            state.run_console_line();
            // keep focus
            state.focus_console = true;
        }
        if ui.button("Clear").clicked() {
            state.log.clear();
        }
    });

    // level legend
    ui.horizontal(|ui| {
        for (lvl, name) in [
            (LogLevel::Info, "info"),
            (LogLevel::Warn, "warn"),
            (LogLevel::Error, "error"),
            (LogLevel::Echo, "echo"),
        ] {
            ui.label(
                RichText::new(name)
                    .small()
                    .color(state.colors.log_color(lvl)),
            );
        }
    });
}

/// Append a formatted analysis summary into the log (used after load).
pub fn dump_summary(state: &mut AppState) {
    let Some(db) = state.db.as_ref() else {
        return;
    };
    let line1 = format!(
        "file={} format={} arch={} base={:X} entry={}",
        db.bin.name,
        db.bin.format.as_str(),
        db.bin.arch.as_str(),
        db.bin.base,
        if db.bin.has_entry {
            format!("{:X}", db.bin.entry)
        } else {
            "none".into()
        }
    );
    let line2 = format!(
        "segments={} imports={} exports={} funcs={} strings={} xrefs={}",
        db.bin.segments.len(),
        db.bin.imports.len(),
        db.bin.exports.len(),
        db.analysis.functions.len(),
        db.analysis.strings.len(),
        db.analysis.xto.len()
    );
    let _ = db;
    state.log_info(line1);
    state.log_info(line2);
}
