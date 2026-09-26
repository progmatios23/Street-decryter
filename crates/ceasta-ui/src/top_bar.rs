//! Top menu bar — File / Edit / View / Debug / Plugins / Help dropdowns.

use crate::theme;
use crate::{AppState, CenterTab, DialogKind, LeftTab, RightTab, UiTheme};
use ceasta_debugger::State as DbgState;
use egui::{Button, Context, TopBottomPanel};

pub fn draw(ctx: &Context, state: &mut AppState) {
    TopBottomPanel::top("top_bar").show(ctx, |ui| {
        egui::menu::bar(ui, |ui| {
            file_menu(ui, state);
            edit_menu(ui, state);
            jump_menu(ui, state);
            view_menu(ui, state);
            debug_menu(ui, state);
            plugins_menu(ui, state);
            help_menu(ui, state);

            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                let dbg_label = match state.dbg.state() {
                    DbgState::None => "idle",
                    DbgState::Running => "RUNNING",
                    DbgState::Stopped => "stopped",
                };
                ui.label(
                    egui::RichText::new(dbg_label)
                        .small()
                        .color(match state.dbg.state() {
                            DbgState::Running => state.colors.comment,
                            DbgState::Stopped => state.colors.pc_arrow,
                            DbgState::None => state.colors.muted,
                        }),
                );
                if let Some(db) = state.db.as_ref() {
                    ui.separator();
                    ui.label(
                        egui::RichText::new(format!(
                            "{}  {}",
                            db.bin.name,
                            db.fmt_addr(state.selected_addr)
                        ))
                        .small()
                        .monospace()
                        .color(state.colors.addr),
                    );
                }
            });
        });

        // debug toolbar strip
        ui.horizontal(|ui| {
            let st = state.dbg.state();
            let has = state.db.is_some();
            let run_label = if st == DbgState::Stopped {
                "Continue"
            } else {
                "Start"
            };
            if ui
                .add_enabled(
                    has && (st == DbgState::None || st == DbgState::Stopped),
                    Button::new(run_label),
                )
                .on_hover_text("F9")
                .clicked()
            {
                state.dbg_continue();
            }
            if ui
                .add_enabled(st == DbgState::Stopped, Button::new("Step into"))
                .on_hover_text("F7")
                .clicked()
            {
                state.dbg_step_into();
            }
            if ui
                .add_enabled(st == DbgState::Stopped, Button::new("Step over"))
                .on_hover_text("F8")
                .clicked()
            {
                state.dbg_step_over();
            }
            if ui
                .add_enabled(st == DbgState::Stopped, Button::new("Run to cursor"))
                .on_hover_text("F4")
                .clicked()
            {
                state.dbg_run_to_cursor();
            }
            if ui
                .add_enabled(st == DbgState::Running, Button::new("Pause"))
                .on_hover_text("F12")
                .clicked()
            {
                state.dbg_pause();
            }
            if ui
                .add_enabled(st != DbgState::None, Button::new("Stop"))
                .on_hover_text(theme::keys("Ctrl+F2"))
                .clicked()
            {
                state.dbg_stop();
            }
            ui.separator();
            ui.label("steps");
            ui.add(
                egui::DragValue::new(&mut state.step_count)
                    .range(1..=100_000)
                    .speed(1),
            );
            ui.separator();
            if ui
                .add_enabled(has, Button::new("Toggle BP"))
                .on_hover_text("F2")
                .clicked()
            {
                state.toggle_breakpoint(state.selected_addr);
            }
        });
    });
}

fn file_menu(ui: &mut egui::Ui, state: &mut AppState) {
    ui.menu_button("File", |ui| {
        if ui
            .add(Button::new("Open…").shortcut_text(theme::keys("Ctrl+O")))
            .clicked()
        {
            state.request_open_file = true;
            ui.close_menu();
        }
        if ui.button("Open as raw code…").clicked() {
            state.open_dialog(DialogKind::OpenRaw);
            ui.close_menu();
        }
        ui.menu_button("Open recent", |ui| {
            if state.recent.is_empty() {
                ui.weak("(empty)");
            }
            let mut pick: Option<std::path::PathBuf> = None;
            for r in &state.recent {
                if ui.button(r.display().to_string()).clicked() {
                    pick = Some(r.clone());
                }
            }
            if let Some(p) = pick {
                if let Err(e) = state.load_file(&p) {
                    state.log_error(format!("{e:#}"));
                }
                ui.close_menu();
            }
        });
        ui.separator();
        let can_save = state.db.as_ref().map(|d| d.dirty).unwrap_or(false) || state.db.is_some();
        if ui
            .add_enabled(
                can_save,
                Button::new("Save").shortcut_text(theme::keys("Ctrl+S")),
            )
            .on_hover_text("write a .ceasta sidecar with names, comments, breakpoints")
            .clicked()
        {
            state.save_project();
            ui.close_menu();
        }
        if ui
            .add_enabled(state.db.is_some(), Button::new("Save as…"))
            .clicked()
        {
            if let Some(path) = rfd::FileDialog::new()
                .add_filter("ceasta project", &["ceasta", "json"])
                .save_file()
            {
                if let Some(db) = state.db.as_mut() {
                    match db.save_project_to(&path) {
                        Ok(()) => {
                            db.dirty = false;
                            state.log_info(format!("saved {}", path.display()));
                        }
                        Err(e) => state.log_error(format!("save as: {e}")),
                    }
                }
            }
            ui.close_menu();
        }
        if ui
            .add_enabled(state.db.is_some(), Button::new("Close file"))
            .clicked()
        {
            state.close_file();
            ui.close_menu();
        }
        ui.separator();
        ui.menu_button("Export for", |ui| {
            if ui
                .add_enabled(state.db.is_some(), Button::new("IDA…"))
                .clicked()
            {
                export_script(state, "ida");
                ui.close_menu();
            }
            if ui
                .add_enabled(state.db.is_some(), Button::new("Ghidra…"))
                .clicked()
            {
                export_script(state, "ghidra");
                ui.close_menu();
            }
            if ui
                .add_enabled(state.db.is_some(), Button::new("x64dbg…"))
                .clicked()
            {
                export_script(state, "x64dbg");
                ui.close_menu();
            }
        });
        if ui
            .add_enabled(state.db.is_some(), Button::new("Import names…"))
            .clicked()
        {
            if let Some(path) = rfd::FileDialog::new()
                .add_filter("Names", &["ceasta", "json", "map"])
                .pick_file()
            {
                if let Some(db) = state.db.as_mut() {
                    let r = ceasta_db::import_names(db, &path);
                    if let Some(e) = r.error {
                        state.log_error(e);
                    } else {
                        state.log_info(r.summary());
                        state.listing_dirty = true;
                    }
                }
            }
            ui.close_menu();
        }
        ui.separator();
        if ui
            .add(Button::new("Exit").shortcut_text(theme::keys("Alt+F4")))
            .clicked()
        {
            state.request_quit = true;
            ui.close_menu();
        }
    });
}

fn export_script(state: &mut AppState, kind: &str) {
    let Some(db) = state.db.as_ref() else {
        return;
    };
    let (text, ext) = match kind {
        "ida" => (ceasta_db::export_ida(db), "py"),
        "ghidra" => (ceasta_db::export_ghidra(db), "java"),
        _ => (ceasta_db::export_x64dbg(db), "dd64"),
    };
    if let Some(path) = rfd::FileDialog::new()
        .add_filter("Export", &[ext])
        .set_file_name(format!("{}_export.{ext}", db.bin.name))
        .save_file()
    {
        match std::fs::write(&path, text) {
            Ok(()) => state.log_info(format!("exported {kind} → {}", path.display())),
            Err(e) => state.log_error(format!("export: {e}")),
        }
    }
}

fn edit_menu(ui: &mut egui::Ui, state: &mut AppState) {
    ui.menu_button("Edit", |ui| {
        let has = state.db.is_some();
        if ui
            .add_enabled(has, Button::new("Rename…").shortcut_text("N"))
            .clicked()
        {
            state.open_dialog(DialogKind::Rename);
            ui.close_menu();
        }
        if ui
            .add_enabled(has, Button::new("Comment…").shortcut_text(";"))
            .clicked()
        {
            state.open_dialog(DialogKind::Comment);
            ui.close_menu();
        }
        ui.separator();
        if ui
            .add_enabled(
                has,
                Button::new("Search…").shortcut_text(theme::keys("Ctrl+F")),
            )
            .clicked()
        {
            state.open_dialog(DialogKind::Find);
            ui.close_menu();
        }
        if ui
            .add_enabled(has, Button::new("Copy address"))
            .clicked()
        {
            if let Some(db) = state.db.as_ref() {
                state.clipboard = db.fmt_addr(state.selected_addr);
                ui.ctx().copy_text(state.clipboard.clone());
                state.log_info(format!("copied {}", state.clipboard));
            }
            ui.close_menu();
        }
        ui.separator();
        if ui
            .add(
                Button::new("Preferences…")
                    .shortcut_text(theme::keys("Ctrl+,")),
            )
            .clicked()
        {
            state.open_dialog(DialogKind::Preferences);
            ui.close_menu();
        }
    });
}

fn jump_menu(ui: &mut egui::Ui, state: &mut AppState) {
    ui.menu_button("Jump", |ui| {
        let has = state.db.is_some();
        if ui
            .add_enabled(has, Button::new("Jump to address or name…").shortcut_text("G"))
            .clicked()
        {
            state.open_dialog(DialogKind::GoTo);
            ui.close_menu();
        }
        if ui
            .add_enabled(has, Button::new("Follow operand").shortcut_text("Enter"))
            .clicked()
        {
            state.follow_operand();
            ui.close_menu();
        }
        if ui
            .add_enabled(
                !state.nav_back_stack.is_empty(),
                Button::new("Back").shortcut_text("Esc"),
            )
            .clicked()
        {
            state.nav_back();
            ui.close_menu();
        }
        if ui
            .add_enabled(
                !state.nav_fwd_stack.is_empty(),
                Button::new("Forward"),
            )
            .clicked()
        {
            state.nav_forward();
            ui.close_menu();
        }
        ui.separator();
        let can_entry = state
            .db
            .as_ref()
            .map(|d| d.bin.has_entry)
            .unwrap_or(false);
        if ui
            .add_enabled(can_entry, Button::new("Entry point"))
            .clicked()
        {
            if let Some(db) = state.db.as_ref() {
                let e = db.bin.entry;
                state.jump(e);
            }
            ui.close_menu();
        }
        if ui
            .add_enabled(has, Button::new("References to here…").shortcut_text("X"))
            .clicked()
        {
            state.open_dialog(DialogKind::Xrefs);
            ui.close_menu();
        }
    });
}

fn view_menu(ui: &mut egui::Ui, state: &mut AppState) {
    ui.menu_button("View", |ui| {
        if ui
            .selectable_label(state.center_tab == CenterTab::Listing, "Disassembly listing")
            .clicked()
        {
            state.center_tab = CenterTab::Listing;
            ui.close_menu();
        }
        if ui
            .selectable_label(state.center_tab == CenterTab::Graph, "Function graph")
            .clicked()
        {
            state.center_tab = CenterTab::Graph;
            ui.close_menu();
        }
        if ui
            .selectable_label(state.center_tab == CenterTab::Pseudo, "Pseudocode")
            .on_hover_text("F5")
            .clicked()
        {
            state.center_tab = CenterTab::Pseudo;
            ui.close_menu();
        }
        if ui
            .selectable_label(state.center_tab == CenterTab::Split, "Listing and pseudocode")
            .clicked()
        {
            state.center_tab = CenterTab::Split;
            ui.close_menu();
        }
        ui.separator();
        ui.checkbox(&mut state.show_left, "Functions panel");
        ui.checkbox(&mut state.show_right, "Info and CPU panels");
        ui.checkbox(&mut state.show_bottom, "Output panel");
        ui.checkbox(&mut state.show_bytes, "Opcode bytes");
        ui.checkbox(&mut state.show_cpu, "CPU / registers");
        ui.separator();
        ui.menu_button("Left panel tab", |ui| {
            for t in LeftTab::all() {
                if ui
                    .selectable_label(state.left_tab == *t, t.as_str())
                    .clicked()
                {
                    state.left_tab = *t;
                    ui.close_menu();
                }
            }
        });
        ui.menu_button("Right panel tab", |ui| {
            for t in [
                RightTab::Xrefs,
                RightTab::Hex,
                RightTab::Info,
                RightTab::Cpu,
                RightTab::Breakpoints,
            ] {
                if ui
                    .selectable_label(state.right_tab == t, t.as_str())
                    .clicked()
                {
                    state.right_tab = t;
                    ui.close_menu();
                }
            }
        });
        ui.separator();
        ui.menu_button("Theme", |ui| {
            for t in [UiTheme::Dark, UiTheme::Light, UiTheme::Contrast] {
                if ui
                    .selectable_label(state.theme == t, t.as_str())
                    .clicked()
                {
                    state.theme = t;
                    state.theme_dirty = true;
                    ui.close_menu();
                }
            }
        });
        if ui
            .add(Button::new("Bigger text").shortcut_text(theme::keys("Ctrl+=")))
            .clicked()
        {
            state.fonts.bump(1.0);
            state.theme_dirty = true;
            ui.close_menu();
        }
        if ui
            .add(Button::new("Smaller text").shortcut_text(theme::keys("Ctrl+-")))
            .clicked()
        {
            state.fonts.bump(-1.0);
            state.theme_dirty = true;
            ui.close_menu();
        }
        if ui
            .add(Button::new("Reset text size").shortcut_text(theme::keys("Ctrl+0")))
            .clicked()
        {
            state.fonts = crate::theme::FontSizes::default();
            state.theme_dirty = true;
            ui.close_menu();
        }
    });
}

fn debug_menu(ui: &mut egui::Ui, state: &mut AppState) {
    ui.menu_button("Debug", |ui| {
        let st = state.dbg.state();
        let has = state.db.is_some();
        let run_label = if st == DbgState::Stopped {
            "Continue"
        } else {
            "Start debugging"
        };
        if ui
            .add_enabled(
                (st == DbgState::None && has) || st == DbgState::Stopped,
                Button::new(run_label).shortcut_text("F9"),
            )
            .clicked()
        {
            state.dbg_continue();
            ui.close_menu();
        }
        if ui
            .add_enabled(
                st == DbgState::Stopped,
                Button::new("Step into").shortcut_text("F7"),
            )
            .clicked()
        {
            state.dbg_step_into();
            ui.close_menu();
        }
        if ui
            .add_enabled(
                st == DbgState::Stopped,
                Button::new("Step over").shortcut_text("F8"),
            )
            .clicked()
        {
            state.dbg_step_over();
            ui.close_menu();
        }
        if ui
            .add_enabled(
                st == DbgState::Stopped,
                Button::new("Run to cursor").shortcut_text("F4"),
            )
            .clicked()
        {
            state.dbg_run_to_cursor();
            ui.close_menu();
        }
        if ui
            .add_enabled(st == DbgState::Running, Button::new("Pause").shortcut_text("F12"))
            .clicked()
        {
            state.dbg_pause();
            ui.close_menu();
        }
        if ui
            .add_enabled(
                st != DbgState::None,
                Button::new("Stop (kill process)").shortcut_text(theme::keys("Ctrl+F2")),
            )
            .clicked()
        {
            state.dbg_stop();
            ui.close_menu();
        }
        if ui
            .add_enabled(st != DbgState::None, Button::new("Detach"))
            .clicked()
        {
            state.dbg_detach();
            ui.close_menu();
        }
        ui.separator();
        if ui
            .add_enabled(has, Button::new("Toggle breakpoint").shortcut_text("F2"))
            .clicked()
        {
            state.toggle_breakpoint(state.selected_addr);
            ui.close_menu();
        }
        if ui
            .add_enabled(st == DbgState::None, Button::new("Attach to process…"))
            .clicked()
        {
            state.open_dialog(DialogKind::Attach);
            ui.close_menu();
        }
        if ui
            .add_enabled(st == DbgState::None, Button::new("Program arguments…"))
            .clicked()
        {
            state.open_dialog(DialogKind::RunArgs);
            ui.close_menu();
        }
        ui.checkbox(&mut state.break_on_entry, "Break at the entry point");
        ui.checkbox(&mut state.break_on_tls, "Break on TLS callbacks");
        ui.checkbox(&mut state.protect_host, "Protect this machine");
        ui.checkbox(&mut state.watch_host, "Watch host health");
        state.sync_dbg_options();
    });
}

fn plugins_menu(ui: &mut egui::Ui, state: &mut AppState) {
    ui.menu_button("Plugins", |ui| {
        if ui.button("Load Lua plugin…").clicked() {
            if let Some(path) = rfd::FileDialog::new()
                .add_filter("Lua", &["lua"])
                .pick_file()
            {
                state.log_info(format!(
                    "plugin selected: {} (run via ceasta-cli / script host)",
                    path.display()
                ));
            }
            ui.close_menu();
        }
        if ui.button("Open plugins folder…").clicked() {
            let dir = std::path::PathBuf::from("plugins");
            if dir.exists() {
                state.log_info(format!("plugins dir: {}", dir.display()));
            } else {
                state.log_warn("no ./plugins directory");
            }
            ui.close_menu();
        }
        ui.separator();
        if ui
            .add(Button::new("Command palette…").shortcut_text(theme::keys("Ctrl+Shift+P")))
            .clicked()
        {
            state.open_dialog(DialogKind::Palette);
            ui.close_menu();
        }
        if ui.button("Focus Lua console").clicked() {
            state.show_bottom = true;
            state.focus_console = true;
            ui.close_menu();
        }
    });
}

fn help_menu(ui: &mut egui::Ui, state: &mut AppState) {
    ui.menu_button("Help", |ui| {
        if ui
            .add(Button::new("About ceasta").shortcut_text("F1"))
            .clicked()
        {
            state.open_dialog(DialogKind::About);
            ui.close_menu();
        }
        if ui.button("Keyboard shortcuts…").clicked() {
            state.open_dialog(DialogKind::Shortcuts);
            ui.close_menu();
        }
        ui.separator();
        if ui.button("Open README").clicked() {
            state.log_info("see README.md in the repository root");
            ui.close_menu();
        }
    });
}
