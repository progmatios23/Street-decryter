//! Modal dialogs — about, go-to, rename, comment, preferences, xrefs, palette, …

use crate::shortcuts;
use crate::{AppState, DialogKind, UiTheme};
use egui::{Context, Key, RichText, Window};

pub fn draw(ctx: &Context, state: &mut AppState) {
    let Some(kind) = state.dialog else {
        return;
    };

    let mut open = true;
    let title = match kind {
        DialogKind::About => "About ceasta",
        DialogKind::GoTo => "Jump to address or name",
        DialogKind::Rename => "Rename",
        DialogKind::Comment => "Comment",
        DialogKind::Find => "Search",
        DialogKind::Preferences => "Preferences",
        DialogKind::Xrefs => "Cross-references",
        DialogKind::Palette => "Command palette",
        DialogKind::Shortcuts => "Keyboard shortcuts",
        DialogKind::OpenRaw => "Open as raw code",
        DialogKind::Attach => "Attach to process",
        DialogKind::RunArgs => "Program arguments",
    };

    let mut close = false;
    let mut apply = false;

    Window::new(title)
        .open(&mut open)
        .collapsible(false)
        .resizable(true)
        .default_width(match kind {
            DialogKind::About | DialogKind::Shortcuts | DialogKind::Palette => 480.0,
            DialogKind::Xrefs | DialogKind::Find => 520.0,
            DialogKind::Preferences => 400.0,
            _ => 360.0,
        })
        .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
        .show(ctx, |ui| {
            match kind {
                DialogKind::About => draw_about(ui, state),
                DialogKind::GoTo => draw_goto(ui, state, &mut apply, &mut close),
                DialogKind::Rename => draw_rename(ui, state, &mut apply, &mut close),
                DialogKind::Comment => draw_comment(ui, state, &mut apply, &mut close),
                DialogKind::Find => draw_find(ui, state, &mut apply, &mut close),
                DialogKind::Preferences => draw_preferences(ui, state, &mut apply, &mut close),
                DialogKind::Xrefs => draw_xrefs(ui, state, &mut close),
                DialogKind::Palette => draw_palette(ui, state, &mut close),
                DialogKind::Shortcuts => {
                    shortcuts::draw_reference(ui);
                    if ui.button("Close").clicked() {
                        close = true;
                    }
                }
                DialogKind::OpenRaw => draw_open_raw(ui, state, &mut apply, &mut close),
                DialogKind::Attach => draw_attach(ui, state, &mut apply, &mut close),
                DialogKind::RunArgs => draw_run_args(ui, state, &mut apply, &mut close),
            }

            // Esc closes
            if ui.input(|i| i.key_pressed(Key::Escape)) {
                close = true;
            }
        });

    if !open || close {
        state.dialog = None;
    }
}

fn draw_about(ui: &mut egui::Ui, state: &AppState) {
    ui.label(
        RichText::new("ceasta")
            .size(22.0)
            .color(state.colors.func),
    );
    ui.label(format!("version {}", env!("CARGO_PKG_VERSION")));
    ui.add_space(8.0);
    ui.label("Disassembler, decompiler and debugger for Windows and Linux binaries.");
    ui.label("Rust-native UI (egui/eframe) — layout mirrors the classic IDA-style shell.");
    ui.add_space(8.0);
    ui.label(
        RichText::new(format!(
            "protect_host={}  break_on_tls={}  watch_host={}",
            state.protect_host, state.break_on_tls, state.watch_host
        ))
        .monospace()
        .small(),
    );
    ui.separator();
    ui.label("License: MIT");
    ui.hyperlink_to(
        "github.com/progmatios23/ceasta-custom",
        "https://github.com/progmatios23/ceasta-custom",
    );
}

fn draw_goto(ui: &mut egui::Ui, state: &mut AppState, apply: &mut bool, close: &mut bool) {
    ui.label("Address or name (e.g. 401000, entry, sub_401000):");
    let resp = ui.add(
        egui::TextEdit::singleline(&mut state.dialog_buf)
            .desired_width(f32::INFINITY)
            .font(egui::TextStyle::Monospace),
    );
    resp.request_focus();
    let enter = resp.lost_focus() && ui.input(|i| i.key_pressed(Key::Enter));
    ui.horizontal(|ui| {
        if ui.button("Jump").clicked() || enter {
            *apply = true;
        }
        if ui.button("Cancel").clicked() {
            *close = true;
        }
    });
    if *apply {
        let buf = state.dialog_buf.clone();
        if let Some(db) = state.db.as_ref() {
            if let Some(a) = db.resolve(&buf) {
                state.jump(a);
                *close = true;
            } else {
                state.log_error(format!("cannot resolve: {buf}"));
            }
        }
        *apply = false;
    }
}

fn draw_rename(ui: &mut egui::Ui, state: &mut AppState, apply: &mut bool, close: &mut bool) {
    ui.label(format!(
        "Rename @ {}",
        crate::theme::hex_compact(state.dialog_addr)
    ));
    let resp = ui.add(
        egui::TextEdit::singleline(&mut state.dialog_buf)
            .desired_width(f32::INFINITY)
            .hint_text("new name"),
    );
    resp.request_focus();
    let enter = resp.lost_focus() && ui.input(|i| i.key_pressed(Key::Enter));
    ui.horizontal(|ui| {
        if ui.button("OK").clicked() || enter {
            *apply = true;
        }
        if ui.button("Cancel").clicked() {
            *close = true;
        }
    });
    if *apply {
        let name = state.dialog_buf.clone();
        let addr = state.dialog_addr;
        state.set_name(addr, name);
        *close = true;
        *apply = false;
    }
}

fn draw_comment(ui: &mut egui::Ui, state: &mut AppState, apply: &mut bool, close: &mut bool) {
    ui.label(format!(
        "Comment @ {}",
        crate::theme::hex_compact(state.dialog_addr)
    ));
    ui.add(
        egui::TextEdit::multiline(&mut state.dialog_buf)
            .desired_width(f32::INFINITY)
            .desired_rows(4),
    );
    ui.horizontal(|ui| {
        if ui.button("OK").clicked() {
            *apply = true;
        }
        if ui.button("Cancel").clicked() {
            *close = true;
        }
    });
    if *apply {
        let text = state.dialog_buf.clone();
        let addr = state.dialog_addr;
        state.set_comment(addr, text);
        *close = true;
        *apply = false;
    }
}

fn draw_find(ui: &mut egui::Ui, state: &mut AppState, apply: &mut bool, close: &mut bool) {
    ui.label("Search names, imports, exports, strings, comments, segments:");
    let resp = ui.add(
        egui::TextEdit::singleline(&mut state.dialog_buf)
            .desired_width(f32::INFINITY)
            .hint_text("query"),
    );
    resp.request_focus();

    let query = state.dialog_buf.clone();
    let mut jump: Option<u64> = None;

    if !query.is_empty() {
        if let Some(db) = state.db.as_ref() {
            let (hits, cut) = ceasta_db::search_everything(db, &query, 40);
            ui.label(
                RichText::new(format!(
                    "{} hits{}",
                    hits.len(),
                    if cut { " (truncated)" } else { "" }
                ))
                .small()
                .color(state.colors.muted),
            );
            egui::ScrollArea::vertical().max_height(280.0).show(ui, |ui| {
                for h in &hits {
                    ui.horizontal(|ui| {
                        if ui
                            .selectable_label(
                                false,
                                RichText::new(crate::theme::hex_compact(h.addr))
                                    .monospace()
                                    .color(state.colors.addr),
                            )
                            .clicked()
                        {
                            jump = Some(h.addr);
                        }
                        ui.label(
                            RichText::new(h.kind.as_str())
                                .small()
                                .color(state.colors.muted),
                        );
                        ui.label(&h.text);
                        if !h.extra.is_empty() {
                            ui.label(RichText::new(&h.extra).small().color(state.colors.muted));
                        }
                    });
                }
            });
        }
    }

    ui.horizontal(|ui| {
        if ui.button("Close").clicked() {
            *close = true;
        }
    });
    let _ = apply;
    if let Some(a) = jump {
        state.jump(a);
        *close = true;
    }
}

fn draw_preferences(ui: &mut egui::Ui, state: &mut AppState, apply: &mut bool, close: &mut bool) {
    ui.heading("Debugger / host protect");
    ui.checkbox(
        &mut state.protect_host,
        "Protect this machine (block attach to self / host processes)",
    );
    ui.checkbox(
        &mut state.break_on_tls,
        "Break on TLS callbacks when debugging",
    );
    ui.checkbox(
        &mut state.watch_host,
        "Watch host health while a debuggee is running",
    );
    ui.checkbox(&mut state.break_on_entry, "Break at the entry point");
    ui.separator();
    ui.heading("Display");
    ui.horizontal(|ui| {
        ui.label("Theme");
        for t in [UiTheme::Dark, UiTheme::Light, UiTheme::Contrast] {
            if ui
                .selectable_label(state.theme == t, t.as_str())
                .clicked()
            {
                state.theme = t;
                state.theme_dirty = true;
            }
        }
    });
    ui.horizontal(|ui| {
        ui.label("UI font");
        if ui
            .add(egui::DragValue::new(&mut state.fonts.ui).range(10.0..=28.0))
            .changed()
        {
            state.theme_dirty = true;
        }
        ui.label("Mono");
        if ui
            .add(egui::DragValue::new(&mut state.fonts.mono).range(10.0..=28.0))
            .changed()
        {
            state.theme_dirty = true;
        }
    });
    ui.checkbox(&mut state.show_bytes, "Show opcode bytes in listing");
    ui.checkbox(&mut state.show_left, "Show left panel");
    ui.checkbox(&mut state.show_right, "Show right panel");
    ui.checkbox(&mut state.show_bottom, "Show output panel");
    ui.checkbox(&mut state.show_cpu, "Show CPU panel");
    ui.separator();
    ui.horizontal(|ui| {
        if ui.button("Apply").clicked() {
            *apply = true;
        }
        if ui.button("Close").clicked() {
            *close = true;
        }
    });
    if *apply {
        state.sync_dbg_options();
        state.theme_dirty = true;
        state.log_info(format!(
            "prefs: protect_host={} break_on_tls={} watch_host={}",
            state.protect_host, state.break_on_tls, state.watch_host
        ));
        *apply = false;
        *close = true;
    }
}

fn draw_xrefs(ui: &mut egui::Ui, state: &mut AppState, close: &mut bool) {
    let addr = state.dialog_addr;
    let (to, from, loc) = {
        let Some(db) = state.db.as_ref() else {
            ui.weak("no file");
            return;
        };
        (
            db.analysis.refs_to(addr).to_vec(),
            db.analysis.refs_from(addr).to_vec(),
            db.location(addr),
        )
    };
    ui.label(format!("References for {loc} @ {:X}", addr));
    let mut jump = None;
    ui.columns(2, |cols| {
        cols[0].strong(format!("To ({})", to.len()));
        egui::ScrollArea::vertical()
            .id_salt("dlg_xref_to")
            .max_height(240.0)
            .show(&mut cols[0], |ui| {
                for x in &to {
                    if ui
                        .selectable_label(false, format!("{:X}  {}", x.from, x.kind.as_str()))
                        .clicked()
                    {
                        jump = Some(x.from);
                    }
                }
            });
        cols[1].strong(format!("From ({})", from.len()));
        egui::ScrollArea::vertical()
            .id_salt("dlg_xref_from")
            .max_height(240.0)
            .show(&mut cols[1], |ui| {
                for x in &from {
                    if ui
                        .selectable_label(false, format!("{:X}  {}", x.to, x.kind.as_str()))
                        .clicked()
                    {
                        jump = Some(x.to);
                    }
                }
            });
    });
    if ui.button("Close").clicked() {
        *close = true;
    }
    if let Some(a) = jump {
        state.jump(a);
        *close = true;
    }
}

fn draw_palette(ui: &mut egui::Ui, state: &mut AppState, close: &mut bool) {
    ui.label("Type to filter actions:");
    ui.add(
        egui::TextEdit::singleline(&mut state.dialog_buf)
            .desired_width(f32::INFINITY)
            .hint_text("open, jump, theme, debug…"),
    );
    let q = state.dialog_buf.to_ascii_lowercase();

    #[derive(Clone, Copy)]
    struct Action {
        name: &'static str,
        keys: &'static str,
        id: u16,
    }
    const ACTIONS: &[Action] = &[
        Action {
            name: "Open file",
            keys: "Ctrl+O",
            id: 1,
        },
        Action {
            name: "Save project",
            keys: "Ctrl+S",
            id: 2,
        },
        Action {
            name: "Go to address",
            keys: "G",
            id: 3,
        },
        Action {
            name: "Rename",
            keys: "N",
            id: 4,
        },
        Action {
            name: "Comment",
            keys: ";",
            id: 5,
        },
        Action {
            name: "Toggle breakpoint",
            keys: "F2",
            id: 6,
        },
        Action {
            name: "Start / continue debugging",
            keys: "F9",
            id: 7,
        },
        Action {
            name: "Step into",
            keys: "F7",
            id: 8,
        },
        Action {
            name: "Step over",
            keys: "F8",
            id: 9,
        },
        Action {
            name: "Show listing",
            keys: "1",
            id: 10,
        },
        Action {
            name: "Show graph",
            keys: "2",
            id: 11,
        },
        Action {
            name: "Show pseudocode",
            keys: "F5",
            id: 12,
        },
        Action {
            name: "Preferences",
            keys: "Ctrl+,",
            id: 13,
        },
        Action {
            name: "Cycle theme",
            keys: "",
            id: 14,
        },
        Action {
            name: "About",
            keys: "F1",
            id: 15,
        },
        Action {
            name: "Focus console",
            keys: "Ctrl+`",
            id: 16,
        },
        Action {
            name: "Entry point",
            keys: "",
            id: 17,
        },
        Action {
            name: "Xrefs to selection",
            keys: "X",
            id: 18,
        },
        Action {
            name: "Close file",
            keys: "",
            id: 19,
        },
        Action {
            name: "Quit",
            keys: "Alt+F4",
            id: 20,
        },
    ];

    let mut run_id: Option<u16> = None;
    egui::ScrollArea::vertical().max_height(300.0).show(ui, |ui| {
        for a in ACTIONS {
            if !q.is_empty() && !a.name.to_ascii_lowercase().contains(&q) {
                continue;
            }
            ui.horizontal(|ui| {
                if ui.selectable_label(false, a.name).clicked() {
                    run_id = Some(a.id);
                }
                if !a.keys.is_empty() {
                    ui.label(RichText::new(a.keys).small().monospace().color(state.colors.muted));
                }
            });
        }
    });

    if let Some(id) = run_id {
        match id {
            1 => state.request_open_file = true,
            2 => state.save_project(),
            3 => {
                state.dialog = None;
                state.open_dialog(DialogKind::GoTo);
                return;
            }
            4 => {
                state.dialog = None;
                state.open_dialog(DialogKind::Rename);
                return;
            }
            5 => {
                state.dialog = None;
                state.open_dialog(DialogKind::Comment);
                return;
            }
            6 => state.toggle_breakpoint(state.selected_addr),
            7 => state.dbg_continue(),
            8 => state.dbg_step_into(),
            9 => state.dbg_step_over(),
            10 => state.center_tab = crate::CenterTab::Listing,
            11 => state.center_tab = crate::CenterTab::Graph,
            12 => state.center_tab = crate::CenterTab::Pseudo,
            13 => {
                state.dialog = None;
                state.open_dialog(DialogKind::Preferences);
                return;
            }
            14 => {
                state.theme = state.theme.next();
                state.theme_dirty = true;
            }
            15 => {
                state.dialog = None;
                state.open_dialog(DialogKind::About);
                return;
            }
            16 => {
                state.show_bottom = true;
                state.focus_console = true;
            }
            17 => {
                if let Some(db) = state.db.as_ref() {
                    if db.bin.has_entry {
                        let e = db.bin.entry;
                        state.jump(e);
                    }
                }
            }
            18 => {
                state.dialog = None;
                state.open_dialog(DialogKind::Xrefs);
                return;
            }
            19 => state.close_file(),
            20 => state.request_quit = true,
            _ => {}
        }
        *close = true;
    }
    if ui.button("Close").clicked() {
        *close = true;
    }
}

fn draw_open_raw(ui: &mut egui::Ui, state: &mut AppState, apply: &mut bool, close: &mut bool) {
    ui.label("Open a file as raw shellcode / flat binary.");
    ui.label("Base address (hex):");
    ui.add(
        egui::TextEdit::singleline(&mut state.dialog_buf)
            .desired_width(160.0)
            .font(egui::TextStyle::Monospace),
    );
    ui.horizontal(|ui| {
        if ui.button("Choose file…").clicked() {
            *apply = true;
        }
        if ui.button("Cancel").clicked() {
            *close = true;
        }
    });
    if *apply {
        let base = u64::from_str_radix(
            state
                .dialog_buf
                .trim()
                .trim_start_matches("0x")
                .trim_start_matches("0X"),
            16,
        )
        .unwrap_or(0x1000);
        if let Some(path) = rfd::FileDialog::new().pick_file() {
            let opts = ceasta_binary::LoadOptions {
                force_raw: true,
                raw_base: base,
                ..Default::default()
            };
            match state.load_file_with(&path, &opts) {
                Ok(()) => {
                    state.log_info(format!("opened raw @ {base:X}"));
                    *close = true;
                }
                Err(e) => state.log_error(format!("{e:#}")),
            }
        }
        *apply = false;
    }
}

fn draw_attach(ui: &mut egui::Ui, state: &mut AppState, apply: &mut bool, close: &mut bool) {
    ui.label("Attach to a running process by PID.");
    ui.label(
        RichText::new("Host protection may refuse attach to this machine's own processes.")
            .small()
            .color(state.colors.warn_or_muted()),
    );
    ui.add(
        egui::TextEdit::singleline(&mut state.dialog_buf)
            .desired_width(120.0)
            .hint_text("pid")
            .font(egui::TextStyle::Monospace),
    );
    ui.horizontal(|ui| {
        if ui.button("Attach").clicked() {
            *apply = true;
        }
        if ui.button("Cancel").clicked() {
            *close = true;
        }
    });
    if *apply {
        state.sync_dbg_options();
        match state.dialog_buf.trim().parse::<u32>() {
            Ok(pid) => match state.dbg.attach(pid) {
                Ok(()) => {
                    state.log_info(format!("attached to {pid}"));
                    state.right_tab = crate::RightTab::Cpu;
                    *close = true;
                }
                Err(e) => state.log_error(format!("attach: {e}")),
            },
            Err(_) => state.log_error("invalid pid"),
        }
        *apply = false;
    }
}

fn draw_run_args(ui: &mut egui::Ui, state: &mut AppState, apply: &mut bool, close: &mut bool) {
    ui.label("Arguments passed when starting the debuggee:");
    ui.add(
        egui::TextEdit::singleline(&mut state.dialog_buf)
            .desired_width(f32::INFINITY)
            .hint_text("--flag value"),
    );
    ui.horizontal(|ui| {
        if ui.button("OK").clicked() {
            *apply = true;
        }
        if ui.button("Cancel").clicked() {
            *close = true;
        }
    });
    if *apply {
        state.run_args = state.dialog_buf.clone();
        state.log_info(format!("run args = {:?}", state.run_args));
        *close = true;
        *apply = false;
    }
}

trait WarnColor {
    fn warn_or_muted(&self) -> egui::Color32;
}

impl WarnColor for crate::ListingColors {
    fn warn_or_muted(&self) -> egui::Color32 {
        self.log_warn
    }
}
