//! Keyboard shortcuts — IDA-ish bindings used across panels.

use crate::{AppState, CenterTab, DialogKind};
use egui::{Key, Modifiers};

/// One named binding (for the Help → Shortcuts dialog).
#[derive(Clone, Copy, Debug)]
pub struct Binding {
    pub action: &'static str,
    pub keys: &'static str,
    pub group: &'static str,
}

/// All documented bindings.
pub const BINDINGS: &[Binding] = &[
    Binding {
        action: "Open file",
        keys: "Ctrl+O",
        group: "File",
    },
    Binding {
        action: "Save project",
        keys: "Ctrl+S",
        group: "File",
    },
    Binding {
        action: "Quit",
        keys: "Alt+F4 / Ctrl+Q",
        group: "File",
    },
    Binding {
        action: "Rename",
        keys: "N",
        group: "Edit",
    },
    Binding {
        action: "Comment",
        keys: ";",
        group: "Edit",
    },
    Binding {
        action: "Search",
        keys: "Ctrl+F",
        group: "Edit",
    },
    Binding {
        action: "Copy address",
        keys: "Ctrl+C",
        group: "Edit",
    },
    Binding {
        action: "Go to address",
        keys: "G",
        group: "Jump",
    },
    Binding {
        action: "Follow / Enter",
        keys: "Enter",
        group: "Jump",
    },
    Binding {
        action: "Back",
        keys: "Esc",
        group: "Jump",
    },
    Binding {
        action: "Xrefs to here",
        keys: "X",
        group: "Jump",
    },
    Binding {
        action: "Listing view",
        keys: "1",
        group: "View",
    },
    Binding {
        action: "Graph view",
        keys: "2",
        group: "View",
    },
    Binding {
        action: "Pseudocode",
        keys: "F5",
        group: "View",
    },
    Binding {
        action: "Toggle bytes",
        keys: "Ctrl+B",
        group: "View",
    },
    Binding {
        action: "Bigger text",
        keys: "Ctrl+=",
        group: "View",
    },
    Binding {
        action: "Smaller text",
        keys: "Ctrl+-",
        group: "View",
    },
    Binding {
        action: "Continue / Start",
        keys: "F9",
        group: "Debug",
    },
    Binding {
        action: "Step into",
        keys: "F7",
        group: "Debug",
    },
    Binding {
        action: "Step over",
        keys: "F8",
        group: "Debug",
    },
    Binding {
        action: "Run to cursor",
        keys: "F4",
        group: "Debug",
    },
    Binding {
        action: "Pause",
        keys: "F12",
        group: "Debug",
    },
    Binding {
        action: "Stop",
        keys: "Ctrl+F2",
        group: "Debug",
    },
    Binding {
        action: "Toggle breakpoint",
        keys: "F2",
        group: "Debug",
    },
    Binding {
        action: "Focus Lua console",
        keys: "Ctrl+`",
        group: "Misc",
    },
    Binding {
        action: "Command palette",
        keys: "Ctrl+Shift+P",
        group: "Misc",
    },
    Binding {
        action: "Preferences",
        keys: "Ctrl+,",
        group: "Misc",
    },
    Binding {
        action: "About",
        keys: "F1",
        group: "Help",
    },
];

/// Handle global shortcuts. Returns true if something was consumed.
pub fn handle(ctx: &egui::Context, state: &mut AppState) -> bool {
    let mut consumed = false;
    let _viewport_focused = ctx.input(|i| i.focused);
    let wants_text = ctx.wants_keyboard_input();

    // Ctrl chords always work.
    if chord(ctx, Modifiers::CTRL, Key::O) {
        state.request_open_file = true;
        consumed = true;
    }
    if chord(ctx, Modifiers::CTRL, Key::S) {
        state.save_project();
        consumed = true;
    }
    if chord(ctx, Modifiers::CTRL, Key::Q) || chord(ctx, Modifiers::ALT, Key::F4) {
        state.request_quit = true;
        consumed = true;
    }
    if chord(ctx, Modifiers::CTRL, Key::F) {
        state.open_dialog(DialogKind::Find);
        consumed = true;
    }
    if chord(ctx, Modifiers::CTRL | Modifiers::SHIFT, Key::P) {
        state.open_dialog(DialogKind::Palette);
        consumed = true;
    }
    if chord(ctx, Modifiers::CTRL, Key::Comma) {
        state.open_dialog(DialogKind::Preferences);
        consumed = true;
    }
    if chord(ctx, Modifiers::CTRL, Key::B) {
        state.show_bytes = !state.show_bytes;
        consumed = true;
    }
    if chord(ctx, Modifiers::CTRL, Key::Equals) || chord(ctx, Modifiers::CTRL, Key::Plus) {
        state.fonts.bump(1.0);
        state.theme_dirty = true;
        consumed = true;
    }
    if chord(ctx, Modifiers::CTRL, Key::Minus) {
        state.fonts.bump(-1.0);
        state.theme_dirty = true;
        consumed = true;
    }
    if chord(ctx, Modifiers::CTRL, Key::Num0) {
        state.fonts = crate::theme::FontSizes::default();
        state.theme_dirty = true;
        consumed = true;
    }
    if chord(ctx, Modifiers::CTRL, Key::Backtick) {
        state.focus_console = true;
        state.show_bottom = true;
        consumed = true;
    }
    if chord(ctx, Modifiers::CTRL, Key::C) && !wants_text {
        if let Some(db) = state.db.as_ref() {
            state.clipboard = db.fmt_addr(state.selected_addr);
            state.log_info(format!("copied {}", state.clipboard));
        }
        consumed = true;
    }
    if chord(ctx, Modifiers::CTRL, Key::F2) {
        state.dbg_stop();
        consumed = true;
    }

    // Function keys.
    if key(ctx, Key::F1) {
        state.open_dialog(DialogKind::About);
        consumed = true;
    }
    if key(ctx, Key::F2) && !wants_text {
        state.toggle_breakpoint(state.selected_addr);
        consumed = true;
    }
    if key(ctx, Key::F4) && !wants_text {
        state.dbg_run_to_cursor();
        consumed = true;
    }
    if key(ctx, Key::F5) && !wants_text {
        state.center_tab = CenterTab::Pseudo;
        consumed = true;
    }
    if key(ctx, Key::F7) && !wants_text {
        state.dbg_step_into();
        consumed = true;
    }
    if key(ctx, Key::F8) && !wants_text {
        state.dbg_step_over();
        consumed = true;
    }
    if key(ctx, Key::F9) && !wants_text {
        state.dbg_continue();
        consumed = true;
    }
    if key(ctx, Key::F12) && !wants_text {
        state.dbg_pause();
        consumed = true;
    }

    if wants_text {
        return consumed;
    }

    // Single-letter IDA keys.
    if key(ctx, Key::N) {
        state.open_dialog(DialogKind::Rename);
        consumed = true;
    }
    if key(ctx, Key::G) {
        state.open_dialog(DialogKind::GoTo);
        consumed = true;
    }
    if key(ctx, Key::X) {
        state.open_dialog(DialogKind::Xrefs);
        consumed = true;
    }
    if key(ctx, Key::Num1) {
        state.center_tab = CenterTab::Listing;
        consumed = true;
    }
    if key(ctx, Key::Num2) {
        state.center_tab = CenterTab::Graph;
        consumed = true;
    }
    if key(ctx, Key::Space) {
        state.center_tab = match state.center_tab {
            CenterTab::Listing => CenterTab::Graph,
            CenterTab::Graph => CenterTab::Pseudo,
            CenterTab::Pseudo => CenterTab::Listing,
            CenterTab::Split => CenterTab::Listing,
        };
        consumed = true;
    }
    if key(ctx, Key::Enter) {
        state.follow_operand();
        consumed = true;
    }
    if key(ctx, Key::Escape) {
        if state.dialog.is_some() {
            state.dialog = None;
        } else {
            state.nav_back();
        }
        consumed = true;
    }
    // Semicolon for comment — egui exposes it as Key::Semicolon on some backends.
    if key(ctx, Key::Semicolon) {
        state.open_dialog(DialogKind::Comment);
        consumed = true;
    }

    consumed
}

fn chord(ctx: &egui::Context, mods: Modifiers, key: Key) -> bool {
    ctx.input(|i| i.modifiers.matches_exact(mods) && i.key_pressed(key))
}

fn key(ctx: &egui::Context, key: Key) -> bool {
    ctx.input(|i| i.modifiers.is_none() && i.key_pressed(key))
}

/// Render the shortcuts reference table inside a dialog body.
pub fn draw_reference(ui: &mut egui::Ui) {
    egui::ScrollArea::vertical().max_height(360.0).show(ui, |ui| {
        let mut last_group = "";
        for b in BINDINGS {
            if b.group != last_group {
                ui.add_space(6.0);
                ui.strong(b.group);
                last_group = b.group;
            }
            ui.horizontal(|ui| {
                ui.monospace(b.keys);
                ui.label(b.action);
            });
        }
    });
}

/// Parse a key chord string for display in menus.
pub fn menu_shortcut(label: &str) -> egui::KeyboardShortcut {
    // Best-effort mapping for egui menu hints.
    let lower = label.to_ascii_lowercase();
    let mut mods = Modifiers::NONE;
    if lower.contains("ctrl") || lower.contains("cmd") {
        mods.ctrl = true;
        mods.command = true;
    }
    if lower.contains("shift") {
        mods.shift = true;
    }
    if lower.contains("alt") {
        mods.alt = true;
    }
    let key = if lower.contains("f1") {
        Key::F1
    } else if lower.contains("f2") {
        Key::F2
    } else if lower.contains("f4") {
        Key::F4
    } else if lower.contains("f5") {
        Key::F5
    } else if lower.contains("f7") {
        Key::F7
    } else if lower.contains("f8") {
        Key::F8
    } else if lower.contains("f9") {
        Key::F9
    } else if lower.contains("f12") {
        Key::F12
    } else if lower.contains('+') {
        // last token
        let last = label.rsplit(['+', ' ']).next().unwrap_or("");
        match last.to_ascii_uppercase().as_str() {
            "O" => Key::O,
            "S" => Key::S,
            "Q" => Key::Q,
            "F" => Key::F,
            "B" => Key::B,
            "C" => Key::C,
            "P" => Key::P,
            "N" => Key::N,
            "G" => Key::G,
            "X" => Key::X,
            "ENTER" => Key::Enter,
            "ESC" | "ESCAPE" => Key::Escape,
            _ => Key::N,
        }
    } else {
        match label.to_ascii_uppercase().as_str() {
            "N" => Key::N,
            "G" => Key::G,
            "X" => Key::X,
            ";" => Key::Semicolon,
            "ENTER" => Key::Enter,
            "ESC" => Key::Escape,
            "SPACE" => Key::Space,
            _ => Key::N,
        }
    };
    egui::KeyboardShortcut::new(mods, key)
}
