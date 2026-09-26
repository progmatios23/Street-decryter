//! Right panel — xrefs, hex dump, info, breakpoints (CPU is a sibling strip).

use crate::{AppState, DialogKind, RightTab};
use ceasta_binary::{PERM_R, PERM_W, PERM_X};
use egui::{RichText, ScrollArea, Sense};

pub fn draw(ui: &mut egui::Ui, state: &mut AppState) {
    crate::theme::section_header(
        ui,
        &state.colors,
        "Inspector",
        state
            .db
            .as_ref()
            .map(|d| d.fmt_addr(state.selected_addr))
            .unwrap_or_else(|| "—".into())
            .as_str(),
    );

    ui.horizontal_wrapped(|ui| {
        for (tab, label) in [
            (RightTab::Xrefs, "Xrefs"),
            (RightTab::Hex, "Hex"),
            (RightTab::Info, "Info"),
            (RightTab::Breakpoints, "BPs"),
            (RightTab::Cpu, "CPU"),
        ] {
            if ui
                .selectable_label(state.right_tab == tab, label)
                .clicked()
            {
                state.right_tab = tab;
            }
        }
    });
    ui.add_space(2.0);

    match state.right_tab {
        RightTab::Xrefs => draw_xrefs(ui, state),
        RightTab::Hex => draw_hex(ui, state),
        RightTab::Info => draw_info(ui, state),
        RightTab::Breakpoints => draw_breakpoints(ui, state),
        RightTab::Cpu => {
            ui.weak("CPU registers are shown in the strip below (or enable Always show CPU).");
        }
    }
}

fn draw_xrefs(ui: &mut egui::Ui, state: &mut AppState) {
    let addr = state.selected_addr;
    let (to_rows, from_rows) = {
        let Some(db) = state.db.as_ref() else {
            ui.weak("(no file)");
            return;
        };
        let to: Vec<(u64, String, String)> = db
            .analysis
            .refs_to(addr)
            .iter()
            .map(|x| (x.from, x.kind.as_str().to_string(), db.location(x.from)))
            .collect();
        let from: Vec<(u64, String, String)> = db
            .analysis
            .refs_from(addr)
            .iter()
            .map(|x| (x.to, x.kind.as_str().to_string(), db.location(x.to)))
            .collect();
        (to, from)
    };

    ui.label(
        RichText::new(format!(
            "{} to · {} from @ {:X}",
            to_rows.len(),
            from_rows.len(),
            addr
        ))
        .small()
        .color(state.colors.muted),
    );

    let mut jump = None;
    ScrollArea::vertical()
        .id_salt("right_xrefs")
        .auto_shrink([false, false])
        .show(ui, |ui| {
            ui.strong("To here");
            for (a, kind, loc) in &to_rows {
                ui.horizontal(|ui| {
                    if ui
                        .selectable_label(
                            false,
                            RichText::new(format!("{a:X}"))
                                .monospace()
                                .color(state.colors.addr),
                        )
                        .clicked()
                    {
                        jump = Some(*a);
                    }
                    ui.label(RichText::new(kind).small().color(state.colors.jump));
                    ui.label(RichText::new(loc).small().color(state.colors.muted));
                });
            }
            if to_rows.is_empty() {
                ui.weak("(none)");
            }
            ui.separator();
            ui.strong("From here");
            for (a, kind, loc) in &from_rows {
                ui.horizontal(|ui| {
                    if ui
                        .selectable_label(
                            false,
                            RichText::new(format!("{a:X}"))
                                .monospace()
                                .color(state.colors.addr),
                        )
                        .clicked()
                    {
                        jump = Some(*a);
                    }
                    ui.label(RichText::new(kind).small().color(state.colors.call));
                    ui.label(RichText::new(loc).small().color(state.colors.muted));
                });
            }
            if from_rows.is_empty() {
                ui.weak("(none)");
            }
        });

    if ui.button("Open xrefs dialog…").clicked() {
        state.open_dialog(DialogKind::Xrefs);
    }
    if let Some(a) = jump {
        state.jump(a);
    }
}

fn draw_hex(ui: &mut egui::Ui, state: &mut AppState) {
    if state.db.is_none() {
        ui.weak("(no file)");
        return;
    }
    let is64 = state.db.as_ref().map(|d| d.bin.is64()).unwrap_or(true);
    let base = state.hex_addr & !0xF;
    ui.horizontal(|ui| {
        ui.label("Address");
        let mut buf = crate::theme::hex_addr(state.hex_addr, is64);
        if ui
            .add(
                egui::TextEdit::singleline(&mut buf)
                    .desired_width(140.0)
                    .font(egui::TextStyle::Monospace),
            )
            .changed()
        {
            if let Some(a) = state.db.as_ref().and_then(|d| d.resolve(&buf)) {
                state.hex_addr = a;
            }
        }
        if ui.button("←").clicked() {
            state.hex_addr = state.hex_addr.saturating_sub(0x40);
        }
        if ui.button("→").clicked() {
            state.hex_addr = state.hex_addr.saturating_add(0x40);
        }
        if ui.button("@ cursor").clicked() {
            state.hex_addr = state.selected_addr;
        }
    });

    let mut jump = None;
    let rows = 24usize;
    let dump: Vec<(u64, Vec<u8>)> = {
        let db = state.db.as_ref().unwrap();
        (0..rows)
            .map(|r| {
                let addr = base + (r as u64) * 16;
                let mut bytes = [0u8; 16];
                let n = db.bin.read(addr, &mut bytes);
                (addr, bytes[..n].to_vec())
            })
            .collect()
    };

    ScrollArea::vertical()
        .id_salt("hex_dump")
        .auto_shrink([false, false])
        .show(ui, |ui| {
            for (addr, bytes) in &dump {
                let n = bytes.len();
                ui.horizontal(|ui| {
                    let resp = ui.add(
                        egui::Label::new(
                            RichText::new(crate::theme::hex_addr(*addr, is64))
                                .monospace()
                                .color(state.colors.addr),
                        )
                        .sense(Sense::click()),
                    );
                    if resp.clicked() {
                        jump = Some(*addr);
                    }
                    ui.add_space(6.0);
                    for i in 0..16 {
                        if i == 8 {
                            ui.add_space(6.0);
                        }
                        if i < n {
                            let b = bytes[i];
                            let a = addr + i as u64;
                            let selected = a == state.selected_addr;
                            let color = if selected {
                                state.colors.pc_arrow
                            } else if (0x20..0x7f).contains(&b) {
                                state.colors.string
                            } else {
                                state.colors.bytes
                            };
                            if ui
                                .selectable_label(
                                    selected,
                                    RichText::new(crate::theme::hex_byte(b))
                                        .monospace()
                                        .color(color),
                                )
                                .clicked()
                            {
                                jump = Some(a);
                            }
                        } else {
                            ui.label(RichText::new("  ").monospace());
                        }
                    }
                    ui.add_space(8.0);
                    let ascii: String = bytes
                        .iter()
                        .map(|&b| {
                            if (0x20..0x7f).contains(&b) {
                                b as char
                            } else {
                                '.'
                            }
                        })
                        .collect();
                    ui.label(
                        RichText::new(ascii)
                            .monospace()
                            .color(state.colors.auto_comment),
                    );
                });
            }
        });
    if let Some(a) = jump {
        state.jump(a);
        state.hex_addr = a;
    }
}

fn draw_info(ui: &mut egui::Ui, state: &mut AppState) {
    let Some(db) = state.db.as_ref() else {
        ui.weak("(no file)");
        return;
    };
    let addr = state.selected_addr;
    ScrollArea::vertical()
        .id_salt("right_info")
        .auto_shrink([false, false])
        .show(ui, |ui| {
            ui.strong("Selection");
            kv(ui, state, "Address", &db.fmt_addr(addr));
            kv(ui, state, "Location", &db.location(addr));
            let name = db.name_at(addr);
            if !name.is_empty() {
                kv(ui, state, "Name", &name);
            }
            if let Some(c) = db.comments.get(&addr) {
                kv(ui, state, "Comment", c);
            }
            if let Some(f) = db.func_at(addr) {
                kv(ui, state, "Function", &f.name);
                kv(
                    ui,
                    state,
                    "Func range",
                    &format!("{}–{}", db.fmt_addr(f.start), db.fmt_addr(f.end)),
                );
            }
            ui.separator();
            ui.strong("Binary");
            kv(ui, state, "File", &db.bin.name);
            kv(ui, state, "Path", &db.bin.path);
            kv(ui, state, "Format", db.bin.format.as_str());
            kv(ui, state, "Arch", db.bin.arch.as_str());
            kv(ui, state, "Base", &db.fmt_addr(db.bin.base));
            if db.bin.has_entry {
                kv(ui, state, "Entry", &db.fmt_addr(db.bin.entry));
            }
            kv(
                ui,
                state,
                "Functions",
                &db.analysis.functions.len().to_string(),
            );
            kv(ui, state, "Strings", &db.analysis.strings.len().to_string());
            kv(ui, state, "Xrefs", &db.analysis.xto.len().to_string());
            if !db.bin.tls_callbacks.is_empty() {
                kv(
                    ui,
                    state,
                    "TLS callbacks",
                    &db.bin.tls_callbacks.len().to_string(),
                );
                for (i, &t) in db.bin.tls_callbacks.iter().enumerate() {
                    kv(ui, state, &format!("  tls[{i}]"), &db.fmt_addr(t));
                }
            }
            ui.separator();
            ui.strong("Segment at cursor");
            if let Some(seg) = db.bin.seg_at(addr) {
                kv(ui, state, "Name", &seg.name);
                kv(
                    ui,
                    state,
                    "Range",
                    &format!("{}–{}", db.fmt_addr(seg.start), db.fmt_addr(seg.end)),
                );
                let mut perms = String::new();
                if seg.perms & PERM_R != 0 {
                    perms.push('r');
                } else {
                    perms.push('-');
                }
                if seg.perms & PERM_W != 0 {
                    perms.push('w');
                } else {
                    perms.push('-');
                }
                if seg.perms & PERM_X != 0 {
                    perms.push('x');
                } else {
                    perms.push('-');
                }
                kv(ui, state, "Perms", &perms);
            } else {
                ui.weak("(unmapped)");
            }
            ui.separator();
            ui.strong("Host / debugger prefs");
            kv(
                ui,
                state,
                "protect_host",
                if state.protect_host { "on" } else { "off" },
            );
            kv(
                ui,
                state,
                "break_on_tls",
                if state.break_on_tls { "on" } else { "off" },
            );
            kv(
                ui,
                state,
                "watch_host",
                if state.watch_host { "on" } else { "off" },
            );
        });
}

fn kv(ui: &mut egui::Ui, state: &AppState, k: &str, v: &str) {
    ui.horizontal(|ui| {
        ui.label(
            RichText::new(k)
                .small()
                .color(state.colors.muted)
                .strong(),
        );
        ui.label(RichText::new(v).monospace());
    });
}

fn draw_breakpoints(ui: &mut egui::Ui, state: &mut AppState) {
    let bps: Vec<u64> = state
        .db
        .as_ref()
        .map(|d| d.breakpoints.iter().copied().collect())
        .unwrap_or_default();
    ui.label(
        RichText::new(format!("{} breakpoints", bps.len()))
            .small()
            .color(state.colors.muted),
    );
    let mut jump = None;
    let mut toggle = None;
    ScrollArea::vertical()
        .id_salt("bp_list")
        .auto_shrink([false, false])
        .show(ui, |ui| {
            for a in &bps {
                ui.horizontal(|ui| {
                    ui.label(RichText::new("●").color(state.colors.bp));
                    let label = state
                        .db
                        .as_ref()
                        .map(|d| {
                            let n = d.name_at(*a);
                            if n.is_empty() {
                                d.fmt_addr(*a)
                            } else {
                                format!("{}  {n}", d.fmt_addr(*a))
                            }
                        })
                        .unwrap_or_else(|| format!("{a:X}"));
                    if ui
                        .selectable_label(state.selected_addr == *a, RichText::new(label).monospace())
                        .clicked()
                    {
                        jump = Some(*a);
                    }
                    if ui.small_button("×").clicked() {
                        toggle = Some(*a);
                    }
                });
            }
            if bps.is_empty() {
                ui.weak("No breakpoints. Press F2 on a listing line.");
            }
        });
    ui.horizontal(|ui| {
        if ui.button("Toggle @ cursor").clicked() {
            toggle = Some(state.selected_addr);
        }
        if ui.button("Clear all").clicked() {
            let all: Vec<u64> = state
                .db
                .as_ref()
                .map(|d| d.breakpoints.iter().copied().collect())
                .unwrap_or_default();
            if let Some(db) = state.db.as_mut() {
                db.breakpoints.clear();
                db.dirty = true;
            }
            for a in &all {
                let _ = state.dbg.del_breakpoint(*a);
            }
            if !all.is_empty() {
                state.log_info("cleared breakpoints");
            }
        }
    });
    if let Some(a) = jump {
        state.jump(a);
    }
    if let Some(a) = toggle {
        state.toggle_breakpoint(a);
    }
}
