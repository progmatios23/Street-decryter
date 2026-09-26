//! CPU / register panel — live debugger registers when stopped.

use crate::AppState;
use ceasta_debugger::State as DbgState;
use egui::{RichText, ScrollArea};

pub fn draw(ui: &mut egui::Ui, state: &mut AppState) {
    let st = state.dbg.state();
    let detail = match st {
        DbgState::None => "idle",
        DbgState::Running => "running",
        DbgState::Stopped => "stopped",
    };
    crate::theme::section_header(ui, &state.colors, "CPU", detail);

    ui.horizontal(|ui| {
        ui.label(RichText::new("State").small().color(state.colors.muted));
        ui.label(
            RichText::new(detail)
                .strong()
                .color(match st {
                    DbgState::Running => state.colors.comment,
                    DbgState::Stopped => state.colors.pc_arrow,
                    DbgState::None => state.colors.muted,
                }),
        );
        if let Some(pid) = state.dbg.pid() {
            ui.separator();
            ui.label(RichText::new(format!("pid {pid}")).monospace());
        }
        let reason = state.dbg.stop_reason().to_string();
        if !reason.is_empty() {
            ui.separator();
            ui.label(RichText::new(reason).small().color(state.colors.auto_comment));
        }
    });

    if st == DbgState::None {
        ui.add_space(4.0);
        ui.weak("Start or attach a process (Debug menu) to see registers.");
        ui.label(
            RichText::new(format!(
                "protect_host={}  break_on_tls={}  watch_host={}",
                state.protect_host, state.break_on_tls, state.watch_host
            ))
            .small()
            .monospace()
            .color(state.colors.muted),
        );
        return;
    }

    let regs = state.dbg.registers().unwrap_or_default();
    let pc = state.dbg.pc().unwrap_or(0);
    let mut jump_to: Option<u64> = None;

    if pc != 0 {
        ui.horizontal(|ui| {
            ui.label(RichText::new("PC").monospace().color(state.colors.kw));
            let r = ui.selectable_label(
                state.selected_addr == pc,
                RichText::new(crate::theme::hex_addr(pc, true))
                    .monospace()
                    .color(state.colors.pc_arrow),
            );
            if r.clicked() {
                jump_to = Some(pc);
            }
            if r.secondary_clicked() {
                jump_to = Some(pc);
            }
        });
    }

    ui.add_space(2.0);
    ScrollArea::vertical()
        .id_salt("cpu_regs")
        .auto_shrink([false, false])
        .max_height(220.0)
        .show(ui, |ui| {
            egui::Grid::new("reg_grid")
                .num_columns(2)
                .striped(true)
                .min_col_width(48.0)
                .show(ui, |ui| {
                    ui.strong("Reg");
                    ui.strong("Value");
                    ui.end_row();
                    if regs.is_empty() {
                        ui.label(RichText::new("(unavailable)").color(state.colors.muted));
                        ui.label("");
                        ui.end_row();
                    }
                    for r in &regs {
                        let is_pc = r.name == "rip" || r.name == "eip" || r.name == "pc";
                        ui.label(
                            RichText::new(&r.name)
                                .monospace()
                                .color(if is_pc {
                                    state.colors.pc_arrow
                                } else {
                                    state.colors.kw
                                }),
                        );
                        let resp = ui.selectable_label(
                            false,
                            RichText::new(format!("{:016X}", r.value))
                                .monospace()
                                .color(state.colors.number),
                        );
                        if resp.clicked() {
                            jump_to = Some(r.value);
                        }
                        resp.context_menu(|ui| {
                            if ui.button("Jump to value").clicked() {
                                jump_to = Some(r.value);
                                ui.close_menu();
                            }
                            if ui.button("Copy").clicked() {
                                let t = format!("{:X}", r.value);
                                state.clipboard = t.clone();
                                ui.ctx().copy_text(t);
                                ui.close_menu();
                            }
                        });
                        ui.end_row();
                    }
                });
        });

    // stack peek near RSP when available
    if let Some(rsp) = regs.iter().find(|r| r.name == "rsp" || r.name == "esp") {
        ui.separator();
        ui.label(RichText::new("Stack").small().color(state.colors.muted));
        let mut buf = [0u8; 8 * 8];
        if let Ok(n) = state.dbg.read_memory(rsp.value, &mut buf) {
            let words = n / 8;
            for i in 0..words {
                let off = i * 8;
                let val = u64::from_le_bytes(buf[off..off + 8].try_into().unwrap_or([0; 8]));
                let addr = rsp.value + (i as u64) * 8;
                ui.horizontal(|ui| {
                    if ui
                        .selectable_label(
                            false,
                            RichText::new(format!("{addr:016X}"))
                                .monospace()
                                .color(state.colors.addr),
                        )
                        .clicked()
                    {
                        jump_to = Some(addr);
                    }
                    if ui
                        .selectable_label(
                            false,
                            RichText::new(format!("{val:016X}"))
                                .monospace()
                                .color(state.colors.data),
                        )
                        .clicked()
                    {
                        jump_to = Some(val);
                    }
                });
            }
        } else {
            ui.weak("(stack unread)");
        }
    }

    if let Some(a) = jump_to {
        state.jump(a);
    }
}
