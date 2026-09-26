//! ceasta GUI — egui/eframe IDA-style desktop shell.
//!
//! Layout (mirrors `legacy/cpp-src/ui/`):
//! - top menu bar (File / Edit / View / Debug / Plugins / Help)
//! - left: functions + imports/exports/strings
//! - center: listing / graph / pseudocode
//! - right: xrefs, hex, segments, CPU when debugging
//! - bottom: output log + Lua-ish console

mod bottom_panel;
mod cpu_panel;
mod dialogs;
mod graph_view;
mod left_panel;
mod listing_view;
mod pseudo_view;
mod right_panel;
mod shortcuts;
mod theme;
mod top_bar;

pub use theme::{FontSizes, ListingColors, UiTheme};

use anyhow::{Context, Result};
use ceasta_analysis::run as analyze;
use ceasta_binary::{open_with, LoadOptions};
use ceasta_db::Database;
use ceasta_debugger::{create as create_debugger, Debugger, State as DbgState};
use std::collections::VecDeque;
use std::path::{Path, PathBuf};

/// Center pane mode.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum CenterTab {
    #[default]
    Listing,
    Graph,
    Pseudo,
    Split,
}

impl CenterTab {
    pub fn as_str(self) -> &'static str {
        match self {
            CenterTab::Listing => "Listing",
            CenterTab::Graph => "Graph",
            CenterTab::Pseudo => "Pseudocode",
            CenterTab::Split => "Split",
        }
    }
}

/// Left-panel sub-tab (functions / imports / exports / strings).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum LeftTab {
    #[default]
    Functions,
    Imports,
    Exports,
    Strings,
    Segments,
}

impl LeftTab {
    pub fn as_str(self) -> &'static str {
        match self {
            LeftTab::Functions => "Functions",
            LeftTab::Imports => "Imports",
            LeftTab::Exports => "Exports",
            LeftTab::Strings => "Strings",
            LeftTab::Segments => "Segments",
        }
    }

    pub fn all() -> &'static [LeftTab] {
        &[
            LeftTab::Functions,
            LeftTab::Imports,
            LeftTab::Exports,
            LeftTab::Strings,
            LeftTab::Segments,
        ]
    }
}

/// Right-panel sub-tab.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum RightTab {
    #[default]
    Xrefs,
    Hex,
    Info,
    Cpu,
    Breakpoints,
}

impl RightTab {
    pub fn as_str(self) -> &'static str {
        match self {
            RightTab::Xrefs => "Xrefs",
            RightTab::Hex => "Hex",
            RightTab::Info => "Info",
            RightTab::Cpu => "CPU",
            RightTab::Breakpoints => "BPs",
        }
    }
}

/// Modal dialog kinds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DialogKind {
    About,
    GoTo,
    Rename,
    Comment,
    Find,
    Preferences,
    Xrefs,
    Palette,
    Shortcuts,
    OpenRaw,
    Attach,
    RunArgs,
}

/// Log severity for the bottom output pane.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LogLevel {
    Info,
    Warn,
    Error,
    Echo,
}

#[derive(Clone, Debug)]
pub struct LogLine {
    pub level: LogLevel,
    pub text: String,
}

/// Application state shared by every panel.
pub struct AppState {
    pub db: Option<Database>,
    pub dbg: Box<dyn Debugger>,

    // navigation / selection
    pub selected_addr: u64,
    pub hex_addr: u64,
    pub nav_back_stack: Vec<u64>,
    pub nav_fwd_stack: Vec<u64>,
    pub scroll_to_addr: Option<u64>,

    // views
    pub center_tab: CenterTab,
    pub left_tab: LeftTab,
    pub right_tab: RightTab,
    pub show_left: bool,
    pub show_right: bool,
    pub show_bottom: bool,
    pub show_bytes: bool,
    pub show_cpu: bool,

    // filters
    pub func_filter: String,
    pub left_filter: String,
    pub string_filter: String,
    pub import_filter: String,
    pub export_filter: String,

    // logging / console
    pub log: VecDeque<LogLine>,
    pub log_to_bottom: bool,
    pub console: String,
    pub console_history: Vec<String>,
    pub history_pos: isize,
    pub focus_console: bool,

    // dialogs
    pub dialog: Option<DialogKind>,
    pub dialog_buf: String,
    pub dialog_addr: u64,

    // theme
    pub theme: UiTheme,
    pub fonts: FontSizes,
    pub colors: ListingColors,
    pub theme_dirty: bool,

    // debugger helpers
    pub step_count: i32,
    pub run_args: String,
    pub attach_pid: String,
    pub break_on_entry: bool,

    // preferences (also mirrored into dbg.options)
    pub protect_host: bool,
    pub break_on_tls: bool,
    pub watch_host: bool,

    // recent files
    pub recent: Vec<PathBuf>,
    pub clipboard: String,

    // one-shot UI requests
    pub request_open_file: bool,
    pub request_quit: bool,
    pub listing_dirty: bool,
    pub status: String,
}

impl Default for AppState {
    fn default() -> Self {
        let dbg = create_debugger();
        let opts = dbg.options().clone();
        Self {
            db: None,
            dbg,
            selected_addr: 0,
            hex_addr: 0,
            nav_back_stack: Vec::new(),
            nav_fwd_stack: Vec::new(),
            scroll_to_addr: None,
            center_tab: CenterTab::Listing,
            left_tab: LeftTab::Functions,
            right_tab: RightTab::Xrefs,
            show_left: true,
            show_right: true,
            show_bottom: true,
            show_bytes: true,
            show_cpu: true,
            func_filter: String::new(),
            left_filter: String::new(),
            string_filter: String::new(),
            import_filter: String::new(),
            export_filter: String::new(),
            log: VecDeque::with_capacity(512),
            log_to_bottom: true,
            console: String::new(),
            console_history: Vec::new(),
            history_pos: -1,
            focus_console: false,
            dialog: None,
            dialog_buf: String::new(),
            dialog_addr: 0,
            theme: UiTheme::Dark,
            fonts: FontSizes::default(),
            colors: ListingColors::default(),
            theme_dirty: true,
            step_count: 1,
            run_args: String::new(),
            attach_pid: String::new(),
            break_on_entry: opts.break_on_entry,
            protect_host: opts.protect_host,
            break_on_tls: opts.break_on_tls,
            watch_host: opts.watch_host,
            recent: Vec::new(),
            clipboard: String::new(),
            request_open_file: false,
            request_quit: false,
            listing_dirty: true,
            status: "ready".into(),
        }
    }
}

impl std::fmt::Debug for AppState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AppState")
            .field("db", &self.db.as_ref().map(|d| d.bin.path.as_str()))
            .field("selected_addr", &self.selected_addr)
            .field("center_tab", &self.center_tab)
            .field("dbg_state", &self.dbg.state())
            .finish()
    }
}

impl AppState {
    pub fn load_file(&mut self, path: &Path) -> Result<()> {
        self.load_file_with(path, &LoadOptions::default())
    }

    pub fn load_file_with(&mut self, path: &Path, opts: &LoadOptions) -> Result<()> {
        self.log_info(format!("opening {}…", path.display()));
        let bin = open_with(path, opts).with_context(|| format!("open {}", path.display()))?;
        let analysis = analyze(&bin);
        let entry = if bin.has_entry { bin.entry } else { bin.base };
        let n_funcs = analysis.functions.len();
        let n_strs = analysis.strings.len();
        let n_xrefs = analysis.xto.len();
        self.db = Some(Database::new(bin, analysis));
        self.selected_addr = entry;
        self.hex_addr = entry;
        self.scroll_to_addr = Some(entry);
        self.nav_back_stack.clear();
        self.nav_fwd_stack.clear();
        self.listing_dirty = true;
        self.push_recent(path.to_path_buf());
        self.status = self.summary();
        self.log_info(format!(
            "loaded {} — {n_funcs} functions, {n_strs} strings, {n_xrefs} xrefs",
            path.display()
        ));
        // try sidecar project
        let project_msg = if let Some(db) = self.db.as_mut() {
            let proj = db.project_path();
            if proj.exists() {
                match db.load_project_file(&proj) {
                    Ok(()) => Some(Ok(proj.display().to_string())),
                    Err(e) => Some(Err(e.to_string())),
                }
            } else {
                None
            }
        } else {
            None
        };
        match project_msg {
            Some(Ok(p)) => self.log_info(format!("restored project {p}")),
            Some(Err(e)) => self.log_warn(format!("project load: {e}")),
            None => {}
        }
        Ok(())
    }

    pub fn close_file(&mut self) {
        if self.db.is_some() {
            self.log_info("closed file");
        }
        self.db = None;
        self.selected_addr = 0;
        self.hex_addr = 0;
        self.nav_back_stack.clear();
        self.nav_fwd_stack.clear();
        self.status = "no file loaded".into();
        self.listing_dirty = true;
    }

    pub fn summary(&self) -> String {
        match &self.db {
            Some(db) => format!(
                "{} — {} {}, {} functions, {} tls callbacks",
                db.bin.name,
                db.bin.format.as_str(),
                db.bin.arch.as_str(),
                db.analysis.functions.len(),
                db.bin.tls_callbacks.len()
            ),
            None => "no file loaded".into(),
        }
    }

    pub fn push_recent(&mut self, path: PathBuf) {
        self.recent.retain(|p| p != &path);
        self.recent.insert(0, path);
        if self.recent.len() > 12 {
            self.recent.truncate(12);
        }
    }

    pub fn log_info(&mut self, text: impl Into<String>) {
        self.push_log(LogLevel::Info, text);
    }
    pub fn log_warn(&mut self, text: impl Into<String>) {
        self.push_log(LogLevel::Warn, text);
    }
    pub fn log_error(&mut self, text: impl Into<String>) {
        self.push_log(LogLevel::Error, text);
    }
    pub fn log_echo(&mut self, text: impl Into<String>) {
        self.push_log(LogLevel::Echo, text);
    }

    fn push_log(&mut self, level: LogLevel, text: impl Into<String>) {
        if self.log.len() >= 2000 {
            self.log.pop_front();
        }
        self.log.push_back(LogLine {
            level,
            text: text.into(),
        });
        self.log_to_bottom = true;
    }

    pub fn open_dialog(&mut self, kind: DialogKind) {
        self.dialog_addr = self.selected_addr;
        self.dialog_buf.clear();
        match kind {
            DialogKind::Rename => {
                if let Some(db) = self.db.as_ref() {
                    self.dialog_buf = db.name_at(self.selected_addr);
                }
            }
            DialogKind::Comment => {
                if let Some(db) = self.db.as_ref() {
                    self.dialog_buf = db
                        .comments
                        .get(&self.selected_addr)
                        .cloned()
                        .unwrap_or_default();
                }
            }
            DialogKind::GoTo | DialogKind::Find => {
                if let Some(db) = self.db.as_ref() {
                    self.dialog_buf = db.fmt_addr(self.selected_addr);
                }
            }
            DialogKind::RunArgs => {
                self.dialog_buf = self.run_args.clone();
            }
            DialogKind::Attach => {
                self.dialog_buf = self.attach_pid.clone();
            }
            DialogKind::OpenRaw => {
                self.dialog_buf = "0x1000".into();
            }
            _ => {}
        }
        self.dialog = Some(kind);
    }

    pub fn jump(&mut self, addr: u64) {
        if addr == self.selected_addr {
            self.scroll_to_addr = Some(addr);
            return;
        }
        if self.selected_addr != 0 || self.db.is_some() {
            self.nav_back_stack.push(self.selected_addr);
            if self.nav_back_stack.len() > 256 {
                self.nav_back_stack.remove(0);
            }
        }
        self.nav_fwd_stack.clear();
        self.selected_addr = addr;
        self.hex_addr = addr;
        self.scroll_to_addr = Some(addr);
        self.listing_dirty = true;
        if let Some(db) = self.db.as_ref() {
            self.status = format!("{} @ {}", db.location(addr), db.fmt_addr(addr));
        }
    }

    pub fn nav_back(&mut self) {
        if let Some(a) = self.nav_back_stack.pop() {
            self.nav_fwd_stack.push(self.selected_addr);
            self.selected_addr = a;
            self.hex_addr = a;
            self.scroll_to_addr = Some(a);
            self.listing_dirty = true;
        }
    }

    pub fn nav_forward(&mut self) {
        if let Some(a) = self.nav_fwd_stack.pop() {
            self.nav_back_stack.push(self.selected_addr);
            self.selected_addr = a;
            self.hex_addr = a;
            self.scroll_to_addr = Some(a);
            self.listing_dirty = true;
        }
    }

    pub fn follow_operand(&mut self) {
        let target = {
            let Some(db) = self.db.as_ref() else {
                return;
            };
            let refs = db.analysis.refs_from(self.selected_addr);
            if let Some(x) = refs.first() {
                Some(x.to)
            } else if let Ok(insn) = ceasta_disasm::decode_at(&db.bin, self.selected_addr) {
                insn.target.or(insn.mem)
            } else {
                None
            }
        };
        if let Some(t) = target {
            self.jump(t);
        }
    }

    pub fn toggle_breakpoint(&mut self, addr: u64) {
        let (info, warn) = {
            let Some(db) = self.db.as_mut() else {
                return;
            };
            if db.breakpoints.contains(&addr) {
                db.breakpoints.remove(&addr);
                let _ = self.dbg.del_breakpoint(addr);
                db.dirty = true;
                (format!("breakpoint removed @ {addr:X}"), None)
            } else {
                db.breakpoints.insert(addr);
                let warn = self
                    .dbg
                    .add_breakpoint(addr)
                    .err()
                    .map(|e| format!("bp software note: {e}"));
                db.dirty = true;
                (format!("breakpoint set @ {addr:X}"), warn)
            }
        };
        if let Some(w) = warn {
            self.log_warn(w);
        }
        self.log_info(info);
    }

    pub fn set_name(&mut self, addr: u64, name: String) {
        let name = name.trim().to_string();
        {
            let Some(db) = self.db.as_mut() else {
                return;
            };
            if name.is_empty() {
                db.names.remove(&addr);
            } else {
                db.set_name(addr, name.clone());
            }
        }
        self.listing_dirty = true;
        self.log_info(format!("rename {addr:X} → {name}"));
    }

    pub fn set_comment(&mut self, addr: u64, text: String) {
        let text = text.trim().to_string();
        {
            let Some(db) = self.db.as_mut() else {
                return;
            };
            db.set_comment(addr, &text);
        }
        self.listing_dirty = true;
        self.log_info(format!("comment @ {addr:X}"));
    }

    pub fn save_project(&mut self) {
        let result = {
            let Some(db) = self.db.as_mut() else {
                self.log_warn("nothing to save");
                return;
            };
            let result = db.save_project();
            if result.is_ok() {
                db.dirty = false;
            }
            result
        };
        match result {
            Ok(p) => self.log_info(format!("saved {}", p.display())),
            Err(e) => self.log_error(format!("save failed: {e}")),
        }
    }

    pub fn sync_dbg_options(&mut self) {
        let o = self.dbg.options_mut();
        o.protect_host = self.protect_host;
        o.break_on_tls = self.break_on_tls;
        o.watch_host = self.watch_host;
        o.break_on_entry = self.break_on_entry;
    }

    pub fn dbg_continue(&mut self) {
        self.sync_dbg_options();
        match self.dbg.state() {
            DbgState::None => {
                let Some(db) = self.db.as_ref() else {
                    self.log_warn("load a file before debugging");
                    return;
                };
                let path = PathBuf::from(&db.bin.path);
                match self.dbg.start(&path, &self.run_args) {
                    Ok(()) => {
                        self.log_info("debugger started");
                        self.right_tab = RightTab::Cpu;
                        self.show_right = true;
                    }
                    Err(e) => self.log_error(format!("start: {e}")),
                }
            }
            DbgState::Stopped => {
                if let Err(e) = self.dbg.cont() {
                    self.log_error(format!("continue: {e}"));
                } else {
                    self.log_info("continue");
                }
            }
            DbgState::Running => self.log_warn("already running"),
        }
    }

    pub fn dbg_step_into(&mut self) {
        for _ in 0..self.step_count.max(1) {
            if let Err(e) = self.dbg.step_into() {
                self.log_error(format!("step into: {e}"));
                break;
            }
        }
        if let Ok(pc) = self.dbg.pc() {
            self.jump(pc);
        }
    }

    pub fn dbg_step_over(&mut self) {
        for _ in 0..self.step_count.max(1) {
            if let Err(e) = self.dbg.step_over() {
                self.log_error(format!("step over: {e}"));
                break;
            }
        }
        if let Ok(pc) = self.dbg.pc() {
            self.jump(pc);
        }
    }

    pub fn dbg_run_to_cursor(&mut self) {
        let addr = self.selected_addr;
        if let Err(e) = self.dbg.add_breakpoint(addr) {
            self.log_warn(format!("run-to bp: {e}"));
        }
        if let Err(e) = self.dbg.cont() {
            self.log_error(format!("run to cursor: {e}"));
        } else {
            self.log_info(format!("run to {addr:X}"));
        }
    }

    pub fn dbg_pause(&mut self) {
        // poll-based backends: kill isn't pause; request a stop via poll side-effect
        self.dbg.poll(0);
        self.log_info("pause requested");
    }

    pub fn dbg_stop(&mut self) {
        self.dbg.kill();
        self.log_info("debugger stopped");
    }

    pub fn dbg_detach(&mut self) {
        self.dbg.detach();
        self.log_info("detached");
    }

    pub fn run_console_line(&mut self) {
        let code = self.console.trim().to_string();
        if code.is_empty() {
            return;
        }
        self.log_echo(format!("> {code}"));
        self.console_history.push(code.clone());
        if self.console_history.len() > 200 {
            self.console_history.remove(0);
        }
        self.history_pos = -1;
        self.console.clear();
        self.exec_console(&code);
    }

    fn exec_console(&mut self, code: &str) {
        let lower = code.to_ascii_lowercase();
        if lower == "help" || lower == "?" {
            self.log_info("commands: help, clear, jump <addr>, name <addr> <name>, comment <addr> <text>, bp <addr>, funcs, strings, entry, theme, prefs");
            self.log_info("or a Lua-like expression (limited): print(...), ceasta.version");
            return;
        }
        if lower == "clear" {
            self.log.clear();
            return;
        }
        if lower == "entry" {
            if let Some(db) = self.db.as_ref() {
                if db.bin.has_entry {
                    let e = db.bin.entry;
                    self.jump(e);
                }
            }
            return;
        }
        if lower == "funcs" {
            let lines: Vec<String> = self
                .db
                .as_ref()
                .map(|db| {
                    let mut lines: Vec<String> = db
                        .analysis
                        .functions
                        .iter()
                        .take(40)
                        .map(|f| {
                            format!(
                                "  {}  {}  {:X}h",
                                db.fmt_addr(f.start),
                                f.name,
                                f.end - f.start
                            )
                        })
                        .collect();
                    if db.analysis.functions.len() > 40 {
                        lines.push(format!(
                            "  … {} more",
                            db.analysis.functions.len() - 40
                        ));
                    }
                    lines
                })
                .unwrap_or_default();
            for line in lines {
                self.log_info(line);
            }
            return;
        }
        if lower == "strings" {
            let lines: Vec<String> = self
                .db
                .as_ref()
                .map(|db| {
                    db.analysis
                        .strings
                        .iter()
                        .take(40)
                        .map(|s| format!("  {}  {:?}", db.fmt_addr(s.addr), trunc(&s.text, 60)))
                        .collect()
                })
                .unwrap_or_default();
            for line in lines {
                self.log_info(line);
            }
            return;
        }
        if lower == "theme" {
            self.theme = self.theme.next();
            self.colors = ListingColors::for_theme(self.theme);
            self.theme_dirty = true;
            self.log_info(format!("theme → {}", self.theme.as_str()));
            return;
        }
        if lower == "prefs" {
            self.open_dialog(DialogKind::Preferences);
            return;
        }
        if let Some(rest) = lower.strip_prefix("jump ") {
            if let Some(db) = self.db.as_ref() {
                if let Some(a) = db.resolve(rest.trim()) {
                    self.jump(a);
                    return;
                }
            }
            self.log_error(format!("unknown address: {rest}"));
            return;
        }
        if let Some(rest) = code.strip_prefix("name ") {
            let mut parts = rest.splitn(2, char::is_whitespace);
            let addr_s = parts.next().unwrap_or("");
            let name = parts.next().unwrap_or("").trim();
            if let Some(db) = self.db.as_ref() {
                if let Some(a) = db.resolve(addr_s) {
                    self.set_name(a, name.to_string());
                    return;
                }
            }
            self.log_error("usage: name <addr> <newname>");
            return;
        }
        if let Some(rest) = code.strip_prefix("comment ") {
            let mut parts = rest.splitn(2, char::is_whitespace);
            let addr_s = parts.next().unwrap_or("");
            let text = parts.next().unwrap_or("").trim();
            if let Some(db) = self.db.as_ref() {
                if let Some(a) = db.resolve(addr_s) {
                    self.set_comment(a, text.to_string());
                    return;
                }
            }
            self.log_error("usage: comment <addr> <text>");
            return;
        }
        if let Some(rest) = lower.strip_prefix("bp ") {
            if let Some(db) = self.db.as_ref() {
                if let Some(a) = db.resolve(rest.trim()) {
                    self.toggle_breakpoint(a);
                    return;
                }
            }
            self.log_error("usage: bp <addr>");
            return;
        }
        if lower.starts_with("print ") || lower == "ceasta.version" || lower.starts_with("ceasta.") {
            self.log_info("(lua host) ceasta lua api 1 — use ceasta-cli / plugins for full scripts");
            if lower == "ceasta.version" {
                self.log_echo("ceasta lua api 1 (Lua 5.4)");
            }
            return;
        }
        self.log_warn(format!("unknown command (try help): {code}"));
    }

    pub fn poll_debugger(&mut self) {
        if self.dbg.state() != DbgState::None {
            self.dbg.poll(0);
            if self.watch_host {
                let _ = ceasta_host::health_check();
            }
            if self.dbg.state() == DbgState::Stopped {
                if let Ok(pc) = self.dbg.pc() {
                    if pc != 0 && pc != self.selected_addr {
                        // soft follow PC while stopped
                        self.selected_addr = pc;
                        self.hex_addr = pc;
                    }
                }
            }
        }
    }

    pub fn current_function_start(&self) -> Option<u64> {
        let db = self.db.as_ref()?;
        db.func_at(self.selected_addr).map(|f| f.start)
    }
}

fn trunc(s: &str, max: usize) -> String {
    let mut out = String::new();
    for (i, ch) in s.chars().enumerate() {
        if i >= max {
            out.push('…');
            break;
        }
        if ch.is_control() {
            out.push('·');
        } else {
            out.push(ch);
        }
    }
    out
}

/// Root eframe application.
pub struct CeastaApp {
    pub state: AppState,
}

impl CeastaApp {
    pub fn new(cc: &eframe::CreationContext<'_>, initial: Option<PathBuf>) -> Self {
        let mut state = AppState::default();
        theme::apply(&cc.egui_ctx, state.theme, &state.fonts);
        state.theme_dirty = false;
        state.log_info(format!(
            "ceasta {} — rust native UI",
            env!("CARGO_PKG_VERSION")
        ));
        state.log_info(format!(
            "protect_host={}, break_on_tls={}, watch_host={}",
            state.protect_host, state.break_on_tls, state.watch_host
        ));
        if let Some(path) = initial {
            if let Err(e) = state.load_file(&path) {
                state.log_error(format!("{e:#}"));
            }
        }
        Self { state }
    }

    fn handle_requests(&mut self, ctx: &egui::Context) {
        if self.state.request_open_file {
            self.state.request_open_file = false;
            if let Some(path) = rfd::FileDialog::new()
                .add_filter(
                    "Binaries",
                    &["exe", "dll", "sys", "so", "elf", "bin", "ceasta"],
                )
                .add_filter("All files", &["*"])
                .pick_file()
            {
                if let Err(e) = self.state.load_file(&path) {
                    self.state.log_error(format!("{e:#}"));
                }
            }
        }
        if self.state.request_quit {
            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
        }
        if self.state.theme_dirty {
            self.state.colors = ListingColors::for_theme(self.state.theme);
            theme::apply(ctx, self.state.theme, &self.state.fonts);
            self.state.theme_dirty = false;
        }
    }
}

impl eframe::App for CeastaApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.state.poll_debugger();
        shortcuts::handle(ctx, &mut self.state);
        self.handle_requests(ctx);

        top_bar::draw(ctx, &mut self.state);

        if self.state.show_bottom {
            egui::TopBottomPanel::bottom("bottom_panel")
                .resizable(true)
                .default_height(140.0)
                .min_height(60.0)
                .show(ctx, |ui| {
                    bottom_panel::draw(ui, &mut self.state);
                });
        }

        if self.state.show_left {
            egui::SidePanel::left("left_panel")
                .resizable(true)
                .default_width(260.0)
                .min_width(160.0)
                .show(ctx, |ui| {
                    left_panel::draw(ui, &mut self.state);
                });
        }

        if self.state.show_right {
            egui::SidePanel::right("right_panel")
                .resizable(true)
                .default_width(300.0)
                .min_width(180.0)
                .show(ctx, |ui| {
                    right_panel::draw(ui, &mut self.state);
                    if self.state.show_cpu
                        || self.state.dbg.state() != DbgState::None
                        || self.state.right_tab == RightTab::Cpu
                    {
                        ui.separator();
                        cpu_panel::draw(ui, &mut self.state);
                    }
                });
        }

        egui::CentralPanel::default().show(ctx, |ui| {
            // tab strip
            ui.horizontal(|ui| {
                for (tab, label) in [
                    (CenterTab::Listing, "Listing"),
                    (CenterTab::Graph, "Graph"),
                    (CenterTab::Pseudo, "Pseudocode"),
                    (CenterTab::Split, "Split"),
                ] {
                    let selected = self.state.center_tab == tab;
                    if ui.selectable_label(selected, label).clicked() {
                        self.state.center_tab = tab;
                    }
                }
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.label(
                        egui::RichText::new(&self.state.status)
                            .small()
                            .color(self.state.colors.muted),
                    );
                });
            });
            ui.separator();

            match self.state.center_tab {
                CenterTab::Listing => listing_view::draw(ui, &mut self.state),
                CenterTab::Graph => graph_view::draw(ui, &mut self.state),
                CenterTab::Pseudo => pseudo_view::draw(ui, &mut self.state),
                CenterTab::Split => {
                    ui.columns(2, |cols| {
                        listing_view::draw(&mut cols[0], &mut self.state);
                        pseudo_view::draw(&mut cols[1], &mut self.state);
                    });
                }
            }
        });

        dialogs::draw(ctx, &mut self.state);

        // status / keepalive while debugging
        if self.state.dbg.state() == DbgState::Running {
            ctx.request_repaint_after(std::time::Duration::from_millis(50));
        }
    }
}

/// Build native options for `eframe::run_native`.
pub fn native_options() -> eframe::NativeOptions {
    eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("ceasta")
            .with_inner_size([1400.0, 900.0])
            .with_min_inner_size([800.0, 500.0]),
        ..Default::default()
    }
}
