//! Theme — colors, fonts, and egui Visuals for the IDA-style UI.
//!
//! Three palettes (dark / light / high-contrast) mirror `legacy/cpp-src/theme.h`.

use egui::{Color32, CornerRadius, FontFamily, FontId, Stroke, Style, Visuals};

/// Which UI palette is active.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum UiTheme {
    #[default]
    Dark,
    Light,
    Contrast,
}

impl UiTheme {
    pub fn as_str(self) -> &'static str {
        match self {
            UiTheme::Dark => "dark",
            UiTheme::Light => "light",
            UiTheme::Contrast => "high contrast",
        }
    }

    pub fn next(self) -> Self {
        match self {
            UiTheme::Dark => UiTheme::Light,
            UiTheme::Light => UiTheme::Contrast,
            UiTheme::Contrast => UiTheme::Dark,
        }
    }
}

/// Syntax / listing colors (updated when the theme changes).
#[derive(Clone, Debug)]
pub struct ListingColors {
    pub addr: Color32,
    pub bytes: Color32,
    pub text: Color32,
    pub comment: Color32,
    pub auto_comment: Color32,
    pub jump: Color32,
    pub call: Color32,
    pub ret: Color32,
    pub nop: Color32,
    pub data: Color32,
    pub string: Color32,
    pub label: Color32,
    pub func: Color32,
    pub segment: Color32,
    pub unknown: Color32,
    pub kw: Color32,
    pub ctype: Color32,
    pub number: Color32,
    pub punct: Color32,
    pub row_selected: Color32,
    pub row_pc: Color32,
    pub row_hover: Color32,
    pub bp: Color32,
    pub pc_arrow: Color32,
    pub band_bg: Color32,
    pub band_code: Color32,
    pub band_func: Color32,
    pub band_data: Color32,
    pub band_string: Color32,
    pub band_unknown: Color32,
    pub band_cursor: Color32,
    pub log_info: Color32,
    pub log_warn: Color32,
    pub log_error: Color32,
    pub log_echo: Color32,
    pub header_bg: Color32,
    pub header_text: Color32,
    pub panel_bg: Color32,
    pub muted: Color32,
}

impl Default for ListingColors {
    fn default() -> Self {
        dark_colors()
    }
}

fn c(r: u8, g: u8, b: u8) -> Color32 {
    Color32::from_rgb(r, g, b)
}

pub fn dark_colors() -> ListingColors {
    ListingColors {
        addr: c(120, 132, 150),
        bytes: c(96, 104, 118),
        text: c(220, 224, 230),
        comment: c(120, 200, 140),
        auto_comment: c(110, 150, 120),
        jump: c(120, 190, 255),
        call: c(255, 205, 110),
        ret: c(255, 120, 120),
        nop: c(110, 116, 128),
        data: c(200, 170, 240),
        string: c(240, 200, 150),
        label: c(150, 210, 255),
        func: c(255, 230, 140),
        segment: c(140, 150, 170),
        unknown: c(150, 130, 110),
        kw: c(198, 149, 230),
        ctype: c(120, 200, 165),
        number: c(230, 185, 140),
        punct: c(150, 156, 168),
        row_selected: c(52, 72, 110),
        row_pc: c(110, 90, 30),
        row_hover: c(40, 46, 58),
        bp: c(230, 70, 70),
        pc_arrow: c(255, 210, 80),
        band_bg: c(20, 22, 28),
        band_code: c(70, 120, 200),
        band_func: c(90, 150, 230),
        band_data: c(150, 150, 165),
        band_string: c(200, 160, 90),
        band_unknown: c(60, 56, 52),
        band_cursor: c(255, 230, 80),
        log_info: c(210, 214, 220),
        log_warn: c(240, 200, 100),
        log_error: c(255, 110, 110),
        log_echo: c(130, 170, 230),
        header_bg: c(26, 28, 34),
        header_text: c(150, 158, 172),
        panel_bg: c(22, 24, 30),
        muted: c(110, 116, 128),
    }
}

pub fn light_colors() -> ListingColors {
    ListingColors {
        addr: c(80, 90, 110),
        bytes: c(120, 128, 140),
        text: c(30, 34, 42),
        comment: c(40, 130, 70),
        auto_comment: c(70, 110, 80),
        jump: c(20, 100, 180),
        call: c(160, 100, 20),
        ret: c(180, 40, 40),
        nop: c(120, 124, 130),
        data: c(120, 70, 160),
        string: c(150, 90, 40),
        label: c(30, 110, 170),
        func: c(140, 100, 20),
        segment: c(90, 100, 120),
        unknown: c(120, 100, 80),
        kw: c(120, 60, 160),
        ctype: c(30, 120, 90),
        number: c(150, 90, 40),
        punct: c(90, 96, 108),
        row_selected: c(180, 200, 230),
        row_pc: c(240, 220, 160),
        row_hover: c(230, 234, 240),
        bp: c(200, 40, 40),
        pc_arrow: c(180, 120, 20),
        band_bg: c(230, 232, 236),
        band_code: c(90, 140, 210),
        band_func: c(70, 130, 200),
        band_data: c(140, 140, 155),
        band_string: c(190, 140, 70),
        band_unknown: c(200, 196, 190),
        band_cursor: c(200, 160, 40),
        log_info: c(40, 44, 52),
        log_warn: c(160, 110, 20),
        log_error: c(180, 40, 40),
        log_echo: c(40, 90, 160),
        header_bg: c(236, 238, 242),
        header_text: c(90, 98, 112),
        panel_bg: c(245, 246, 248),
        muted: c(120, 126, 138),
    }
}

pub fn contrast_colors() -> ListingColors {
    ListingColors {
        addr: c(180, 190, 200),
        bytes: c(160, 170, 180),
        text: Color32::WHITE,
        comment: c(100, 255, 140),
        auto_comment: c(120, 220, 140),
        jump: c(100, 200, 255),
        call: c(255, 220, 80),
        ret: c(255, 100, 100),
        nop: c(160, 160, 160),
        data: c(220, 180, 255),
        string: c(255, 210, 140),
        label: c(160, 220, 255),
        func: c(255, 240, 120),
        segment: c(180, 190, 200),
        unknown: c(200, 180, 160),
        kw: c(220, 160, 255),
        ctype: c(100, 230, 180),
        number: c(255, 200, 120),
        punct: c(200, 200, 200),
        row_selected: c(40, 80, 160),
        row_pc: c(140, 100, 0),
        row_hover: c(50, 50, 60),
        bp: c(255, 60, 60),
        pc_arrow: c(255, 230, 60),
        band_bg: Color32::BLACK,
        band_code: c(80, 140, 255),
        band_func: c(100, 160, 255),
        band_data: c(180, 180, 180),
        band_string: c(255, 180, 60),
        band_unknown: c(80, 80, 80),
        band_cursor: c(255, 255, 0),
        log_info: Color32::WHITE,
        log_warn: c(255, 220, 80),
        log_error: c(255, 80, 80),
        log_echo: c(120, 180, 255),
        header_bg: c(10, 10, 14),
        header_text: c(200, 200, 210),
        panel_bg: Color32::BLACK,
        muted: c(160, 160, 170),
    }
}

impl ListingColors {
    pub fn for_theme(theme: UiTheme) -> Self {
        match theme {
            UiTheme::Dark => dark_colors(),
            UiTheme::Light => light_colors(),
            UiTheme::Contrast => contrast_colors(),
        }
    }

    pub fn log_color(&self, level: crate::LogLevel) -> Color32 {
        match level {
            crate::LogLevel::Info => self.log_info,
            crate::LogLevel::Warn => self.log_warn,
            crate::LogLevel::Error => self.log_error,
            crate::LogLevel::Echo => self.log_echo,
        }
    }

    pub fn style_for_mnemonic(&self, mnemonic: &str, flow: ceasta_disasm::Flow) -> Color32 {
        use ceasta_disasm::Flow;
        let m = mnemonic.to_ascii_lowercase();
        if m == "nop" || m.starts_with("nop ") {
            return self.nop;
        }
        if m == "ret" || m == "retn" || m == "retf" || m == "leave" {
            return self.ret;
        }
        match flow {
            Flow::Call => self.call,
            Flow::Jump | Flow::Cond => self.jump,
            Flow::Ret | Flow::Stop => self.ret,
            Flow::Normal => self.text,
        }
    }
}

/// Font sizes used across panels.
#[derive(Clone, Debug)]
pub struct FontSizes {
    pub ui: f32,
    pub mono: f32,
    pub header: f32,
    pub title: f32,
}

impl Default for FontSizes {
    fn default() -> Self {
        Self {
            ui: 14.0,
            mono: 13.0,
            header: 13.0,
            title: 22.0,
        }
    }
}

impl FontSizes {
    pub fn clamp(mut self) -> Self {
        self.ui = self.ui.clamp(10.0, 28.0);
        self.mono = self.mono.clamp(10.0, 28.0);
        self.header = self.header.clamp(10.0, 24.0);
        self.title = self.title.clamp(16.0, 40.0);
        self
    }

    pub fn bump(&mut self, delta: f32) {
        self.ui = (self.ui + delta).clamp(10.0, 28.0);
        self.mono = (self.mono + delta).clamp(10.0, 28.0);
        self.header = (self.header + delta).clamp(10.0, 24.0);
    }

    pub fn mono_id(&self) -> FontId {
        FontId::new(self.mono, FontFamily::Monospace)
    }

    pub fn ui_id(&self) -> FontId {
        FontId::new(self.ui, FontFamily::Proportional)
    }

    pub fn header_id(&self) -> FontId {
        FontId::new(self.header, FontFamily::Proportional)
    }

    pub fn title_id(&self) -> FontId {
        FontId::new(self.title, FontFamily::Proportional)
    }
}

/// Apply theme colors + font sizes to an egui context.
pub fn apply(ctx: &egui::Context, theme: UiTheme, fonts: &FontSizes) {
    let colors = ListingColors::for_theme(theme);
    let mut style = (*ctx.style()).clone();
    style.text_styles.insert(
        egui::TextStyle::Body,
        FontId::new(fonts.ui, FontFamily::Proportional),
    );
    style.text_styles.insert(
        egui::TextStyle::Button,
        FontId::new(fonts.ui, FontFamily::Proportional),
    );
    style.text_styles.insert(
        egui::TextStyle::Heading,
        FontId::new(fonts.header + 2.0, FontFamily::Proportional),
    );
    style.text_styles.insert(
        egui::TextStyle::Monospace,
        FontId::new(fonts.mono, FontFamily::Monospace),
    );
    style.text_styles.insert(
        egui::TextStyle::Small,
        FontId::new((fonts.ui - 2.0).max(10.0), FontFamily::Proportional),
    );
    style.spacing.item_spacing = egui::vec2(6.0_f32, 4.0_f32);
    style.spacing.window_margin = egui::Margin::same(6);
    style.visuals = match theme {
        UiTheme::Dark | UiTheme::Contrast => dark_visuals(&colors, theme == UiTheme::Contrast),
        UiTheme::Light => light_visuals(&colors),
    };
    ctx.set_style(style);
}

fn dark_visuals(colors: &ListingColors, contrast: bool) -> Visuals {
    let mut v = Visuals::dark();
    v.override_text_color = Some(colors.text);
    v.widgets.noninteractive.bg_fill = colors.panel_bg;
    v.widgets.inactive.bg_fill = if contrast {
        Color32::from_rgb(20, 20, 24)
    } else {
        Color32::from_rgb(32, 34, 42)
    };
    v.widgets.hovered.bg_fill = Color32::from_rgb(48, 52, 64);
    v.widgets.active.bg_fill = Color32::from_rgb(56, 64, 88);
    v.selection.bg_fill = colors.row_selected;
    v.panel_fill = colors.panel_bg;
    v.window_fill = colors.panel_bg;
    v.extreme_bg_color = Color32::from_rgb(14, 16, 20);
    v.faint_bg_color = colors.header_bg;
    v.window_stroke = Stroke::new(1.0_f32, Color32::from_rgb(50, 54, 64));
    v.window_corner_radius = CornerRadius::same(2);
    v.menu_corner_radius = CornerRadius::same(2);
    v
}

fn light_visuals(colors: &ListingColors) -> Visuals {
    let mut v = Visuals::light();
    v.override_text_color = Some(colors.text);
    v.widgets.noninteractive.bg_fill = colors.panel_bg;
    v.selection.bg_fill = colors.row_selected;
    v.panel_fill = colors.panel_bg;
    v.window_fill = colors.panel_bg;
    v.faint_bg_color = colors.header_bg;
    v.window_corner_radius = CornerRadius::same(2);
    v.menu_corner_radius = CornerRadius::same(2);
    v
}

/// Shortcut label helper (Ctrl vs Cmd on macOS — egui already remaps modifiers).
pub fn keys(label: &str) -> String {
    #[cfg(target_os = "macos")]
    {
        label
            .replace("Ctrl+", "Cmd+")
            .replace("ctrl+", "cmd+")
            .replace("Alt+F4", "Cmd+Q")
    }
    #[cfg(not(target_os = "macos"))]
    {
        label.to_string()
    }
}

/// Small utility: paint a solid header strip above a panel section.
pub fn section_header(ui: &mut egui::Ui, colors: &ListingColors, title: &str, detail: &str) {
    let avail = ui.available_width();
    let (rect, _) = ui.allocate_exact_size(
        egui::vec2(avail, ui.spacing().interact_size.y),
        egui::Sense::hover(),
    );
    ui.painter()
        .rect_filled(rect, CornerRadius::ZERO, colors.header_bg);
    ui.painter().text(
        rect.left_center() + egui::vec2(8.0, 0.0),
        egui::Align2::LEFT_CENTER,
        title,
        FontId::new(12.0, FontFamily::Proportional),
        colors.header_text,
    );
    if !detail.is_empty() {
        ui.painter().text(
            rect.right_center() - egui::vec2(8.0, 0.0),
            egui::Align2::RIGHT_CENTER,
            detail,
            FontId::new(11.0, FontFamily::Monospace),
            colors.muted,
        );
    }
}

/// Format a byte as two hex digits.
pub fn hex_byte(b: u8) -> String {
    format!("{b:02X}")
}

/// Format an address with a fixed width.
pub fn hex_addr(addr: u64, is64: bool) -> String {
    if is64 {
        format!("{addr:016X}")
    } else {
        format!("{addr:08X}")
    }
}

/// Compact hex (no leading zeros beyond one digit).
pub fn hex_compact(addr: u64) -> String {
    format!("{addr:X}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn theme_cycle() {
        assert_eq!(UiTheme::Dark.next(), UiTheme::Light);
        assert_eq!(UiTheme::Contrast.next(), UiTheme::Dark);
    }

    #[test]
    fn font_clamp() {
        let f = FontSizes {
            ui: 100.0,
            mono: 1.0,
            header: 50.0,
            title: 5.0,
        }
        .clamp();
        assert!(f.ui <= 28.0);
        assert!(f.mono >= 10.0);
    }
}
