//! Byte classification for hex view colouring.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ByteClass {
    Empty,
    Zero,
    Printable,
    Whitespace,
    HighBit,
    Ff,
    Other,
}

impl ByteClass {
    pub fn as_str(self) -> &'static str {
        match self {
            ByteClass::Empty => "empty",
            ByteClass::Zero => "zero",
            ByteClass::Printable => "printable",
            ByteClass::Whitespace => "ws",
            ByteClass::HighBit => "high",
            ByteClass::Ff => "ff",
            ByteClass::Other => "other",
        }
    }
}

pub fn classify_byte(b: u8) -> ByteClass {
    match b {
        0x00 => ByteClass::Zero,
        0xff => ByteClass::Ff,
        0x09 | 0x0a | 0x0d => ByteClass::Whitespace,
        0x20..=0x7e => ByteClass::Printable,
        0x80..=0xfe => ByteClass::HighBit,
        _ => ByteClass::Other,
    }
}

pub fn ascii_glyph(b: u8) -> char {
    match b {
        0x20..=0x7e => b as char,
        _ => '.',
    }
}

/// Simple palette indices the UI can map to colours.
#[derive(Clone, Copy, Debug)]
pub struct HexPalette {
    pub zero: u32,
    pub printable: u32,
    pub high: u32,
    pub ff: u32,
    pub other: u32,
    pub addr: u32,
    pub ascii: u32,
}

impl Default for HexPalette {
    fn default() -> Self {
        Self {
            zero: 0x6_6666_66,
            printable: 0xff_d4_d4_d4,
            high: 0xff_c9_a2_6e,
            ff: 0xff_e0_6c_75,
            other: 0xff_a0_a0_a0,
            addr: 0xff_7a_a2_f7,
            ascii: 0xff_98_c3_79,
        }
    }
}

impl HexPalette {
    pub fn color_for(self, c: ByteClass) -> u32 {
        match c {
            ByteClass::Empty => 0x00_0000_00,
            ByteClass::Zero => self.zero,
            ByteClass::Printable | ByteClass::Whitespace => self.printable,
            ByteClass::HighBit => self.high,
            ByteClass::Ff => self.ff,
            ByteClass::Other => self.other,
        }
    }
}

/// Named colour themes.
pub fn theme_dark() -> HexPalette {
    HexPalette::default()
}

pub fn theme_light() -> HexPalette {
    HexPalette {
        zero: 0xff_bb_bb_bb,
        printable: 0xff_22_22_22,
        high: 0xff_a0_60_00,
        ff: 0xff_c0_20_20,
        other: 0xff_55_55_55,
        addr: 0xff_20_40_a0,
        ascii: 0xff_20_80_40,
    }
}

pub fn theme_green_phosphor() -> HexPalette {
    HexPalette {
        zero: 0xff_1a_3a_1a,
        printable: 0xff_33_ff_66,
        high: 0xff_88_ff_88,
        ff: 0xff_cc_ff_cc,
        other: 0xff_22_aa_44,
        addr: 0xff_66_ff_99,
        ascii: 0xff_44_dd_66,
    }
}
