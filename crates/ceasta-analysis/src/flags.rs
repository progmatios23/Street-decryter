//! IDA-style per-byte flags (matches C++ `fl_*`).

pub const FL_CODE: u8 = 1;
pub const FL_TAIL: u8 = 2;
pub const FL_FUNC: u8 = 4;
pub const FL_STR: u8 = 8;
pub const FL_DATA: u8 = 16;
pub const FL_LABEL: u8 = 32;
