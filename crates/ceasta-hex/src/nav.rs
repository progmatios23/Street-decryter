//! Hex view navigation / caret state.

#[derive(Clone, Debug)]
pub struct HexViewState {
    pub top_addr: u64,
    pub caret: HexCaret,
    pub rows: usize,
    pub cols: usize,
    pub selection: Option<(u64, u64)>,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct HexCaret {
    pub addr: u64,
    /// 0 = high nibble, 1 = low nibble, 2 = ascii pane
    pub nibble: u8,
    pub in_ascii: bool,
}

impl Default for HexViewState {
    fn default() -> Self {
        Self {
            top_addr: 0,
            caret: HexCaret::default(),
            rows: 16,
            cols: 16,
            selection: None,
        }
    }
}

impl HexViewState {
    pub fn page_bytes(&self) -> usize {
        self.rows.saturating_mul(self.cols.max(1))
    }

    pub fn goto(&mut self, addr: u64) {
        self.caret.addr = addr;
        let page = self.page_bytes() as u64;
        if page == 0 {
            self.top_addr = addr;
            return;
        }
        if addr < self.top_addr || addr >= self.top_addr + page {
            self.top_addr = addr & !((self.cols as u64).saturating_sub(1));
        }
    }

    pub fn move_by(&mut self, delta: i64) {
        let a = if delta >= 0 {
            self.caret.addr.saturating_add(delta as u64)
        } else {
            self.caret.addr.saturating_sub((-delta) as u64)
        };
        self.goto(a);
    }

    pub fn page_down(&mut self) {
        self.move_by(self.page_bytes() as i64);
    }

    pub fn page_up(&mut self) {
        self.move_by(-(self.page_bytes() as i64));
    }

    pub fn select_to(&mut self, addr: u64) {
        let start = self.selection.map(|(s, _)| s).unwrap_or(self.caret.addr);
        let (a, b) = if start <= addr {
            (start, addr)
        } else {
            (addr, start)
        };
        self.selection = Some((a, b));
        self.caret.addr = addr;
    }

    pub fn clear_selection(&mut self) {
        self.selection = None;
    }

    pub fn selection_len(&self) -> u64 {
        match self.selection {
            Some((a, b)) => b.saturating_sub(a).saturating_add(1),
            None => 0,
        }
    }
}

pub fn offset_of_addr(base: u64, addr: u64) -> Option<usize> {
    if addr < base {
        None
    } else {
        Some((addr - base) as usize)
    }
}

pub fn addr_of_offset(base: u64, offset: usize) -> u64 {
    base.saturating_add(offset as u64)
}

pub fn column_at(offset: usize, cols: usize) -> usize {
    if cols == 0 {
        0
    } else {
        offset % cols
    }
}

pub fn row_at(offset: usize, cols: usize) -> usize {
    if cols == 0 {
        0
    } else {
        offset / cols
    }
}

/// Hit-test: given pixel-ish column index in the hex pane, return byte index in row.
pub fn hit_test_hex_col(col: usize, group: usize) -> Option<usize> {
    // each byte is "XX " (3 cols), plus group spaces
    // simplified: ignore group gaps for hit testing helpers used by UI
    let _ = group;
    Some(col / 3)
}
