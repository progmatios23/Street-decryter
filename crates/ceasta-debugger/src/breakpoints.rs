//! Software breakpoint bookkeeping (INT3 / 0xCC). Original bytes are restored on remove.

use std::collections::HashMap;

pub const INT3: u8 = 0xCC;

#[derive(Debug, Default)]
pub struct BreakpointStore {
    /// address → original byte under the INT3
    sites: HashMap<u64, u8>,
    temp: Option<(u64, u8, String)>,
    /// address to re-arm after a single-step past a permanent BP
    pub reinsert: Option<u64>,
}

impl BreakpointStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn has(&self, addr: u64) -> bool {
        self.sites.contains_key(&addr)
            || self
                .temp
                .as_ref()
                .map(|(a, _, _)| *a == addr)
                .unwrap_or(false)
    }

    pub fn original(&self, addr: u64) -> Option<u8> {
        if let Some(b) = self.sites.get(&addr) {
            return Some(*b);
        }
        self.temp
            .as_ref()
            .filter(|(a, _, _)| *a == addr)
            .map(|(_, b, _)| *b)
    }

    pub fn iter_permanent(&self) -> impl Iterator<Item = (u64, u8)> + '_ {
        self.sites.iter().map(|(a, b)| (*a, *b))
    }

    pub fn insert_permanent(&mut self, addr: u64, orig: u8) {
        self.sites.insert(addr, orig);
    }

    pub fn remove_permanent(&mut self, addr: u64) -> Option<u8> {
        if self.reinsert == Some(addr) {
            self.reinsert = None;
        }
        let orig = self.sites.remove(&addr)?;
        if let Some((t, _, _)) = self.temp {
            if t == addr {
                // keep temp's view of the original byte in sync
                if let Some(t) = self.temp.as_mut() {
                    t.1 = orig;
                }
                return Some(orig);
            }
        }
        Some(orig)
    }

    pub fn set_temp(&mut self, addr: u64, orig: u8, reason: impl Into<String>) {
        self.clear_temp_meta();
        self.temp = Some((addr, orig, reason.into()));
    }

    pub fn take_temp(&mut self) -> Option<(u64, u8, String)> {
        self.temp.take()
    }

    pub fn temp(&self) -> Option<(u64, u8, &str)> {
        self.temp
            .as_ref()
            .map(|(a, b, r)| (*a, *b, r.as_str()))
    }

    pub fn clear_temp_meta(&mut self) {
        self.temp = None;
    }

    pub fn hide_int3(&self, addr: u64, byte: u8) -> u8 {
        if byte == INT3 {
            if let Some(orig) = self.original(addr) {
                return orig;
            }
        }
        byte
    }
}
