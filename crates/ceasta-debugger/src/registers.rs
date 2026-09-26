//! Register values presented to callers (x86_64 GPRs first).

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegValue {
    pub name: String,
    pub value: u64,
}

impl RegValue {
    pub fn new(name: impl Into<String>, value: u64) -> Self {
        Self {
            name: name.into(),
            value,
        }
    }
}

/// Snapshot of the common x86_64 general-purpose registers.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct X64Regs {
    pub rax: u64,
    pub rbx: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub rbp: u64,
    pub rsp: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    pub rip: u64,
    pub eflags: u64,
    pub cs: u64,
    pub ss: u64,
    pub ds: u64,
    pub es: u64,
    pub fs: u64,
    pub gs: u64,
    pub fs_base: u64,
    pub gs_base: u64,
    pub orig_rax: u64,
}

impl X64Regs {
    pub fn pc(&self) -> u64 {
        self.rip
    }

    pub fn sp(&self) -> u64 {
        self.rsp
    }

    pub fn to_list(&self) -> Vec<RegValue> {
        vec![
            RegValue::new("rax", self.rax),
            RegValue::new("rbx", self.rbx),
            RegValue::new("rcx", self.rcx),
            RegValue::new("rdx", self.rdx),
            RegValue::new("rsi", self.rsi),
            RegValue::new("rdi", self.rdi),
            RegValue::new("rbp", self.rbp),
            RegValue::new("rsp", self.rsp),
            RegValue::new("r8", self.r8),
            RegValue::new("r9", self.r9),
            RegValue::new("r10", self.r10),
            RegValue::new("r11", self.r11),
            RegValue::new("r12", self.r12),
            RegValue::new("r13", self.r13),
            RegValue::new("r14", self.r14),
            RegValue::new("r15", self.r15),
            RegValue::new("rip", self.rip),
            RegValue::new("eflags", self.eflags),
            RegValue::new("cs", self.cs),
            RegValue::new("ss", self.ss),
            RegValue::new("ds", self.ds),
            RegValue::new("es", self.es),
            RegValue::new("fs", self.fs),
            RegValue::new("gs", self.gs),
            RegValue::new("fs_base", self.fs_base),
            RegValue::new("gs_base", self.gs_base),
            RegValue::new("orig_rax", self.orig_rax),
        ]
    }
}
