//! Disassembly — pure Rust x86/x64 via iced-x86.

use ceasta_binary::{Arch, Binary};
use iced_x86::{
    Code, Decoder, DecoderOptions, Formatter, Instruction, IntelFormatter, MemorySize, Mnemonic,
    OpKind, Register,
};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("unsupported arch for the rust decoder: {0:?} (arm64 comes next)")]
    UnsupportedArch(Arch),
    #[error("no bytes at {0:#x}")]
    Unmapped(u64),
}

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Clone, Debug)]
pub struct Insn {
    pub addr: u64,
    pub size: u32,
    pub bytes: [u8; 16],
    pub mnemonic: String,
    pub operands: String,
    pub text: String,
    pub flow: Flow,
    /// Direct near/far branch target when known.
    pub target: Option<u64>,
    /// Branch through a register or memory operand.
    pub indirect: bool,
    /// Absolute address of a resolved memory operand (RIP-relative or absolute).
    pub mem: Option<u64>,
    pub mem_size: u8,
    pub mem_rip: bool,
    /// `mem` is an address computation (LEA), not a load/store.
    pub is_lea: bool,
    pub mem_write: bool,
    /// Non-branch immediate (push/mov imm, etc.).
    pub imm: Option<u64>,
    pub code: u32,
}

impl Insn {
    pub fn next(&self) -> u64 {
        self.addr + u64::from(self.size)
    }

    pub fn is_branch(&self) -> bool {
        matches!(self.flow, Flow::Jump | Flow::Cond | Flow::Call)
    }

    pub fn is_nop(&self) -> bool {
        matches!(
            Code::try_from(self.code as usize).ok(),
            Some(
                Code::Nopd
                    | Code::Nopw
                    | Code::Nopq
                    | Code::Nop_rm16
                    | Code::Nop_rm32
                    | Code::Nop_rm64
                    | Code::Pause
            )
        ) || self.mnemonic.eq_ignore_ascii_case("nop")
    }

    pub fn is_endbr(&self) -> bool {
        matches!(
            Code::try_from(self.code as usize).ok(),
            Some(Code::Endbr32 | Code::Endbr64)
        )
    }

    pub fn is_int3(&self) -> bool {
        self.size == 1 && self.bytes[0] == 0xcc
    }

    pub fn is_push(&self) -> bool {
        self.mnemonic.eq_ignore_ascii_case("push")
    }

    pub fn is_move(&self) -> bool {
        matches!(
            self.mnemonic.as_str(),
            "mov" | "movzx" | "movsx" | "movsxd" | "movaps" | "movdqa" | "movdqu"
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Flow {
    Normal,
    Jump,
    Cond,
    Call,
    Ret,
    Stop,
}

pub fn decode_at(bin: &Binary, addr: u64) -> Result<Insn> {
    match bin.arch {
        Arch::X86 | Arch::X64 => decode_x86(bin, addr),
        Arch::Arm64 => Err(Error::UnsupportedArch(Arch::Arm64)),
    }
}

fn decode_x86(bin: &Binary, addr: u64) -> Result<Insn> {
    let mut buf = [0u8; 16];
    let n = bin.read(addr, &mut buf);
    if n == 0 {
        return Err(Error::Unmapped(addr));
    }
    let bitness = bin.arch.bits();
    let mut decoder = Decoder::with_ip(bitness, &buf[..n], addr, DecoderOptions::NONE);
    let mut inst = Instruction::default();
    decoder.decode_out(&mut inst);
    if inst.is_invalid() || inst.len() == 0 {
        return Err(Error::Unmapped(addr));
    }

    let mut formatter = IntelFormatter::new();
    let mut text = String::new();
    formatter.format(&inst, &mut text);

    let (mnemonic, operands) = match text.split_once(' ') {
        Some((m, o)) => (m.to_string(), o.trim().to_string()),
        None => (text.clone(), String::new()),
    };

    let (flow, target, indirect) = classify(&inst);
    let (mem, mem_size, mem_rip, is_lea, mem_write) = mem_info(&inst);
    let imm = non_branch_imm(&inst, flow);

    let mut bytes = [0u8; 16];
    let len = inst.len().min(16);
    bytes[..len].copy_from_slice(&buf[..len]);

    Ok(Insn {
        addr,
        size: inst.len() as u32,
        bytes,
        mnemonic,
        operands,
        text,
        flow,
        target,
        indirect,
        mem,
        mem_size,
        mem_rip,
        is_lea,
        mem_write,
        imm,
        code: inst.code() as u32,
    })
}

fn classify(inst: &Instruction) -> (Flow, Option<u64>, bool) {
    use iced_x86::FlowControl;
    match inst.flow_control() {
        FlowControl::Next => (Flow::Normal, None, false),
        FlowControl::UnconditionalBranch => {
            if is_indirect_branch(inst) {
                (Flow::Jump, None, true)
            } else {
                (
                    Flow::Jump,
                    Some(inst.near_branch_target()).filter(|&t| t != 0),
                    false,
                )
            }
        }
        FlowControl::ConditionalBranch => (
            Flow::Cond,
            Some(inst.near_branch_target()).filter(|&t| t != 0),
            false,
        ),
        FlowControl::Call => {
            if is_indirect_branch(inst) {
                (Flow::Call, None, true)
            } else {
                (
                    Flow::Call,
                    Some(inst.near_branch_target()).filter(|&t| t != 0),
                    false,
                )
            }
        }
        FlowControl::Return => (Flow::Ret, None, false),
        FlowControl::Interrupt | FlowControl::Exception | FlowControl::XbeginXabortXend => {
            (Flow::Stop, None, false)
        }
        FlowControl::IndirectBranch => (Flow::Jump, None, true),
        FlowControl::IndirectCall => (Flow::Call, None, true),
    }
}

fn is_indirect_branch(inst: &Instruction) -> bool {
    matches!(
        inst.op0_kind(),
        OpKind::Register | OpKind::Memory | OpKind::MemorySegSI | OpKind::MemorySegESI
            | OpKind::MemorySegRSI | OpKind::MemoryESDI | OpKind::MemoryESEDI
            | OpKind::MemoryESRDI
    ) && !matches!(
        inst.op0_kind(),
        OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64
            | OpKind::FarBranch16 | OpKind::FarBranch32
    )
}

fn mem_info(inst: &Instruction) -> (Option<u64>, u8, bool, bool, bool) {
    let is_lea = inst.mnemonic() == Mnemonic::Lea;
    let mut mem = None;
    let mut mem_rip = false;
    let mut mem_write = false;
    let mut mem_size = 0u8;

    for i in 0..inst.op_count() {
        let kind = inst.op_kind(i);
        if !matches!(
            kind,
            OpKind::Memory
                | OpKind::MemorySegSI
                | OpKind::MemorySegESI
                | OpKind::MemorySegRSI
                | OpKind::MemoryESDI
                | OpKind::MemoryESEDI
                | OpKind::MemoryESRDI
        ) {
            continue;
        }
        mem_size = memory_size_bytes(inst.memory_size());
        if i == 0 && !is_lea {
            mem_write = true;
        }
        if inst.is_ip_rel_memory_operand() {
            mem = Some(inst.ip_rel_memory_address());
            mem_rip = true;
        } else if inst.memory_base() == Register::None
            && inst.memory_index() == Register::None
            && inst.memory_displ_size() > 0
        {
            // Absolute displacement (common in 32-bit and some 64-bit forms).
            mem = Some(inst.memory_displacement64());
        }
        break;
    }

    (mem, mem_size, mem_rip, is_lea, mem_write)
}

fn memory_size_bytes(ms: MemorySize) -> u8 {
    match ms.size() {
        n if n > 0 && n <= 255 => n as u8,
        _ => 0,
    }
}

fn non_branch_imm(inst: &Instruction, flow: Flow) -> Option<u64> {
    if matches!(flow, Flow::Jump | Flow::Cond | Flow::Call) {
        return None;
    }
    for i in 0..inst.op_count() {
        match inst.op_kind(i) {
            OpKind::Immediate8
            | OpKind::Immediate8_2nd
            | OpKind::Immediate16
            | OpKind::Immediate32
            | OpKind::Immediate64
            | OpKind::Immediate8to16
            | OpKind::Immediate8to32
            | OpKind::Immediate8to64
            | OpKind::Immediate32to64 => {
                return Some(inst.immediate(i));
            }
            _ => {}
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use ceasta_binary::{Arch, Binary, Format, Segment, PERM_R, PERM_X};

    fn text_bin(bytes: &[u8]) -> Binary {
        let mut bin = Binary::empty("t.bin", Format::Raw, Arch::X64);
        bin.base = 0x1000;
        bin.segments.push(Segment {
            name: ".text".into(),
            start: 0x1000,
            end: 0x1000 + bytes.len() as u64,
            perms: PERM_R | PERM_X,
            file_off: 0,
            file_size: bytes.len() as u64,
            data: bytes.to_vec(),
        });
        bin
    }

    #[test]
    fn decodes_nop() {
        let bin = text_bin(&[0x90]);
        let insn = decode_at(&bin, 0x1000).unwrap();
        assert_eq!(insn.mnemonic, "nop");
        assert_eq!(insn.size, 1);
        assert!(insn.is_nop());
    }

    #[test]
    fn decodes_call_rel() {
        // e8 00 00 00 00  — call next
        let bin = text_bin(&[0xe8, 0x00, 0x00, 0x00, 0x00]);
        let insn = decode_at(&bin, 0x1000).unwrap();
        assert_eq!(insn.flow, Flow::Call);
        assert_eq!(insn.target, Some(0x1005));
        assert!(!insn.indirect);
    }

    #[test]
    fn decodes_rip_lea() {
        // 48 8d 05 00 00 00 00 — lea rax, [rip+0]
        let bin = text_bin(&[0x48, 0x8d, 0x05, 0x00, 0x00, 0x00, 0x00]);
        let insn = decode_at(&bin, 0x1000).unwrap();
        assert!(insn.is_lea);
        assert_eq!(insn.mem, Some(0x1007));
        assert!(insn.mem_rip);
    }
}
