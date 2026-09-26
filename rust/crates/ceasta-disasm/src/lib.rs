//! Disassembly — pure Rust x86/x64 via iced-x86.

use ceasta_binary::{Arch, Binary};
use iced_x86::{Decoder, DecoderOptions, Formatter, Instruction, IntelFormatter};
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
    pub mnemonic: String,
    pub operands: String,
    pub text: String,
    pub flow: Flow,
    pub target: Option<u64>,
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

    let (flow, target) = classify(&inst);

    Ok(Insn {
        addr,
        size: inst.len() as u32,
        mnemonic,
        operands,
        text,
        flow,
        target,
    })
}

fn classify(inst: &Instruction) -> (Flow, Option<u64>) {
    use iced_x86::FlowControl;
    match inst.flow_control() {
        FlowControl::Next => (Flow::Normal, None),
        FlowControl::UnconditionalBranch => {
            (Flow::Jump, Some(inst.near_branch_target()).filter(|&t| t != 0))
        }
        FlowControl::ConditionalBranch => {
            (Flow::Cond, Some(inst.near_branch_target()).filter(|&t| t != 0))
        }
        FlowControl::Call => (Flow::Call, Some(inst.near_branch_target()).filter(|&t| t != 0)),
        FlowControl::Return => (Flow::Ret, None),
        FlowControl::Interrupt | FlowControl::Exception | FlowControl::XbeginXabortXend => {
            (Flow::Stop, None)
        }
        _ => (Flow::Normal, None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ceasta_binary::{Arch, Binary, Format, Segment, PERM_R, PERM_X};

    #[test]
    fn decodes_nop() {
        let mut bin = Binary::empty("nop.bin", Format::Raw, Arch::X64);
        bin.base = 0x1000;
        bin.segments.push(Segment {
            name: ".text".into(),
            start: 0x1000,
            end: 0x1001,
            perms: PERM_R | PERM_X,
            file_off: 0,
            file_size: 1,
            data: vec![0x90],
        });
        let insn = decode_at(&bin, 0x1000).unwrap();
        assert_eq!(insn.mnemonic, "nop");
        assert_eq!(insn.size, 1);
    }
}
