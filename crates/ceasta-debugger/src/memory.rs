//! Memory helpers built on word-sized peek/poke (ptrace PEEKDATA / POKEDATA).

use crate::Result;
use std::mem::size_of;

pub type Word = usize;

/// Read `buf.len()` bytes starting at `addr` via `peek(aligned_word_addr) -> Word`.
pub fn read_bytes<F>(addr: u64, buf: &mut [u8], mut peek: F) -> Result<usize>
where
    F: FnMut(u64) -> Result<Word>,
{
    if buf.is_empty() {
        return Ok(0);
    }
    let word = size_of::<Word>() as u64;
    let mut done = 0usize;
    while done < buf.len() {
        let cur = addr + done as u64;
        let aligned = cur & !(word - 1);
        let w = match peek(aligned) {
            Ok(v) => v,
            Err(_) if done > 0 => break,
            Err(e) => return Err(e),
        };
        let bytes = w.to_ne_bytes();
        let off = (cur - aligned) as usize;
        for i in off..bytes.len() {
            if done >= buf.len() {
                break;
            }
            buf[done] = bytes[i];
            done += 1;
        }
    }
    Ok(done)
}

/// Write `data` starting at `addr` via peek + poke of whole words.
pub fn write_bytes<FPeek, FPoke>(
    addr: u64,
    data: &[u8],
    mut peek: FPeek,
    mut poke: FPoke,
) -> Result<()>
where
    FPeek: FnMut(u64) -> Result<Word>,
    FPoke: FnMut(u64, Word) -> Result<()>,
{
    if data.is_empty() {
        return Ok(());
    }
    let word = size_of::<Word>() as u64;
    let mut i = 0usize;
    while i < data.len() {
        let cur = addr + i as u64;
        let aligned = cur & !(word - 1);
        let mut bytes = peek(aligned)?.to_ne_bytes();
        let mut off = (cur - aligned) as usize;
        while off < bytes.len() && i < data.len() {
            bytes[off] = data[i];
            off += 1;
            i += 1;
        }
        let new_word = Word::from_ne_bytes(bytes);
        poke(aligned, new_word)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Error;

    #[test]
    fn read_write_roundtrip() {
        let mut mem = [0u8; 32];
        // seed
        for (i, b) in mem.iter_mut().enumerate() {
            *b = i as u8;
        }
        let peek = |addr: u64| -> Result<Word> {
            let i = addr as usize;
            if i + 8 > mem.len() {
                return Err(Error::Msg("oob".into()));
            }
            let mut buf = [0u8; 8];
            buf.copy_from_slice(&mem[i..i + 8]);
            Ok(Word::from_ne_bytes(buf))
        };
        // need interior mutability for poke in test — use a cell
        use std::cell::RefCell;
        let cell = RefCell::new(mem);
        let peek2 = |addr: u64| -> Result<Word> {
            let m = cell.borrow();
            let i = addr as usize;
            if i + 8 > m.len() {
                return Err(Error::Msg("oob".into()));
            }
            let mut buf = [0u8; 8];
            buf.copy_from_slice(&m[i..i + 8]);
            Ok(Word::from_ne_bytes(buf))
        };
        let poke2 = |addr: u64, w: Word| -> Result<()> {
            let mut m = cell.borrow_mut();
            let i = addr as usize;
            if i + 8 > m.len() {
                return Err(Error::Msg("oob".into()));
            }
            m[i..i + 8].copy_from_slice(&w.to_ne_bytes());
            Ok(())
        };
        write_bytes(3, &[0xAA, 0xBB, 0xCC], peek2, poke2).unwrap();
        let mut out = [0u8; 3];
        assert_eq!(read_bytes(3, &mut out, peek2).unwrap(), 3);
        assert_eq!(out, [0xAA, 0xBB, 0xCC]);
        let _ = peek;
    }
}
