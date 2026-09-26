//! Hex pattern search helpers.

#[derive(Clone, Debug)]
pub struct HexNeedle {
    pub bytes: Vec<Option<u8>>,
}

impl HexNeedle {
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    pub fn matches_at(&self, data: &[u8], off: usize) -> bool {
        if off + self.bytes.len() > data.len() {
            return false;
        }
        self.bytes.iter().enumerate().all(|(i, b)| match b {
            None => true,
            Some(x) => data[off + i] == *x,
        })
    }
}

pub fn parse_hex_nibbles(pattern: &str) -> Result<HexNeedle, String> {
    let mut bytes = Vec::new();
    for tok in pattern.split_whitespace() {
        if tok == "?" || tok == "??" {
            bytes.push(None);
            continue;
        }
        if tok.len() != 2 {
            return Err(format!("bad hex byte: {tok}"));
        }
        let v = u8::from_str_radix(tok, 16).map_err(|_| format!("bad hex byte: {tok}"))?;
        bytes.push(Some(v));
    }
    if bytes.is_empty() {
        return Err("empty pattern".into());
    }
    Ok(HexNeedle { bytes })
}

pub fn find_hex_pattern(data: &[u8], needle: &HexNeedle, max: usize) -> Vec<usize> {
    let mut hits = Vec::new();
    if needle.is_empty() || data.len() < needle.len() {
        return hits;
    }
    for i in 0..=data.len() - needle.len() {
        if needle.matches_at(data, i) {
            hits.push(i);
            if hits.len() >= max {
                break;
            }
        }
    }
    hits
}

pub fn find_in_binary(
    bin: &ceasta_binary::Binary,
    pattern: &str,
    max: usize,
) -> Result<Vec<u64>, String> {
    let needle = parse_hex_nibbles(pattern)?;
    let mut hits = Vec::new();
    for seg in &bin.segments {
        for off in find_hex_pattern(&seg.data, &needle, max.saturating_sub(hits.len())) {
            hits.push(seg.start + off as u64);
            if hits.len() >= max {
                return Ok(hits);
            }
        }
    }
    Ok(hits)
}


pub fn find_nop_slide(data: &[u8], max: usize) -> Vec<usize> {
    let needle = parse_hex_nibbles("90 90 90 90").expect("static pattern");
    find_hex_pattern(data, &needle, max)
}

pub fn find_int3(data: &[u8], max: usize) -> Vec<usize> {
    let needle = parse_hex_nibbles("CC").expect("static pattern");
    find_hex_pattern(data, &needle, max)
}

pub fn find_ret(data: &[u8], max: usize) -> Vec<usize> {
    let needle = parse_hex_nibbles("C3").expect("static pattern");
    find_hex_pattern(data, &needle, max)
}

pub fn find_xor_eax(data: &[u8], max: usize) -> Vec<usize> {
    let needle = parse_hex_nibbles("31 C0").expect("static pattern");
    find_hex_pattern(data, &needle, max)
}

pub fn find_xor_rax(data: &[u8], max: usize) -> Vec<usize> {
    let needle = parse_hex_nibbles("48 31 C0").expect("static pattern");
    find_hex_pattern(data, &needle, max)
}

pub fn find_call_rel(data: &[u8], max: usize) -> Vec<usize> {
    let needle = parse_hex_nibbles("E8 ?? ?? ?? ??").expect("static pattern");
    find_hex_pattern(data, &needle, max)
}

pub fn find_jmp_rel(data: &[u8], max: usize) -> Vec<usize> {
    let needle = parse_hex_nibbles("E9 ?? ?? ?? ??").expect("static pattern");
    find_hex_pattern(data, &needle, max)
}

pub fn find_lea_rip(data: &[u8], max: usize) -> Vec<usize> {
    let needle = parse_hex_nibbles("48 8D ?? ??").expect("static pattern");
    find_hex_pattern(data, &needle, max)
}

pub fn find_mov_rax_imm(data: &[u8], max: usize) -> Vec<usize> {
    let needle = parse_hex_nibbles("48 B8").expect("static pattern");
    find_hex_pattern(data, &needle, max)
}

pub fn find_push_rbp(data: &[u8], max: usize) -> Vec<usize> {
    let needle = parse_hex_nibbles("55").expect("static pattern");
    find_hex_pattern(data, &needle, max)
}
