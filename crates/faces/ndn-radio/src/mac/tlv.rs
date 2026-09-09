//! Minimal TLV-VAR (de)serialisation shared by the NDR MAC's small wire codecs (`capability`,
//! `opacity`) — big-endian VAR-NUMBER, the NDN convention. Dependency-free and `no_std`-friendly, kept
//! here rather than pulling `ndn-tlv`'s reader/writer into these byte-level helpers.

/// Append a VAR-NUMBER (`<253` = one byte; `253/254/255` = u16/u32/u64, big-endian).
pub(crate) fn put_var(out: &mut Vec<u8>, v: u64) {
    if v < 253 {
        out.push(v as u8);
    } else if v <= 0xffff {
        out.push(253);
        out.extend_from_slice(&(v as u16).to_be_bytes());
    } else if v <= 0xffff_ffff {
        out.push(254);
        out.extend_from_slice(&(v as u32).to_be_bytes());
    } else {
        out.push(255);
        out.extend_from_slice(&v.to_be_bytes());
    }
}

/// Append a TLV: `type`, `length`, `value`.
pub(crate) fn put_tlv(out: &mut Vec<u8>, t: u64, v: &[u8]) {
    put_var(out, t);
    put_var(out, v.len() as u64);
    out.extend_from_slice(v);
}

/// Read one VAR-NUMBER at `b[*p]`, advancing `*p`. `None` if it runs off the end.
pub(crate) fn read_var(b: &[u8], p: &mut usize) -> Option<u64> {
    let first = *b.get(*p)?;
    if first < 253 {
        *p += 1;
        Some(first as u64)
    } else {
        let n = match first {
            253 => 2,
            254 => 4,
            _ => 8,
        };
        let end = *p + 1 + n;
        let mut v = 0u64;
        for &x in b.get(*p + 1..end)? {
            v = (v << 8) | x as u64;
        }
        *p = end;
        Some(v)
    }
}
