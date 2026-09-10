//! **Name extraction** — the named-data radio's one canonical path from an on-air frame to the
//! `/`-joined normalized name. This is the parse the MAC decides relevance on (the in-frame filter
//! it once fed is retired; see `firmware/NDR_MAC_SPEC.md`).
//!
//! It is a #44 keyspace primitive, peer to [`prefix_hash`](crate::mac::prefix_hash): a producer and a
//! receiver registering a `/`-string prefix **must** derive their bytes here so the two agree. It
//! lives in the shared control-plane crate — not in any one bearer's face — precisely so no bearer
//! grows a private copy that can drift (the failure the golden-vector oracle exists to catch). Every
//! bearer calls the same [`inner_name`] + [`ndn_name_to_slash`].
//!
//! Pure: TLV/LP parsing over borrowed bytes, no IO — consistent with the crate's sans-IO contract.

/// Extract the NDN **Name** TLV bytes from an LP-framed wire frame's inner packet. Returns `None`
/// for a non-first fragment (the name is only in fragment 0) or a parse miss. The one bounded
/// NDN-structure peek a bearer needs to compile its own Data's name into an in-frame filter.
pub fn inner_name(wire: &[u8]) -> Option<&[u8]> {
    // The network packet bytes: the LP `Fragment` (0x50) value. A multi-fragment
    // frame exposes it via extract_fragment (only fragment 0 has the name); a
    // single LP packet we scan for the 0x50 TLV; a bare packet is used as-is.
    let pkt: &[u8] = if let Some(h) = ndn_packet::lp::extract_fragment(wire) {
        if h.frag_index != 0 {
            return None;
        }
        wire.get(h.frag_start..h.frag_end)?
    } else if wire.first() == Some(&0x64) {
        lp_fragment_value(wire)?
    } else {
        wire
    };
    // pkt = Interest(0x05) | Data(0x06) { Name(0x07){…}, … } — return the Name TLV.
    named_tlv(pkt, 0x07)
}

/// Render an NDN **Name** TLV (`0x07 { 0x08 len comp … }`) to the `/`-joined byte form the in-frame
/// name filters iterate (`/x/y`), so a producer compiling the wire name and a receiver registering a
/// `/`-string prefix compute filter positions over identical bytes.
///
/// Component values are used verbatim. A raw `/` inside a component would create a false
/// prefix boundary — rare for `GenericNameComponent`s, and harmless in the safe direction
/// (an extra false positive; the receiver's exact table does the exact match). Falls back to the raw
/// TLV bytes if it won't parse, so the filter is still deterministic rather than panicking.
pub fn ndn_name_to_slash(name_tlv: &[u8]) -> Vec<u8> {
    fn parse(name_tlv: &[u8]) -> Option<Vec<u8>> {
        let (t, tn) = ndn_tlv::read_varu64(name_tlv).ok()?;
        if t != 0x07 {
            return None;
        }
        let (len, ln) = ndn_tlv::read_varu64(name_tlv.get(tn..)?).ok()?;
        let body = name_tlv.get(tn + ln..tn + ln + len as usize)?;
        let mut out = Vec::new();
        let mut pos = 0;
        while pos < body.len() {
            let (_ct, a) = ndn_tlv::read_varu64(body.get(pos..)?).ok()?;
            pos += a;
            let (cl, b) = ndn_tlv::read_varu64(body.get(pos..)?).ok()?;
            pos += b;
            let val = body.get(pos..pos + cl as usize)?;
            pos += cl as usize;
            out.push(b'/');
            out.extend_from_slice(val);
        }
        if out.is_empty() {
            out.push(b'/'); // the root name
        }
        Some(out)
    }
    parse(name_tlv).unwrap_or_else(|| name_tlv.to_vec())
}

/// Convenience: the full frame → `/`-joined name in one call. `None` for a nameless/continuation
/// frame. Bearers that want the name in one step (e.g. the LoRa name-parse path) use this.
pub fn wire_to_name_slash(wire: &[u8]) -> Option<Vec<u8>> {
    Some(ndn_name_to_slash(inner_name(wire)?))
}

/// The value bytes of the LP `Fragment` (0x50) TLV inside a single LP packet (0x64).
///
/// ☠ **This stripped the header TWICE** (P7 D1, MEASURED): it computed `body` = the LpPacket's
/// *value*, then handed that to [`named_tlv_value`], which strips **another** type+length header
/// before iterating. So it skipped past the `Fragment` TLV's own header and searched the *Data
/// packet's* sub-TLVs for a `0x50` that is not there — `inner_name` returned `None` on
/// **2000 / 2000** single-fragment LpPackets, the shape `ndn_packet::lp::encode_lp_packet` produces
/// and `control.rs`'s own reception reports use.
///
/// Both directions were live: any code path that derived relevance or a schedule from the
/// unfragmented LP object's name got `None` here — the name the frame plainly carried was invisible
/// to `inner_name`, so single-fragment traffic was treated as nameless. This fix restores the name
/// on that shape, which is why D1 was a *prerequisite* for the name-parse relevance path and not a
/// tidy-up.
///
/// [`named_tlv_value`] already does the outer strip. One call, one strip.
fn lp_fragment_value(lp: &[u8]) -> Option<&[u8]> {
    named_tlv_value(lp, 0x50)
}

/// Find the first sub-TLV of type `want` inside `parent`'s value and return it
/// **including** its type+length header (the hash input for a name is the whole
/// Name TLV). `parent` starts with an outer type+len wrapping the sub-TLVs.
fn named_tlv(parent: &[u8], want: u64) -> Option<&[u8]> {
    let (_, tn) = ndn_tlv::read_varu64(parent).ok()?;
    let (len, ln) = ndn_tlv::read_varu64(parent.get(tn..)?).ok()?;
    let body = parent.get(tn + ln..tn + ln + len as usize)?;
    let mut pos = 0;
    while pos < body.len() {
        let start = pos;
        let (t, a) = ndn_tlv::read_varu64(body.get(pos..)?).ok()?;
        pos += a;
        let (l, b) = ndn_tlv::read_varu64(body.get(pos..)?).ok()?;
        pos += b + l as usize;
        if t == want {
            return body.get(start..pos);
        }
    }
    None
}

/// Like [`named_tlv`] but returns the sub-TLV's **value** (no header).
fn named_tlv_value(parent: &[u8], want: u64) -> Option<&[u8]> {
    let (_, tn) = ndn_tlv::read_varu64(parent).ok()?;
    let (len, ln) = ndn_tlv::read_varu64(parent.get(tn..)?).ok()?;
    let body = parent.get(tn + ln..tn + ln + len as usize)?;
    let mut pos = 0;
    while pos < body.len() {
        let (t, a) = ndn_tlv::read_varu64(body.get(pos..)?).ok()?;
        pos += a;
        let (l, b) = ndn_tlv::read_varu64(body.get(pos..)?).ok()?;
        pos += b;
        if t == want {
            return body.get(pos..pos + l as usize);
        }
        pos += l as usize;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn name_tlv(comps: &[&[u8]]) -> Vec<u8> {
        let mut n = Vec::new();
        for c in comps {
            n.push(0x08);
            n.push(c.len() as u8);
            n.extend_from_slice(c);
        }
        let mut out = vec![0x07, n.len() as u8];
        out.extend_from_slice(&n);
        out
    }

    fn data_pkt(comps: &[&[u8]]) -> Vec<u8> {
        let nm = name_tlv(comps);
        let mut out = vec![0x06, nm.len() as u8];
        out.extend_from_slice(&nm);
        out
    }

    /// **P7 D1, pinned.** A single-fragment `LpPacket{ Fragment{ Data } }` — the shape
    /// `ndn_packet::lp::encode_lp_packet` emits — must yield its Name. It yielded `None` on
    /// 2000/2000 of them, which addressed every unfragmented LP object BROADCAST with no filter.
    #[test]
    fn a_single_fragment_lp_packet_yields_its_name() {
        let data = data_pkt(&[b"ndn", b"edu", b"course"]);
        let lp = ndn_packet::lp::encode_lp_packet(&data);
        let got = inner_name(&lp).map(ndn_name_to_slash);
        assert_eq!(
            got.as_deref(),
            Some(&b"/ndn/edu/course"[..]),
            "the parser cannot see a single-fragment LpPacket — the name silently \
             disappears on this wire (P7 D1)"
        );
        // …and it agrees with ndn_packet's own extractor, which always did this correctly.
        assert_eq!(
            got,
            ndn_packet::lp::lp_ndn_packet_bytes(&lp)
                .and_then(inner_name)
                .map(ndn_name_to_slash)
        );
        // The other two shapes must be unaffected.
        assert_eq!(
            inner_name(&data).map(ndn_name_to_slash).as_deref(),
            Some(&b"/ndn/edu/course"[..]),
            "a bare Data regressed"
        );
    }

    /// The multi-fragment path is the one that always worked; it must keep working, and a non-first
    /// fragment must still report "no name" rather than a wrong one.
    #[test]
    fn multi_fragment_lp_keeps_working_and_a_continuation_has_no_name() {
        fn tlv(t: u8, v: &[u8]) -> Vec<u8> {
            let mut o = vec![t, v.len() as u8];
            o.extend_from_slice(v);
            o
        }
        let data = data_pkt(&[b"a", b"b"]);
        let mk = |idx: u64| {
            let mut inner = Vec::new();
            inner.extend(tlv(0x51, &7u64.to_be_bytes()));
            inner.extend(tlv(0x52, &idx.to_be_bytes()));
            inner.extend(tlv(0x53, &2u64.to_be_bytes()));
            inner.extend(tlv(0x50, &data));
            tlv(0x64, &inner)
        };
        assert_eq!(
            inner_name(&mk(0)).map(ndn_name_to_slash).as_deref(),
            Some(&b"/a/b"[..])
        );
        assert!(
            inner_name(&mk(1)).is_none(),
            "a continuation fragment carries no Name"
        );
    }
}
