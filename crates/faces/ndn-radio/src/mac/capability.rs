//! **NdrCapability** (NDR_MAC_SPEC §5) — the per-link capability descriptor: an NDNLPv2 link field a
//! node stamps on the **Interests** it sends, read off the reverse path so a Data return can pick the
//! rate / channel / timing the *next hop* can actually receive. Observe-don't-handshake, hop-local,
//! soft-state (expires with the PIT entry, re-stamped by every Interest ⇒ mobility-safe). Absent or
//! stale ⇒ the floor (base rate, always-listen, no hop, this bearer).
//!
//! ## TLV assignments (item 7 — experimental range, peers `al_lal` 0x0360 / trace_context 0x0520)
//! Only **sender-relevant** receiver capabilities ride the wire; node-local ones (off-host parse,
//! off-host serve) are invisible. A clock is prerequisite for `Hop`/`Sleep`; its absence is simply
//! neither flag present — no separate bit.

use crate::mac::tlv::{put_tlv, read_var};

/// The `NdrCapability` link-field container.
pub const TLV_NDR_CAPABILITY: u64 = 0x0380;
/// `MaxRate` — highest PHY rate the sender reliably *receives*, as an MCS index (worst-receiver rate).
pub const TLV_NDR_MAX_RATE: u64 = 0x0381;
/// `Hop` (flag, empty value) — the sender is channel-agile and will follow `F(prefix,epoch).channel`.
pub const TLV_NDR_HOP: u64 = 0x0382;
/// `Sleep` (optional) — empty value ⇒ duty-cycles on the per-prefix `F.phase`; a 2×u32 value ⇒ a
/// consolidated node window `(window_us, period_us)`.
pub const TLV_NDR_SLEEP: u64 = 0x0383;
/// `Phys` — bearer bitset (bit0 Wi-Fi, bit1 LoRa, bit2 BLE, …) for bearer/relay selection.
pub const TLV_NDR_PHYS: u64 = 0x0384;

/// A node's sleep mode as advertised.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SleepMode {
    /// Duty-cycles on the per-prefix rendezvous phase (zero-config; the default for few-prefix nodes).
    PerPrefixPhase,
    /// A consolidated node listen window `(window_us, period_us)` — for a many-prefix node.
    Window { window_us: u32, period_us: u32 },
}

/// The §5 descriptor. `Default` is the **floor** (nothing advertised ⇒ base rate, always-listen, no
/// hop, this-bearer) — exactly what a receiver assumes when the field is absent or stale.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct NdrCapability {
    /// Highest MCS the sender reliably receives (`None` ⇒ base/legacy rate floor).
    pub max_rate: Option<u8>,
    /// Channel-agile (can follow the rendezvous channel). Requires a clock.
    pub hop: bool,
    /// Duty-cycle mode (`None` ⇒ always-listen). Requires a clock.
    pub sleep: Option<SleepMode>,
    /// Bearer bitset (`0` ⇒ unstated ⇒ this-bearer only).
    pub phys: u8,
}

impl NdrCapability {
    /// Is this the floor (nothing worth advertising)? Then a sender may omit the field entirely.
    pub fn is_floor(&self) -> bool {
        *self == NdrCapability::default()
    }

    /// The container's **value** bytes — the sub-TLVs, without the `0x0380` type+length wrapper. This is
    /// what a face writes as an NDNLPv2 link field (`write_tlv(TLV_NDR_CAPABILITY, &encode_value())`).
    pub fn encode_value(&self) -> Vec<u8> {
        let mut inner = Vec::new();
        if let Some(r) = self.max_rate {
            put_tlv(&mut inner, TLV_NDR_MAX_RATE, &[r]);
        }
        if self.hop {
            put_tlv(&mut inner, TLV_NDR_HOP, &[]);
        }
        match self.sleep {
            Some(SleepMode::PerPrefixPhase) => put_tlv(&mut inner, TLV_NDR_SLEEP, &[]),
            Some(SleepMode::Window { window_us, period_us }) => {
                let mut v = Vec::with_capacity(8);
                v.extend_from_slice(&window_us.to_be_bytes());
                v.extend_from_slice(&period_us.to_be_bytes());
                put_tlv(&mut inner, TLV_NDR_SLEEP, &v);
            }
            None => {}
        }
        if self.phys != 0 {
            put_tlv(&mut inner, TLV_NDR_PHYS, &[self.phys]);
        }
        inner
    }

    /// Decode from the container's **value** bytes (the sub-TLVs). Unknown sub-fields are skipped.
    pub fn decode_value(body: &[u8]) -> Option<Self> {
        let mut c = NdrCapability::default();
        let mut q = 0;
        while q < body.len() {
            let st = read_var(body, &mut q)?;
            let sl = read_var(body, &mut q)? as usize;
            let sv = body.get(q..q + sl)?;
            match st {
                TLV_NDR_MAX_RATE if sl >= 1 => c.max_rate = Some(sv[0]),
                TLV_NDR_HOP => c.hop = true,
                TLV_NDR_SLEEP => {
                    c.sleep = Some(if sl >= 8 {
                        SleepMode::Window {
                            window_us: u32::from_be_bytes(sv[0..4].try_into().ok()?),
                            period_us: u32::from_be_bytes(sv[4..8].try_into().ok()?),
                        }
                    } else {
                        SleepMode::PerPrefixPhase
                    });
                }
                TLV_NDR_PHYS if sl >= 1 => c.phys = sv[0],
                _ => {}
            }
            q += sl;
        }
        Some(c)
    }

    /// Encode the full `NdrCapability` link field (`0x0380 { … }`, type+length+value).
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        put_tlv(&mut out, TLV_NDR_CAPABILITY, &self.encode_value());
        out
    }

    /// Decode from the full container TLV bytes (as `encode` produced). `None` if not an `NdrCapability`.
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let mut p = 0;
        if read_var(bytes, &mut p)? != TLV_NDR_CAPABILITY {
            return None;
        }
        let len = read_var(bytes, &mut p)? as usize;
        Self::decode_value(bytes.get(p..p + len)?)
    }

    /// **Worst-receiver rate** (§5) — the MCS to send to this next hop: the min of our own reachable
    /// MCS and the neighbour's advertised `MaxRate`. Absent/floor capability ⇒ our own cap unchanged
    /// (the sender degrades to the base rate elsewhere). This is the merge a Data return applies.
    pub fn worst_receiver_mcs(&self, our_max_mcs: u8) -> u8 {
        match self.max_rate {
            Some(r) => our_max_mcs.min(r),
            None => our_max_mcs,
        }
    }
}

/// Splice this node's `NdrCapability` into an outgoing **Interest** LP wire as an NDNLPv2 link field
/// (`0x0380`), in header order before the Fragment — the §5 "stamp it on every Interest" step. A
/// non-LP or floor capability is returned unchanged (a sender may omit the floor). Mirrors
/// `ndn_packet::lp::splice_into_lp_wire` for trace context.
pub fn splice_into_lp_wire(lp_wire: bytes::Bytes, cap: &NdrCapability) -> bytes::Bytes {
    use ndn_packet::tlv_type::{LP_FRAGMENT, LP_PACKET};
    use ndn_tlv::{TlvReader, TlvWriter};
    if cap.is_floor() || lp_wire.first() != Some(&(LP_PACKET as u8)) {
        return lp_wire;
    }
    let mut outer = TlvReader::new(lp_wire.clone());
    let Ok((typ, value)) = outer.read_tlv() else { return lp_wire };
    if typ != LP_PACKET {
        return lp_wire;
    }
    let mut inner = TlvReader::new(value);
    let mut headers: Vec<(u64, bytes::Bytes)> = Vec::new();
    let mut fragment: Option<(u64, bytes::Bytes)> = None;
    while !inner.is_empty() {
        let Ok((t, v)) = inner.read_tlv() else { return lp_wire };
        if t == LP_FRAGMENT {
            fragment = Some((t, v));
            continue;
        }
        if t == TLV_NDR_CAPABILITY {
            continue; // replace any existing (hop-local: each forwarder overwrites with its own)
        }
        headers.push((t, v));
    }
    let val = cap.encode_value();
    let mut w = TlvWriter::new();
    w.write_nested(LP_PACKET, |w| {
        let mut inserted = false;
        for (t, v) in &headers {
            if !inserted && *t > TLV_NDR_CAPABILITY {
                w.write_tlv(TLV_NDR_CAPABILITY, &val);
                inserted = true;
            }
            w.write_tlv(*t, v);
        }
        if !inserted {
            w.write_tlv(TLV_NDR_CAPABILITY, &val);
        }
        if let Some((t, v)) = fragment {
            w.write_tlv(t, &v);
        }
    });
    w.finish()
}

/// Extract the `NdrCapability` from a received Interest's LP wire (the reverse path). `None` if not LP,
/// malformed, or no capability field — the caller then assumes the **floor**.
pub fn extract_from_lp_wire(lp_wire: &bytes::Bytes) -> Option<NdrCapability> {
    use ndn_packet::tlv_type::{LP_FRAGMENT, LP_PACKET};
    use ndn_tlv::TlvReader;
    if lp_wire.first() != Some(&(LP_PACKET as u8)) {
        return None;
    }
    let mut outer = TlvReader::new(lp_wire.clone());
    let (typ, value) = outer.read_tlv().ok()?;
    if typ != LP_PACKET {
        return None;
    }
    let mut inner = TlvReader::new(value);
    while !inner.is_empty() {
        let (t, v) = inner.read_tlv().ok()?;
        if t == TLV_NDR_CAPABILITY {
            return NdrCapability::decode_value(&v);
        }
        if t == LP_FRAGMENT {
            return None;
        }
    }
    None
}

/// **Reverse-path capability soft-state** (§5.2) — the per-neighbour store a face keeps: the last
/// `NdrCapability` heard from each next hop (keyed on its link id / ephemeral source), with the time it
/// was heard. A Data return (or an Interest forwarded to that neighbour) consults it to pick rate /
/// channel / timing; **stale or absent ⇒ the floor**. Soft-state: `get` returns `None` past `stale_ms`,
/// so it expires like a PIT entry and is re-stamped by every Interest (mobility-safe). Bounded by
/// eviction of the oldest past `cap` so a neighbour-churning flood cannot grow it without limit.
pub struct CapabilityStore {
    seen: std::collections::HashMap<u64, (NdrCapability, u64)>,
    stale_ms: u64,
    cap: usize,
}

impl CapabilityStore {
    /// `stale_ms` = how long a heard capability stays fresh (pair it with the PIT lifetime); `cap` =
    /// max neighbours kept (oldest evicted past it).
    pub fn new(stale_ms: u64, cap: usize) -> Self {
        Self {
            seen: std::collections::HashMap::new(),
            stale_ms: stale_ms.max(1),
            cap: cap.max(1),
        }
    }

    /// Record `cap` heard from `link` (an Interest's reverse path) at `now_ms`. Re-stamps freshness.
    pub fn observe(&mut self, link: u64, cap: NdrCapability, now_ms: u64) {
        if self.seen.len() >= self.cap && !self.seen.contains_key(&link) {
            if let Some(&oldest) = self
                .seen
                .iter()
                .min_by_key(|(_, (_, ts))| *ts)
                .map(|(k, _)| k)
            {
                self.seen.remove(&oldest);
            }
        }
        self.seen.insert(link, (cap, now_ms));
    }

    /// The fresh capability for `link`, or `None` (⇒ **floor**) if never heard or stale at `now_ms`.
    pub fn get(&self, link: u64, now_ms: u64) -> Option<NdrCapability> {
        self.seen
            .get(&link)
            .filter(|(_, ts)| now_ms.saturating_sub(*ts) <= self.stale_ms)
            .map(|(c, _)| *c)
    }

    /// Drop stale entries (call on a timer; not required for correctness — `get` already gates).
    pub fn prune(&mut self, now_ms: u64) {
        let stale = self.stale_ms;
        self.seen.retain(|_, (_, ts)| now_ms.saturating_sub(*ts) <= stale);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_every_field() {
        let c = NdrCapability {
            max_rate: Some(7),
            hop: true,
            sleep: Some(SleepMode::Window { window_us: 62_500, period_us: 1_000_000 }),
            phys: 0b0000_0101,
        };
        assert_eq!(NdrCapability::decode(&c.encode()), Some(c));
    }

    #[test]
    fn floor_round_trips_and_is_detected() {
        let c = NdrCapability::default();
        assert!(c.is_floor());
        assert_eq!(NdrCapability::decode(&c.encode()), Some(c));
    }

    #[test]
    fn per_prefix_sleep_is_the_empty_value() {
        let c = NdrCapability { sleep: Some(SleepMode::PerPrefixPhase), ..Default::default() };
        let w = c.encode();
        assert_eq!(NdrCapability::decode(&w), Some(c));
    }

    #[test]
    fn a_non_capability_tlv_decodes_none() {
        assert_eq!(NdrCapability::decode(&[0x07, 0x01, 0x00]), None);
    }



    #[test]
    fn worst_receiver_takes_the_min() {
        let hi = NdrCapability { max_rate: Some(7), ..Default::default() };
        assert_eq!(hi.worst_receiver_mcs(4), 4, "clamp to our own cap");
        let lo = NdrCapability { max_rate: Some(2), ..Default::default() };
        assert_eq!(lo.worst_receiver_mcs(7), 2, "clamp to the weak receiver");
        assert_eq!(NdrCapability::default().worst_receiver_mcs(6), 6, "floor: our cap unchanged");
    }

    #[test]
    fn splice_then_extract_from_lp_wire_roundtrips() {
        use bytes::Bytes;
        use ndn_tlv::TlvWriter;
        // Minimal LP packet: 0x64 { 0x50 <interest> }.
        let mut w = TlvWriter::new();
        w.write_nested(ndn_packet::tlv_type::LP_PACKET, |w| {
            w.write_tlv(ndn_packet::tlv_type::LP_FRAGMENT, &[0x05u8, 0x02, 0x07, 0x00]);
        });
        let lp = w.finish();
        let cap = NdrCapability { max_rate: Some(5), hop: true, phys: 0b101, ..Default::default() };
        let spliced = splice_into_lp_wire(lp.clone(), &cap);
        assert_ne!(spliced, lp, "the field was added");
        assert_eq!(extract_from_lp_wire(&spliced), Some(cap));
        // A floor capability is a no-op (a sender may omit it).
        assert_eq!(splice_into_lp_wire(lp.clone(), &NdrCapability::default()), lp);
        // Re-splice overwrites (hop-local), still one field.
        let cap2 = NdrCapability { max_rate: Some(2), ..Default::default() };
        let re = splice_into_lp_wire(spliced, &cap2);
        assert_eq!(extract_from_lp_wire(&re), Some(cap2));
    }

    #[test]
    fn store_is_soft_state_floor_on_stale_or_absent() {
        let mut s = CapabilityStore::new(1_000, 8);
        let c = NdrCapability { max_rate: Some(5), ..Default::default() };
        assert_eq!(s.get(42, 0), None, "absent -> floor");
        s.observe(42, c, 1_000);
        assert_eq!(s.get(42, 1_500), Some(c), "fresh within stale_ms");
        assert_eq!(s.get(42, 2_500), None, "past stale_ms -> floor");
    }

    #[test]
    fn store_bounds_neighbours_by_eviction() {
        let mut s = CapabilityStore::new(10_000, 2);
        s.observe(1, NdrCapability::default(), 1);
        s.observe(2, NdrCapability::default(), 2);
        s.observe(3, NdrCapability::default(), 3); // evicts link 1 (oldest)
        assert_eq!(s.get(1, 3), None);
        assert!(s.get(2, 3).is_some() && s.get(3, 3).is_some());
    }

    #[test]
    fn unknown_subfields_are_skipped() {
        // A container with a MaxRate and an unknown sub-TLV (0x03ff) still decodes the known field.
        let mut inner = Vec::new();
        put_tlv(&mut inner, TLV_NDR_MAX_RATE, &[4]);
        put_tlv(&mut inner, 0x03ff, &[9, 9, 9]);
        let mut w = Vec::new();
        put_tlv(&mut w, TLV_NDR_CAPABILITY, &inner);
        assert_eq!(NdrCapability::decode(&w).unwrap().max_rate, Some(4));
    }
}
