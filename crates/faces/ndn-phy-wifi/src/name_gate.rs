//! **One name-filtering gate, shared by both faces** (#82).
//!
//! Before this, the same decision was implemented twice and differently:
//!
//! | | `WifiPhy::rx_accepts` | `RadioMediumFace`'s RX loop |
//! |---|---|---|
//! | Tier-0 prefix-set filter | yes | yes, open-coded inline |
//! | Tier-1 (BF-FIB/PIT/CS) | yes | **no** |
//! | NDN-NIC baseline (#101) | yes | **no** |
//! | drop accounting | yes | **no** |
//!
//! Two faces doing one job, with the features on opposite sides — which is the whole of #82. The
//! copies had already begun to drift: every filtering feature added recently landed only in
//! `WifiPhy`, the face #82 says should *disappear* into `RadioMediumFace`. Extracting the
//! gate is the step that stops the drift; the remaining collapse can then happen without carrying two
//! divergent filter paths through it.
//!
//! The gate is deliberately **one type with one `admits`**, not a trait: there is exactly one policy
//! here and a trait would invite a second implementation, which is the situation being fixed.

use portable_atomic::AtomicU64;
use std::sync::Arc;
use std::sync::atomic::Ordering;

use crate::tier0::{PrefixFilter, WifiWideBlur, fingerprint_from_htc};
use crate::{BROADCAST, inner_name, ndn_name_to_slash};

/// Which frames pass, before any NDN decode.
#[derive(Clone)]
pub enum RxFilter {
    /// Keep every frame (promiscuous / broadcast join).
    Open,
    /// **Tier-0** (#91): keep any frame whose in-frame prefix-set filter (`addr1 ‖ addr2`) could be
    /// under one of these registered-prefix masks. Exact on the negative (definitely-not-under →
    /// drop, never parse), over-accepts on the positive.
    Bloom(Arc<[PrefixFilter]>),
    /// **Tier-0 WIDE profile** (#39): the layered 126-bit base + 48-bit extra Blur. Each mask is a
    /// [`WifiWideBlur`] (base + extra projection for one registered prefix). A **wide** frame (carrying
    /// `addr4`) is tested against BOTH regions — strictly lower false-positive rate than the base
    /// alone; a **base** frame (no `addr4`) is tested against the base region only, so a wide receiver
    /// never false-negatives a commodity sender. This is the receive side of the coexistence contract.
    WideBloom(Arc<[WifiWideBlur]>),
    /// **The NDN-NIC baseline** (#101) — receiver-side BF-FIB over registered prefixes, queried with
    /// the *parsed* name. For A/B measurement, not production: it needs the parse Tier-0 exists to
    /// avoid, so selecting it forfeits the point.
    NdnNic(Arc<crate::ndn_nic::NdnNicFilter>),
}

/// Tier-0 (+ optional Tier-1) admission for one face.
pub struct NameGate {
    filter: RxFilter,
    /// **Tier-1** (#92), when this node runs one. `None` on an endpoint, where Tier-0 alone is the
    /// right trade — #101 measured Tier-0's false-positive rate climbing with registered-prefix
    /// count, so it suits small E and a relay wants Tier-1 instead.
    tier1: Option<Arc<std::sync::RwLock<crate::tier1::Tier1>>>,
    dropped_tier0: AtomicU64,
    dropped_tier1: AtomicU64,
    /// Frames the prefix filter would have dropped but the wide-profile fingerprint **rescued** —
    /// an exact PIT/CS hit answered parse-free from HT Control. Counted so the win is observable.
    fp_rescued: AtomicU64,
}

impl NameGate {
    /// A gate that admits everything — the default, and what a face without name filtering uses.
    pub fn open() -> Self {
        Self::new(RxFilter::Open, None)
    }

    pub fn new(
        filter: RxFilter,
        tier1: Option<Arc<std::sync::RwLock<crate::tier1::Tier1>>>,
    ) -> Self {
        Self {
            filter,
            tier1,
            dropped_tier0: AtomicU64::new(0),
            dropped_tier1: AtomicU64::new(0),
            fp_rescued: AtomicU64::new(0),
        }
    }

    /// The current Tier-0 filter, so a builder can replace the Tier-1 half without discarding it
    /// (and vice versa). Cheap — `RxFilter` is `Arc`s.
    pub fn filter(&self) -> RxFilter {
        self.filter.clone()
    }

    /// The live Tier-1 handle, for the forwarder to drive from its real PIT/CS.
    pub fn tier1(&self) -> Option<Arc<std::sync::RwLock<crate::tier1::Tier1>>> {
        self.tier1.clone()
    }

    pub fn dropped_tier0(&self) -> u64 {
        self.dropped_tier0.load(Ordering::Relaxed)
    }

    pub fn dropped_tier1(&self) -> u64 {
        self.dropped_tier1.load(Ordering::Relaxed)
    }

    /// How many frames the wide-profile fingerprint rescued from a Tier-0 drop (parse-free PIT/CS).
    pub fn fp_rescued(&self) -> u64 {
        self.fp_rescued.load(Ordering::Relaxed)
    }

    /// **Does this frame pass?** `addr1 ‖ addr2` carry the Tier-0 filter; `wire` is the payload,
    /// needed only by the tiers that parse.
    ///
    /// Broadcast always passes: a frame with no group is addressed to everyone, and dropping it here
    /// would silently break discovery and the time beacons.
    pub fn admits(
        &self,
        addr1: Option<[u8; 6]>,
        addr2: Option<[u8; 6]>,
        addr3: Option<[u8; 6]>,
        wire: &[u8],
    ) -> bool {
        self.admits_wide(addr1, addr2, addr3, None, None, wire)
    }

    /// [`admits`](Self::admits) for the **wide profile**: `addr4` carries the extra Blur projection
    /// and `htc` the exact-match fingerprint + profile marker. Both `None` ⇒ a base 3-address frame,
    /// and this behaves exactly like `admits`. A base receiver ([`RxFilter::Bloom`]) ignores the wide
    /// fields entirely; a wide receiver ([`RxFilter::WideBloom`]) tightens Tier-0 with the extra region
    /// and can rescue an exact PIT/CS hit from the fingerprint without ever parsing the name.
    pub fn admits_wide(
        &self,
        addr1: Option<[u8; 6]>,
        addr2: Option<[u8; 6]>,
        addr3: Option<[u8; 6]>,
        addr4: Option<[u8; 6]>,
        htc: Option<[u8; 4]>,
        wire: &[u8],
    ) -> bool {
        // **Broadcast skips TIER-0 ONLY, never Tier-1.**
        //
        // Tier-0 reads the filter out of `addr1 ‖ addr2`, so a frame with no group address carries no
        // filter to test and must pass. Tier-1 is a different question — "do I want this name?" — and
        // on a broadcast medium *every* frame is broadcast, so returning early here would disable
        // Tier-1 entirely. Consolidating the two gates, I first wrote a single early return and two
        // Tier-1 tests failed immediately; without them this would have shipped as a filter that
        // quietly does nothing on exactly the medium it was built for.
        let tier0_ok = match (addr1, &self.filter) {
            (None, _) => true,
            (Some(a1), _) if a1 == BROADCAST => true,
            (Some(_), RxFilter::Open) => true,
            (Some(a1), RxFilter::Bloom(masks)) => {
                let Some(a2) = addr2 else { return true };
                // The 126-bit Blur spans addr1‖addr2‖addr3[0..4] (wire-format-spec §5.3). addr3's
                // last two bytes are the ephemeral ID + flags, not filter — a legacy frame with no
                // addr3 leaves those four bytes clear, which only *loosens* the match (over-accept),
                // never a false negative.
                let mut w = [0u8; 16];
                w[..6].copy_from_slice(&a1);
                w[6..12].copy_from_slice(&a2);
                if let Some(a3) = addr3 {
                    w[12..16].copy_from_slice(&a3[..4]);
                }
                let frame = PrefixFilter::from_wire(w);
                masks.iter().any(|m| frame.may_match(m))
            }
            (Some(a1), RxFilter::WideBloom(masks)) => {
                let Some(a2) = addr2 else { return true };
                // Reconstruct the 126-bit base exactly as the Bloom arm — the coexistence floor.
                let mut w = [0u8; 16];
                w[..6].copy_from_slice(&a1);
                w[6..12].copy_from_slice(&a2);
                if let Some(a3) = addr3 {
                    w[12..16].copy_from_slice(&a3[..4]);
                }
                let base = PrefixFilter::from_wire(w);
                match addr4 {
                    // A wide frame carries the extra projection in addr4: test BOTH regions, which
                    // is strictly tighter (lower FP) than the base alone — the whole point of #35.
                    Some(a4) => {
                        let frame = WifiWideBlur::from_parts(base, a4);
                        masks.iter().any(|m| frame.may_match(m))
                    }
                    // A base (commodity) sender reached a wide receiver: only the base region exists
                    // on the wire, so test the base region of each mask. Never a false negative.
                    None => masks.iter().any(|m| base.may_match(m.base())),
                }
            }
            // The baseline's cost is visible here: it cannot answer without decoding far enough to
            // find the Name TLV. The Tier-0 arm above never touches `wire`.
            (Some(_), RxFilter::NdnNic(bf)) => match inner_name(wire) {
                Some(name) => bf.may_serve(&ndn_name_to_slash(name)),
                None => true,
            },
        };
        if !tier0_ok {
            // Wide-profile parse-free RESCUE: a frame the prefix filter drops may still be EXACTLY a
            // name we have outstanding (PIT) or cached (CS). The fingerprint in HT Control answers
            // that without a parse. It only ever ADMITS (never a false negative), so it is safe to
            // consult here — it can rescue a frame Tier-0 dropped, never suppress one it kept.
            if let (Some(htc), Some(t1)) = (htc, self.tier1.as_ref())
                && let Some(fp) = fingerprint_from_htc(&htc)
                && let Ok(g) = t1.read()
            {
                let v = g.probe_fingerprint(fp);
                if v.pit || v.cs {
                    self.fp_rescued.fetch_add(1, Ordering::Relaxed);
                    return true;
                }
            }
            self.dropped_tier0.fetch_add(1, Ordering::Relaxed);
            return false;
        }

        // ── Tier-1: on the parsed name, after Tier-0 admits ──────────────────────────────────
        // A frame with no name (a non-first fragment) passes: reassembly needs it, and the first
        // fragment already faced both gates.
        if let Some(t1) = self.tier1.as_ref()
            && let Some(name) = inner_name(wire)
        {
            let slash = ndn_name_to_slash(name);
            let miss = match t1.read() {
                Ok(g) => g.lookup(&slash).is_miss(),
                // A poisoned lock must not silently start dropping traffic: fail open. The filter is
                // an optimisation; the forwarder behind it is the correctness layer.
                Err(_) => false,
            };
            if miss {
                self.dropped_tier1.fetch_add(1, Ordering::Relaxed);
                return false;
            }
        }
        true
    }
}

impl Default for NameGate {
    fn default() -> Self {
        Self::open()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::GroupKey;
    use crate::tier0::WideFrame;
    use crate::tier1::Tier1;

    const KEY: GroupKey = GroupKey(*b"ndn/wide-gatek!!");

    /// One name's wide-profile header fields (addr1..addr4 + HTC), as a wide sender emits them.
    fn wide_fields(name: &[u8]) -> ([u8; 6], [u8; 6], [u8; 6], [u8; 6], [u8; 4]) {
        let f = WideFrame::of_name(&KEY.0, name, 0x11, 0x00).to_fields();
        (f.addr1, f.addr2, f.addr3, f.addr4, f.htc)
    }

    /// A wide receiver admits a wide frame under a registered prefix, admits a **base** sender's
    /// 3-address frame for the same name (coexistence, zero false negatives), and drops a wide frame
    /// for an unrelated name.
    #[test]
    fn wide_gate_admits_under_prefix_and_coexists_with_base_sender() {
        let masks = crate::wide_bloom_masks_for(&KEY, &["/ndn/edu"]);
        let gate = NameGate::new(RxFilter::WideBloom(masks), None);

        let (a1, a2, a3, a4, htc) = wide_fields(b"/ndn/edu/course/v1");
        // Wide frame (addr4 + HTC present): admitted on both regions.
        assert!(gate.admits_wide(Some(a1), Some(a2), Some(a3), Some(a4), Some(htc), b""));
        // The SAME sender as a base 3-address frame (no addr4/HTC): still admitted on the base region.
        assert!(
            gate.admits_wide(Some(a1), Some(a2), Some(a3), None, None, b""),
            "a base (commodity) sender must never be false-negatived by a wide receiver"
        );

        // A wide frame for a name NOT under /ndn/edu is dropped (no Tier-1 to rescue it).
        let (u1, u2, u3, u4, uhtc) = wide_fields(b"/video/clip/42");
        assert!(!gate.admits_wide(Some(u1), Some(u2), Some(u3), Some(u4), Some(uhtc), b""));
    }

    /// The wide extra region can only TIGHTEN: any frame the wide gate admits, the base gate also
    /// admits (the base region is a subset test). Checked across many names — the wide gate never
    /// admits something the base gate rejects (that would be a false negative).
    #[test]
    fn wide_admission_is_a_subset_of_base_admission() {
        let wide = NameGate::new(
            RxFilter::WideBloom(crate::wide_bloom_masks_for(&KEY, &["/ndn/edu"])),
            None,
        );
        let base = NameGate::new(
            RxFilter::Bloom(crate::bloom_masks_for(&KEY, &["/ndn/edu"])),
            None,
        );
        for i in 0..500u32 {
            let name = format!("/ndn/edu/s{}/v{}", i % 50, i);
            let (a1, a2, a3, a4, htc) = wide_fields(name.as_bytes());
            let w = wide.admits_wide(Some(a1), Some(a2), Some(a3), Some(a4), Some(htc), b"");
            let b = base.admits_wide(Some(a1), Some(a2), Some(a3), None, None, b"");
            assert!(!w || b, "wide admitted {name} that base rejected — a false negative");
        }
    }

    /// The wide fingerprint **rescues** an exact PIT hit the prefix filter would drop — parse-free,
    /// from HT Control. A base frame (no HTC) for the same name gets no rescue.
    #[test]
    fn wide_fingerprint_rescues_exact_pit_hit_the_filter_dropped() {
        // Registered prefix is /some/other, so /a/b/c is NOT under the Tier-0 filter → it drops.
        let masks = crate::wide_bloom_masks_for(&KEY, &["/some/other"]);
        // Tier-1 keyed identically to the wide fingerprint, holding an outstanding Interest for /a/b/c.
        let mut t1 = Tier1::new(&KEY.0, 4096, 4);
        t1.add_pit(b"/a/b/c");
        t1.sync();
        let gate = NameGate::new(RxFilter::WideBloom(masks), Some(Arc::new(std::sync::RwLock::new(t1))));

        let (a1, a2, a3, a4, htc) = wide_fields(b"/a/b/c");
        // Wide frame: Tier-0 drops it, but the fingerprint PIT-hit rescues it (parse-free).
        assert!(
            gate.admits_wide(Some(a1), Some(a2), Some(a3), Some(a4), Some(htc), b""),
            "an exact outstanding-Interest match must be rescued by the fingerprint"
        );
        assert_eq!(gate.fp_rescued(), 1, "the rescue is counted");
        // A base frame (no HTC) for the same name: no fingerprint, no rescue → dropped.
        assert!(!gate.admits_wide(Some(a1), Some(a2), Some(a3), None, None, b""));
        assert_eq!(gate.fp_rescued(), 1, "base frame did not rescue");
    }
}
