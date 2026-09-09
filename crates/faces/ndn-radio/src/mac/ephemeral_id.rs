//! **The 8-bit ephemeral ID + cooperative deconfliction** — the enabler for the wire-format redesign's
//! 128:8 address partition (`wire-format-spec.md` §4).
//!
//! The addressing redesign narrows the on-air source ID from a 46-bit random nonce to **8 bits**. The
//! in-frame name filter that originally spent the 38 freed address bits is retired, but the narrow ID
//! is kept because 8 bits + cooperative deconfliction is enough. Eight bits collide often (the
//! birthday bound is ~19 neighbours), so aliases are resolved **cooperatively and beacon-free**, never
//! by width:
//!
//! - **Pick-Free-Slot (PFS)** — on boot/rotation a node picks an ID it has *not* recently overheard.
//!   Cheap, but blind to *hidden* nodes (IDs it cannot hear), so it is only the initial pick.
//! - **Detect-And-Rotate (DAR)** — the workhorse. A **common neighbour** that overhears one ID carrying
//!   two distinct contents within a short window infers an alias and piggybacks a 1-bit collision signal
//!   (`FLAG_ID_COLLISION`, spec §5.4) on data it already sends; a node receiving that signal for its own
//!   ID rotates. No dedicated frame — it rides existing traffic (the control-plane tenet).
//!
//! Two halves live here: [`EphemeralId`] (the allocator — PFS + rotate-on-signal) and [`AliasDetector`]
//! (the observer — decide *when* to emit the collision signal). This module is pure decision logic with
//! no I/O; the medium wires `note_heard`/`note_collision` to the RX path and the detector's verdict to
//! the flags byte.

/// Bits in the on-air ephemeral ID (`addr3[4]`).
pub const ID_BITS: u32 = 8;
/// Size of the ID space (256).
pub const ID_SPACE: usize = 1 << ID_BITS;

/// A node's own ephemeral ID plus the Pick-Free-Slot / Detect-And-Rotate state that keeps it
/// alias-free. Soft state: a residual alias degrades an RSSI estimate or over-counts a neighbour, never
/// a delivery — which is why 8 bits + deconfliction is safe where a durable address would not be.
pub struct EphemeralId {
    id: u8,
    /// Last time (ms) each ID value was overheard on air; `0` = never. An ID heard within `stale_ms` is
    /// considered taken by a neighbour.
    seen: [u64; ID_SPACE],
    stale_ms: u64,
    rng: u64,
}

impl EphemeralId {
    /// A fresh ID, PFS-picked from an empty neighbour view (so effectively random at boot). `boot_seed`
    /// seeds the xorshift picker; `stale_ms` is how long an overheard ID stays "taken".
    pub fn new(boot_seed: u64, stale_ms: u64) -> Self {
        let mut s = Self {
            id: 0,
            seen: [0; ID_SPACE],
            stale_ms: stale_ms.max(1),
            rng: boot_seed | 1,
        };
        s.id = s.pick_free(0);
        s
    }

    fn next_rng(&mut self) -> u64 {
        // xorshift64 — deterministic, no std Rng (this crate is sans-IO and sans-rand).
        self.rng ^= self.rng << 13;
        self.rng ^= self.rng >> 7;
        self.rng ^= self.rng << 17;
        self.rng
    }

    /// Pick an ID not currently taken by a fresh neighbour (PFS). Random among the free set; if every
    /// value is fresh (≥256 audible neighbours — pathological), fall back to the *stalest*, which is the
    /// least-recently-heard and so the most likely to have moved on.
    fn pick_free(&mut self, now_ms: u64) -> u8 {
        let mut free_count = 0usize;
        for i in 0..ID_SPACE {
            let t = self.seen[i];
            if t == 0 || now_ms.saturating_sub(t) > self.stale_ms {
                free_count += 1;
            }
        }
        if free_count == 0 {
            // Saturated: take the stalest (smallest last-heard timestamp).
            let mut best = 0u8;
            let mut oldest = u64::MAX;
            for i in 0..ID_SPACE {
                if self.seen[i] < oldest {
                    oldest = self.seen[i];
                    best = i as u8;
                }
            }
            return best;
        }
        // Walk to the r-th free slot (avoids allocating a Vec of frees).
        let mut target = (self.next_rng() as usize) % free_count;
        for i in 0..ID_SPACE {
            let t = self.seen[i];
            if t == 0 || now_ms.saturating_sub(t) > self.stale_ms {
                if target == 0 {
                    return i as u8;
                }
                target -= 1;
            }
        }
        self.id // unreachable given free_count>0, but keep total
    }

    /// This node's current on-air ID.
    pub fn current(&self) -> u8 {
        self.id
    }

    /// Feed an overheard source ID — PFS input. Marks the value taken so a future pick avoids it.
    pub fn note_heard(&mut self, id: u8, now_ms: u64) {
        self.seen[id as usize] = now_ms;
    }

    /// **DAR**: a common neighbour signalled our ID is aliased. Mark it taken and rotate to a free slot.
    /// Returns the new ID.
    pub fn note_collision(&mut self, now_ms: u64) -> u8 {
        self.seen[self.id as usize] = now_ms;
        self.id = self.pick_free(now_ms);
        self.id
    }

    /// Periodic PFS refresh (e.g. on the rotation period) — re-pick from the current neighbour view to
    /// bound linkability and shed a stale alias even without a DAR signal.
    pub fn rotate(&mut self, now_ms: u64) -> u8 {
        self.id = self.pick_free(now_ms);
        self.id
    }
}

/// The observer half of DAR: a node uses this on frames it overhears to decide whether to piggyback a
/// collision signal toward a sender. It flags an **alias** when one ID carries two *different* content
/// fingerprints within a short window — which one node, transmitting its own coherent stream, would not
/// produce. The fingerprint is any cheap per-sender-distinguishing value the medium already has (e.g. the
/// object-name hash, or the per-frame RSSI).
pub struct AliasDetector {
    last: [(u64, u64); ID_SPACE], // (fingerprint, ms) per ID
    window_ms: u64,
}

impl AliasDetector {
    /// `window_ms` is how close in time two different-fingerprint frames on one ID must be to read as a
    /// live alias rather than the same node having simply moved on to new content.
    pub fn new(window_ms: u64) -> Self {
        Self {
            last: [(0, 0); ID_SPACE],
            window_ms: window_ms.max(1),
        }
    }

    /// Observe a frame from `id` carrying `fingerprint` at `now_ms`. Returns `true` if this looks like an
    /// alias (same ID, *different* fingerprint, within the window) — the caller should then set
    /// `FLAG_ID_COLLISION` on data it sends so the aliasing senders rotate (DAR).
    pub fn observe(&mut self, id: u8, fingerprint: u64, now_ms: u64) -> bool {
        let (fp, t) = self.last[id as usize];
        let alias = t != 0 && now_ms.saturating_sub(t) <= self.window_ms && fp != fingerprint;
        self.last[id as usize] = (fingerprint, now_ms);
        alias
    }
}

/// Flags byte (`addr3[5]`, wire-format-spec §5.4), LSB first.
pub const FLAG_BODY_PREFIX: u8 = 0b0000_0001;
pub const FLAG_ID_COLLISION: u8 = 0b0000_0010;
/// Bits 2..4 — the **class-commitment slice index**. `0` = no commitment on this frame; `1..=7`
/// selects slice `idx - 1` of the folded schedule commitment (below).
pub const FLAG_COMMIT_IDX_MASK: u8 = 0b0001_1100;
/// Bits 5..7 — the three commitment bits the selected slice carries.
pub const FLAG_COMMIT_BITS_MASK: u8 = 0b1110_0000;

// ---------------------------------------------------------------------------------------------
// The piggybacked class commitment (#93) — "compare, don't reassemble"
// ---------------------------------------------------------------------------------------------
//
// A node's schedule-map digest (`SchedParams::digest()`, 64 bits) is the value two neighbours must
// agree on or their slot maps differ. It used to travel ONLY on the time beacon — and only the clock
// master transmits one (`NDN_SCHED_MASTER=1`), so a NON-MASTER node that classified names
// differently put nothing on the air and was never caught. That is both a coverage hole and a
// violation of the control-plane tenet ("overhear / piggyback, never beacon", spec §4): the check
// depended on the one dedicated frame the doctrine forbids leaning on.
//
// ☠ **The obvious construction is arithmetically unavailable.** Six spare bits split into `i` index
// bits and `b = 6 - i` payload bits needs `n = ceil(64/b)` slices and `i >= ceil(log2 n)`; that
// inequality has NO solution (b=1 needs 6 index bits of 5; b=2 needs 5 of 4; … b=5 needs 4 of 1).
// A 64-bit value cannot be rebuilt from this byte at any split, and every reassembling variant also
// inherits the "did I mix two epochs?" problem.
//
// **So nothing is reassembled.** A receiver never needs the neighbour's digest *value*; it needs the
// one-bit answer "is yours equal to mine?". Each frame therefore carries a COMPLETE, self-contained
// comparison of three bits — a slice of a 21-bit fold of the digest, plus which slice it is. A slice
// is compared on arrival and discarded; two slices are never combined, so no value can be assembled
// from two epochs and there is no generation counter, no round boundary, and no mixed-epoch case.
// The only cross-frame state is CONFIDENCE (which slices have been checked), and that is honest to
// reset whenever either side's digest moves.
//
// ⚠ **21 bits is not 64 bits, and this must never be published as catching a deliberate defector.**
// `class_digest` was widened 32 -> 64 because an offline search forged a 32-bit collision in ~10 s;
// a 21-bit fold is forgeable instantly. What this catches is a neighbour whose configuration
// HONESTLY differs — the real #93 scenario. Division of labour: **coverage from the piggyback (every
// node, every data frame), width from the beacon (the master only).**

/// Slices in one commitment round (index `0` is reserved for "absent", so `2^3 - 1`).
pub const COMMITMENT_SLICES: u8 = 7;
/// Bits of the folded commitment a full round covers (`COMMITMENT_SLICES * 3`).
pub const COMMITMENT_BITS: u8 = 21;
/// Mismatching slices required before a neighbour is called divergent.
///
/// Not a correctness requirement — one mismatch is already proof of a different digest *if the byte
/// is trustworthy*. It is there because `addr3` is not always `id ‖ flags` on this wire (the A-MSDU
/// and legacy builders overwrite it with `addr1`/`dst`), so a caller that forgets the
/// `addr3 == addr1` guard would otherwise turn filler bytes into a partition report. Two independent
/// mismatches from one ephemeral ID cost one extra frame and remove that whole class of noise.
pub const DIVERGENCE_DEBOUNCE: u8 = 2;

/// Fold a 64-bit schedule digest into the 21 bits a full commitment round carries.
///
/// XOR-folding, not truncation: every bit of `digest` reaches the fold, so a divergence confined to
/// the high half is as visible as one in the low half. (Truncation would make the whole class
/// commitment — which lives in the digest's tail — invisible to the piggyback.)
pub fn fold_commitment(digest: u64) -> u32 {
    ((digest ^ (digest >> 21) ^ (digest >> 42) ^ (digest >> 63)) & 0x1F_FFFF) as u32
}

/// Pack slice `idx` (`1..=COMMITMENT_SLICES`) of `folded` into the flags byte's bits 2..7.
/// Out-of-range `idx` yields `0` — "no commitment", which is always safe to emit.
pub fn encode_commitment_slice(folded: u32, idx: u8) -> u8 {
    if idx == 0 || idx > COMMITMENT_SLICES {
        return 0;
    }
    let bits = ((folded >> (3 * (idx as u32 - 1))) & 0x7) as u8;
    ((idx << 2) & FLAG_COMMIT_IDX_MASK) | ((bits << 5) & FLAG_COMMIT_BITS_MASK)
}

/// `(slice, three bits)` from a flags byte, or `None` when the frame carries **no** commitment.
///
/// `None` is load-bearing, not decoration. Three senders emit index `0`: a node on the pre-#93 wire
/// (the spec said bits 2..7 MUST be 0), a DAR **hint** frame (whose `addr3[4]` is somebody *else's*
/// ID, so filing a slice there would accuse an innocent node), and the `addr3 == addr1` shapes.
/// Reading `0` as data would report a divergence against the entire installed base.
pub fn decode_commitment_slice(flags: u8) -> Option<(u8, u8)> {
    let idx = (flags & FLAG_COMMIT_IDX_MASK) >> 2;
    (idx != 0).then(|| (idx - 1, (flags & FLAG_COMMIT_BITS_MASK) >> 5))
}

/// What a receiver can honestly say about one neighbour's schedule agreement.
///
/// **`Unknown` is not `Divergent`, and `Agreeing` is not "the same map".** A half-collected round
/// says only how many bits have been checked; asserting a partition from it would trade a silent
/// defect for a noisy false one (and every neighbour starts half-collected).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Agreement {
    /// No slice has been heard from this neighbour — unjudged. Never a partition.
    Unknown,
    /// `bits` of [`COMMITMENT_BITS`] have been compared and matched; none mismatched.
    Agreeing { bits: u8 },
    /// `mismatches` slices disagreed: this neighbour computes a different schedule map.
    Divergent { mismatches: u8 },
}

impl Agreement {
    /// The only test that may be reported as a partition.
    pub fn is_divergent(&self) -> bool {
        matches!(self, Agreement::Divergent { .. })
    }
    /// `true` once a whole round has been compared with no mismatch.
    pub fn is_complete(&self) -> bool {
        matches!(self, Agreement::Agreeing { bits } if *bits >= COMMITMENT_BITS)
    }
}

/// One `observe` result: the neighbour's standing verdict, plus whether THIS frame is the one that
/// crossed the debounce (so the caller warns once per divergence, not once per frame).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SliceVerdict {
    pub agreement: Agreement,
    pub newly_divergent: bool,
}

#[derive(Clone, Copy)]
struct SliceState {
    /// Bit `s` set = slice `s` has been compared and MATCHED.
    seen: u8,
    mismatch: u8,
    last_ms: u64,
}

impl SliceState {
    const EMPTY: Self = Self {
        seen: 0,
        mismatch: 0,
        last_ms: 0,
    };
    fn agreement(&self) -> Agreement {
        if self.mismatch >= DIVERGENCE_DEBOUNCE {
            Agreement::Divergent {
                mismatches: self.mismatch,
            }
        } else if self.seen == 0 {
            Agreement::Unknown
        } else {
            Agreement::Agreeing {
                bits: 3 * self.seen.count_ones() as u8,
            }
        }
    }
}

/// Per-neighbour accumulation of commitment slices overheard on ordinary data.
///
/// Keyed on the 8-bit ephemeral ID, which is safe **because the state is a comparison, not a value**:
/// under an ID alias, two agreeing neighbours merge into an entry that still reads *agree*, and a
/// disagreeing one still reads *mismatch*. Aliasing can neither fabricate nor hide a divergence.
///
/// All of it is soft state: dropped when a neighbour goes quiet for `stale_ms`, and cleared wholesale
/// when OUR OWN commitment changes (every accumulated agreement was against the old value).
pub struct ClassCommitmentWatch {
    per_id: [SliceState; ID_SPACE],
    ours: u32,
    stale_ms: u64,
    divergences: u32,
}

impl ClassCommitmentWatch {
    pub fn new(stale_ms: u64) -> Self {
        Self {
            per_id: [SliceState::EMPTY; ID_SPACE],
            ours: u32::MAX, // not a valid 21-bit fold: the first observe seeds `ours` honestly
            stale_ms: stale_ms.max(1),
            divergences: 0,
        }
    }

    /// Compare the slice on one received frame against `ours` (= [`fold_commitment`] of our own
    /// schedule digest).
    ///
    /// The caller MUST have established that `flags` really is the id-carrying flags byte — i.e. that
    /// `addr3 != addr1` — before calling; see [`DIVERGENCE_DEBOUNCE`].
    pub fn observe(&mut self, id: u8, flags: u8, ours: u32, now_ms: u64) -> SliceVerdict {
        if ours != self.ours {
            self.per_id = [SliceState::EMPTY; ID_SPACE];
            self.ours = ours;
        }
        let stale = self.stale_ms;
        let st = &mut self.per_id[id as usize];
        if st.last_ms != 0 && now_ms.saturating_sub(st.last_ms) > stale {
            *st = SliceState::EMPTY;
        }
        let Some((s, theirs)) = decode_commitment_slice(flags) else {
            // No commitment on this frame: not evidence of anything, in either direction.
            return SliceVerdict {
                agreement: st.agreement(),
                newly_divergent: false,
            };
        };
        st.last_ms = now_ms.max(1);
        let mine = ((ours >> (3 * s as u32)) & 0x7) as u8;
        let mut newly_divergent = false;
        if mine == theirs {
            st.seen |= 1 << s;
        } else {
            let before = st.mismatch;
            st.mismatch = st.mismatch.saturating_add(1);
            newly_divergent = before < DIVERGENCE_DEBOUNCE && st.mismatch >= DIVERGENCE_DEBOUNCE;
        }
        if newly_divergent {
            self.divergences = self.divergences.saturating_add(1);
        }
        SliceVerdict {
            agreement: st.agreement(),
            newly_divergent,
        }
    }

    /// The standing verdict for one neighbour, without feeding it evidence.
    pub fn agreement_for(&self, id: u8) -> Agreement {
        self.per_id[id as usize].agreement()
    }

    /// How many neighbours have crossed the debounce since boot (an operator counter).
    pub fn divergences(&self) -> u32 {
        self.divergences
    }
}

/// The whole cooperative-deconfliction unit the medium holds **one of** (shared, per node): the
/// allocator, the alias detector, and the pending DAR hint. The medium calls [`tx_id`](Self::tx_id) on
/// send and [`rx`](Self::rx) on receive — no other wiring.
pub struct IdDeconfliction {
    id: EphemeralId,
    detector: AliasDetector,
    /// A conflicted ID we detected and owe a DAR hint for, delivered on our next data frame.
    pending_hint: Option<u8>,
    /// Which commitment slice the next ordinary frame carries — round-robin `1..=COMMITMENT_SLICES`.
    /// Advanced only when a slice is actually emitted, so a burst of DAR hints does not skip slices.
    next_slice: u8,
}

impl IdDeconfliction {
    pub fn new(boot_seed: u64, stale_ms: u64, window_ms: u64) -> Self {
        Self {
            id: EphemeralId::new(boot_seed, stale_ms),
            detector: AliasDetector::new(window_ms),
            pending_hint: None,
            next_slice: 1,
        }
    }

    /// `(addr3[4], addr3[5])` for the next TX. A pending DAR hint rides this one frame: `addr3[4]`
    /// carries the **conflicted** ID and `FLAG_ID_COLLISION` is set — sacrificing our own ID
    /// attribution on this frame (soft state) to tell the aliasing senders to rotate.
    ///
    /// `commitment` is [`fold_commitment`] of this node's schedule-map digest, or `None` where the
    /// node runs no scheduler and therefore has no map to commit to. When present, the next slice of
    /// it rides bits 2..7 — this is what makes a NON-MASTER divergence visible, since every node's
    /// ordinary data frames carry it and only the master ever sends a beacon.
    ///
    /// The commitment is deliberately SUPPRESSED on the hint branch: a hint frame's `addr3[4]` is the
    /// conflicted ID, i.e. some other node's, so a slice there would be filed against that node.
    /// It is a parameter rather than stored state so the caller cannot leave a stale fold on the air
    /// after its own map moves.
    pub fn tx_id(&mut self, commitment: Option<u32>) -> (u8, u8) {
        match self.pending_hint.take() {
            Some(x) => (x, FLAG_ID_COLLISION),
            None => {
                let flags = match commitment {
                    Some(folded) => {
                        let idx = self.next_slice;
                        self.next_slice = if idx >= COMMITMENT_SLICES { 1 } else { idx + 1 };
                        encode_commitment_slice(folded, idx)
                    }
                    None => 0,
                };
                (self.id.current(), flags)
            }
        }
    }

    /// Feed a received id-carrying frame's ID + flags + RSSI. Runs PFS (`note_heard`), DAR-rotate (on a hint
    /// naming our ID), and DAR-detect (an ID carrying two RSSI fingerprints in the window → queue a
    /// hint). Returns `true` if this was a hint frame (its ID is the conflicted one, not a real
    /// neighbour — the caller must NOT key a neighbour on it).
    pub fn rx(&mut self, id: u8, flags: u8, rssi: Option<i8>, now_ms: u64) -> bool {
        if flags & FLAG_ID_COLLISION != 0 {
            if id == self.id.current() {
                self.id.note_collision(now_ms);
            }
            return true;
        }
        self.id.note_heard(id, now_ms);
        // Two transmitters under one ID ⇒ different RSSI within the window. A coarse ~6 dB bucket is the
        // only sender-distinguishing signal on an identity-free radio; a single fading sender may flip a
        // bucket and cost one spurious rotation (soft).
        if let Some(r) = rssi {
            let fp = (r as i64).div_euclid(6) as u64;
            if self.detector.observe(id, fp, now_ms) {
                self.pending_hint = Some(id);
            }
        }
        false
    }

    pub fn current(&self) -> u8 {
        self.id.current()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pfs_picks_an_id_no_neighbour_is_using() {
        let mut e = EphemeralId::new(0xABCD, 10_000);
        // Fill most of the space as taken; leave exactly one free (value 200).
        for i in 0..ID_SPACE {
            if i != 200 {
                e.note_heard(i as u8, 1_000);
            }
        }
        assert_eq!(e.rotate(1_000), 200, "PFS must pick the one free slot");
    }

    #[test]
    fn dar_rotates_off_a_contended_id() {
        let mut e = EphemeralId::new(0x1234, 10_000);
        let before = e.current();
        // Everyone else is silent, so the only taken value is our own after the signal → we must move.
        let after = e.note_collision(2_000);
        assert_ne!(after, before, "a collision signal must rotate our ID");
        assert_eq!(e.current(), after);
    }

    #[test]
    fn pfs_stays_alias_free_across_a_neighbourhood() {
        // 16 nodes each pick via PFS while overhearing the others' picks in turn — the beacon-free
        // deconfliction should keep them distinct (well under the 8-bit birthday bound of ~19).
        let mut nodes: Vec<EphemeralId> = (0..16)
            .map(|i| EphemeralId::new(0x9E37_79B9 ^ (i as u64 * 0x100_0001), 10_000))
            .collect();
        // Gossip round: each node hears every already-placed node, then re-picks.
        for i in 0..nodes.len() {
            for j in 0..i {
                let heard = nodes[j].current();
                nodes[i].note_heard(heard, 1_000);
            }
            let id = nodes[i].rotate(1_000);
            // No earlier node shares it.
            for j in 0..i {
                assert_ne!(id, nodes[j].current(), "node {i} aliased node {j}");
            }
        }
    }

    #[test]
    fn deconfliction_unit_detects_aliases_and_rotates_on_a_hint() {
        let mut d = IdDeconfliction::new(0xABCD, 10_000, 500);
        // Normal send: our current ID, flags clear.
        let (id0, f0) = d.tx_id(None);
        assert_eq!(f0, 0);

        // Two transmitters under one ID (id 42) at very different RSSI within the window → an alias is
        // detected and a DAR hint is queued.
        assert!(!d.rx(42, 0, Some(-40), 1_000));
        assert!(!d.rx(42, 0, Some(-80), 1_050));
        // Our next TX piggybacks the hint: addr3[4] = the conflicted ID (42), flag set.
        let (hid, hf) = d.tx_id(None);
        assert_eq!(hid, 42);
        assert_eq!(hf & FLAG_ID_COLLISION, FLAG_ID_COLLISION);
        // The hint is one-shot — the following TX is back to our own ID.
        let (id2, f2) = d.tx_id(None);
        assert_eq!(f2, 0);
        assert_eq!(
            id2, id0,
            "our own ID is unchanged by sending a hint about someone else"
        );

        // Receiving a hint that names OUR id rotates us; the return is `true` (a hint, not a neighbour).
        let mine = d.current();
        assert!(d.rx(mine, FLAG_ID_COLLISION, Some(-50), 2_000));
        assert_ne!(
            d.current(),
            mine,
            "a collision hint for our ID must rotate us"
        );
        // A hint for someone else's ID leaves us put.
        let now = d.current();
        let other = now.wrapping_add(7);
        assert!(d.rx(other, FLAG_ID_COLLISION, Some(-50), 2_100));
        assert_eq!(d.current(), now, "a hint for another ID must not move us");
    }

    #[test]
    fn detector_flags_two_contents_on_one_id_but_not_a_single_stream() {
        let mut d = AliasDetector::new(500);
        // One sender, one ID, evolving content over time — NOT an alias (spaced beyond the window).
        assert!(!d.observe(42, 0x1111, 1_000));
        assert!(
            !d.observe(42, 0x2222, 2_000),
            "same id, later content, outside window = not an alias"
        );
        // Two senders on ID 42 within the window, different fingerprints → alias.
        assert!(!d.observe(42, 0xAAAA, 3_000));
        assert!(
            d.observe(42, 0xBBBB, 3_100),
            "same id, different content, within window = alias"
        );
        // Same content within the window (a retransmit) is NOT an alias.
        assert!(!d.observe(7, 0xCAFE, 4_000));
        assert!(
            !d.observe(7, 0xCAFE, 4_050),
            "same content = one sender, not an alias"
        );
    }

    // -----------------------------------------------------------------------------------------
    // The piggybacked class commitment
    // -----------------------------------------------------------------------------------------

    #[test]
    fn a_full_round_of_slices_covers_every_bit_of_the_fold() {
        // The round must reconstruct the fold exactly — not because a receiver ever reassembles one
        // (it does not), but because a slice the round never emits is a divergence nobody can see.
        let folded = 0x0015_5AA5 & 0x1F_FFFF;
        let mut rebuilt = 0u32;
        let mut covered = 0u8;
        for idx in 1..=COMMITMENT_SLICES {
            let flags = encode_commitment_slice(folded, idx);
            let (s, bits) = decode_commitment_slice(flags).expect("a slice is present");
            assert_eq!(s, idx - 1);
            rebuilt |= (bits as u32) << (3 * s as u32);
            covered |= 1 << s;
        }
        assert_eq!(rebuilt, folded, "the round covers all {COMMITMENT_BITS} bits");
        assert_eq!(covered, 0x7f, "all seven slices are emitted exactly once");
    }

    #[test]
    fn every_bit_of_the_digest_reaches_the_fold() {
        // Truncation would hide the class commitment entirely (it lives in the digest's tail), so
        // this asserts the fold is a fold: flipping ANY single digest bit moves it.
        let base = 0x0123_4567_89ab_cdefu64;
        let f0 = fold_commitment(base);
        for b in 0..64 {
            assert_ne!(
                fold_commitment(base ^ (1u64 << b)),
                f0,
                "digest bit {b} does not reach the fold"
            );
        }
    }

    #[test]
    fn index_zero_means_absent_not_a_zero_slice() {
        // The pre-#93 wire mandates bits 2..7 = 0. Reading that as data would report a divergence
        // against every legacy neighbour — a false partition against the whole installed base.
        assert_eq!(decode_commitment_slice(0), None);
        assert_eq!(decode_commitment_slice(FLAG_ID_COLLISION), None);
        assert_eq!(decode_commitment_slice(FLAG_BODY_PREFIX), None);
        let mut w = ClassCommitmentWatch::new(10_000);
        for t in 0..20 {
            let v = w.observe(9, 0, 0x1F_FFFF, 1_000 + t);
            assert_eq!(v.agreement, Agreement::Unknown);
            assert!(!v.newly_divergent);
        }
    }

    #[test]
    fn a_hint_frame_carries_no_slice_and_does_not_consume_one() {
        let mut d = IdDeconfliction::new(0xABCD, 10_000, 500);
        let folded = fold_commitment(0xDEAD_BEEF_CAFE_F00D);
        let (_, f1) = d.tx_id(Some(folded));
        assert_eq!(decode_commitment_slice(f1).map(|(s, _)| s), Some(0));
        // Queue a hint.
        assert!(!d.rx(42, 0, Some(-40), 1_000));
        assert!(!d.rx(42, 0, Some(-80), 1_050));
        let (hid, hf) = d.tx_id(Some(folded));
        assert_eq!(hid, 42, "the hint names the conflicted ID, not ours");
        assert_eq!(
            decode_commitment_slice(hf),
            None,
            "a slice on a hint frame would be filed against an innocent node"
        );
        // The round resumes at slice 1, not slice 2 — the hint consumed no slice.
        let (_, f2) = d.tx_id(Some(folded));
        assert_eq!(decode_commitment_slice(f2).map(|(s, _)| s), Some(1));
    }

    #[test]
    fn a_half_collected_commitment_never_reports_a_partition() {
        // THE safety property: every neighbour starts half-collected, so if a partial round could
        // read as divergent the mechanism would false-partition the entire fleet on frame one.
        let ours = fold_commitment(0x1234_5678_9abc_def0);
        let mut d = IdDeconfliction::new(0x55, 10_000, 500);
        let mut w = ClassCommitmentWatch::new(10_000);
        for i in 0..COMMITMENT_SLICES {
            let (id, flags) = d.tx_id(Some(ours)); // an AGREEING neighbour
            let v = w.observe(id, flags, ours, 1_000 + i as u64);
            assert!(!v.agreement.is_divergent(), "agreeing peer never diverges");
            assert!(!v.newly_divergent);
            let want = Agreement::Agreeing {
                bits: 3 * (i + 1),
            };
            assert_eq!(v.agreement, want, "partial rounds report bits, not a verdict");
            assert_eq!(v.agreement.is_complete(), i + 1 == COMMITMENT_SLICES);
        }
    }

    #[test]
    fn a_divergent_neighbour_is_detected_within_a_round() {
        let ours = fold_commitment(0x1234_5678_9abc_def0);
        let theirs = fold_commitment(0x1234_5678_9abc_def1); // one digest bit apart
        assert_ne!(ours, theirs);
        let mut d = IdDeconfliction::new(0x55, 10_000, 500);
        let mut w = ClassCommitmentWatch::new(10_000);
        let mut verdict = Agreement::Unknown;
        let mut frames = 0u32;
        for i in 0..(COMMITMENT_SLICES * 2) {
            let (id, flags) = d.tx_id(Some(theirs));
            let v = w.observe(id, flags, ours, 1_000 + i as u64);
            frames += 1;
            verdict = v.agreement;
            if v.newly_divergent {
                break;
            }
        }
        assert!(verdict.is_divergent(), "a different digest must be caught");
        assert!(
            frames <= COMMITMENT_SLICES as u32 + 1,
            "detection took {frames} frames; a round is {COMMITMENT_SLICES}"
        );
        assert_eq!(w.divergences(), 1);
    }

    #[test]
    fn our_own_commitment_moving_clears_every_accumulated_agreement() {
        let a = fold_commitment(0xAAAA_AAAA_AAAA_AAAA);
        let mut d = IdDeconfliction::new(0x55, 10_000, 500);
        let mut w = ClassCommitmentWatch::new(10_000);
        for i in 0..3 {
            let (id, flags) = d.tx_id(Some(a));
            w.observe(id, flags, a, 1_000 + i);
        }
        assert!(matches!(w.agreement_for(d.current()), Agreement::Agreeing { .. }));
        // Our map moves: everything we accumulated was agreement with a value we no longer hold.
        let b = fold_commitment(0xBBBB_BBBB_BBBB_BBBB);
        let (id, flags) = d.tx_id(Some(a));
        let v = w.observe(id, flags, b, 2_000);
        assert!(
            !v.agreement.is_divergent() || v.newly_divergent,
            "no stale verdict survives our own change"
        );
        assert!(
            !matches!(w.agreement_for(255 - id), Agreement::Agreeing { .. }),
            "the whole table is cleared, not just the neighbour that spoke"
        );
    }

    #[test]
    fn an_id_alias_can_neither_fabricate_nor_hide_a_divergence() {
        // Two neighbours share ID 7. Keying on 8 bits is safe only because the state is a COMPARISON,
        // not a value: merged agreement still reads agree, and one defector still reads mismatch.
        let ours = fold_commitment(0x0F0F_0F0F_0F0F_0F0F);
        let mut w = ClassCommitmentWatch::new(10_000);
        let mut honest = IdDeconfliction::new(1, 10_000, 500);
        let mut also_honest = IdDeconfliction::new(2, 10_000, 500);
        for i in 0..COMMITMENT_SLICES as u64 {
            let (_, f1) = honest.tx_id(Some(ours));
            let (_, f2) = also_honest.tx_id(Some(ours));
            assert!(!w.observe(7, f1, ours, 1_000 + i).agreement.is_divergent());
            assert!(!w.observe(7, f2, ours, 1_000 + i).agreement.is_divergent());
        }
        // Now a defector joins the alias.
        let theirs = fold_commitment(0x0F0F_0F0F_0F0F_0F0E);
        let mut defector = IdDeconfliction::new(3, 10_000, 500);
        let mut caught = false;
        for i in 0..(COMMITMENT_SLICES as u64 * 3) {
            let (_, f) = defector.tx_id(Some(theirs));
            if w.observe(7, f, ours, 2_000 + i).agreement.is_divergent() {
                caught = true;
                break;
            }
        }
        assert!(caught, "an aliased defector is still caught");
    }

    #[test]
    fn a_quiet_neighbour_is_forgotten_rather_than_kept_as_a_verdict() {
        let ours = fold_commitment(0x1111_2222_3333_4444);
        let theirs = fold_commitment(0x1111_2222_3333_4445);
        let mut d = IdDeconfliction::new(0x55, 10_000, 500);
        let mut w = ClassCommitmentWatch::new(1_000);
        for i in 0..(COMMITMENT_SLICES as u64 * 2) {
            let (id, f) = d.tx_id(Some(theirs));
            w.observe(id, f, ours, 1_000 + i);
        }
        let id = d.current();
        assert!(w.agreement_for(id).is_divergent());
        // Long silence, then it comes back agreeing (it was reconfigured): the stale verdict must not
        // outlive the evidence.
        let (id2, f) = d.tx_id(Some(ours));
        assert_eq!(id2, id);
        let v = w.observe(id2, f, ours, 1_000_000);
        assert_eq!(v.agreement, Agreement::Agreeing { bits: 3 });
    }
}
