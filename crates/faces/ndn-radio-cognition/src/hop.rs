//! **The name-keyed hop plan** — a `(carrier, period)` table derived from a NAME, written to the
//! radio's own hop sequencer.
//!
//! ## Why this is now worth building
//!
//! Name-keyed hopping has existed as a *function* on this stack for a while and had no actuator
//! that could keep up with it. The host-retune path cannot hop at slot scale — MEASURED, a
//! Waveshare SX1262 channel change is a **161 ms** full image calibration — so a per-slot hop
//! driven from the host was never going to be more than a design note.
//!
//! Intra-packet hopping changes the arithmetic completely. The LR2021's
//! `WriteLrFhssHoppingTable` / `SetLoraHopping` take up to **40 `(frequency, dwell)` couples**
//! and the *chip* walks them, so the host writes a table once and the radio does the hopping at
//! whatever rate the modem supports. A schedule DERIVED FROM A NAME is exactly a table of that
//! shape, which is what makes this the first real actuator for the idea.
//!
//! ## Why hopping, on this bench, is not optional
//!
//! HaLow co-bands with LoRa in 902-928 MHz here, and MEASURED, a mid-band LoRa channel
//! (ch 65 = 915 MHz) **collapses** when HaLow runs; the workaround was to cede the middle and
//! sit on the band edge (ch 78 = 928 MHz). Hopping is how a name coexists with a co-band
//! interferer instead of ceding to it: a hop plan spreads one name's airtime across the whole
//! advertised span, so an interferer that owns part of the band costs a fraction of the frames
//! rather than all of them, and two *different* names get *different* subsets, which spreads our
//! own traffic too.
//!
//! ## The rule that shapes the derivation: shared inputs only
//!
//! Nothing is negotiated on air. Both ends must compute a **bit-identical** list or the link is
//! gone — so every input to [`name_hop_plan`] is a fact both ends hold identically:
//!
//! * the **#44 group key** (already shared: the same key the group-key rendezvous is computed under);
//! * the **name**;
//! * the **carrier set** the group operates on, in Hz, canonicalised here (sorted,
//!   deduplicated) so two nodes that enumerate the same band plan in different orders still
//!   agree — the same kind of shared configuration the fixed channel already is;
//! * the **hop period** and the **table length**, which are configuration.
//!
//! Carriers are in **Hz**, not channel indices, because Hz is what the actuator takes
//! ([`RadioKnobs::set_hop_plan`](ndn_radio_hal::RadioKnobs::set_hop_plan), and `CMD_SET_HOP`
//! under it) and because the index→Hz map is a per-backend fact. A pure control-plane crate
//! that invented its own map would eventually disagree with the one `set_channel` uses; taking
//! the carriers as given means the plan and the tune can never land on different frequencies.
//!
//! ⚠ **Local measurement must never enter this derivation.** Steering the plan away from a
//! locally-busy channel is the obvious next idea and it is exactly wrong: occupancy is a local
//! observation, the two ends measure different neighbourhoods, and a plan derived from it splits
//! the pair. Channel *avoidance* belongs where a shared decision can carry it (the advertised
//! channel set, or a cooperative map both ends have converged on) — not here.
//!
//! ## Why the #44 keyspace, and not a new one
//!
//! The hop draws are SipHash-2-4 under the group key, via [`siphash24`](ndn_frame_io::siphash24) —
//! the #44 shared keyspace, the *same* keyed primitive the group-key rendezvous already uses. Three
//! reasons, in order of importance:
//!
//! 1. **One key to distribute and rotate.** A group already shares exactly one 16-byte key. A
//!    second keyspace would mean a second key to provision, and a node that had one and not the
//!    other would filter correctly and hop wrongly — a failure with no error message.
//! 2. **The adversarial property carries over.** SipHash under the full key is a keyed PRF, so
//!    an outsider watching frames cannot recover the key and therefore cannot predict (or
//!    deliberately camp on) a private group's hop sequence. That property is the whole reason
//!    the #44 keyspace uses keyed SipHash rather than FNV; deriving hops from an unkeyed hash would hand it
//!    straight back. (The firmware's own `hop_channel` uses unkeyed FNV-1a for exactly the
//!    reason this design supersedes: it had to hash on an MCU with no key. Here the host
//!    computes the table and writes it, so the keyed hash is free.)
//! 3. **One hash family.** #44's whole point is that name→bits derivations in this stack share
//!    a primitive rather than accumulating one per feature.
//!
//! Hop draws are separated from any other name-derivation under the same key by **XOR-ing a domain
//! constant into the key** ([`HOP_KEY_DOMAIN`]), and separated from each other by an index byte
//! appended to the message. So a name's hop sequence is independent of every other keyed derivation
//! under the same shared key.

use ndn_frame_io::siphash24;

/// The #44 shared-keyspace keyed hash — formerly `mac::tier0::name_hash`. The in-frame filter that
/// shared this primitive is retired; the hop plan keeps using the same keyed SipHash-2-4.
fn name_hash(key: &[u8; 16], name: &[u8]) -> u64 {
    siphash24(key, name)
}

/// Most carriers a hop table holds — the LR20xx `WriteLrFhssHoppingTable` / `SetLoraHopping`
/// limit, which `CMD_SET_HOP` pins as the wire bound too, and therefore the cap on any plan this
/// crate emits. A radio whose [`HopCapability::max_list_len`](crate::HopCapability) is smaller
/// gets a prefix — see [`HopPlan::truncated`].
pub const MAX_HOP_COUPLES: usize = 40;

/// Domain separator XOR-ed into the #44 group key so hop draws are an independent PRF evaluation
/// from every other keyed name-derivation under the same key; a distinct constant, so the
/// derivations cannot correlate.
pub const HOP_KEY_DOMAIN: [u8; 16] = *b"ndn/hop-plan\0\0\0\0";

/// A name's hop table: an ordered, deterministic list of carriers (Hz) plus the period the radio
/// advances through them. Built by [`name_hop_plan`]; written to the radio by the PHY through
/// [`RadioKnobs::set_hop_plan`](ndn_radio_hal::RadioKnobs::set_hop_plan).
///
/// The `period` is carried, not interpreted: its unit is the radio's
/// ([`HopCapability::period_unit`](crate::HopCapability)) — **LoRa symbols** on a LoRa-modulation
/// radio, whose wall-clock value moves with SF and bandwidth, or microseconds elsewhere. A plan
/// that converted it to a duration here would be wrong on half the fleet.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct HopPlan {
    freqs_hz: Vec<u32>,
    period: u16,
}

impl HopPlan {
    /// The carriers, in hop order.
    pub fn freqs_hz(&self) -> &[u32] {
        &self.freqs_hz
    }

    /// The hop period, in the radio's own unit.
    pub fn period(&self) -> u16 {
        self.period
    }

    /// Number of carriers (0 = nothing to actuate).
    pub fn len(&self) -> usize {
        self.freqs_hz.len()
    }

    pub fn is_empty(&self) -> bool {
        self.freqs_hz.is_empty()
    }

    /// The carrier this plan sits on at hop index `epoch`, wrapping — the read a receiver uses to
    /// know where a name is *now*, given a common-view epoch. `None` for an empty plan.
    pub fn carrier_at(&self, epoch: u64) -> Option<u32> {
        if self.freqs_hz.is_empty() {
            return None;
        }
        Some(self.freqs_hz[(epoch % self.freqs_hz.len() as u64) as usize])
    }

    /// Truncate to what a radio's hop engine will actually accept
    /// ([`HopCapability::max_list_len`](crate::HopCapability)). A radio with a shorter table still
    /// hops — over a *prefix* of the same derived sequence, so both ends still agree as long as
    /// they agree on the length.
    pub fn truncated(mut self, max: usize) -> Self {
        self.freqs_hz.truncate(max.min(MAX_HOP_COUPLES));
        self
    }
}

/// The #44 hop key: the group key with [`HOP_KEY_DOMAIN`] XOR-ed in.
fn hop_key(key: &[u8; 16]) -> [u8; 16] {
    let mut k = *key;
    for (b, d) in k.iter_mut().zip(HOP_KEY_DOMAIN.iter()) {
        *b ^= *d;
    }
    k
}

/// Draw `i` for `name` — SipHash-2-4 under the hop key over `name ‖ 0x00 ‖ i`.
fn draw(key: &[u8; 16], name: &[u8], i: usize) -> u64 {
    let mut msg = Vec::with_capacity(name.len() + 2);
    msg.extend_from_slice(name);
    msg.push(0x00); // separator: `/a` + index 1 must not collide with `/a\x01` + index 0
    msg.push(i as u8);
    name_hash(key, &msg)
}

/// An evenly-spaced carrier grid — a convenience for stating a band plan as three numbers
/// (`902 MHz .. 928 MHz` every `1 MHz`, say) instead of listing 27 carriers at every wiring site.
///
/// It is *configuration*, not a discovered fact: whoever calls it is asserting the plan both ends
/// run. An empty or inverted span yields an empty grid rather than a fabricated carrier.
pub fn carrier_grid(min_hz: u32, max_hz: u32, step_hz: u32) -> Vec<u32> {
    if step_hz == 0 || max_hz < min_hz {
        return Vec::new();
    }
    (0..)
        .map(|i| min_hz.saturating_add(i * step_hz))
        .take_while(|&f| f <= max_hz)
        .take(1024)
        .collect()
}

/// **Derive a name's hop plan.**
///
/// `carriers_hz` is the group's band plan; it is canonicalised (sorted, deduplicated) before use
/// so two nodes enumerating it in different orders still derive the same list. The sequence is a
/// **keyed Fisher-Yates shuffle** of that set, so:
///
/// * every carrier in the plan is one the caller declared;
/// * no carrier repeats until the table has been exhausted (a repeat would waste a dwell);
/// * when the band plan is larger than the table, a name occupies a name-specific *subset* —
///   different names spread onto different carriers, which is the coexistence property this
///   exists for;
/// * when it is smaller, the plan is a full permutation and the name visits everything.
///
/// `len` requests a table length; it is clamped to the carrier count and to [`MAX_HOP_COUPLES`].
/// `period` is passed through in the radio's own unit (see [`HopPlan`]).
///
/// An empty `carriers_hz` yields an empty plan (nothing to actuate), never a fabricated carrier.
pub fn name_hop_plan(
    key: &[u8; 16],
    name: &[u8],
    carriers_hz: &[u32],
    period: u16,
    len: usize,
) -> HopPlan {
    let mut pool: Vec<u32> = carriers_hz.to_vec();
    pool.sort_unstable();
    pool.dedup();
    if pool.is_empty() || len == 0 {
        return HopPlan::default();
    }
    let k = hop_key(key);
    let take = len.min(pool.len()).min(MAX_HOP_COUPLES);

    // Keyed Fisher-Yates, partial: only the first `take` positions have to be settled.
    let n = pool.len();
    for i in 0..take.min(n.saturating_sub(1)) {
        let span = (n - i) as u64;
        let j = i + (draw(&k, name, i) % span) as usize;
        pool.swap(i, j);
    }
    pool.truncate(take);
    HopPlan {
        freqs_hz: pool,
        period,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: [u8; 16] = *b"ndn/hop-test-key";
    /// The 902-928 MHz US ISM span this bench actually runs in at 1 MHz spacing — the band HaLow
    /// co-bands with, and the one a mid-band LoRa carrier was MEASURED to collapse in.
    fn us915() -> Vec<u32> {
        carrier_grid(902_000_000, 928_000_000, 1_000_000)
    }

    #[test]
    fn a_carrier_grid_is_three_numbers_and_nothing_more() {
        let g = us915();
        assert_eq!(g.len(), 27);
        assert_eq!(g[0], 902_000_000);
        assert_eq!(*g.last().unwrap(), 928_000_000);
        assert!(carrier_grid(928_000_000, 902_000_000, 1_000_000).is_empty());
        assert!(carrier_grid(902_000_000, 928_000_000, 0).is_empty());
    }

    /// **The property the whole design rests on.** Two nodes, no negotiation, same key + same
    /// name + same band plan ⇒ byte-identical hop lists. Checked across many names, several table
    /// lengths and a reversed carrier enumeration, because a divergence here is not a slow link,
    /// it is no link.
    #[test]
    fn both_ends_derive_the_same_hop_list() {
        let mut reversed = us915();
        reversed.reverse(); // the peer enumerated its band plan the other way round
        for i in 0..64u32 {
            let name = format!("/ndn/lora-cog/A/seq/{i}").into_bytes();
            for len in [1usize, 4, 8, 27, 40, 100] {
                let a = name_hop_plan(&KEY, &name, &us915(), 12, len);
                let b = name_hop_plan(&KEY, &name, &reversed, 12, len);
                assert_eq!(a, b, "the two ends diverged for {len} hops");
                assert!(!a.is_empty());
                assert_eq!(a.period(), 12);
            }
        }
    }

    /// Every carrier in a plan came from the declared band plan, the length respects both the
    /// request and the hardware cap, and no carrier is spent twice.
    #[test]
    fn a_plan_stays_inside_the_declared_band_plan() {
        let pool = us915();
        for i in 0..32u32 {
            let name = format!("/ndn/x/{i}").into_bytes();
            let p = name_hop_plan(&KEY, &name, &pool, 8, 100);
            assert_eq!(p.len(), MAX_HOP_COUPLES.min(pool.len()));
            let mut seen = std::collections::HashSet::new();
            for &f in p.freqs_hz() {
                assert!(pool.contains(&f), "invented carrier {f}");
                assert!(seen.insert(f), "carrier {f} used twice");
            }
        }
    }

    /// Different names take different hop sequences — the coexistence property. Not a guarantee
    /// for any single pair (a shuffle can coincide), so it is asserted over a population, where a
    /// systematic failure would show.
    #[test]
    fn different_names_spread_onto_different_sequences() {
        let pool = us915();
        let plans: Vec<HopPlan> = (0..64)
            .map(|i| name_hop_plan(&KEY, format!("/ndn/n{i}").as_bytes(), &pool, 8, 8))
            .collect();
        let identical = plans
            .iter()
            .enumerate()
            .flat_map(|(i, a)| plans[i + 1..].iter().map(move |b| (a, b)))
            .filter(|(a, b)| a == b)
            .count();
        assert_eq!(identical, 0, "distinct names collided on a whole sequence");
        // And the first hop is genuinely spread, not parked on one carrier.
        let firsts: std::collections::HashSet<u32> =
            plans.iter().filter_map(|p| p.carrier_at(0)).collect();
        assert!(
            firsts.len() > pool.len() / 2,
            "first hops clustered onto {} of {} carriers",
            firsts.len(),
            pool.len()
        );
    }

    /// The key is load-bearing: a different group key gives a different sequence for the same
    /// name, which is what stops an outsider camping on a private group's hops.
    #[test]
    fn the_group_key_changes_the_sequence() {
        let pool = us915();
        let other = *b"ndn/hop-other-k!";
        let differ = (0..32)
            .filter(|i| {
                let n = format!("/ndn/k{i}");
                name_hop_plan(&KEY, n.as_bytes(), &pool, 8, 8)
                    != name_hop_plan(&other, n.as_bytes(), &pool, 8, 8)
            })
            .count();
        assert_eq!(differ, 32, "the key must change every sequence");
    }

    /// Degenerate inputs produce nothing to actuate, never an invented carrier.
    #[test]
    fn no_carriers_means_no_plan() {
        assert!(name_hop_plan(&KEY, b"/a", &[], 8, 8).is_empty());
        assert!(name_hop_plan(&KEY, b"/a", &us915(), 8, 0).is_empty());
        let single = name_hop_plan(&KEY, b"/a", &[915_000_000], 8, 40);
        assert_eq!(single.len(), 1);
        assert_eq!(
            single.carrier_at(7),
            Some(915_000_000),
            "one carrier wraps to itself"
        );
    }

    /// A radio with a shorter hop sequencer gets a PREFIX of the same sequence, so two nodes that
    /// agree on the length still agree on the hops.
    #[test]
    fn truncation_keeps_the_prefix() {
        let pool = us915();
        let full = name_hop_plan(&KEY, b"/ndn/trunc", &pool, 8, 40);
        let short = name_hop_plan(&KEY, b"/ndn/trunc", &pool, 8, 12);
        assert_eq!(&full.freqs_hz()[..12], short.freqs_hz());
        assert_eq!(full.clone().truncated(12), short);
    }
}
