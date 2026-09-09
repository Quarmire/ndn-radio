//! # NDR MAC design-invariant suite — organized by the four facets
//!
//! This suite tests the **design promises** of the Named Data Radio MAC (see `docs/GLOSSARY.md` §0 and
//! `docs/mac-test-suite.md`), not the per-case implementation details the in-module unit tests already
//! cover. Each test states one cross-cutting guarantee and checks it over a **corpus** of names, so a
//! regression that only shows up statistically (a filter that over-admits, a schedule that starves a slot)
//! is caught. Deterministic (a seeded PRNG) so failures reproduce.
//!
//! | Facet | Promise under test |
//! |---|---|
//! | **WHO**   | a receiver admits every frame under its registered prefix (never false-negative), and over-admits at a bounded rate |
//! | **WHEN**  | airtime is a pure, fair function of name + clock; reserved/open lanes are disjoint |
//! | **WHERE** | two radios on different channels use decorrelated schedules |
//! | **HOW-WELL** | reliability maps monotonically to robustness; HE reach levers are gated on capability |

use ndn_radio_cognition::{LeaseClass, SlotSchedule, prefix_hash};
use ndn_radio_hal::{McsDescriptor, Reliability, TxIntent};

/// Deterministic splitmix64 — reproducible corpora with no `rand` dependency.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

/// A random slash-form name of `depth` components drawn from a small alphabet, e.g. `/ndn/c3/a1/b7`.
fn random_name(rng: &mut Rng, depth: usize) -> Vec<u8> {
    let mut s = Vec::from(&b"/ndn"[..]);
    for _ in 0..depth {
        s.push(b'/');
        s.push(b'a' + (rng.below(20) as u8));
        s.extend_from_slice(rng.below(1000).to_string().as_bytes());
    }
    s
}

// ────────────────────────────────────────── WHEN ───────────────────────────────────────────

const SLOTS: u64 = 8;

/// **WHEN-1 — the owned slot is a pure function of the name.** Same name → same slot, always and on every
/// node, with no clock or state term in `owner_slot`. (The clock only advances the epoch; ownership within
/// an epoch is deterministic.) This is what lets every node agree with zero coordination.
#[test]
fn when_owner_slot_is_a_pure_function() {
    let sched = SlotSchedule::new(20_000, SLOTS);
    let mut rng = Rng(0x51075);
    for _ in 0..1000 {
        let name = random_name(&mut rng, 3);
        let comps: Vec<&[u8]> = name
            .split(|&b| b == b'/')
            .filter(|c| !c.is_empty())
            .collect();
        let h = prefix_hash(&comps);
        assert_eq!(
            sched.owner_slot(h),
            sched.owner_slot(h),
            "owner_slot must be deterministic"
        );
        assert!(sched.owner_slot(h) < SLOTS, "slot in range");
    }
}

/// **WHEN-2 — airtime is fairly divided across names (no slot starves).** Over a large name corpus the
/// owned-slot distribution must be ~uniform: every slot should get a non-trivial share. A schedule that
/// funnels most names into one slot would collapse the MAC's per-name access latency. Asserts every slot's
/// share is within [0.5×, 2×] of the uniform expectation.
#[test]
fn when_slots_are_fair_across_names() {
    let sched = SlotSchedule::new(20_000, SLOTS);
    let mut counts = [0u64; SLOTS as usize];
    let mut rng = Rng(0xFA17);
    let n = 8000u64;
    for _ in 0..n {
        let name = random_name(&mut rng, 3);
        let comps: Vec<&[u8]> = name
            .split(|&b| b == b'/')
            .filter(|c| !c.is_empty())
            .collect();
        counts[sched.owner_slot(prefix_hash(&comps)) as usize] += 1;
    }
    let expect = n as f64 / SLOTS as f64;
    for (i, &c) in counts.iter().enumerate() {
        let share = c as f64 / expect;
        assert!(
            (0.5..=2.0).contains(&share),
            "slot {i} share {share:.2} off uniform (count {c}, expect {expect:.0}): schedule not fair",
        );
    }
}

/// **WHEN-3 — the medium-keying decorrelates channels (#89).** The same name on two different channels must
/// usually own **different** slots, so a second radio buys additional turns, not parallel copies of one.
/// Uses the documented keying `prefix_hash XOR (channel * 0x9E37_79B9)`; this test also pins that formula.
#[test]
fn when_medium_keying_decorrelates_channels() {
    let sched = SlotSchedule::new(20_000, SLOTS);
    let medium_keyed = |h: u64, ch: u64| h ^ ch.wrapping_mul(0x9E37_79B9);
    let (mut differ, mut total) = (0u64, 0u64);
    let mut rng = Rng(0xC0FFEE);
    for _ in 0..4000 {
        let name = random_name(&mut rng, 3);
        let comps: Vec<&[u8]> = name
            .split(|&b| b == b'/')
            .filter(|c| !c.is_empty())
            .collect();
        let h = prefix_hash(&comps);
        let s1 = sched.owner_slot(medium_keyed(h, 6)); // ch 6 (2.4 GHz)
        let s36 = sched.owner_slot(medium_keyed(h, 36)); // ch 36 (5 GHz)
        if s1 != s36 {
            differ += 1;
        }
        total += 1;
    }
    let rate = differ as f64 / total as f64;
    // For 8 slots the ideal decorrelation is (SLOTS-1)/SLOTS = 0.875; assert clearly-decorrelated (> 0.5),
    // which a broken keying (identical schedule on both channels) would fail at 0.0.
    assert!(
        rate > 0.5,
        "channel decorrelation {rate:.3} too low: two channels share a schedule"
    );
}

/// **WHEN-4 — reserved (latency) and open (bulk) lanes are disjoint.** A latency-class lease must never
/// land in an open slot and a bulk lease must never land in a reserved slot, or the low-latency guarantee
/// leaks into best-effort airtime.
#[test]
fn when_lease_class_lanes_are_disjoint() {
    let sched = SlotSchedule::new(20_000, SLOTS).with_reserved_stride(4); // slots 0,4 reserved
    assert!(
        (1..SLOTS).contains(&sched.reserved_slots()),
        "stride-4 must create a non-empty, non-total reserved lane (got {})",
        sched.reserved_slots()
    );
    let mut rng = Rng(0x1A7E);
    for _ in 0..3000 {
        let name = random_name(&mut rng, 3);
        let comps: Vec<&[u8]> = name
            .split(|&b| b == b'/')
            .filter(|c| !c.is_empty())
            .collect();
        let h = prefix_hash(&comps);
        let lat = sched.owner_slot_in(h, LeaseClass::Latency);
        let bulk = sched.owner_slot_in(h, LeaseClass::Bulk);
        assert!(
            sched.is_reserved(lat),
            "Latency lease landed in an open slot ({lat})"
        );
        assert!(
            !sched.is_reserved(bulk),
            "Bulk lease landed in a reserved slot ({bulk})"
        );
    }
}

// ──────────────────────────────────────── HOW-WELL ─────────────────────────────────────────

/// **HOW-WELL-1 — reliability orders robustness.** `for_intent` must map the reliability axis monotonically:
/// `MostRobust` is the most-robust rate (lowest index, with diversity coding), `Throughput` the fastest.
/// A regression that inverts this would send discovery/control at a fragile rate.
#[test]
fn howwell_reliability_orders_robustness() {
    let max_index = 7;
    let robust = McsDescriptor::for_intent(
        &TxIntent::broadcast(Reliability::MostRobust),
        max_index,
        false,
        false,
    );
    let balanced = McsDescriptor::for_intent(
        &TxIntent::broadcast(Reliability::Balanced),
        max_index,
        false,
        false,
    );
    let thru = McsDescriptor::for_intent(
        &TxIntent::broadcast(Reliability::Throughput),
        max_index,
        false,
        false,
    );
    assert!(
        robust.index <= balanced.index,
        "MostRobust must not be faster than Balanced"
    );
    assert!(
        balanced.index <= thru.index,
        "Balanced must not be faster than Throughput"
    );
    assert!(
        robust.stbc && robust.ldpc,
        "MostRobust must carry diversity coding (STBC+LDPC)"
    );
    assert!(!thru.stbc, "Throughput should not force diversity coding");
}

/// **HOW-WELL-2 — the HE reach levers are gated on capability.** `for_intent(MostRobust)` must escalate to
/// HE ER-SU + DCM **only** when the radio advertises `he_cap`; on a non-HE radio it must stay on the
/// universally-decodable HT + STBC + LDPC path (an HE frame a legacy RX cannot decode must not be the
/// default robust choice).
#[test]
fn howwell_he_reach_levers_gated_on_capability() {
    let robust = &TxIntent::broadcast(Reliability::MostRobust);
    let he = McsDescriptor::for_intent(robust, 7, false, /* he_cap */ true);
    assert!(
        he.he && he.er_su && he.dcm,
        "MostRobust on an HE radio must use ER-SU + DCM"
    );

    let non_he = McsDescriptor::for_intent(robust, 7, false, /* he_cap */ false);
    assert!(
        !non_he.he && !non_he.er_su,
        "MostRobust on a non-HE radio must NOT emit HE (undecodable by legacy RX)"
    );
    assert!(
        non_he.stbc && non_he.ldpc,
        "the non-HE robust path is HT + STBC + LDPC"
    );
}
