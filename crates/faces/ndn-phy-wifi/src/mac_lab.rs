//! **P2 — the MAC lab**: conformance properties for the named-token MAC on a modeled medium,
//! off-air, before any campaign ("one filter, one map" plan §4).
//!
//! Why this exists, from the project's own record: M5 reopened on air twice; the +119% defect fell
//! out of counters, not air hours; #96's decisive result was a controlled falsification. Every
//! defect in this file's scope is harness-findable in minutes and air-findable in a campaign —
//! so the campaign gate is "this suite is green" (P6 red-by-design), and an on-air anomaly comes
//! back HERE as a new property before any re-run.
//!
//! The lab already paid for itself while being built: the #93 lease geometry (`owner_slot_in`,
//! `is_reserved`) had **no caller in the gate** — owners were placed by plain modulo and a fresh
//! claim could take a reserved lane. Property P2 would have been red for a reason nobody had
//! written down. The actuation was completed first (class rides the `GroupTable`, the gate places
//! by class, claims refuse lanes), and the properties below now hold against the real code paths.
//!
//! Time: properties that need a timeline run on the real wall clock with ms slots — the same
//! technique the fourth-suppressor test uses — with tolerances stated at each assert. Everything
//! else is scripted/pure. The "same suite over loopback drivers" step (plan §4.9) is deferred;
//! these properties drive `FaceScheduler` directly.

use std::sync::Arc;

use ndn_radio_cognition::ephemeral_id::{
    Agreement, COMMITMENT_SLICES, ClassCommitmentWatch, IdDeconfliction,
};

use super::*;

// ---------------------------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------------------------

/// A minimal broadcast medium with an asymmetric hearing matrix: `deliver(i, ...)` hands node
/// `i`'s frame to every node that can hear `i`. No loss model, no delay — the properties here are
/// about the MAP and the CLAIM DISCIPLINE, not PHY fidelity (that is ndn-sim's job).
struct Medium<const N: usize> {
    nodes: Vec<Arc<FaceScheduler>>,
    hear: [[bool; N]; N],
}

impl<const N: usize> Medium<N> {
    fn deliver(&self, from: usize, group: Option<&[u8; 6]>, addr: Option<&[u8; 6]>, wire: &[u8]) {
        // Each lab node's §2 nonce is derived from its index — stable per node, distinct across
        // nodes, exactly what a real EphemeralSource provides within one rotation period.
        let nonce = [0x02, 0x4e, 0x44, 0x4e, 0x00, from as u8 + 1];
        for (j, node) in self.nodes.iter().enumerate() {
            if j != from && self.hear[from][j] {
                // Legacy broadcast shape: the nonce rides addr2.
                node.observe_rx(group, Some(&nonce), None, wire);
            }
        }
    }
}

/// A lab scheduler: wall clock (shared by every in-process node, which is what makes the maps
/// agree), claimable, no hop.
fn lab_sched(slot: SlotSchedule, groups: Option<Arc<GroupTable>>) -> FaceScheduler {
    let s = FaceScheduler {
        slot: Some(slot),
        hop: None,
        // Attached below through `with_groups`, not by field assignment: that builder is what pins
        // the table's slot depth AND its class assignment into `sched_params` (D2), so a lab node
        // that side-stepped it would carry a pin its own map contradicts.
        groups: None,
        // …and capture the pin from the schedule actually in force rather than defaulting it, so
        // `map_digest()` in the lab means what it means on air (the default said reserved = 0 while
        // the lab ran a reserved-lane stride).
        sched_params: crate::sched::SchedParams::capture(
            1,
            ClockSource::Wall,
            Some(&slot),
            None,
        ),
        clock_source: ClockSource::Wall,
        knobs: None,
        bw: crate::Bandwidth::default(),
        current_ch: AtomicU8::new(36),
        hw: Mutex::new(RadioHwClock::realtek()),
        cv: Mutex::new(RadioHwClock::common_view()),
        cv_hw: Mutex::new(None),
        master: false,
        net: Mutex::new(NetworkTime::new(u64::MAX)),
        claimable: true,
        last_domain_rx: AtomicU64::new(0),
        stats: super::SchedStats::default(),
        slots: super::SlotState::new(slot.slots() as usize),
        hold_slot_start: AtomicU64::new(u64::MAX),
        lease_until: AtomicU64::new(0),
        claim_unknown: false,
        lease_max: 1,
        rate: None,
        clock_skew_us: 0,
        base: Instant::now(),
    };
    match groups {
        Some(g) => s.with_groups(g),
        None => s,
    }
}

fn data_wire(comps: &[&[u8]]) -> Vec<u8> {
    let mut name = Vec::new();
    for c in comps {
        name.push(0x08);
        name.push(c.len() as u8);
        name.extend_from_slice(c);
    }
    let mut tlv = vec![0x07, name.len() as u8];
    tlv.extend_from_slice(&name);
    let mut d = vec![0x06, tlv.len() as u8];
    d.extend_from_slice(&tlv);
    d
}

/// Spin (async, coarse) until the wall clock sits inside a slot satisfying `want`.
async fn wait_for_slot(s: &FaceScheduler, want: impl Fn(u64, u64) -> bool) -> u64 {
    let slot = s.slot.unwrap();
    loop {
        let now = s.now_us();
        let k = slot.current_slot(now);
        // Only accept an instant with most of the slot still ahead, so a subsequent claim's
        // jitter + airtime always fits and timing slack cannot masquerade as a property failure.
        if want(k, now) && slot.slot_remaining_us(now) > slot.slot_us() * 3 / 4 {
            return now;
        }
        tokio::time::sleep(Duration::from_micros(200)).await;
    }
}

// ---------------------------------------------------------------------------------------------
// P1 — map agreement: every node computes the same (slot, class) map; lanes/open disjoint.
// ---------------------------------------------------------------------------------------------
#[test]
fn prop_p1_map_agreement() {
    let table = || {
        Arc::new(
            GroupTable::new(&[
                    b"/alarm".as_slice(),
                    b"/bulk".as_slice(),
                    b"/ndn".as_slice(),
                ],
            )
            .with_latency_unauthorised(&[b"/alarm".as_slice()]),
        )
    };
    let slot = SlotSchedule::new(3000, 8).with_reserved_stride(4);
    let nodes: Vec<FaceScheduler> = (0..5).map(|_| lab_sched(slot, Some(table()))).collect();

    for name in [
        &b"/alarm/1"[..],
        b"/bulk/x/y",
        b"/ndn/z",
        b"/unregistered/q",
    ] {
        let wire = {
            let comps: Vec<&[u8]> = name
                .split(|&b| b == b'/')
                .filter(|c| !c.is_empty())
                .collect();
            data_wire(&comps)
        };
        let views: Vec<(u64, LeaseClass, u64)> = nodes
            .iter()
            .map(|n| {
                let (h, c) = n.name_group(&wire).expect("keyed");
                (h, c, slot.owner_slot_in(n.medium_keyed(h), c))
            })
            .collect();
        assert!(
            views.windows(2).all(|w| w[0] == w[1]),
            "nodes disagree about {} — two maps: {views:?}",
            String::from_utf8_lossy(name)
        );
        // Class placement is disjoint by construction, and the map must show it.
        let (_, class, owned) = views[0];
        match class {
            LeaseClass::Latency => assert!(slot.is_reserved(owned), "latency outside its lane"),
            LeaseClass::Bulk => assert!(!slot.is_reserved(owned), "bulk inside a lane"),
        }
    }
}

// ---------------------------------------------------------------------------------------------
// P1b — the CONVERSE of P1: a node that does not compute the same (slot, class) map is DETECTED.
//
// P1 asserts five nodes agree. Nothing asserted what happens when one does not, and until the class
// commitment the answer was "nothing": `LeaseClass` is a per-node input (`with_latency…` takes a
// slice literal) and it was outside the `SchedParams` pin, so a node that promoted its own prefixes
// into the reserved lanes emitted a digest IDENTICAL to the honest fleet's while placing that
// name in a lane the others keep clear (#93). Agreement is unenforceable here by design — there is no
// convergence protocol, §2 law 6 — which is exactly why the DETECTION half has to be a property.
//
// ☠ **This property used to be true in the lab and false on air**, and that is why it is written
// this way now. It called `build_beacon()` on the defector — but `lab_sched` sets `master: false`,
// and the face spawns the beacon task ONLY behind `sched.is_master()` (`medium.rs`,
// `NDN_SCHED_MASTER=1`). So the old assertion exercised a frame the defector would never transmit:
// a non-master defector was undetectable by anyone, and the property said otherwise. The carrier is
// now the commitment slice piggybacked on ordinary data (`addr3[5]` bits 2..7,
// `IdDeconfliction::tx_id` -> `ClassCommitmentWatch::observe`), which every node sends, so the
// property below asserts detection for a defector with `is_master() == false` — the case that
// matters and the case that was uncovered.
// ---------------------------------------------------------------------------------------------
#[test]
fn prop_p1b_class_divergence_is_detected_on_ordinary_data_from_a_non_master() {
    let regs = [
        b"/alarm".as_slice(),
        b"/bulk".as_slice(),
        b"/ndn".as_slice(),
    ];
    let slot = SlotSchedule::new(3000, 8).with_reserved_stride(4);
    // The fleet's lane policy: /alarm, and only /alarm.
    let honest = || {
        Arc::new(GroupTable::new(&regs).with_latency_unauthorised(&[b"/alarm".as_slice()]))
    };
    // The defector runs that policy AND helps itself to a lane for its own bulk traffic. Identical
    // registration set, identical schedule inputs — the class assignment is the only difference.
    let defecting = Arc::new(
        GroupTable::new(&regs)
            .with_latency_unauthorised(&[b"/alarm".as_slice(), b"/bulk".as_slice()]),
    );

    let nodes: Vec<FaceScheduler> = (0..4).map(|_| lab_sched(slot, Some(honest()))).collect();
    let defector = lab_sched(slot, Some(defecting));

    // Premise: the divergence is real, not notional — /bulk leaves the open slots for a lane.
    let wire = data_wire(&[b"bulk".as_slice(), b"x".as_slice()]);
    let (hh, hc) = nodes[0].name_group(&wire).expect("keyed");
    let (dh, dc) = defector.name_group(&wire).expect("keyed");
    assert_eq!(hh, dh, "premise: the slot KEY is unchanged; only the class moved");
    assert!(
        !slot.is_reserved(slot.owner_slot_in(nodes[0].medium_keyed(hh), hc))
            && slot.is_reserved(slot.owner_slot_in(defector.medium_keyed(dh), dc)),
        "premise: the promotion moves /bulk out of the open slots and into a reserved lane"
    );

    // ⚠ The premise that makes this the RIGHT property: NOBODY here is the clock master, so nobody
    // transmits a beacon. Detection must come off ordinary data or it does not exist.
    assert!(
        !defector.is_master() && nodes.iter().all(|n| !n.is_master()),
        "premise: this is the uncovered case — a non-master defector among non-master peers"
    );

    // The defector's ordinary data frames, as `medium.rs` builds them: one commitment slice per
    // frame from the same allocator the TX path uses.
    let mut defector_tx = IdDeconfliction::new(0xD1D1, 300_000, 2_000);
    let mut honest_tx = IdDeconfliction::new(0x0A0A, 300_000, 2_000);

    // The property, half 1: every honest node flags the defector within one round of its traffic.
    for (i, n) in nodes.iter().enumerate() {
        let mut w = ClassCommitmentWatch::new(300_000);
        let mut caught_after = None;
        for f in 0..(COMMITMENT_SLICES as u64 * 2) {
            let (id, flags) = defector_tx.tx_id(Some(defector.class_commitment()));
            let v = w.observe(id, flags, n.class_commitment(), 1_000 + f);
            if v.newly_divergent {
                caught_after = Some(f + 1);
                break;
            }
            assert!(
                !v.agreement.is_divergent(),
                "node {i}: a partially collected round reported a partition"
            );
        }
        let frames = caught_after.expect("node did not detect a promoted lane assignment");
        assert!(
            frames <= COMMITMENT_SLICES as u64 + 1,
            "node {i} needed {frames} frames; a full round is {COMMITMENT_SLICES}"
        );
    }

    // The property, half 2: no honest node flags another, ever — not once, not at any point in the
    // round. A detector that fires on agreement is worse than no detector.
    for (i, n) in nodes.iter().enumerate() {
        let mut w = ClassCommitmentWatch::new(300_000);
        for f in 0..(COMMITMENT_SLICES as u64 * 5) {
            let (id, flags) = honest_tx.tx_id(Some(nodes[0].class_commitment()));
            let v = w.observe(id, flags, n.class_commitment(), 1_000 + f);
            assert!(
                !v.newly_divergent && !v.agreement.is_divergent(),
                "node {i} false-partitioned against an honest peer at frame {f}"
            );
        }
        assert!(
            w.agreement_for(honest_tx.current()).is_complete(),
            "node {i} should have compared a whole round with an honest peer"
        );
    }

    // Detection is symmetric — the defector sees the split too, off the fleet's ordinary data.
    let mut w = ClassCommitmentWatch::new(300_000);
    let mut saw = false;
    for f in 0..(COMMITMENT_SLICES as u64 * 2) {
        let (id, flags) = honest_tx.tx_id(Some(nodes[0].class_commitment()));
        saw |= w
            .observe(id, flags, defector.class_commitment(), 2_000 + f)
            .newly_divergent;
    }
    assert!(saw, "detection is symmetric — the defector sees the split too");

    // And the beacon check still works where a master DOES run: retracting the claim did not delete
    // the mechanism, it narrowed what it covers (and it keeps the full 64 bits).
    assert!(
        nodes[0].beacon_indicates_partition(&defector.build_beacon()),
        "the master-only beacon carrier still detects the same divergence, at 64-bit width"
    );
}

// ---------------------------------------------------------------------------------------------
// P1c — the SAFETY half of P1b: a half-collected commitment must never report a partition.
//
// Every neighbour begins half-collected, so if a partial round could read as divergent the detector
// would false-partition the entire fleet on frame one — trading a silent defect for a noisy false
// one. This is the property that pins "compare, don't reassemble": there is no accumulated VALUE to
// be half-built, only accumulated confidence, and confidence below a full round says `Agreeing(n of
// 21)` or `Unknown` — never a verdict.
// ---------------------------------------------------------------------------------------------
#[test]
fn prop_p1c_a_half_collected_commitment_never_reports_a_partition() {
    let regs = [b"/alarm".as_slice(), b"/bulk".as_slice()];
    let slot = SlotSchedule::new(3000, 8).with_reserved_stride(4);
    let honest = Arc::new(
        GroupTable::new(&regs).with_latency_unauthorised(&[b"/alarm".as_slice()]),
    );
    let node = lab_sched(slot, Some(honest.clone()));
    let peer = lab_sched(slot, Some(honest));
    assert_eq!(node.class_commitment(), peer.class_commitment());

    let mut tx = IdDeconfliction::new(0xBEEF, 300_000, 2_000);
    let mut w = ClassCommitmentWatch::new(300_000);

    // A neighbour we have never heard is UNJUDGED, not divergent.
    assert_eq!(w.agreement_for(7), Agreement::Unknown);

    // Frames with no commitment at all (the pre-#93 wire, where bits 2..7 MUST be 0, and every DAR
    // hint frame) add no evidence in either direction — reading index 0 as a zero slice would
    // partition us against the whole installed base.
    for t in 0..32 {
        let v = w.observe(7, 0, node.class_commitment(), 1_000 + t);
        assert_eq!(v.agreement, Agreement::Unknown, "index 0 is absent, not data");
        assert!(!v.newly_divergent);
    }

    // A partial round from an agreeing peer reports BITS COMPARED, never "same map" and never a
    // partition.
    for i in 0..COMMITMENT_SLICES {
        let (id, flags) = tx.tx_id(Some(peer.class_commitment()));
        let v = w.observe(id, flags, node.class_commitment(), 2_000 + i as u64);
        assert_eq!(v.agreement, Agreement::Agreeing { bits: 3 * (i + 1) });
        assert!(!v.agreement.is_divergent());
        assert_eq!(
            v.agreement.is_complete(),
            i + 1 == COMMITMENT_SLICES,
            "only a whole round is complete"
        );
    }
}

// ---------------------------------------------------------------------------------------------
// P2 — lanes inviolate: a bulk owner is never placed in a lane (P1 above) and a bulk CLAIM never
// takes one, idle or not — the half of #93 the geometry shipped without.
// ---------------------------------------------------------------------------------------------
#[tokio::test]
async fn prop_p2_lanes_inviolate_under_claim_pressure() {
    let slot = SlotSchedule::new(3000, 8).with_reserved_stride(4); // lanes 0, 4
    let s = lab_sched(slot, None);
    let h = prefix_hash(&[b"bulk"]);
    let air = wifi_airtime_us(200, Some(7));

    // Give the claim everything it could want: evidence for every slot, total silence.
    let now = s.now_us();
    for c in s.slots.heard.iter() {
        c.store(now, Ordering::Relaxed);
    }

    // In a lane: refused, no matter how hungry the claimant is.
    for _ in 0..4 {
        s.note_deferred(h); // max demand bias
    }
    wait_for_slot(&s, |k, _| slot.is_reserved(k)).await;
    assert!(
        !s.try_claim(&slot, h, LeaseClass::Bulk, air).await,
        "a bulk claim took a reserved lane — the lanes' bounded-delay guarantee is void"
    );
    // Latency never claims at all: its lane comes round within one stride, which IS its bound.
    assert!(!s.try_claim(&slot, h, LeaseClass::Latency, air).await);

    // Sanity: the same claimant, in an idle open slot far from its own, still wins — the lane
    // refusal must not have killed the claim machinery ( +119% rides on it).
    let own = slot.owner_slot_in(h, LeaseClass::Bulk); // the claim's own-turn check is class-aware
    let mut claimed = false;
    // The CCLF jitter is an epoch-mixed draw (#87): a single attempt can legitimately lose to the
    // draw + margin, so a few superframes of attempts separate "the machinery is dead" from "this
    // epoch's draw was long".
    for _ in 0..6 {
        wait_for_slot(&s, |k, now| {
            !slot.is_reserved(k)
                && k != own
                && slot.wait_us_in(h, LeaseClass::Bulk, now) > slot.slot_us()
        })
        .await;
        for c in s.slots.heard.iter() {
            c.store(s.now_us().saturating_sub(1), Ordering::Relaxed); // fresh evidence, pre-claim
        }
        s.last_domain_rx.store(0, Ordering::Relaxed);
        if s.try_claim(&slot, h, LeaseClass::Bulk, air).await {
            claimed = true;
            break;
        }
    }
    assert!(
        claimed,
        "an idle, evidenced open slot must still be claimable"
    );
}

// ---------------------------------------------------------------------------------------------
// P3 — latency access delay bounded under saturating bulk: the lanes' whole claim.
// ---------------------------------------------------------------------------------------------
#[tokio::test]
async fn prop_p3_latency_delay_bounded_under_saturating_bulk() {
    let table = Arc::new(
        GroupTable::new(&[b"/alarm".as_slice(), b"/bulk".as_slice()])
            .with_latency_unauthorised(&[b"/alarm".as_slice()]),
    );
    let slot = SlotSchedule::new(3000, 8).with_reserved_stride(4);
    let lat = Arc::new(lab_sched(slot, Some(table.clone())));
    let mut bulk = lab_sched(slot, Some(table));
    bulk.lease_max = 8; // maximal leases: the most bulk pressure the schedule permits
    let bulk = Arc::new(bulk);

    // Saturating bulk: gate frames back-to-back for the whole run.
    let blast = {
        let bulk = bulk.clone();
        tokio::spawn(async move {
            let wire = data_wire(&[b"bulk", b"seg"]);
            let mut sent = 0u32;
            let end = Instant::now() + Duration::from_millis(600);
            while Instant::now() < end {
                bulk.gate(&wire).await;
                sent += 1;
            }
            sent
        })
    };

    // The latency name's access delay: successive gate() completions, measured under that load.
    let wire = data_wire(&[b"alarm", b"now"]);
    let mut worst = Duration::ZERO;
    let mut t = Instant::now();
    for _ in 0..12 {
        lat.gate(&wire).await;
        worst = worst.max(t.elapsed());
        t = Instant::now();
    }
    let sent = blast.await.unwrap();
    assert!(
        sent > 20,
        "fixture: bulk must actually have been saturating (sent {sent})"
    );

    // Bound: one full superframe (its lane's period is stride*slot = 12 ms; the superframe, 24 ms,
    // is the conservative statement) + generous scheduler-timing slack. The property is that the
    // bound does not scale with bulk load — without lanes it would be unbounded behind an 8-slot
    // lease.
    let bound = Duration::from_micros(slot.superframe_us() + 2 * slot.slot_us());
    assert!(
        worst <= bound,
        "latency access delay {worst:?} exceeded {bound:?} under saturating bulk — the lanes' \
         guarantee failed"
    );
}

// ---------------------------------------------------------------------------------------------
// P4 — no claim against an audible owner; P5 — ownership blind to foreign frames at any fill.
// ---------------------------------------------------------------------------------------------
#[tokio::test]
async fn prop_p4_p5_audible_owner_and_foreign_blindness() {
    let slot = SlotSchedule::new(3000, 8);
    let s = lab_sched(slot, None);
    let h = prefix_hash(&[b"mine"]);
    let air = wifi_airtime_us(200, Some(7));
    let owner_wire = data_wire(&[b"owner", b"1"]);

    // P4: the owner of the current slot speaks (any domain frame since slot start) — no claim.
    let own = slot.owner_slot(h);
    wait_for_slot(&s, |k, now| {
        k != own && slot.wait_us(h, now) > slot.slot_us()
    })
    .await;
    for c in s.slots.heard.iter() {
        c.store(s.now_us(), Ordering::Relaxed);
    }
    s.observe_rx(Some(&ndn_radio_hal::BROADCAST), None, None, &owner_wire); // the owner, audibly, NOW
    assert!(
        !s.try_claim(&slot, h, LeaseClass::Bulk, air).await,
        "claimed over an audible owner — theft, not opportunism"
    );

    // P5: foreign frames — real-MAC unicast, the all-ones frame, and a just-under-cap flood — are
    // ambient at ANY rate: they neither mark the domain busy nor forge presence.
    let s2 = lab_sched(slot, None);
    let before_presence: Vec<u64> = s2
        .slots
        .heard
        .iter()
        .map(|c| c.load(Ordering::Relaxed))
        .collect();
    let mut near_cap = [0u8; 12];
    near_cap[0] = 0b0000_0011; // passes the origin bits…
    for i in 1..8 {
        near_cap[i] = 0xff; // …but 56+ bits: over FILL_CAP, dead at the cap
    }
    for i in 0..5_000u32 {
        let mut foreign = [0x00u8, 0x1b, 0x44, 0x11, 0x3a, 0xb7]; // real-OUI unicast, U/L=0
        foreign[5] = i as u8;
        s2.observe_rx(
            Some(&foreign),
            Some(&[0x00, 0x1b, 0x44, 0, 0, 1]),
            None,
            b"",
        );
        s2.observe_rx(Some(&[0xffu8; 6]), Some(&[0xffu8; 6]), None, b""); // all-ones
        s2.observe_rx(
            Some(near_cap[..6].try_into().unwrap()),
            Some(near_cap[6..12].try_into().unwrap()),
            None,
            b"",
        );
    }
    assert_eq!(
        s2.last_domain_rx.load(Ordering::Relaxed),
        0,
        "foreign frames marked the domain busy"
    );
    assert_eq!(
        s2.slots
            .heard
            .iter()
            .map(|c| c.load(Ordering::Relaxed))
            .collect::<Vec<_>>(),
        before_presence,
        "foreign frames forged presence"
    );
    assert_eq!(
        s2.ambient_frames(),
        15_000,
        "and every one of them was counted, not dropped silently"
    );
}

// ---------------------------------------------------------------------------------------------
// P6 — hidden terminal. FLIPPED for the realistic relay (P4: relay discounting via the §2 nonce);
// red-by-design only for the narrowed residual (a pure-silent relay), which no passive local rule
// can distinguish from the owner.
// ---------------------------------------------------------------------------------------------

/// Build the A–B–C chain (A–B, B–C audible; A–C hidden) and return everything the two P6 arms need.
async fn p6_setup() -> (Medium<3>, u64, u64, u64) {
    let slot = SlotSchedule::new(3000, 8);
    let nodes: Vec<Arc<FaceScheduler>> = (0..3).map(|_| Arc::new(lab_sched(slot, None))).collect();
    let m = Medium::<3> {
        nodes,
        hear: [
            [false, true, false],
            [true, false, true],
            [false, true, false],
        ],
    };
    let a = &m.nodes[0];
    let c_wire = data_wire(&[b"c", b"data"]);
    let (c_hash, _) = a.name_group(&c_wire).unwrap();
    let c_slot = slot.owner_slot(a.medium_keyed(c_hash));
    // A group for A far enough from /c's slot that "own turn not imminent" holds inside it.
    let a_name = (0..500u32)
        .map(|i| format!("a{i}"))
        .find(|n| {
            let (h, _) = a.name_group(&data_wire(&[n.as_bytes()])).unwrap();
            let d = (slot.owner_slot(a.medium_keyed(h)) + slot.slots() - c_slot) % slot.slots();
            (3..=5).contains(&d)
        })
        .expect("a suitably distant group exists");
    let (a_hash, _) = a.name_group(&data_wire(&[a_name.as_bytes()])).unwrap();
    let a_keyed = a.medium_keyed(a_hash);
    (m, a_keyed, c_slot, c_hash)
}

/// **The realistic relay — GREEN since P4.** B relays /c *and* carries its own /b traffic, as a
/// real forwarder does. A sees nonce_B evidencing two different slots within the window, infers
/// "relay, not owner", discounts the /c evidence, and refuses the claim — no collision at B.
#[tokio::test]
async fn prop_p6_hidden_terminal_refused_when_the_relay_is_recognizable() {
    let (m, a_keyed, c_slot, c_hash) = p6_setup().await;
    let a = &m.nodes[0];
    let slot = a.slot.unwrap();
    let air = wifi_airtime_us(200, Some(7));
    let c_wire = data_wire(&[b"c", b"data"]);

    // B's own traffic must land on a slot other than /c's, or the cross-slot signature is
    // invisible; find such a group for B.
    let b_name = (0..500u32)
        .map(|i| format!("b{i}"))
        .find(|n| {
            let (h, _) = a.name_group(&data_wire(&[n.as_bytes()])).unwrap();
            slot.owner_slot(a.medium_keyed(h)) != c_slot
        })
        .unwrap();
    m.deliver(
        1,
        Some(&ndn_radio_hal::BROADCAST),
        None,
        &data_wire(&[b_name.as_bytes()]),
    );
    m.deliver(1, Some(&ndn_radio_hal::BROADCAST), None, &c_wire); // the relay of /c

    let mut claimed = false;
    for _ in 0..6 {
        wait_for_slot(a, |k, _| k == c_slot).await;
        m.deliver(2, Some(&ndn_radio_hal::BROADCAST), None, &c_wire); // hidden C transmits
        if a.try_claim(&slot, a_keyed, LeaseClass::Bulk, air).await {
            claimed = true;
            break;
        }
        wait_for_slot(a, |k, _| k != c_slot).await;
    }
    assert!(
        !claimed,
        "A claimed a slot whose only evidence came from a recognizable relay — the P4 nonce          discounting failed and the frame collides with hidden C at B"
    );
    let _ = c_hash;
}

/// **The residual — RED-BY-DESIGN, narrowed.** A pure-silent relay (B never transmits its own
/// traffic) is indistinguishable from the owner by any passive local rule: its nonce evidences
/// exactly one slot, exactly as a real owner's would. The hidden second holder behind it stays
/// hidden, and the claim collides at B. Closing THIS needs second-hand knowledge — the
/// reception-report plane (B observes the collision and its reports already reach A) — not more
/// local inference. §2 nonce rotation also reopens the recognizable-relay window until the rotated
/// nonce is seen twice. This test PASSES by demonstrating the collision; flip it when the
/// report-fed mechanism lands.
#[tokio::test]
async fn prop_p6_residual_pure_silent_relay_still_collides() {
    let (m, a_keyed, c_slot, _) = p6_setup().await;
    let a = &m.nodes[0];
    let slot = a.slot.unwrap();
    let air = wifi_airtime_us(200, Some(7));
    let c_wire = data_wire(&[b"c", b"data"]);

    // B relays /c and NOTHING else: a single-slot nonce, indistinguishable from the owner.
    m.deliver(1, Some(&ndn_radio_hal::BROADCAST), None, &c_wire);

    let mut collision_at_b = false;
    for _ in 0..6 {
        wait_for_slot(a, |k, _| k == c_slot).await;
        m.deliver(2, Some(&ndn_radio_hal::BROADCAST), None, &c_wire);
        if a.try_claim(&slot, a_keyed, LeaseClass::Bulk, air).await {
            collision_at_b = true;
            break;
        }
        wait_for_slot(a, |k, _| k != c_slot).await;
    }
    assert!(
        collision_at_b,
        "residual UNEXPECTEDLY CLOSED: the pure-silent-relay claim was refused. If a report-fed          (second-hand) mechanism now closes it, flip this to assert the refusal."
    );
}

// ---------------------------------------------------------------------------------------------
// P11 — clock skew × long frames: no shared boundary, lanes cannot protect (claim-C v2's anomaly,
// returned as the property the gate rule demands before v3).
// ---------------------------------------------------------------------------------------------

/// The claim-C v2 anomaly, reproduced off-air and bounded: with `clock=wall` and ms-class
/// cross-node skew, the two nodes' slot maps have NO SHARED BOUNDARY — `fits_now` keeps a frame
/// inside the SENDER's view of its slot, so a long frame near A's slot-end radiates into C's view
/// of the lane, and lanes protect nothing (measured on air: lanes 85.1% ≈ flat 85.3% at ~66%
/// duty). With skew ≪ frame airtime (the common-view clock's regime), the overlap vanishes —
/// which is v3's registered prediction, demonstrated here first.
#[tokio::test]
async fn prop_p11_skew_times_long_frames_defeats_lanes_and_cv_restores_them() {
    // Slot 6 ms, frame ~1.9 ms (the v2 shape, time-scaled), lane stride 4.
    let slot = SlotSchedule::new(6_000, 8).with_reserved_stride(4);
    let air: u64 = 1_900;
    let lane_period_ms = slot.slot_us() * 4 / 1000;

    /// Drive A (bulk owner, long frames, skewed by `skew_us`) and C (alarm at each lane start,
    /// unskewed) for `dur_ms`; return (alarms, alarms overlapped by an A-frame in flight).
    async fn run(
        slot: SlotSchedule,
        air: u64,
        skew_us: i64,
        dur_ms: u64,
        lane_period_ms: u64,
    ) -> (u32, u32) {
        let mut a = lab_sched(slot, None);
        a.clock_skew_us = skew_us;
        a.lease_max = 8; // the campaign shape: leases across the open slots, ~66% duty
        let a = Arc::new(a);
        let a_hash = prefix_hash(&[b"bulk"]);
        // A: transmit in every owned/claimable open slot, back-to-back long frames. Record real
        // wall intervals — the MEDIUM's time, which is what actually overlaps on air.
        let tx_log: Arc<Mutex<Vec<(u64, u64)>>> = Arc::new(Mutex::new(Vec::new()));
        let a_task = {
            let (a, log) = (a.clone(), tx_log.clone());
            let wire = data_wire(&[b"bulk", b"x"]);
            tokio::spawn(async move {
                let end = Instant::now() + Duration::from_millis(dur_ms);
                while Instant::now() < end {
                    // Fresh singleton evidence for every slot (nonce 0 = unknown, skips the relay
                    // check): the campaign condition — A's claims+leases run over ALL open slots,
                    // so its frames border the lanes every superframe. Without this, lab-A owns one
                    // slot and rarely touches a lane edge (measured 3/60 vs the campaign's ~15%).
                    let now = a.now_us();
                    for c in a.slots.heard.iter() {
                        c.store(now, Ordering::Relaxed);
                    }
                    a.last_domain_rx.store(0, Ordering::Relaxed);
                    a.gate(&wire).await; // waits for A's VIEW of an allowed slot
                    let t0 = wall_us();
                    log.lock().unwrap().push((t0, t0 + air));
                    tokio::time::sleep(Duration::from_micros(air)).await; // the frame is on air
                }
            })
        };
        // C: an alarm at each of ITS lane starts, deterministically (sleep-until the next
        // wall-clock lane boundary — the real owner path fires at its lane start; polling missed
        // instances and arbitrary-phase firing measured artifacts in both directions).
        let mut alarms = 0u32;
        let mut hit = 0u32;
        let _ = lane_period_ms;
        let end = Instant::now() + Duration::from_millis(dur_ms);
        while Instant::now() < end {
            let t = wall_us();
            // Next lane start strictly after now (+200 µs so we never re-fire the current one).
            let mut k = slot.current_slot(t) + 1;
            let mut start = slot.slot_start_us(t) + slot.slot_us();
            while !slot.is_reserved(k % slot.slots()) {
                k += 1;
                start += slot.slot_us();
            }
            tokio::time::sleep(Duration::from_micros(start.saturating_sub(t) + 20)).await;
            let t = wall_us();
            alarms += 1;
            let log = tx_log.lock().unwrap();
            if log.iter().rev().take(64).any(|&(s, e)| s < t + 90 && e > t) {
                hit += 1;
            }
        }
        a_task.abort();
        let _ = a_hash;
        (alarms, hit)
    }

    // Arm 1: 2 ms skew (NTP-class) — a substantial fraction of alarms meet an A-frame in flight,
    // IN THE LANES SCHEDULE: the lane exists, but not where A thinks it is.
    // A LAGGING (the sign that exposes the lane START, where the owner fires): A's pre-lane open
    // slot ends 2 ms into the lane in wall time, plus an in-flight 1.9 ms frame's tail.
    // ⚠ FIXTURE vs PROPERTY. This harness measures a timing property in REAL time (deliberately —
    // the medium's time is what actually overlaps), so a loaded machine gathers fewer lane
    // occurrences in a fixed window and the run ends data-starved. That is not a property
    // violation, and conflating the two made this test fail ~50% under parallel load while passing
    // consistently on a quiet one. Extend the window until there is enough data, bounded; only a
    // genuine shortfall after the cap is a failure, and it says so.
    /// Minimum lane occurrences per arm before the rates are compared. Both arms feed a RATIO, and
    /// a ratio of two small binomials is dominated by sampling error — 40 was too few.
    const MIN_ALARMS: u32 = 120;
    let (mut alarms, mut hit) = run(slot, air, -2_000, 1_500, lane_period_ms).await;
    for _ in 0..3 {
        if alarms >= MIN_ALARMS {
            break;
        }
        let (a2, h2) = run(slot, air, -2_000, 3_000, lane_period_ms).await;
        alarms += a2;
        hit += h2;
    }
    assert!(
        alarms >= MIN_ALARMS,
        "FIXTURE (not the property): only {alarms} lane occurrences after extending the window — \
         the machine is too loaded to gather data, rerun on a quiet host"
    );
    let skewed_rate = hit as f64 / alarms as f64;
    assert!(
        skewed_rate > 0.10,
        "with 2 ms skew and 1.9 ms frames, boundary overlap must be substantial — got          {hit}/{alarms}; the v2 anomaly measured ~15% on air"
    );

    // Arm 2: 0 skew (the common-view regime, residual ≪ frame airtime) — overlap collapses.
    // Same data-starvation guard as arm 1: `cv_rate` is a RATIO, so a handful of alarms makes it
    // wildly noisy (1 hit in 3 alarms reads as 0.33) and the comparison below becomes a coin flip.
    // Guarding only arm 1 just moved the flake here.
    let (mut alarms2, mut hit2) = run(slot, air, 0, 1_500, lane_period_ms).await;
    for _ in 0..3 {
        if alarms2 >= MIN_ALARMS {
            break;
        }
        let (a2, h2) = run(slot, air, 0, 3_000, lane_period_ms).await;
        alarms2 += a2;
        hit2 += h2;
    }
    assert!(
        alarms2 >= MIN_ALARMS,
        "FIXTURE (not the property): only {alarms2} lane occurrences in the zero-skew arm — \
         machine too loaded to gather data, rerun on a quiet host"
    );
    let cv_rate = hit2 as f64 / alarms2 as f64;
    // ⚠ THE MARGIN IS A STATISTICS QUESTION, and the original 3.0 was not sound at this sample
    // size. Both rates are binomial: at n≈64 the standard error on a ~0.16 rate is ±0.046, i.e.
    // ~29% relative, so a threshold demanding "more than exactly 3x" is a coin flip near the mean.
    // A captured failure had skewed 30/64 = 0.469 and cv 10/63 = 0.159 — a 2.95x reduction, the
    // property clearly holding, rejected for missing 3.00x. Fixed on both axes: MIN_ALARMS raises
    // n so the estimate is tighter, and the margin is 2.5x so the assertion tests the EFFECT
    // (common view substantially collapses boundary overlap) rather than sampling noise.
    // ⚠ A FIXED MULTIPLICATIVE MARGIN ON TWO NOISY RATES IS STILL A COIN FLIP, and raising n and
    // relaxing 3.0 -> 2.5 only moved where the flip lands: MEASURED, this assertion failed about
    // 1 run in 4 while the property held every time. Both rates are binomial, so their ratio has
    // its own sampling error, and a threshold compared against the POINT ESTIMATE ignores it —
    // exactly the error this project keeps making on hardware and then correcting.
    //
    // Test the effect against that error instead. The log ratio's standard error is
    //   se = sqrt((1-p1)/(n1*p1) + (1-p2)/(n2*p2))
    // so `z = ln(p1/p2) / se` says whether the reduction is resolved, and a separate size floor
    // says whether it is big enough to be the predicted effect rather than a sliver. At n = 120
    // and a true 2.5x reduction this yields z ~ 3.2 — comfortably clear of the 2.0 gate, which is
    // why it stops flipping without weakening what is being claimed.
    let reduction = if hit2 == 0 {
        f64::INFINITY // no overlap at all under common view: the strongest possible outcome
    } else {
        skewed_rate / cv_rate
    };
    let se = ((1.0 - skewed_rate) / (alarms as f64 * skewed_rate)
        + (1.0 - cv_rate) / (alarms2 as f64 * cv_rate))
        .sqrt();
    let z = if reduction.is_finite() {
        reduction.ln() / se
    } else {
        f64::INFINITY
    };
    assert!(
        reduction > 1.8 && z > 2.0,
        "with shared time the lane is where everyone thinks it is: {hit2}/{alarms2} \
         ({cv_rate:.3}) vs skewed {hit}/{alarms} ({skewed_rate:.3}) — reduction {reduction:.2}x, \
         z = {z:.2}. v3's registered prediction requires a resolved (z > 2) reduction of at least \
         1.8x; a point estimate alone is sampling noise at this n."
    );
}

fn wall_us() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_micros() as u64)
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------------------------
// P10 — the election/hold counter split (the P5-campaign anomaly, returned as a property).
// ---------------------------------------------------------------------------------------------

/// **A lease burst is continuations, not elections** — the distinction `claim_attempts` erased.
/// The P5 campaign registered claim B on attempts-per-sent and found the counter dominated by
/// per-frame hold checks (87–91% "win rates" were holds), so the metric could not see election
/// cost at all. The split counters make the claim measurable: exactly ONE election is paid per won
/// lease, and every subsequent frame in the burst is a continuation.
#[tokio::test]
async fn prop_p10_a_lease_burst_pays_one_election() {
    let slot = SlotSchedule::new(3000, 8);
    let mut s = lab_sched(slot, None);
    s.lease_max = 8;
    let s = s;
    let h_raw = prefix_hash(&[b"mine"]);
    let h = s.medium_keyed(h_raw);
    let air = wifi_airtime_us(200, Some(7));

    // A claimable situation: fresh singleton evidence everywhere, silence, own turn distant.
    let own = slot.owner_slot_in(h, LeaseClass::Bulk);
    let mut won = false;
    for _ in 0..6 {
        wait_for_slot(&s, |k, now| {
            k != own && slot.wait_us_in(h, LeaseClass::Bulk, now) > slot.slot_us()
        })
        .await;
        for c in s.slots.heard.iter() {
            c.store(s.now_us().saturating_sub(1), Ordering::Relaxed);
        }
        s.last_domain_rx.store(0, Ordering::Relaxed);
        if s.try_claim(&slot, h, LeaseClass::Bulk, air).await {
            won = true;
            break;
        }
    }
    assert!(won, "fixture: the election must be winnable");
    let (elections, elections_won, holds) = s.election_counts();
    assert_eq!(elections_won, 1, "one win");
    assert!(
        holds == 0,
        "no continuations yet — the win itself is not a continuation"
    );
    let elections_paid = elections; // could be >1: earlier attempts may have lost their draw

    // The burst: every further frame inside the leased window must be a CONTINUATION — zero new
    // elections. This is the fact the campaign metric was blind to.
    let mut continued = 0;
    while continued < 5 {
        if s.try_claim(&slot, h, LeaseClass::Bulk, air).await {
            continued += 1;
        } else {
            break; // lease boundary reached (wall clock) — however many we got, none elected
        }
    }
    let (e2, w2, h2) = s.election_counts();
    assert_eq!(
        e2,
        elections_paid,
        "a burst inside a won lease paid {} extra election(s) — the lease is not amortizing",
        e2 - elections_paid
    );
    assert_eq!(
        h2 as usize, continued,
        "every burst frame is a continuation"
    );
    assert_eq!(w2, 1, "and none of them is a new election win");

    // And the compat counter still conflates them, by documented design — the reason B needed
    // re-registration on election_counts rather than a silent redefinition of claim_counts.
    let (attempts, wins) = s.claim_counts();
    assert!(attempts as usize >= 1 + continued);
    assert_eq!(wins as usize, 1 + continued);
}

// ---------------------------------------------------------------------------------------------
// P7 — per-bearer parallelism; P8 — no boundary crossing at any rate/MTU; P9 — claimant fairness.
// ---------------------------------------------------------------------------------------------
#[test]
fn prop_p7_channels_stagger_the_map() {
    let slot = SlotSchedule::new(3000, 8);
    let s36 = lab_sched(slot, None);
    let s149 = lab_sched(slot, None);
    s149.current_ch.store(149, Ordering::Relaxed);
    // Same names, different medium ⇒ a staggered assignment (#89): at least some names own
    // different slots per channel, so two bearers transmit different names at one instant.
    let names: Vec<u64> = (0..32u32)
        .map(|i| prefix_hash(&[format!("n{i}").as_bytes()]))
        .collect();
    let differing = names
        .iter()
        .filter(|h| {
            slot.owner_slot(s36.medium_keyed(**h)) != slot.owner_slot(s149.medium_keyed(**h))
        })
        .count();
    assert!(
        differing >= names.len() / 2,
        "channel keying barely staggers the map ({differing}/32) — bearers would serialize"
    );
}

#[test]
fn prop_p8_no_transmission_crosses_a_boundary() {
    for &slot_us in &[1_000u64, 3_000, 20_000] {
        let slot = SlotSchedule::new(slot_us, 8);
        for &mtu in &[64usize, 256, 1500, 2272] {
            for mcs in [Some(0u8), Some(4), Some(7), None] {
                let air = wifi_airtime_us(mtu, mcs);
                for t in (0..slot_us).step_by((slot_us / 50).max(1) as usize) {
                    if slot.fits_now(t, air) {
                        assert!(
                            t % slot_us + air <= slot_us,
                            "fits_now admitted a boundary crossing: slot {slot_us}µs mtu {mtu} \
                             mcs {mcs:?} t {t} air {air}"
                        );
                    }
                }
                // And a frame that cannot fit at all is never admitted anywhere.
                if air > slot_us {
                    assert!((0..slot_us).all(|t| !slot.fits_now(t, air)));
                }
            }
        }
    }
}

#[test]
fn prop_p9_claimant_fairness_demand_weighted() {
    let slot = SlotSchedule::new(3_000, 8);
    let s = lab_sched(slot, None);
    let names: Vec<u64> = (0..8u32)
        .map(|i| prefix_hash(&[format!("g{i}").as_bytes()]))
        .collect();

    // Equal demand: every name wins some epochs, none dominates (the #87 rotation, at lab scale).
    let mut wins = std::collections::HashMap::new();
    for e in 0..2_000u64 {
        let w = names
            .iter()
            .min_by_key(|n| s.cclf_jitter_us(**n, 3_000, e, 200))
            .unwrap();
        *wins.entry(*w).or_insert(0u32) += 1;
    }
    assert_eq!(wins.len(), names.len(), "a claimant is starved: {wins:?}");
    assert!(
        *wins.values().max().unwrap() < 1_000,
        "a claimant dominates: {wins:?}"
    );

    // Demand weighting (#95): give one name backlog; its win share must rise, and the rest must
    // still win — bias, not capture.
    let favored = names[3];
    for _ in 0..3 {
        s.note_deferred(favored);
    }
    let mut wins2 = std::collections::HashMap::new();
    for e in 0..2_000u64 {
        let w = names
            .iter()
            .min_by_key(|n| s.cclf_jitter_us(**n, 3_000, e, 200))
            .unwrap();
        *wins2.entry(*w).or_insert(0u32) += 1;
    }
    assert!(
        wins2[&favored] > wins[&favored] * 3 / 2,
        "backlog did not bias the election: {} -> {}",
        wins[&favored],
        wins2[&favored]
    );
    assert_eq!(
        wins2.len(),
        names.len(),
        "demand bias starved someone: {wins2:?}"
    );
}
