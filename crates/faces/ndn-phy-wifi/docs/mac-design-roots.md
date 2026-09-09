> # ⚠ PARTIALLY SUPERSEDED — the in-frame name filter is RETIRED.
> Any mention below of the in-frame **name filter** (Blur / Tier-0 / fingerprint / GCS / NameGate)
> describes a **removed** mechanism. Relevance is now decided by **parsing the NDN name** the frame
> already carries. **Design of record: `firmware/NDR_MAC_SPEC.md`.** The non-filter material here
> (temporal access, spectrum/multi-radio, link adaptation, the ephemeral-id addressing doctrine, the
> single wireless face) remains current.

# The MAC's roots — where each problem came from, and proof it is not imaginary

The named-data-radio MAC has grown by iterative review, and a review can hallucinate a problem and
then "fix" it. This doc traces the design and its three most recent findings (D1/D2/D3) back to the
**originating design commitment** each derives from, with the in-tree citation, so a reader can
confirm we solved a real problem rather than an invented one. The test is always the same: *name the
commitment, show it is stated in a source document written before the finding, and show the finding
is a consequence of it — not a strawman.*

## 0. The originating problem

**Contention on a half-duplex, broadcast, ad-hoc, coordinator-free named-data radio.** Every node
shares one channel; there are no ACKs, no association, no AP. The whole MAC exists to let named data
share that medium without a coordinator, computing every coordination artifact from `(name, clock)`
rather than announcing it.

- `time-slice-mac.md:16-18,27` — "Contention is the named-radio pain — half-duplex broadcast, exposed
  terminals, the storm CCLF fights"; the schedule is "computed, never announced… No coordinator, no
  host [state]."
- `cclf-named-mac.md:92` — "it needs no ACKs, no election messages, no coordinator."

This is a real problem (contention is measured throughout #36/#37/#54/#111), and the coordinator-free
constraint is a deliberate commitment, not a convenience. Everything below is a consequence of it.

## 1. D1 — the owner-slot residue collision

**Commitment it derives from:** ownership is *computed*, `owner_slot = prefix_hash % N`, and the
result is claimed to be **collision-free at scale**.

- Mechanism, stated: `time-slice-mac.md:90` (`owner_slot = prefix_hash % N`);
  `named-filter-mac-redesign.md:233` ("the name whose registered prefix hashes to `s mod N`").
- Guarantee, stated **unconditionally**: `named-token-scheduling.md:107` ("collision-free at scale"),
  `:46` ("one name's turn at a time"), `time-slice-mac.md:66` ("the computed token stay collision-free
  at scale").
- Regime, measured: `named-token-scheduling.md:91` evaluates **16 active names**; the deployed
  schedule is ~8 slots (`NDN_SCHED_SLOT=8:20000`, p6-hidden-terminal-prereg.md:33).

**Why it is real, not imaginary.** `hash % N` is a residue class: with more than `N` *active* names,
two distinct names deterministically share a slot (pigeonhole). Both then take the "collision-free
turn" and collide at their receivers, unseen by either. The doctrine promises collision-freedom *at
scale* and measures a 16-active regime against 8 slots, yet **no document anywhere acknowledges two
distinct active names sharing a slot** (verified by grep across all `docs/*.md`; the only "collide"
hit is the flat-hash false-positive discussion at `mac-addressing-doctrine.md:330`, a different
subject). D1 is therefore the gap between a stated guarantee and the mechanism's actual reach — a real
unaddressed contradiction. It is **distinct from the hidden terminal** (#94/p6), which is *can't-hear
the owner*, not *two owners of one slot*.

Fix (f04449d, validated on air a0a8bb4): detection-triggered shared-slot backoff — turn-taking is bought
only when a co-owner is locally evident. It does not change the `hash % N` map; it repairs the reach
of the guarantee the map already promised.

## 2. D2 — the unpinned schedule parameters

**Commitment it derives from:** the **shared-map law** — a computed schedule is collision-free *only
if every node computes the same map*.

- `mac-synthesis.md:39` (§2.3) — "Every facet needs a *shared* view or it breaks."
- `temporal-access-chapter.md:31` — "This buys collision-freedom **only if nodes agree on
  `epoch(t)`**", and `:135` — "every node must agree where a slot begins."

**Why it is real.** The slot map is a function of slot width, slot count, reserved-lane stride, clock
class, and the channel set — all of which were read from per-node env vars (`NDN_SCHED_SLOT`, etc.,
`sched.rs` `from_env`). Two nodes with different `NDN_SCHED_SLOT` silently compute disjoint maps: no
error, no collision report. The shared-map law says these must be identical; nothing enforced or even
detected a mismatch. D2 is a direct, unmet consequence of a stated law.

Fix (a4e0220/845f3ea): a versioned `SchedParams` capturing the shared set, digested onto the time
beacon so a mismatch is **detected** (not corrected — the design corrects nothing, by §2 law 6).

**The set was incomplete, and the gap was the one class the map reads (#93).** `SchedParams` pinned
the lane *count* (`reserved`) and nothing about the *assignment*. But `LeaseClass` is a per-node
input — `GroupTable::with_latency` took a slice literal, and `RadioMediumFace`'s one-liner
`with_bloom_latency(&k, mine, mine)` promoted every prefix a node sends — and with lanes reserved,
`SlotSchedule::owner_slot_in` places a `Latency` name in a lane bulk cannot enter. So a node that
unilaterally promoted its own prefixes computed a *different map* while emitting a digest
**identical** to an honest neighbour's, and `beacon_indicates_partition` never fired. The design's
whole defence at `sched.rs` ("every node must classify a prefix identically or their slot maps
diverge, which is why class rides the registration set — already shared") rested on a set that is not
in fact shared: `registered_prefixes` is what *this* node serves.

Fix: `SchedParams::class_digest` (`SCHED_PARAMS_VERSION` 1 → 2) — an order-independent FNV-1a over
the canonically-sorted set of latency slot-group keys, populated in `with_groups` from the table
actually installed. Scope is deliberately narrow, because a false partition is how a detector's
information content goes to zero: `Bulk` entries are OUT (a depth-exact bulk entry produces the same
`(key, class)` pair as no entry at all, so nodes with disjoint bulk registrations must digest alike),
masks are OUT, entry order is OUT, and the whole term is `0` when no lanes are reserved — where the
class is not read and committing to it would false-partition by construction. IN alongside the
latency keys: any registration *shallower* than `slot_depth`, which overrides the shared fallback key
and is the one map-affecting thing a bulk entry can do (unreachable at the shipping `slot_depth = 1`,
latent above it). The version bump means every v1↔v2 pair reads "partitioned"; that is a rollout to
finish, not a shim to write. As before this **detects, and does not authenticate** — FNV-1a is
unkeyed here on purpose (#44).

**Retraction — the CARRIER was wrong, and the claim overstated (2026-09).** The class commitment was
correct as a computation and shipped on the wrong frame. It rode the **time beacon**, and `medium.rs`
spawns the beacon task only behind `sched.is_master()` (`NDN_SCHED_MASTER=1`). So the claim
"a node that classifies differently is detected" was true only of a defecting **master**, plus
misconfiguration on nodes reading that master's beacon; a **non-master** defector put no digest on
the air and was exactly as invisible as before the fix. Two things made this a real hole rather than a
wording slip: `campaign_p5` — the campaign that would have exercised the claim — sets no master at
all, so its coverage was **zero nodes**; and `prop_p1b` asserted the detection by calling
`build_beacon()` on a lab node with `master: false`, i.e. on a frame that node would never transmit.
A green property that misrepresents the mechanism is worse than a missing one.

It also violated the control-plane tenet the same document set states — *"overhear / piggyback, never
beacon"* (wire-format-spec §4) — by making a detector depend on the one dedicated frame the design
avoids.

**Fix: piggyback the commitment on ordinary data** (`addr3[5]` bits 2–7, wire-format-spec §5.4a).
Six spare bits cannot *reassemble* a 64-bit digest — with `i` index bits and `6−i` payload bits the
constraint `i ≥ ⌈log₂⌈64/(6−i)⌉⌉` has **no** solution — so nothing is reassembled: each frame carries
a **complete 3-bit comparison** (one slice of a 21-bit XOR fold, plus its index), compared on arrival
and discarded. Slices are never combined, so the mixed-epoch question does not arise; the only
cross-frame state is confidence, reported as `Unknown` / `Agreeing{bits}` / `Divergent`, and a
half-collected round is **never** a partition. Index `0` means "absent" — emitted by pre-#93 nodes,
by DAR hint frames, and by the `addr3 == addr1` shapes — because reading it as data would
false-partition the whole installed base.

**What is kept and why.** The beacon carrier stays exactly as it was (21 bytes,
`SCHED_PARAMS_VERSION` still 2, `class_digest` still in the fold): it is the only frame that
establishes a shared timeline, and it carries the full **64 bits** where the piggyback carries 21. A
21-bit fold is forgeable instantly — the 32→64 widening of `class_digest` was bought by an offline
collision found in ~10 s — so **the piggyback must never be published as catching a deliberate
defector**. Division of labour: coverage from the piggyback, width from the beacon.

**Two pre-existing defects the carrier forced out first**, both live before this change:
`addr3` is not always `id ‖ flags` (the A-MSDU builder writes `addr3 = addr1`, the base builder falls
back to `addr3 = dst`), so every legacy-shaped frame was being read as a DAR hint naming ID `0xff`;
and `observe_rx` folded all six `addr3` bytes into the §2 presence nonce, which made two sightings of
one transmitter compare unequal and biased `owner_in_range` toward **more** claims — the unsafe
direction, opposite to that code's own stated safe-direction argument.

**Still not covered, stated rather than papered over:** aggregated (A-MSDU) frames carry no
commitment and no ephemeral ID, so a deployment that batches everything falls back to beacon-only;
LoRa and BLE have no flags byte at all; and none of this has been measured on air — the latency
figures are arithmetic over a configured frame rate, not a measurement.

## 3. D3 — the slot key re-coupled the granularity the filter decoupled

**Commitment it derives from:** the name filter's central innovation — **every receiver matches at
its own granularity** (the roles thesis).

- `named-filter-mac-redesign.md:92-93` — "the granularity the receiver registered. With a prefix-set
  BF the sender ships *all* granularities at once and every receiver matches at *its own*.
  Longest-prefix match becomes a receiver-local decision."
- `name-filter-chapter.md:49` — "E — the number of prefixes a receiver has registered" (per-node).

**Why it is real.** The same redesign doc that makes granularity per-receiver *also* defines the slot
owner as "the name whose **registered prefix** hashes to `s mod N`" (`:233`) — and P1 implemented the
slot key as the *longest locally-registered prefix* (`sched.rs`, pre-fix). Registration tables are
legitimately per-node (that is the roles thesis), so node A (`/x`) and node B (`/x/y`) key one name to
different slots. The filter deliberately decoupled granularity; the slot key silently re-coupled it.
D3 is a latent contradiction **inside the source design**, not an external invention.

Fix (a4e0220): the slot key is a shared constant, `H(first slot_depth components)`; the filter keeps
per-receiver granularity, the slot does not.

## 4. The honest test for future findings

Before "fixing" anything, name the commitment it derives from and cite the source document. If no such
commitment exists — if the problem cannot be traced to a stated design decision or a measured regime —
treat it as suspect until a measurement or a source proves it real. D1/D2/D3 each pass this test; that
is the difference between a repair and an invention.
