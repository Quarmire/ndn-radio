> # ⛔ RETIRED — the in-frame name filter is dropped from the design.
> This document designs the in-frame **name filter** (Blur / Tier-0 / fingerprint / GCS). That
> mechanism has been **removed**. Relevance is now decided by **parsing the NDN name** the frame
> already carries (off-host where the radio keeps up, host-fallback where it doesn't).
> **Design of record: `firmware/NDR_MAC_SPEC.md`.** This file is kept only as the historical record
> that led to retiring the filter — see `reports/ndr-mac-report/REPORT.md` for the measured evidence.

# P7 — does the Tier-0 ∥ Tier-1 name filter PAY, and does the serial wiring waste work? PRE-REGISTRATION

**Committed before any measurement exists (the gate rule).** Verified the way P5(c) was: before the
first run,

```
git ls-files | grep -E 'p7-|filter_cost_benefit'
```

must show **this file and nothing else** — no harness, no CSV, no result. If a data file or the
example already exists when this is committed, the campaign is void and restarts under a new name.

**This is version 2 of P7.** Version 1 was committed at `cebc803` and **STOPPED during
pre-registration, before a single measurement**, because its arms encoded an architectural
misconception: it treated NDN-NIC as a rival to beat and Tier-1 as a competing filter, and it swept
width without ever asking what each table answers. Version 1 is preserved in git history precisely so
that this replacement cannot be mistaken for a post-hoc rewrite — nothing was measured under v1, so
nothing is being retro-fitted. What v1 got right (the validity argument, the airtime correction, the
confounder list, the CPU-timing discipline) is carried forward here and attributed.

This campaign exists because an external audit asked the question the project has never actually
answered: **is the Tier-0 / Tier-1 name filter necessary and beneficial at all?** Not "does it
discriminate" — P5(c) answered that on air — but *does it pay for itself*, *was the thing P5(c)
measured even the design*, and *does the way it is wired today waste work*.

---

## 1. The architecture, corrected — because half the deliverable is getting this right

The v1 misconception was not a detail; it produced the wrong arms. So the architecture is written
down here, verified against the code with file:line, **before** any arm is defined.

### 1.1 NDN-NIC is the ANCESTOR, not a competitor

Tier-0 and Tier-1 together **are** NDN-NIC's design, adapted to a radio. The paper's three tables are
re-homed, not replaced:

| NDN-NIC table | where it lives here | queried with | parse? |
|---|---|---|---|
| **BF-FIB** | **Tier-0** — the same prefix-shaped admission, moved into the frame | mask compare over `addr1‖addr2‖addr3[0:4]` | **no** |
| **BF-PIT** | the **fingerprint** — `Tier1::probe_fingerprint` (`tier1.rs:400`) | 24 carried bits from HT Control | **no** |
| **BF-CS** | the **fingerprint** again, backed by a Bloom filter sized for the far more numerous CS entries | the same 24 carried bits | **no** |

`crates/faces/ndn-phy-wifi/src/ndn_nic.rs` is therefore an **ablation of one table** — the ancestor's
BF-FIB alone, queried the paper's way (on the parsed name) — so the cost of answering the FIB
question *after* the parse can be measured against answering it *before* one. It is not a rival arm,
and **"Tier-0 beats NDN-NIC" is not a claim this campaign makes, tests, or wants.** The competitor
framing has been removed from `ndn_nic.rs` and `name_gate.rs` in the same change that committed this
file.

### 1.2 The verified split: Tier-0 answers FIB-shaped admission. The FINGERPRINT answers PIT and CS

The design as stated to the audit was "Tier-0 subsumes the FIB **and PIT** parts; the fingerprint is
the CS part." **The code does not support the PIT half of that, and this campaign is built on the
corrected version.** The evidence:

* `RxFilter::Bloom(Arc<[PrefixFilter]>)` / `RxFilter::WideBloom(Arc<[WifiWideBlur]>)`
  (`name_gate.rs:62`, `:68`) hold an **immutable** mask set, built once at face construction from
  `registered_prefixes` (`lib.rs:576-591`, `medium.rs:934-968`, `medium.rs:1016-1029`). **There is no
  API to add or remove a mask.** The PIT churns per Interest and is fed live into *Tier-1* through
  `Tier1Feed` / `ObservedPit` (`tier1.rs:865`, tests at `:645` and `:730`). So in the shipped code,
  PIT-shaped admission is not Tier-0's at all.
* Even with such an API it would not pay. Two independent reasons, both measured or in code:
  (i) Tier-0's false-positive rate is `1 − (1 − p̄)^E` in the mask count `E` — **measured on air**,
  P5(c), 140 331 frames — so folding a churning PIT into `E` saturates the filter;
  (ii) `clamp_prefix` (`tier0.rs:300`) truncates any registration deeper than `MAX_DEPTH − 1` = **7**
  components to its 7-component ancestor. A PIT entry is a *full name*, modally ~10–13 components on
  the realistic corpus, so a PIT mask degenerates into "admit that entire depth-7 subtree". That is
  not PIT admission; it is an over-broad FIB entry wearing a PIT's name.
* The fingerprint path answers **both** PIT-exact and CS, not CS alone: `probe_fingerprint` returns
  `Verdict { fib: false, pit, cs }` (`tier1.rs:400-406`) and the gate admits on `v.pit || v.cs`
  (`name_gate.rs:237-241`). The stated design was *right about the mechanism and understated its
  scope.*
* The CS mechanism genuinely answers direction (b): `cache()` inserts **every prefix** of the cached
  name (`tier1.rs:327-334`), so a `CanBePrefix` Interest's own fingerprint probes BF-CS directly and
  hits a deeper cached name — with no parse. Confirmed in code, with one depth caveat in §3.2.

**Corrected one-line statement of the architecture, used by every arm below:**
> Tier-0's mask compare subsumes NDN-NIC's **BF-FIB**. The carried 24-bit fingerprint subsumes its
> **BF-PIT and BF-CS**. Both are parse-free. Neither is supposed to channel through the other.

### 1.3 Intended PARALLEL, built SERIAL — and exactly where

`NameGate::admits_wide` (`name_gate.rs:158`) computes `tier0_ok` first (`:175-222`) and consults
Tier-1 only downstream, at two sites that behave completely differently:

| site | fires when | parses? | can it | conforms to §1.2? |
|---|---|---|---|---|
| fingerprint rescue (`:223-245`) | Tier-0 **rejected** | **no** — reads `htc` | only **ADMIT** | **yes** |
| `Tier1::lookup` (`:247-275`) | Tier-0 **admitted** | **yes** — `inner_name(wire)` | only **REJECT** (`is_miss`) | **no** |

The second site consults all three tables (`tier1.rs:369-388`), two of which re-ask answered
questions:

* `lookup().fib` is `fib_covers` (`tier1.rs:351-359`) — a prefix walk of the **parsed** name against
  a BF-FIB that `with_tier1` (`lib.rs:861-880`) registered on the *same* prefix list the Tier-0 masks
  were built from. That is Tier-0's question, re-asked after the parse.
* `lookup().cs` is `self.cs.may_contain(name)`, and `Table::positions(name)` is *defined* as
  `positions_fp(name_fingerprint(&self.key, name))` (`tier1.rs:163-165`). So on a wide frame
  `lookup(name).cs ≡ probe_fingerprint(fp).cs` **bit for bit** — the parsed probe recomputes from the
  parsed name the exact 24-bit value the frame already carried in HT Control.
* `lookup().pit` is a prefix walk over BF-PIT, a strict superset of `probe_fingerprint().pit`
  (exact-name only). The only thing it buys is the implicit-digest case (an outstanding Interest that
  is a proper prefix of the Data name) — and Tier-0's mask for that Interest name covers the same
  case in the frame, without a parse.

There is a **veto asymmetry**: the rescue can only admit; `lookup` can only reject. A parallel
arrangement ORs evidence. This one ANDs on admit and ORs on reject.

### 1.4 The circularity this campaign is really testing

Follow the veto: if Tier-0 admits a genuinely FIB-relevant frame and Tier-1 held *no* BF-FIB table,
`is_miss()` would be true and the frame would be **dropped** — a false negative on a frame Tier-0 got
right. So **Tier-1's BF-FIB exists, on the admit path, to undo the veto that Tier-1's own `is_miss`
introduces.** Remove the veto and the table's admit-path job disappears with it. Whether that is
genuinely circular — or whether BF-FIB is adding independent evidence Tier-0 did not have — is H3,
and it is measurable.

### 1.5 Three further record corrections, established while verifying the above

1. **The shipped base is 126 bits, not 94.** `M_BITS = 126` (`tier0.rs:69`), `WIFI_BASE_BLUR = M_BITS`
   (`tier0.rs:211`), and `RxFilter::Bloom` reconstructs `addr1‖addr2‖addr3[0:4]`
   (`name_gate.rs:185-191`). **94 is the pre-repack width** (`addr1‖addr2`, 96 wire bits − 2 reserved),
   and it is what P5(c) measured: `campaign_e_sweep.rs:172-180` fills only `w[..12]` and leaves
   `w[12..16]` zero. So P5(c)'s on-air curve is for a width this crate no longer emits. The audit
   brief's "94 shipped, 126 wide base" is inverted: **126 is shipped; 94 is historical; 174 is the
   wide profile (126 base + 48 extra in `addr4`).** The stale "94-bit" sentence in `tier1.rs` has been
   corrected in the same change as this file.
2. **`with_wide_bloom` makes the face wide on BOTH halves.** Its doc said "TX stays the base
   profile"; the code two lines below sets `self.tx_wide = true` (`medium.rs:1016-1029`). Doc
   corrected. Its **zero call sites** stand: the wide profile has never gone on air *through the
   face*. `examples/wide_profile_onair.rs` drives `build_dot11` directly, and **no result from it is
   recorded anywhere in this tree** (§3.1).
3. **`examples/name_filter_eval.rs` does not have PIT/CS registration sets**, despite its header
   claiming "FIB (shallow routes) / PIT / CS (deep names) registration sets" (`:12`). `gen_corpus`
   returns `Corpus { names, fib, depths }` (`:109-151`) — FIB only. This campaign must **build** the
   PIT and CS sets; it cannot borrow them. Stated here so the §7.1 method is not read as reuse of
   something that exists.

---

## 2. What is already established, and is not re-litigated

* **P5(c) / #106, on air, N = 140 331 attributable frames, four arms, Wilson 95% CIs.** Zero false
  negatives at every E. Tier-0 FP 0.006% (E=1) → 6.573% (E=64). The OR-of-E-masks law
  `FP(E) = 1 − (1 − p̄)^E` holds once `p̄` is the per-prefix *mean* rather than one prefix's outlier.
  **The in-frame bits survive the air.** Built on, not re-measured. Subject to §1.5(1): that curve is
  the 94-bit width.
* **The filter costs ZERO additional airtime on the base profile.** `build_dot11` emits
  `addr3.unwrap_or(dst)` and a `Duration` of `[0x00, 0x00]` whether or not a filter is present
  (`ndn-frame-io/src/frame.rs:244`, `:336`), so the filter RECYCLES bytes the frame must send anyway.
  MEASURED, not argued: `tier0_wire_cost::the_filter_costs_no_additional_airtime`
  (`ndn-frame-io/src/frame.rs:1031-1066`) asserts the two frames are byte-length identical. The
  "12 bytes/frame of permanent airtime" that `ndn_nic.rs` and `tier1.rs` both used to claim does not
  exist.
* **k = 4 at m = 126** (200 names / 400 000 trials, `tier0.rs:88-106`). Not re-derived per width here;
  see §9 C4.

---

## 3. Why an offline sweep is valid — and what it does NOT cover

**Valid.** The false-positive rate is a function of the in-frame filter BITS and the query masks, not
of link margin, distance, rate or drift. P5(c) made that argument to justify evaluating every arm on
one capture; taken one step further it says the FP/FN half needs no air *provided the bits that reach
the receiver are the bits the sender wrote* — and P5(c) established exactly that, on air, at 140 331
frames with zero false negatives, for the base region. So an offline sweep over the **production
code paths** measures the same quantity the air would, at sample sizes and widths the bench cannot
reach, with traffic held identical across arms by construction.

The cost half is CPU work — a property of the code and the host, not the channel. Offline by nature.

### 3.1 Does NOT cover — declared before the run

1. **Whether the WIDE bits survive the air.** `addr4` and HT Control may be rewritten, dropped or
   stripped by a chip's monitor TX/RX path. That is a hardware question owned by
   `examples/wide_profile_onair.rs`, and **no result from it exists anywhere in this tree** (grepped;
   §1.5(2)). Every width ≥ 174 here — and therefore **every arm that uses the fingerprint**, since
   `build_dot11` emits HT Control only when `addr4` *and* `htc` are both set
   (`frame.rs:281-306`) — is a measurement of the *design*, explicitly conditional on an on-air fact
   not yet in hand. Any conclusion at 174/190, or about arms B/C/D, carries that condition **in the
   same sentence**.
2. **Whether `Duration/ID` is writable in practice.** Some chips compute Duration in hardware and
   overwrite it; #96 measured only that stock Wi-Fi *ignores* our NAV, not that no station honours
   it. The 190 arm is conditional and labelled so.
3. **The wide profile's airtime.** Computed and asserted (§5.3), deliberately **not** priced into the
   equation.
4. **Wake / DMA / interrupt cost avoided on constrained receivers.** Excluded. Biases the result
   **against** the filter; stated with every result.
5. **Any delivery, latency or throughput effect.** None measured. This campaign cannot say the filter
   makes a link faster.
6. **Embedded-target cost.** The parse:AND ratio is measured on one host CPU. Mitigated — not solved
   — by reporting every crossover as a function of that ratio (§8.2).
7. **Whether `c_name` is duplicated downstream.** Arm C's `inner_name(wire)` may or may not be work
   the forwarder would repeat. That is an integration question about `ndn-fwd`, not a filter
   question, and it is **not settled here**. Consequence: arm C's cost is reported both with `c_name`
   charged and with it free, and the second form is the one that is *generous* to the status quo.
8. **Multi-hop / relay behaviour.** One receiver, one registration set.

### 3.2 One thing this campaign expects to find BROKEN, said in advance

`Tier1::cache` inserts prefixes via `for_each_prefix` (`tier1.rs:334`), which caps at
`MAX_DEPTH = 8` (`tier0.rs:110`, `:271-286`). But `lookup(name).cs` and `probe_fingerprint(fp)` probe
the **full, unclamped** name. So a `CanBePrefix` Interest at depth ≥ 9 that genuinely IS a prefix of
a cached name will **miss BF-CS** — a direction-(b) false negative, in the exact mechanism
`tier1.rs`'s own header opens by describing. On this corpus (modal depth ~10–13) that is reachable.
This is pre-registered as **H1(b)** below, predicted to FAIL, with the mechanism named now so that a
failure is a confirmed prediction rather than a discovery, and a non-failure means this reading of
the code is wrong and must be said so.

---

## 4. Arms — following the CORRECTED architecture

The question is **not** "which filter wins". It is: *what does each table answer, at what cost, and
does the serial arrangement waste work?* Every arm therefore differs in **which table answers what**,
not in whose filter is better.

### 4.1 Tier-0 widths

Every width is **layered**, never re-modulused: the base region is bit-identical across all of them
(the coexistence floor — a base-only receiver must read a wide sender's frame), and extra regions are
independent keyed projections on top (`WideBlur::extra_positions`, `EXTRA_DOMAIN`, `tier0.rs:407`,
`:445-452`).

| width | bits | construction | wire fields | added airtime |
|---|---|---|---|---|
| **94** | 94 | `positions_m(key, pfx, 94)` — the **historical** width P5(c) measured | `addr1‖addr2` (96 − 2 reserved) | 0 B |
| **126** | 126 | `PrefixFilter` / `positions` — `M_BITS`, **the SHIPPED base** | `addr1‖addr2‖addr3[0:4]` | 0 B |
| **174** | 126 + 48 | `WifiWideBlur = WideBlur<6>` — **the DESIGNED wide profile** | + `addr4` | **+12 B** |
| **190** | 126 + 64 | `WideBlur<8>`, extra bytes 0..6 → `addr4`, 6..8 → `Duration/ID` | + `addr4` + `Duration/ID` | +12 B |

190 is deliberately **one contiguous 64-bit extra region**, not 48 + a separate 16. A 16-bit region
taking up to `MAX_DEPTH × K` = 32 set operations saturates (~86% fill) and discriminates almost
nothing alone; folded into 64 the same bits are worth far more. Both constructions were considered;
the contiguous one is registered as primary and the split one is **not run**. Registered now so the
choice cannot be made after seeing a number.

`E ∈ {1, 2, 4, 8, 16, 32, 64, 128}` at every width.

### 4.2 The five arms

Let `t0(f)` = the Tier-0 mask compare at the arm's width; `fp(f)` = `probe_fingerprint` on the
frame's carried 24-bit fingerprint (PIT-exact ∨ CS); `lk(f)` = `Tier1::lookup` on the **parsed** name.

| arm | admits iff | Tier-1 tables held | parses? | what it isolates |
|---|---|---|---|---|
| **A** — Tier-0 alone | `t0` | none | never | what prefix-shaped admission alone achieves, per width |
| **B** — Tier-0 + fingerprint rescue | `t0 ∨ (¬t0 ∧ fp)` | pit, cs | never | the shipped parse-free path (`name_gate.rs:191-208`) |
| **C** — Tier-0 + Tier-1-as-built | `(t0 ∧ ¬lk.is_miss) ∨ (¬t0 ∧ fp)` | fib, pit, cs | **on every admitted frame** | **THE STATUS QUO** — literally `admits_wide` with `tier1 = Some` |
| **D** — Tier-0 ∥ Tier-1-CS/PIT | `t0 ∨ fp`, both evaluated on **every** frame, OR-ed | pit, cs — **no BF-FIB** | never | **the stated design**: no duplicated fib/pit, no parse, no veto |
| **N** — no filter | `true` | none | (everything goes downstream) | the null against which net benefit is defined; the arm that wins if the answer is "it does not pay" |

Three consequences of these definitions are themselves pre-registered predictions, because they are
the sharpest things in the campaign:

* **B and D have the SAME admit set, always.** `t0 ∨ fp` and `t0 ∨ (¬t0 ∧ fp)` are the same Boolean
  function. They differ only in **cost**: D probes the fingerprint on every frame, B only on the
  `(1 − a_A)` fraction Tier-0 rejected. So **B is a strict cost optimisation of D with identical
  output** — which means the rescue's placement "after Tier-0" is *not* the architectural problem.
  The problem is specific to the `lookup` site in C. If a single frame's decision differs between B
  and D, the harness is wrong (T6).
* **C differs from B/D only by the veto** — it rejects some frames they admit. Those are exactly
  Tier-0's false positives that BF-FIB/BF-PIT/BF-CS catch on the parsed name. Everything C buys, and
  everything it costs, is in that difference.
* **A ⊆ B = D, and C ⊆ B.** Any violation is a harness bug, not a finding.

### 4.3 The ablation, and where it sits

`ndn_nic` — `NdnNicFilter::paper_default(&key, prefixes_E)`, 16 KB, k = 2, admit iff
`may_serve(parsed_name)` — is run **as an ablation of arm A, not as a rival**: it answers Tier-0's
own question (BF-FIB) from *behind* the parse instead of in front of it. Its number is reported in
one place only, to price §1.1's claim: *moving the FIB question in front of the parse costs X and
saves Y*. It is not ranked against Tier-0, and no "winner" is declared between them.

---

## 5. The cost model — stated as an equation BEFORE it is measured

### 5.1 Terms

Per **received** frame, all in nanoseconds of receiver CPU:

| symbol | what | how obtained |
|---|---|---|
| `m(E)` | masks actually tested, after `coverage_antichain` dedup (`lib.rs:576-591`) | counted; **can be < E**, and using `E` where the code uses `m(E)` would overstate the cost |
| `c_mask(w)` | one `may_match` against one mask at width `w` | timed on the production type; **data-dependent** (`any()` short-circuits, `may_match` short-circuits per word, and `PrefixFilter::may_match` runs the `FILL_CAP` popcount first) so it is MEASURED, never modelled as `E × constant` |
| `c_fp` | `fingerprint_from_htc` + `probe_fingerprint` — 2 Bloom probes, k = 4 | timed |
| `c_name` | `inner_name(wire)` + `ndn_name_to_slash` — **the parse Tier-0 exists to avoid** | timed on the corpus's real NDNLPv2/NDN-TLV wire encodings |
| `c_lookup` | `Tier1::lookup` — 2 prefix walks + 1 direct probe | timed |
| `c_t2` | downstream work on an admitted frame (full decode + forwarder decision) — **the thing the filter saves** | **not measured directly**; carried as a parameter and every crossover reported as a curve over `ρ = c_t2 / c_mask(126)` |
| `a_X(E,w)` | arm `X`'s admit rate | counted |

### 5.2 The equation

```
W_N          = c_t2
W_A(E,w)     = m(E)·c_mask(w)                                            + a_A·c_t2
W_B(E,w)     = m(E)·c_mask(w) + (1 − a_A)·c_fp                           + a_B·c_t2
W_D(E,w)     = m(E)·c_mask(w) +           c_fp                           + a_B·c_t2
W_C(E,w)     = m(E)·c_mask(w) + (1 − a_A)·c_fp + a_A·(c_name + c_lookup) + a_C·c_t2
```

Benefit against the null, per frame:

```
Benefit(X) = W_N − W_X          Benefit > 0 ⇒ the filter pays.  Benefit ≤ 0 ⇒ it does not.
```

And the audit's actual question, the waste of the serial wiring:

```
W_C − W_D = a_A·(c_name + c_lookup − c_fp)  −  (a_B − a_C)·c_t2
            └─ extra work C does per admitted frame ─┘   └─ extra suppression it buys ─┘
```

`W_C − W_D > 0` ⇒ **the serial Tier-1 wastes work.** That single inequality is H3(c).

Both algebraic forms of every `Benefit` are computed independently and must agree to floating-point
tolerance; disagreement voids the run (T6).

### 5.3 Airtime is NOT a term — and exactly why

**At widths 94 and 126 airtime is not a term because it is MEASURED to be zero.** The base 802.11
data frame carries `addr1‖addr2‖addr3` and a `Duration/ID` whether or not a filter is present; the
filter overwrites bytes already on the air. That is not an argument, it is
`tier0_wire_cost::the_filter_costs_no_additional_airtime`.

**At widths 174 and 190 that statement is FALSE, and this campaign says so up front.** The wide
profile is a 4-address QoS-Data + HT-Control frame. From `build_dot11` (`frame.rs:281-336`): base
header = 2+2+6+6+6+2 = **24 B**; wide header = 2+2+6+6+6+2+6+2+4 = **36 B**. **+12 B per frame,
forever** — about 16 µs at legacy 6 Mbit/s. It is precisely the cost the project once wrongly
attributed to the *base* profile, and it is real here.

The campaign therefore:

* does **not** put airtime into any `W` — these are receiver-**work** equations in nanoseconds of
  CPU, and converting microseconds of air into them needs an exchange rate **nobody in this project
  has measured**. Inventing one would rest a conclusion on an unmeasured constant, which the house
  rules forbid outright;
* **asserts** 24 B / 36 B with a length test in the harness, so +12 B is a measurement and not
  arithmetic-from-reading-the-code (T7);
* prints `+12 B/frame` in the same row as **every** 174 and 190 result, and `0 B` on every 94/126 row,
  so no reader can take a wide-width win without seeing what it costs on the air;
* states the bias: **excluding airtime biases the result IN FAVOUR of the wide widths**, and
  therefore in favour of arms B/C/D, which need the fingerprint and so need the wide frame.

---

## 6. Claims — stated so they can FAIL

> These are the campaign. Each names its refutation condition; each directional claim commits a
> magnitude NOW.

### H1 — Safety (HARD), split into the direction it protects and the direction it may not

**H1(a) — direction (a), prefix-shaped admission. Predicted to HOLD.** Across every width
w ∈ {94, 126, 174, 190}, every E ∈ {1…128}, every one of the R = 32 registration draws, and every
frame, **false negatives = exactly 0**, where a false negative is a frame whose name IS under a
registered prefix and whose arm rejects it. This explicitly includes:
(i) the **mixed-population** case — a base-profile sender's frame at a wide-profile receiver, tested
on the base region alone (`admits_wide` with `addr4 = None`), because testing an all-zero extra
region against a non-zero extra mask is a false-negative machine (`name_gate.rs:213`);
(ii) the **`FILL_CAP`** path — `may_match` rejects any frame whose base popcount exceeds 64
(`tier0.rs:360-373`), so a legitimate corpus name tripping that cap IS a false negative;
(iii) the **`clamp_prefix`** path at every registration depth.
**Refuted by FN ≥ 1 anywhere.** On refutation the campaign STOPS, the defect becomes a lab property
with a regression test, and no further arm is run or reported as valid. `FILL_CAP`, `K`, `MAX_DEPTH`
and `CLAMP` are **not** re-tuned to make H1(a) pass.

**H1(b) — direction (b), CanBePrefix-CS at depth. Predicted to FAIL, mechanism named in advance.**
For a `CanBePrefix` Interest whose name is a genuine prefix of a cached name **at depth ≥ 9**, arms
B, C and D will reject it, because `cache()` inserts prefixes through `for_each_prefix` (capped at
`MAX_DEPTH = 8`) while `lookup`/`probe_fingerprint` probe the unclamped full name (§3.2). Committed
prediction: **FN(b) = 0 for Interest depth ≤ 7, and FN(b) > 0 — approaching 100% of such Interests —
at depth ≥ 9.** A failure here does **not** void the direction-(a) arms (they measure a different
question) but is filed as a lab property immediately, before any results section is written.
**If H1(b) does NOT fail, this reading of the code is wrong** and that is reported in those words.

### H2 — Width buys discrimination

The per-prefix false-positive probability `p̄(w)` of **arm A** falls materially and monotonically
along 94 → 126 → 174 → 190 on one fixed corpus. Because the corpus cancels in a ratio, the
predictions are committed as **ratios on the same corpus**, with bands:

| ratio | point estimate | band | refuted if |
|---|---|---|---|
| `p̄(126)/p̄(94)` | **0.37** | 0.20 – 0.70 | outside |
| `p̄(174)/p̄(126)` | **0.056** | 0.02 – 0.15 | outside |
| `p̄(190)/p̄(174)` | **0.43** | 0.25 – 0.75 | outside |

**Refuted hard if any ratio is ≥ 1** — a wider filter that does not discriminate better means the
layering is broken (correlated projections), not that width is worthless, and sends the extra-region
construction back to the lab. `p̄_base`, `p̄_extra` and `p̄_combined` are reported **separately** so
the independence assumption is visible rather than assumed (§9 C3).

### H3 — Tier-1's fib/pit tables add ~nothing over Tier-0 at the designed width: the duplication is measurable waste

Three independently refutable halves. **This is the claim the audit is owed, and it is the one most
likely to embarrass the design if it is wrong.**

**H3(a) — BF-FIB is re-deriving, not adding.** Restrict to frames arm A **admits** at w = 174.
Of those where `lookup()` returns `fib ∧ ¬pit ∧ ¬cs`, the fraction that are **genuinely FIB-relevant
by ground truth** is predicted **≥ 99%** at every E ≤ 128. That is the operational meaning of "the
table is a copy": BF-FIB is re-establishing relevance Tier-0 already established, not admitting on
independent grounds. **Refuted if < 99%** at any E — which would mean BF-FIB admits frames Tier-0 had
no grounds for, i.e. it is a genuinely additive table and §1.4's circularity reading is wrong.

**H3(b) — BF-CS on the parsed name is bit-identical work.** On every wide frame, at every width and
every E, `lookup(name).cs` and `probe_fingerprint(fp).cs` agree on **100.000%** of frames — not
"approximately", *exactly* — because `Table::positions(name)` is *defined* as
`positions_fp(name_fingerprint(key, name))` (`tier1.rs:163-165`). **Refuted by a single
disagreement**, which would mean the fingerprint on the wire and the fingerprint recomputed from the
parsed name disagree: a wire or parse defect, not a filter result, and the campaign stops to find it.

**H3(c) — the cost half, with direction and magnitude.** At the designed width w = 174:
`W_C − W_D > 0` — the status quo costs more than the stated design — **for every E ≤ 128, at the
measured ρ**. Committed magnitude: at (E = 8, w = 174), `W_C − W_D` lies between
**+0.4 · c_name and +1.0 · c_name** per received frame.
And the contrast that makes it a claim rather than a tautology: **at w = 94 there exists an E
(predicted E ≥ 32) where `W_C − W_D < 0`** — the serial Tier-1 *does* pay, but only at the width the
project no longer ships, because only there is Tier-0's FP large enough for the veto to earn its
parse.
**Refuted** if C beats D at 174 at any E ≤ 128; or if C never beats D at 94 anywhere in the sweep; or
if the (E = 8, 174) magnitude lands outside its band.

**If all three halves hold, the pre-registered conclusion is:** *the `lookup` site duplicates work
Tier-0 and the fingerprint already did, and the correct change is to delete the veto and the BF-FIB
table from the RX path, keeping BF-PIT/BF-CS behind the fingerprint — i.e. arm D.* If H3(c) is
refuted, the pre-registered conclusion is the opposite and is reported as the headline: *the serial
Tier-1 earns its parse, and §1.3's "serial is wrong" reading was an aesthetic judgement dressed as an
architectural one.*

### H4 — A crossover E* exists per width, and MOVES with width

Two crossovers, both reported per width, both predicted now.

**H4(a) — the FP crossover** `E*_FP(w)` = smallest E at which arm A's FP over irrelevant frames
crosses **5%**:

| width | committed prediction | refuted if |
|---|---|---|
| 94 | **E\*_FP ∈ [4, 8]** — *worse* than P5(c)'s on-air 64, because this corpus's ~10–13-component names set far more bits than P5(c)'s depth-2 `/p<i>/<seq>` | outside [2, 16] |
| 126 | **E\*_FP ∈ [16, 48]** | outside [8, 96] |
| 174 | **E\*_FP > 128** (beyond the swept range) | FP(174, E) ≥ 5% at any E ≤ 128 |
| 190 | **E\*_FP > 128** | FP(190, E) ≥ 5% at any E ≤ 128 |

plus the movement claim: `E*_FP(174) / E*_FP(94) ≥ 8`, point estimate **16–32×**. **Refuted** if the
ratio < 4, or if `E*_FP` is not monotonically non-decreasing in width.
If this holds, the sentence `tier1.rs` has been justifying Tier-1 with — *"past ~8–32 prefixes a relay
wants a filter whose FP does not climb with E"* — is a property of a width we ship by accident, and
must be rewritten against these numbers.

**H4(b) — the NET crossover** `E*_net(w)` = smallest E at which `Benefit(A) ≤ 0`. Committed
prediction: it exists **inside** the swept range for widths 94 and 126 (point estimate
`32 ≤ E*_net ≤ 128` at the measured ρ), and — crucially — **it does NOT move with width the way
`E*_FP` does**: `E*_net(174) ∈ [0.5, 2.0] × E*_net(126)`, because the wide mask AND costs ~1.5–2×
more (more words, plus the same `FILL_CAP` popcount) while its FP saving is already near-saturated.
**Refuted** if no width crosses anywhere in E ≤ 128 at the measured ρ, or if `E*_net(174)` lands
outside its band.

**Refutation of H4(b) in the "no width ever crosses" direction would be a result IN THE DESIGN'S
FAVOUR**, and will be reported in exactly those words rather than buried.

**If H4(a) and H4(b) both hold, the pre-registered conclusion is:** *width fixes Tier-0's
**discrimination** but not its **O(E) work**, so Tier-1's justification MOVES — from "FP climbs with
E" to "mask ANDs climb with E" — rather than disappearing.* That is the outcome currently thought
most likely, written here so it can fail.

---

## 7. Method

### 7.1 Production code, extended corpus

The harness is a new example, `crates/faces/ndn-phy-wifi/examples/filter_cost_benefit.rs`. It

* **reuses `examples/name_filter_eval.rs`'s corpus generator** — Zipf-popular namespace roots
  (s = 1.1), per-root vocabularies, deep versioned/segmented names at modal depth ~10–13,
  `/ndn/<org>/<app>` roots — at a **pinned seed committed here: `seed = 1`**, with exactly two
  declared changes:
  1. `ROOTS` raised 32 → 256, so E = 128 registrations can be drawn without exhausting the namespace;
  2. **PIT and CS registration sets are ADDED**, because the generator does not have them despite its
     header claiming it does (§1.5(3)). Construction, fixed here: the **PIT** set is `P` full names
     drawn uniformly from the traffic stream *and then removed from it* (so a PIT hit is ground truth,
     not an accident); the **CS** set is `S` full names drawn the same way, inserted with
     `Tier1::cache`; `P = S = 256`, and `basic_cs` left at its production default (`true`).
  No other change to the generator, so the traffic cannot be tuned to the result.
* drives the **production filter code**, never a lookalike: `tier0::PrefixFilter`,
  `tier0::WideBlur<N>`, `tier0::positions_m`, `tier1::Tier1`, `ndn_nic::NdnNicFilter`, and the real
  `NameGate::admits_wide` decision path for arms B and C. A cost-benefit claim about the shipped
  design that runs a reimplementation is not a claim about the shipped design.

**Ground truth** is exact, from the corpus, never estimated: a frame is *relevant* iff (a) some
registered FIB prefix is a component-ancestor of its name, or (b) its name is, or extends, a PIT
name, or (c) its name is a component-ancestor of a CS name. The three channels are tracked and
reported **separately**, because H3 is entirely about which channel each table serves.

P5(c) used toy `/p<i>/<seq>` names at depth 2. Realistic depth is the point of this corpus, and it is
expected to move the curve — H4(a) commits to the direction.

### 7.2 The lesson P5(c) paid for: never anchor on one prefix

P5(c)'s pre-registered independence prediction was REFUTED because it anchored `FP(1)` on a single
prefix, `/p0`, that proved a 16× low outlier. Not repeated here:

* every (E, w) cell is the mean over **R = 32 independent registration draws**, each drawing E
  prefixes from the FIB in Zipf-popularity order with an independent offset;
* the **per-prefix FP distribution** (min, p50, mean, p99, max) is reported at every width, so
  heterogeneity is visible rather than inferred;
* `p̄(w)` is fitted from the large-E cells — P5(c) showed that is the stable estimator — and the fit is
  reported alongside the direct measurement.

### 7.3 CPU measurement

One host, named in the results with its CPU model, `rustc` version and opt-level. `--release`.
`black_box` on every input and output. Medians of ≥ 10⁵ iterations; p50 and p99 both reported. Every
`c_*` term is measured **interleaved in the same loop nest**, so a thermal or frequency excursion hits
all of them rather than one. A run whose `c_name` p99/p50 ratio exceeds **3** is discarded as
noise-dominated and re-run — that bar is set **here**, before any timing exists.

### 7.4 Freshness / silent-zero guard (P5(c)'s rule, carried forward)

Every CSV carries N per cell, the corpus seed, the corpus name count, `|masks|` after
`coverage_antichain`, and the PIT/CS set sizes. A cell with N = 0, or `|masks| = 0` where E > 0, or
FP exactly 0 across every draw at a width where the model predicts a nonzero rate, is
**instrument-invalid** — re-run, not reported as a win. Every re-run is stated in the results.

---

## 8. Pre-named thresholds

### 8.1 Pass / fail, fixed here before the run

| # | bar | refutation |
|---|---|---|
| T1 | **FN = 0** for direction (a) at every width, E, draw and frame — including base-sender→wide-receiver and the `FILL_CAP` path | any FN ≥ 1 ⇒ H1(a) refuted, campaign STOPS, lab property first |
| T2 | every H2 ratio inside its band | outside ⇒ H2 refuted for that pair |
| T3 | H3(a): ≥ 99% of `fib ∧ ¬pit ∧ ¬cs` admits are genuinely FIB-relevant at 174 | < 99% ⇒ H3(a) refuted |
| T4 | H3(b): `lookup().cs` ≡ `probe_fingerprint().cs` on **100.000%** of wide frames | one disagreement ⇒ wire/parse defect, campaign STOPS |
| T5 | H3(c): `W_C − W_D > 0` for all E ≤ 128 at w = 174; `< 0` for some E ≥ 32 at w = 94; magnitude at (8, 174) in [0.4, 1.0]·`c_name` | any part fails ⇒ H3(c) refuted |
| T6 | arms B and D reach **identical** decisions on every frame; `A ⊆ B = D`; `C ⊆ B` | any violation ⇒ harness bug, run void |
| T7 | base header 24 B, wide header 36 B, asserted by a length test | mismatch ⇒ the +12 B figure is wrong, every wide row re-derived |
| T8 | H4(a) table + ratio ≥ 4; H4(b) band | outside ⇒ that half refuted |
| T9 | both algebraic forms of every `Benefit` agree to float tolerance | disagreement ⇒ harness bug, run void |
| T10 | H1(b): FN(b) = 0 at Interest depth ≤ 7 | FN(b) > 0 at depth ≤ 7 ⇒ a *different*, unpredicted defect; campaign STOPS |

### 8.2 Reported as MEASUREMENTS, with no pass/fail bar

Following P5(c), which reported its crossover without a directional pre-commitment:

* **`E*_net(w, ρ)` as a curve over ρ ∈ [1, 10⁴]** — so a reader on a different CPU, or on the
  LR2021/nRF54L15 firmware target where this campaign cannot measure, reads off their own crossover
  instead of inheriting this host's. **The single most important guard against the result depending
  on one machine.**
* `ρ = c_t2 / c_mask(126)` as measured, p50 and p99.
* `r(E)` — the moving irrelevant-traffic ceiling. Note `r` FALLS with E (registering more makes more
  traffic genuinely wanted); `tier1.rs` and `ndn_nic.rs` both record that reporting raw reject rate
  against a moving ceiling is how this was got wrong before.
* Relevance broken out by channel (FIB / PIT / CS), per E.
* Base-region popcount distribution per width and depth; whether `FILL_CAP` ever fired.
* Receiver state: mask bytes per (E, w) (16·`m(E)` base, 22·`m(E)` wide), `Tier1` table bytes,
  `NdnNicFilter::table_bytes()`.
* `m(E)` vs E after `coverage_antichain`.
* `fp_rescued` counts — how much work the rescue actually recovers.
* `+12 B/frame` on every 174/190 row; `0 B` on every 94/126 row.
* The `ndn_nic` ablation's single row (§4.3).

---

## 9. Confounders and threats to validity — named before the run

* **C1 — Name-distribution dependence.** FP is a function of the name distribution at least as much
  as of the filter; `tier0.rs:94-99` records that at m = 94 two independent harnesses disagreed on the
  k = 4..8 ordering *because the name distribution dominated*. Mitigation: one fixed corpus at a
  committed seed across every arm, so the distribution cancels in every cross-arm comparison; all H2
  predictions stated as ratios; absolutes reported but **never** laid beside P5(c)'s on-air absolutes
  as if they were the same measurement (they are not — different names, different width).
* **C2 — Per-prefix heterogeneity.** One prefix can carry most of a width's FP (P5(c): `/p1` alone
  ~0.8%). Mitigation: R = 32 draws + the full per-prefix distribution (§7.2). This is the confounder
  that refuted the last campaign's prediction; it is the one designed against hardest.
* **C3 — Layer independence.** The wide-width case rests on the extra region being an *independent*
  projection (`EXTRA_DOMAIN`-separated key) so combined FP ≈ `p̄_base × p̄_extra`. If the regions are
  correlated, H2's 174/126 ratio blows past its band — which is why the band exists and why a ratio
  ≥ 1 is called a construction defect rather than a null result.
* **C4 — k is not re-derived per width.** k = 4 was measured at m = 126. Held at 4 for **every** width,
  including 94, 174 and 190, because changing two variables at once makes the width comparison
  uninterpretable. Consequence, stated up front: the wide widths may be reported at a **sub-optimal
  k**, which **biases against them**. A per-width k sweep is separate work and is not done here.
* **C5 — No fill cap on the extra region.** `PrefixFilter::may_match` applies `FILL_CAP` to the base
  (`tier0.rs:360-373`), and `WideBlur::may_match` inherits only that — the extra region has **no cap**
  (`tier0.rs:483-492`). At 48 bits taking up to `MAX_DEPTH × K` = 32 sets, saturation is plausible on
  deep names. Reported as extra-region fill per depth; if it saturates, H2's 174 ratio is expected to
  degrade and that is a finding, not a nuisance.
* **C6 — Hash choice.** All widths use the production `siphash24`-under-`GroupKey` pipeline with
  Kirsch–Mitzenmacher double hashing, via `positions_m` unmodified — `tier0.rs:59-64` records that
  splitting one hash instead of two independent keyed evaluations measured 1.3–3.4× worse. But double
  hashing does correlate positions at small m, which is why measured base FP (0.559% at m = 126) sits
  ~2× above the naive independence model, and why H2's bands are wide.
* **C7 — CPU measurement noise.** Handled by §7.3 and neutralised as a *conclusion* dependency by
  reporting `E*_net(ρ)` as a curve (§8.2).
* **C8 — `coverage_antichain` dedup.** `m(E)` can be < E; cost is `O(m(E))`, not `O(E)`. Reported
  explicitly — using E would overstate it, and that is the kind of unmeasured number the house rules
  forbid.
* **C9 — Arms B, C and D are conditional on an unmeasured wire fact.** They need the fingerprint,
  which needs HT Control, which `build_dot11` emits only on the wide 4-address frame — a profile with
  **zero production call sites** and **no recorded on-air survival result**. Every conclusion about
  B, C or D carries that condition in the same sentence, every time.
* **C10 — Arm C's parse may not be wasted.** If the forwarder would parse the name anyway, `c_name`
  is not a cost C uniquely bears. Not settled here (§3.1 item 7); C is therefore reported **both
  ways**, and the generous form is the one quoted whenever C is compared to D.

---

## 10. Reporting rule — what gets reported regardless of outcome

1. **Every cell**: 4 widths × 8 E × 5 arms × {FP with Wilson 95% CI, FN by direction, `r(E)`,
   `m(E)`, `c_*` p50/p99, `W`, `Benefit`}, plus the `ndn_nic` ablation row and the no-filter control.
   No arm dropped, no best-of, no re-run for a nicer number. A re-run happens only under §7.4 or the
   §7.3 noise bar, and every re-run is stated.
2. **Each of H1(a), H1(b), H2, H3(a), H3(b), H3(c), H4(a), H4(b) marked CONFIRMED or REFUTED against
   its §8.1 bar, by name**, with the number that decided it. A refuted prediction reported honestly is
   worth more than a confirmed one; P5(c)'s most valuable line was its refutation, and this document
   expects to produce at least one — H1(b) is predicted to be it.
3. **Both algebraic forms of every `Benefit`**, so a reader can check the equation was not quietly
   changed after the fact.
4. **The §3.1 "does NOT cover" list, restated in the results** — particularly the unmeasured on-air
   survival of `addr4`, HT Control and `Duration/ID`, on which every fingerprint arm depends.
5. **The bias directions, all four, stated with the verdict and not in a footnote:** excluding
   wake/DMA biases **against** the filter; holding k = 4 at every width biases **against** the wide
   widths; excluding airtime biases **for** the wide widths and so for arms B/C/D; charging `c_name`
   to arm C biases **against** the status quo, which is why C is also reported with it free.
6. **If the design does not pay, that is the finding and it is the headline.** Registered in advance,
   in the words that will be used:
   * If `Benefit(A) ≤ 0` across the useful range of E at every width — *Tier-0's in-frame filter does
     not earn its receiver-side work on this traffic, and the correct action is to delete it, not to
     widen it.*
   * If it pays only at small E — *Tier-0 is an endpoint mechanism, and calling it a MAC-layer
     primitive overstates it.*
   * If it pays at every E at the designed width — then §1.5(1)'s finding, that the project has been
     shipping and measuring different widths, is the headline instead, and `tier1.rs`'s justifying
     sentence is rewritten against measured numbers rather than remembered ones.
   * If H3 holds — *the `lookup` site is measurable waste; delete the veto and the BF-FIB table from
     the RX path and keep BF-PIT/BF-CS behind the fingerprint (arm D).*
   * If H3(c) is refuted — *the serial Tier-1 earns its parse, and this document's §1.3 reading was an
     aesthetic judgement dressed as an architectural one.*
7. **Non-goals, stated so they cannot become quiet goals.** This campaign does **not** wire
   `with_wide_bloom` into anything (its zero call sites are a finding, not a task list — wiring it is
   separate work gated on the on-air result §3.1 says does not exist). It does **not** change
   `name_gate.rs`'s behaviour. It does **not** rank Tier-0 against NDN-NIC, and no "winner" between
   them is declared.

---

## 11. Deliverables

* `crates/faces/ndn-phy-wifi/examples/filter_cost_benefit.rs` — the harness (does not exist yet; its
  absence at commit time is part of the gate rule).
* `crates/faces/ndn-phy-wifi/docs/data/name-filter/p7-fp.csv`, `p7-cost.csv`,
  `p7-crossover-vs-rho.csv`, `p7-per-prefix.csv`, `p7-arm-diff.csv`.
* A `## RESULTS` section appended to **this file**, in the P5(c) style: the tables, each claim marked
  against its bar, **the refutations first**.

---
---

# RESULTS

**Run.** `crates/faces/ndn-phy-wifi/examples/filter_cost_benefit.rs`, one run, no re-runs
(§7.4 and the §7.3 noise bar never tripped: `c_name` p99/p50 = 1.10).
Host **Apple M4 Pro**, `rustc 1.96.0 (ac68faa20 2026-05-25)`, `--release`. Wall clock 52.8 s.
Corpus seed **1**, **100 000** frames (100 000 unique names), avg depth 10.01, modal depth 11,
|FIB| = 264, |PIT| = |CS| = 256. **R = 32** draws × 8 E × 4 widths × 5 arms ⇒
**N = 3 200 000 decisions per (arm, E, width) cell** — 22.8× P5(c)'s on-air 140 331.
CSVs: `docs/data/name-filter/p7-{fp,cost,crossover-vs-rho,per-prefix,arm-diff}.csv`.

Gate rule re-verified before the run: `git ls-files | grep -E 'p7-|filter_cost_benefit'` returned
this file and nothing else.

---

## 0. THE REFUTATIONS AND THE DEFECTS, FIRST

Five things went wrong, four of them in the code rather than in the predictions. §10.2 says a refuted
prediction reported honestly is worth more than a confirmed one; here the code was worth more than
either.

### D1 — ☠ `inner_name` **cannot parse a single-fragment LpPacket at all**, so Tier-1's veto and Tier-0's TX addressing both silently disappear on that wire

Found by self-check S2, which exists only because the first harness build could not reproduce the
production gate (S5 failed 1198/24 000) and the cause had to be chased.

```
S2 the real RX-path parser (`inner_name` + `ndn_name_to_slash`) on three wire shapes:
   LP fragment 0 of 2  0x64{0x51,0x52,0x53,0x50{Data}} : /r15c0/…/s69916   (2000/2000 exact)
   bare Data           0x06{0x07{…}}                   : /r15c0/…/s69916   (2000/2000 exact)
   single-fragment LP  0x64{0x50{Data}}                : None  ← THE PARSER CANNOT SEE THIS WIRE (0/2000)
   …the same wire through ndn_packet's own lp_ndn_packet_bytes: /r15c0/…/s69916
   lp::extract_fragment on the same wire: false
```

**Mechanism.** `ndn-radio/src/mac/name.rs::lp_fragment_value` computes `body` = the LpPacket's
*value*, then calls `named_tlv_value(body, 0x50)` — and `named_tlv_value` strips **another**
type+length header before iterating. It therefore skips past the `Fragment` TLV's own header and
searches the *Data packet's* sub-TLVs for a `0x50`, which is not there. One strip too many.
`ndn_packet::lp::lp_ndn_packet_bytes` does the same job correctly on the same bytes, which is what
makes this a duplicate-parser bug rather than a wire question.

**Consequences, both directions, both in shipped code paths.**
* **RX** — `NameGate::admits_wide` reaches `if let Some(name) = inner_name(wire)`, gets `None`, and
  **falls through to `true`**. On this wire shape Tier-1's veto never fires, and `RxFilter::NdnNic`
  (`name_gate.rs:218-221`) likewise returns `true` for every frame.
* **TX** — `Tier0Addresser::wire_for` (`lib.rs:509`) tries `extract_fragment` (returns `false`
  above, because a single fragment carries no Sequence/FragIndex/FragCount) and falls back to
  `compute(wire)` → `inner_name(wire)?` → `None`. `medium.rs:1453` then addresses the frame
  `None => (BROADCAST, nonce, None, None, None)` — **broadcast, no Tier-0 filter at all.**
* `ndn_packet::lp::encode_lp_packet` produces exactly this shape, and
  `control.rs:401` (`broadcast_report_frame`, the radio's own reception reports) uses it.

**This campaign is not affected**, because the primary wire shape here is LP fragment 0 of a
2-fragment object — the shape the medium's own fragmenter emits — and S2 asserts 2000/2000 exact
before anything else runs. But every unfragmented LP object on air today carries no filter.

### D2 — H1(b): the `MAX_DEPTH` clamp breaks CanBePrefix-CS, one component EARLIER than predicted

Pre-registered as *predicted to FAIL at depth ≥ 9*. It fails at **depth 8**.

| Interest depth | trials | `lookup().cs` hits | `probe_fingerprint().cs` hits | FN(b) |
|---|---|---|---|---|
| 1 – 7 | 400 each | 400 | 400 | **0.000%** |
| **8** | 400 | **0** | **0** | **100.000%** |
| 9 | 400 | 5 | 5 | 98.750% |
| 10 – 14 | 400 each | 1 – 4 | 1 – 4 | 99.0 – 99.75% |

`cache()` inserts through `for_each_prefix`, which yields `/` plus the 1…7-component prefixes and
then the **full name only if the name has ≤ `MAX_DEPTH` = 8 components**. A cached name at depth 14
therefore contributes nothing at depth 8 or deeper, while `lookup`/`probe_fingerprint` probe the
unclamped name. The residual 1–5 hits at depth ≥ 9 are Bloom false positives, not matches.
**T10 holds** (FN(b) = 0 at depth ≤ 7), so this is the predicted defect and not a different one.

### D3 — UNREGISTERED, found while running D2: the same clamp breaks **BF-PIT exact match**, and refutes a claim in `tier1.rs`

`tier1.rs`'s header states that `lookup().pit` is *"a strict **superset** of
`probe_fingerprint().pit` (exact-name only)"*. Measured, 400 names per depth:

| PIT-entry depth | `lookup().pit` hits | `probe_fingerprint().pit` hits | parsed walk misses |
|---|---|---|---|
| 1 – 8 | 400 | 400 | 0 |
| **9 – 14** | **0** | **400** | **100%** |

The relation **inverts at depth 9**: the parsed prefix walk cannot see an exact PIT entry that the
carried 24-bit fingerprint finds every time. The corpus's modal name depth is 11, so on this traffic
the majority of PIT entries are invisible to the very path that is allowed to veto. `tier1.rs`'s own
header warns that "a stale BF-PIT drops Data the node is waiting for"; this is that failure, from a
depth clamp rather than from staleness.

### D4 — the "MEASURED zero airtime" claim rests on a **vacuous** test

`ndn-frame-io`'s `tier0_wire_cost::the_filter_costs_no_additional_airtime` builds both frames with
`FrameFormat::Raw80211`, whose `build_dot11` arm copies `frame.payload` **verbatim and emits no
address fields at all**. Both sides are the 1-byte payload; the assertion passes for any address
arrangement, including one that did add 12 bytes. Measured here:

```
S7  802.11 MAC header bytes (FrameFormat::RawNdn, 32 B payload):
    no filter 24 | base + filter 24 | wide 36   → filter adds 0 B, wide adds 12 B
S7b the cited test's format (Raw80211): 32 B vs 32 B — a payload passthrough
```

**The claim is true; its cited measurement did not measure it.** T7 is satisfied by S7 above:
24 B base, 36 B wide, +12 B on the wide profile — asserted, not read off the source.

### D5 — `examples/campaign_e_sweep.rs` is a **stale instrument**: re-run today it would false-negative 69.53% of the time

P5(c) reassembles `addr1‖addr2` only (`campaign_e_sweep.rs:172-180`, `w[..12]`) but queries with
`PrefixFilter::mask_for`, which is 126 bits since the repack. Replaying that exact arrangement
offline on P5(c)'s own toy `/p<i>/<seq>` names, over frames that genuinely are under their own
registered prefix:

```
false negatives = 3560 / 5120 = 69.53%
```

which is what `1 − (94/126)^4 = 69.1%` predicts. P5(c)'s **result** is not impeached — it was
internally consistent for the width that shipped when it ran, and §1.5(1) already recorded that the
width was 94. Its **harness** is: it must be repacked to 16 bytes before it is used again, or its
zero-FN safety invariant will fire spuriously. §7.4's silent-zero rule exists for exactly this.

### R1 — H3(c) is **half refuted**, and the magnitude half could never have been met

See §5. `W_C − W_D < 0 for some E ≥ 32 at w = 94` is **REFUTED at the only measured anchor**, and the
committed magnitude at (E = 8, w = 174) — 0.4 to 1.0 · `c_name` — is **REFUTED by a factor of ~8 in
the direction the prediction could not recover from**: 0.051 · `c_name` measured, and
0.054 · `c_name` is its **maximum over all ρ**. Diagnosed in §5.3.

---

## 1. SAFETY — T1, and the whole point of the design

```
T1 / H1(a) direction-(a) false negatives, ALL arms × widths × E × draws : 0
   arm A_tier0        direction-(a) FN = 0     total FN (all 3 channels) = 430 029
   arm B_t0_or_fp     direction-(a) FN = 0     total FN (all 3 channels) = 156 903
   arm C_status_quo   direction-(a) FN = 0     total FN (all 3 channels) = 174 654
   arm D_parallel     direction-(a) FN = 0     total FN (all 3 channels) = 156 903
   arm N_nofilter     direction-(a) FN = 0     total FN (all 3 channels) =       0
H1(a)(i) mixed population (base sender → wide receiver): FN = 0
T6 arms B and D identical on every frame: PASS.  A ⊆ B / C ⊆ B violations: 0
T4 / H3(b) lookup(name).cs vs probe_fingerprint(fp).cs over 25 600 000 wide frames: 0 disagreements
FILL_CAP fired on 0 of 100 000 frames at every width (base popcount p50 = 29, p99 = 34, max = 36 / 126)
```

> **H1(a) — CONFIRMED.** Zero direction-(a) false negatives over 3.2 M decisions × 8 E × 4 widths ×
> 5 arms = **512 million scored decisions**, including the mixed-population case (S6 proves a wide
> receiver's base-region test is bit-identical to a base receiver's, so the 174/190 rows inherit
> w = 126's count) and the `FILL_CAP` path (which never fired).

The other-channel FN counts are **not** H1(a) violations and are the most useful safety number in the
run:

* arm **A** false-negatives 430 029 frames that are PIT- or CS-relevant — Tier-0 cannot see those
  channels by construction. **That is the argument for the fingerprint, quantified.**
* arms **B/D** cut it to 156 903 — the fingerprint recovers 63.5% of them for 3.0 ns.
* arm **C** is *worse than B/D by exactly 17 751 frames*, and that difference is **exactly** the sum
  of the `veto FN` column across the whole grid (11 526 + 5 672 + 305 + 248 = 17 751). See §4.

---

## 2. H2 — width buys discrimination

Per-prefix false-positive probability of arm A, 264 prefixes × 20 000 frames = 5 258 690 non-ancestor
trials per width:

| w | p̄ (Wilson 95%) | per-prefix min / p50 / mean / p99 / max | p̄ fitted from E = 128 |
|---|---|---|---|
| 94 | **0.817941%** [0.810279, 0.825676] | 0.170 / 0.447 / 0.818 / 5.210 / 8.523 % | 0.808% |
| 126 | **0.366726%** [0.361596, 0.371929] | 0.035 / 0.145 / 0.366 / 5.128 / 7.425 % | 0.359% |
| 174 | **0.023200%** [0.021934, 0.024538] | 0.000 / 0.010 / 0.023 / 0.270 / 0.596 % | 0.025% |
| 190 | **0.010820%** [0.009967, 0.011746] | 0.000 / 0.005 / 0.011 / 0.115 / 0.376 % | 0.011% |

| ratio | predicted | band | measured | |
|---|---|---|---|---|
| p̄(126)/p̄(94) | 0.37 | 0.20 – 0.70 | **0.4484** | **CONFIRMED** |
| p̄(174)/p̄(126) | 0.056 | 0.02 – 0.15 | **0.0633** | **CONFIRMED** |
| p̄(190)/p̄(174) | 0.43 | 0.25 – 0.75 | **0.4664** | **CONFIRMED** |

> **H2 — CONFIRMED, all three ratios, all three point estimates inside their bands.** The layered
> extra region is an independent projection as C3 assumed; nothing is correlated. The direct and
> fitted p̄ agree to within 1.5% at every width (§7.2's estimator check).

Two things the pre-registration asked to be visible rather than assumed:

* **C2 heterogeneity is severe and it is what P5(c) tripped over.** At w = 126 the p99 prefix
  (5.13%) is **35× the median** (0.145%). A campaign anchored on one prefix could land anywhere in
  that range. R = 32 draws is what makes the ratios above stable.
* **C5 — the extra region does NOT saturate.** Measured fill by depth: base 28.4 / 126 bits (23%),
  174-extra 24.2 / 48 (50%), 190-extra 25.8 / 64 (40%), essentially flat across depths 7–13
  (depth 8 is the outlier at 31.4 / 26.3 / 28.2 — it is the deepest depth at which
  `for_each_prefix` emits the *full* name, so it sets one more prefix than its neighbours).

---

## 3. H4(a) — the FP crossover, and what it does to `tier1.rs`'s justifying sentence

Arm A's false-positive rate over irrelevant frames (denominator = frames irrelevant on all three
channels; the direction-(a)-only denominator differs in the 4th decimal and is in `p7-fp.csv`):

| E | m(E) | r(E) | **94** | **126** | **174** | **190** |
|---|---|---|---|---|---|---|
| 1 | 1.0 | 99.12% | 0.6786% | 0.2878% | 0.0157% | 0.0063% |
| 2 | 2.0 | 98.81% | 1.5210% | 0.7933% | 0.0506% | 0.0255% |
| 4 | 4.0 | 98.27% | 3.0200% | 1.6302% | 0.1022% | 0.0498% |
| 8 | 8.0 | 97.19% | **5.8829%** | 3.0178% | 0.2126% | 0.0919% |
| 16 | 15.7 | 92.52% | 11.5153% | **5.3453%** | 0.3645% | 0.1655% |
| 32 | 30.8 | 84.48% | 23.2146% | 9.8921% | 0.6673% | 0.3222% |
| 64 | 61.9 | 72.33% | 40.0591% | 21.2007% | 1.5451% | 0.7325% |
| 128 | 124.2 | 50.96% | 63.5016% | 36.0095% | **3.0022%** | **1.4180%** |

(Every cell has a Wilson 95% CI in `p7-fp.csv`; the widest half-width in the table is ±0.037 pp.
`m(E) < E` from E = 16 because `coverage_antichain` drops the depth-4 aggregates once their roots are
drawn — C8, reported rather than assumed. `r(E)` falls from 99.1% to 51.0%, the moving ceiling §8.2
required.)

| width | predicted | band | measured | |
|---|---|---|---|---|
| 94 | E*_FP ∈ [4, 8] | [2, 16] | **8** | **CONFIRMED** |
| 126 | E*_FP ∈ [16, 48] | [8, 96] | **16** | **CONFIRMED** |
| 174 | > 128 | FP < 5% at every E ≤ 128 | **> 128** (3.00% at E = 128) | **CONFIRMED** |
| 190 | > 128 | same | **> 128** (1.42% at E = 128) | **CONFIRMED** |
| movement | E*_FP(174)/E*_FP(94) ≥ 4, point 16–32× | | **> 16×**, and monotone non-decreasing in width | **CONFIRMED** |

> **H4(a) — CONFIRMED in every cell**, including the pre-registered *worse than P5(c)'s on-air 64*
> claim for the 94-bit width: E*_FP(94) = **8**, an 8× move, because this corpus's ~10–13-component
> names set 28 bits where P5(c)'s depth-2 `/p<i>/<seq>` set ~12.

**Consequence for the record, as §6 required.** `tier1.rs` justifies Tier-1 with *"past ~8–32
prefixes a relay wants a filter whose FP does not climb with E"*. Measured on realistic names:
that threshold is **8** at the historical 94, **16** at the **shipped** 126, and **> 128** at the
**designed** 174. The sentence is right for the width the project measured and wrong for the width it
designed — at 174 a relay can carry 128 registered prefixes and still false-positive on 3% of
irrelevant traffic.

---

## 4. H3(a) / H3(b) — what the second Tier-1 site actually does

### H3(a) — BF-FIB is re-deriving, not adding

Frames arm A admits at w = 174, restricted to those where `lookup()` returned `fib ∧ ¬pit ∧ ¬cs`:

| E | fib-only admits | genuinely FIB-relevant | fraction |
|---|---|---|---|
| 1 | 11 962 | 11 962 | **100.0000%** |
| 8 | 73 924 | 73 924 | **100.0000%** |
| 32 | 482 304 | 482 304 | **100.0000%** |
| 128 | 1 559 628 | 1 559 628 | **100.0000%** |

> **H3(a) — CONFIRMED**, and not marginally: **100.0000% at every E**, bar ≥ 99%. Tier-1's BF-FIB
> never admitted a frame on grounds Tier-0 did not already have. §1.4's circularity reading stands:
> on the admit path that table only re-establishes relevance Tier-0 established.

### H3(b) — the parsed CS probe is bit-identical work

> **H3(b) — CONFIRMED. 0 disagreements in 25 600 000 wide frames.** `lookup(name).cs` and
> `probe_fingerprint(fp).cs` agree exactly, as `Table::positions(name) ≡ positions_fp(name_fingerprint(key, name))`
> requires. The parsed probe recomputes, from a name it paid 209 ns to parse, the identical 24-bit
> value the frame carried in HT Control for **3.0 ns**.

### The direct quantification the audit asked for

Per (E, width): `parses` = frames Tier-0 admitted, each paying `inner_name + ndn_name_to_slash +
Tier1::lookup`. `redundant` = of those, the ones where `lookup().fib` was true, i.e. the parse only
re-derived Tier-0's own answer. `veto` = the parse changed the answer to *reject*. `veto FN` = the
veto rejected a genuinely relevant frame that the parallel arm D admitted. `T0rej & T1rej` = frames
Tier-0 rejected that Tier-1 would also have rejected — the parses Tier-0 **saved**.

**w = 174 (the designed width)** — N = 3 200 000 frames per row:

| E | parses | redundant | veto | veto FN | rescued | T0rej & T1rej | T0rej, T1adm | wasted ns/frame |
|---|---|---|---|---|---|---|---|---|
| 1 | 12 472 | 11 973 (**96.0%**) | 498 | 0 | 11 545 | 3 181 681 | 5 847 | 1.7 |
| 8 | 80 626 | 73 988 (**91.8%**) | 6 629 | 17 | 11 228 | 3 113 707 | 5 667 | 10.4 |
| 32 | 500 882 | 482 774 (**96.4%**) | 18 079 | 42 | 9 577 | 2 694 375 | 4 743 | 67.6 |
| 128 | 1 610 110 | 1 560 962 (**96.9%**) | 49 073 | 118 | 5 495 | 1 587 226 | 2 664 | 216.3 |

**w = 126 (the shipped width)**:

| E | parses | redundant | veto | veto FN | rescued | T0rej & T1rej | T0rej, T1adm | wasted ns/frame |
|---|---|---|---|---|---|---|---|---|
| 1 | 21 142 | 11 973 (56.6%) | 9 150 | 25 | 11 512 | 3 173 029 | 5 829 | 1.7 |
| 8 | 168 299 | 73 988 (44.0%) | 94 128 | 303 | 10 911 | 3 026 208 | 5 493 | 10.4 |
| 32 | 751 465 | 482 774 (64.2%) | 268 210 | 867 | 8 713 | 2 444 244 | 4 291 | 67.6 |
| 128 | 2 151 167 | 1 560 962 (**72.6%**) | 589 183 | 2 069 | 3 583 | 1 047 116 | 1 717 | 216.3 |

**Answers to the audit's two questions, in numbers:**

1. **"How many frames does Tier-1's fib/pit drop that Tier-0 already dropped?"** — the `T0rej & T1rej`
   column: at (E = 128, w = 174) **1 587 226** of the 1 589 890 frames Tier-0 rejected, Tier-1 would
   have rejected too. **99.83%** of Tier-0's rejections are rejections Tier-1 duplicates. In the other
   direction only **2 664** frames (0.17%) are ones Tier-1 would have admitted and Tier-0 did not —
   and the fingerprint already rescues **5 495** of Tier-0's rejects for 3.0 ns, which is *more* than
   the parsed lookup would have found, because of D3.
2. **"What does that redundancy cost in parses?"** — at w = 174, **91.8–98.5% of every parse the
   status quo pays produces an answer Tier-0 already gave**, costing **1.7 – 216.3 ns per received
   frame** (`redundant/N × (c_name + c_lookup)`). At E = 128 that is **216 ns/frame of pure
   re-derivation**, against a whole-filter budget of 1 918 ns.

**But the veto is not worthless, and this is where the pre-registered conclusion has to bend.**
Arm C's false-positive rate is *flat at 0.017 – 0.037% at every width and every E* — because Tier-1's
BF-FIB is a 32 768-bit table, not 126 in-frame bits, and its own FP is ~0.001%. At (E = 128,
w = 126) the veto is the difference between **36.01%** (arm A) and **0.017%** (arm C). Deleting it
outright, as §10.6 pre-wrote, would cost that.

---

## 5. H3(c) — the cost half

`W_C − W_D = a_A·(c_name + c_lookup − c_fp) − (a_B − a_C)·c_t2`, both algebraic forms computed
independently and agreeing to float tolerance at every one of the 32 cells (**T9 PASS**).

### 5.1 The measured costs — ns per received frame, Apple M4 Pro, release

| term | what | p50 | p99 |
|---|---|---|---|
| `c_name` | `inner_name` + `ndn_name_to_slash` on the real LP/NDN-TLV wire | **209.0** | 230.9 |
| `c_lookup` | `Tier1::lookup` (2 prefix walks + 1 direct probe) | **234.5 – 240.8** | — |
| `c_fp` | `fingerprint_from_htc` + `probe_fingerprint` | **3.0** | 6.0 |
| `c_decode` | `ndn_packet::Data::decode` — a **measured lower bound** on `c_t2` | **246.2** | 259.5 |
| `c_nic` | `NdnNicFilter::may_serve` on the parsed name | **166.7** | 177.2 |
| `c_mask(126)` | one `may_match` (= `c_t0` at E = 1, m(1) = 1) | **15.6** | — |

`c_t0(E, w)` — measured as one quantity, never modelled as `E × constant`, exactly as §5.1 requires:

| E | m(E) | c_t0(94) | c_t0(126) | c_t0(174) | c_t0(190) |
|---|---|---|---|---|---|
| 1 | 1 | 15.6 | 15.6 | 15.8 | 15.8 |
| 8 | 8 | 127.3 | 126.2 | 130.8 | 130.8 |
| 32 | 32 | 452.4 | 466.8 | 510.6 | 512.5 |
| 128 | 128 | 1128.1 | **1497.9** | **1917.5** | 1937.1 |

**Read that against `c_name` = 209 ns.** From E ≈ 16 the mask scan alone costs more than the parse it
exists to avoid. That is H4(b)'s conclusion arriving through the cost model rather than the FP model.

**`c_t2` is a parameter, and ρ is the campaign's single largest open variable.** §5.1 declared `c_t2`
unmeasured; §6 then asked for verdicts "at the measured ρ", which does not exist. The honest
substitute is a **measured lower bound**: `c_decode` = 246.2 ns is a full `Data::decode` and nothing
else — no signature verification, no PIT/CS lookup, no FIB longest-prefix match, no forwarding
decision. So

```
ρ_lb = c_decode / c_mask(126) = 15.8      ← a LOWER BOUND on ρ, not ρ
```

and every verdict below is given **at ρ_lb** and **as a function of ρ**. Nothing here rests on an
invented constant.

### 5.2 H3(c), part by part

| bar | measured | verdict |
|---|---|---|
| `W_C − W_D > 0` at w = 174 for every E ≤ 128, at the measured ρ | +1.70 → +217.84 ns, positive at all 8 E at ρ_lb | **CONFIRMED** |
| `W_C − W_D < 0` for some E ≥ 32 at w = 94 | positive at every E at ρ_lb; turns negative only for ρ > 50.5 | **REFUTED** |
| magnitude at (E = 8, w = 174) ∈ [0.4, 1.0]·`c_name` | **0.051 · c_name** (10.74 ns) | **REFUTED** |

The sign-flip points, which is the form the answer actually takes:

| w | ρ*(flip) at E = 1 | E = 8 | E = 32 | E = 128 |
|---|---|---|---|---|
| 94 | 44.6 | 40.3 | **50.5** | 70.8 |
| 126 | 66.2 | 51.2 | 80.0 | 103.2 |
| 174 | 718.0 | **348.5** | 790.8 | 927.4 |
| 190 | 1736.4 | 767.5 | 1604.7 | 1928.5 |

Both halves of H3(c) can only hold **simultaneously** for ρ ∈ (50.5, 348.5) — a real window, but one
this campaign cannot place a measured ρ inside. At ρ_lb = 15.8 the serial Tier-1 wastes work at every
width and every E; above ρ ≈ 50 it starts earning its parse at 94, and above ρ ≈ 349 at 174 too.

### 5.3 Diagnosing the magnitude refutation — it could never have been met

`W_C − W_D` is bounded above by `X = a_A·(c_name + c_lookup − c_fp)`, its value at ρ = 0. At
(E = 8, w = 174), `X` = **11.25 ns = 0.054 · c_name**. The pre-registered band starts at 0.4·c_name,
so **no value of ρ, on any host, could have satisfied it.**

The error is identifiable and it is not in the measurement: the whole term scales with `a_A`, and the
band implicitly assumed `a_A ≈ 0.4 – 1.0`. Measured `a_A`(E = 8, w = 174) = **2.52%**
(80 626 / 3 200 000). The prediction was written for a filter that admits most of its traffic; the
designed width admits one frame in forty. **The magnitude band was a claim about the admit rate
wearing a cost prediction's clothes**, and stating it in units of `c_name` hid that — in units of
`a_A·c_name` it would have been ~1.0 and correct.

---

## 6. H4(b) — the net crossover, as a curve

`Benefit(A) = (1 − a_A)·c_t2 − c_t0(E, w)`. Smallest E with `Benefit(A) ≤ 0`:

| ρ | w = 94 | w = 126 | w = 174 | w = 190 |
|---|---|---|---|---|
| 1 | 1 | 1 | 1 | 1 |
| 3 | 4 | 4 | 4 | 4 |
| 10 | 16 | 16 | 16 | 16 |
| **15.8 = ρ_lb** | **16** | **16** | **16** | **16** |
| 30 | 32 | 32 | 32 | 32 |
| 100 | 64 | 128 | 128 | 128 |
| 300 | 128 | > 128 | > 128 | > 128 |
| ≥ 1000 | > 128 | > 128 | > 128 | > 128 |

and its continuous form, `ρ*_net(E, w)` = the ρ **above** which Tier-0 still pays at that E:

| E | w = 94 | w = 126 | w = 174 | w = 190 |
|---|---|---|---|---|
| 1 | 1.0 | 1.0 | 1.0 | 1.0 |
| 8 | 8.9 | 8.5 | 8.6 | 8.6 |
| 32 | 44.5 | 39.1 | 38.8 | 38.9 |
| 128 | 387.2 | 293.3 | **247.7** | 246.2 |

| bar | measured | verdict |
|---|---|---|
| a crossover exists inside E ≤ 128 at the measured ρ | E*_net = 16 at every width at ρ_lb | **CONFIRMED** |
| `E*_net(174) ∈ [0.5, 2.0] × E*_net(126)` | ratio **1.00** — identical at every ρ ≤ 100 | **CONFIRMED** |

> **H4(b) — CONFIRMED, and the "does not move with width" half is stronger than predicted: it does
> not move *at all*.** The point estimate `32 ≤ E*_net ≤ 128` sits above the measured 16 at ρ_lb, but
> that was a point estimate, not a bar, and ρ_lb is a lower bound on ρ.

> **The pre-registered joint conclusion of H4(a)+H4(b) is CONFIRMED in the words it was written in:**
> *width fixes Tier-0's **discrimination** but not its **O(E) work**, so Tier-1's justification MOVES
> — from "FP climbs with E" to "mask ANDs climb with E" — rather than disappearing.* E*_FP moves
> 8 → 16 → >128 → >128 with width; E*_net does not move at all.

### 6.1 UNREGISTERED — the O(E) work is ~6–10× larger than it needs to be

`PrefixFilter::may_match` runs `self.popcount()` — a 126-iteration bit loop over the **frame** —
before every mask test, although the fill cap does not depend on the mask. Hoisting it once per
frame, decisions asserted identical on the whole cost sample at every E:

| E | c_t0(126) as built | popcount hoisted | speedup |
|---|---|---|---|
| 1 | 15.6 ns | 15.5 ns | 1.01× |
| 8 | 126.2 ns | 22.0 ns | **5.75×** |
| 32 | 466.8 ns | 48.1 ns | **9.71×** |
| 128 | 1497.9 ns | 278.3 ns | **5.38×** |

This is the most actionable number in the campaign: it moves `ρ*_net(128, 126)` from **293.3 to
≈ 55**, i.e. it changes the answer to "does Tier-0 pay at E = 128" for every ρ between those two.
It is a pure cost change — same admissions, same FP, same FN.

---

## 7. The ablation (§4.3) — moving the FIB question in front of the parse

Not a rival, not ranked, one row as registered. `NdnNicFilter::paper_default` = 16 384 B, k = 2, over
the same E prefixes, queried on the parsed name.

* **Cost to answer:** `c_name + c_nic` = 209.0 + 166.7 = **375.7 ns/frame**, against Tier-0 answering
  the same question in front of the parse at `c_t0(E = 8, w = 174)` = **130.8 ns/frame**.
* **Discrimination:** BF-FIB's FP is 0.0000% up to E = 32 and 0.0007% at E = 128, with 0 direction-(a)
  FN — far better than any in-frame width, which is what 16 KB buys over 174 bits.

**The honest statement of the trade, and the only one this campaign makes about NDN-NIC:** the
ancestor's table is ~2 000× larger and ~130× more discriminating at E = 128; moving its question in
front of the parse costs that discrimination and buys 245 ns/frame plus the ability to *not receive*
the frame at all. No winner is declared, and none is implied.

**Tier-1 occupancy, for the record** (32 768 bits/table, k = 4 — a sizing the pre-registration left
unfixed and which is declared here): BF-FIB 0.01–1.56% full, BF-PIT 3.06%, BF-CS 13.44% → 7.01% as E
grows, because the Basic-CS rule skips more cached names as more of them fall under a registered
prefix (`cs_skipped` 1.3 → 124.6 of 256). **The Basic-CS rule empties BF-CS for exactly the traffic
Tier-0 already admits**, which is what it is for, and it means direction (b) only ever fires outside
the registered FIB.

---

## 8. VERDICT — in the words §10.6 registered, and the ones it did not

**Against §10.6's pre-written options, the one that fires is the third, with the second as its
qualifier:**

> *If it pays at every E at the designed width — then §1.5(1)'s finding, that the project has been
> shipping and measuring different widths, is the headline instead, and `tier1.rs`'s justifying
> sentence is rewritten against measured numbers rather than remembered ones.*

Tier-0 at the designed width **pays at every E ≤ 128 whenever ρ ≥ 248**, and pays up to E = 8 even at
`ρ_lb` = 15.8, which is a `Data::decode` and nothing else. It is safe (0 direction-(a) FN in 512 M
scored decisions), it costs **0 bytes of airtime on the base profile** and +12 B on the wide one, and
width buys exactly the discrimination it was designed to buy (p̄ 0.818% → 0.0232%, 35×). And
§1.5(1) is indeed the headline: the project **measured 94, ships 126, and designed 174**, and the
three have E*_FP of 8, 16 and > 128 — the sentence `tier1.rs` has been justifying Tier-1 with is a
property of a width nothing emits.

**But the campaign cannot close the question it was asked**, and this is the single most important
sentence in this document: *whether the filter pays is a function of ρ, and **ρ has never been
measured in this project***. `c_t2` — the downstream work an admitted frame causes — was declared a
parameter in §5.1 and is the only term separating "delete it" from "widen it". The measured lower
bound puts E*_net at 16; a forwarder decision on top of the decode plausibly puts it past 128. **The
next campaign is not another filter sweep. It is measuring `c_t2` on a real forwarder.**

**On the serial wiring — §1.3's reading is upheld in mechanism and overturned in remedy.**

* The duplication is real and now measured: **91.8 – 98.5%** of the parses the status quo pays at the
  designed width re-derive an answer Tier-0 already gave, at **1.7 – 216.3 ns/frame**; the parsed CS
  probe is bit-identical to a 3.0 ns fingerprint probe on **25.6 M / 25.6 M** frames; BF-FIB admits on
  independent grounds **0.0000%** of the time.
* **The pre-registered remedy — "delete the veto and the BF-FIB table from the RX path" — is NOT
  supported.** The veto holds arm C's FP flat at 0.017 – 0.037% where arm A reaches 36.01% (w = 126,
  E = 128). Deleting it trades a 216 ns/frame parse for a 2 000× worse false-positive rate.
* **The measurable harm of the serial wiring is not the wasted parse. It is 17 751 false negatives.**
  Arm C rejects exactly that many relevant frames that arm D admits — Data satisfying an outstanding
  PIT entry deeper than 8 components (D3), and CanBePrefix Interests deeper than 7 (D2) — because the
  veto can only reject while the rescue can only admit.
* **And the fix is one line and 3.0 ns.** Arm D — `t0 ∨ fp`, the fingerprint consulted on the *admit*
  path as well as the reject path — has **zero** veto false negatives by construction, keeps every one
  of the veto's rejections, and costs `c_fp` = 3.0 ns on the frames Tier-0 admits. The correct change
  is therefore **not** to delete the veto but to make the gate what §1.2 says it is: `(t0 ∧ ¬lk.is_miss) ∨ fp`.
  That is a behaviour change and is out of this campaign's scope (§10.7); it is the first item of the
  next one.

**Ordered work this produced**, none of it done here:

1. **D1** — fix `lp_fragment_value`'s double strip (or delete the duplicate parser and call
   `ndn_packet::lp::lp_ndn_packet_bytes`). Today, an unfragmented LP object goes out **broadcast with
   no filter** and arrives past a Tier-1 that never fires. Regression test: `inner_name` on
   `encode_lp_packet(data)`.
2. **D2 / D3** — reconcile the `MAX_DEPTH` clamp between `cache`/`add_pit` (insert side) and
   `lookup`/`probe_fingerprint` (query side). Correct `tier1.rs`'s "strict superset" claim.
3. **§6.1** — hoist `may_match`'s `FILL_CAP` popcount out of the mask loop (5.4 – 9.7×, identical
   decisions).
4. **Measure `c_t2`.** Until then no one can say whether this filter pays at large E.
5. **D5** — repack `campaign_e_sweep.rs` to 16 filter bytes before it is run again.
6. **D4** — re-point `tier0_wire_cost::the_filter_costs_no_additional_airtime` at
   `FrameFormat::RawNdn`; on `Raw80211` it asserts nothing.
7. Then, and only then, the behaviour change: arm D.

---

## 9. WHAT THIS CAMPAIGN DID NOT MEASURE — restated with the verdict, per §10.4

1. **Whether the WIDE bits survive the air.** `addr4`, HT Control and `Duration/ID` may be rewritten
   or stripped by a chip's monitor path. **No result from `examples/wide_profile_onair.rs` exists
   anywhere in this tree.** Every number at w = 174 and w = 190, and **every arm that uses the
   fingerprint (B, C, D) at any width**, is a measurement of the *design*, conditional on a wire fact
   not in hand.
2. **`c_t2`.** Bounded below by a measured `Data::decode` (246.2 ns); never measured. Every
   crossover is reported as a curve over ρ for this reason.
3. **The wide profile's airtime.** Asserted at +12 B/frame (S7), deliberately not priced into any `W`
   — converting µs of air into ns of CPU needs an exchange rate nobody here has measured.
4. **Wake / DMA / interrupt cost avoided on a constrained receiver.** Excluded; biases **against**
   the filter.
5. **Any delivery, latency or throughput effect.** None. This campaign cannot say the filter makes a
   link faster.
6. **Embedded-target cost.** One host CPU; mitigated by the ρ curve, not solved.
7. **Whether `c_name` is duplicated downstream.** Arm C is reported with `c_name` charged; with it
   free, arm C's cost falls by `a_A · 209 ns` and every ρ\* in §5.2 rises by ~5×. Not settled here.
8. **Multi-hop / relay behaviour.** One receiver, one registration set.

**The four bias directions, with the verdict and not in a footnote:** excluding wake/DMA biases
**against** the filter; holding k = 4 at every width biases **against** 174/190; excluding airtime
biases **for** 174/190 and therefore for arms B/C/D; charging `c_name` to arm C biases **against** the
status quo.

**Two method choices the pre-registration left open, declared here rather than buried:**
`Tier1::new(bits_each = 32768, k = 4)` (§7 above), and §7.1's "P full names drawn uniformly from the
traffic stream *and then removed from it*" read as **sampling without replacement** — the frames for
those names remain in the stream. Under the other reading (removing the frames) the PIT and CS
relevance channels would have no positive instances at all and H1(b)/H3 would be untestable.
