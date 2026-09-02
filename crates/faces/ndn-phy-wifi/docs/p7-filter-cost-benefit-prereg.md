# P7 campaign — does the Tier-0 / Tier-1 name filter PAY? width × E cost-benefit — PRE-REGISTRATION

**Committed before any measurement exists (the gate rule).** Verified the same way P5(c) was: before
the first run, `git ls-files crates/faces/ndn-phy-wifi/docs/p7-filter-cost-benefit-prereg.md` must
show this file tracked, and

```
git ls-files | grep -E 'p7-|filter_cost_benefit'
```

must show **this file and nothing else** — no harness, no CSV, no result. If a data file or the
example already exists when this is committed, the campaign is void and restarts under a new name.

This campaign exists because an external audit asked the question the project has never actually
answered: **is the Tier-0 / Tier-1 name-filter design necessary and beneficial at all?** Not "does it
discriminate" — P5(c) answered that on air — but *does it pay for itself*, and *was the thing P5(c)
measured even the design*.

---

## 1. What is already established, and is not re-litigated here

* **#106 / P5(c) (on air, N = 140 331 attributable frames, one capture, four arms, Wilson 95% CIs).**
  Zero false negatives at every E for every filter. Tier-0 FP 0.006% (E=1) → 6.573% (E=64); NDN-NIC
  and Tier-1 ≤ 0.026% throughout. The OR-of-E-masks law `FP(E) = 1 − (1 − p̄)^E` holds once p̄ is the
  per-prefix *mean* and not one prefix's outlier. **The in-frame bits survive the air.** That is a
  fact this campaign builds on and does not re-measure.
* **The filter costs ZERO additional airtime on the base profile.** An 802.11 data frame carries
  `addr1‖addr2‖addr3` unconditionally — `build_dot11` emits `addr3.unwrap_or(dst)` with or without a
  filter — so the filter RECYCLES bytes the frame must send anyway. MEASURED, not argued:
  `ndn-frame-io`'s `tier0_wire_cost::the_filter_costs_no_additional_airtime` asserts the two frames
  are byte-length identical. The "12 bytes/frame of permanent airtime" that `ndn_nic.rs` and
  `tier1.rs` both used to claim does not exist. Tier-0 trades receiver **state** for receiver
  **work** — never airtime for memory.
* **k = 4 at m = 126** (200 names / 400 000 trials, host replication, ±1σ, `tier0.rs`). Not re-derived
  per width here; see §9, confounder C4.

## 2. The two things P5(c) does NOT establish — the reason for this campaign

### 2.1 ★ It measured the wrong filter width

P5(c) ran `with_tx_bloom(OPEN_GROUP_KEY)` and reassembled a **12-byte** filter from `addr1‖addr2`:
96 wire bits, 94 usable after the I/G and U/L bits are reserved. The design does not specify 94. It
specifies a base of **126** (`tier0::M_BITS` = `WIFI_BASE_BLUR`, spanning `addr1‖addr2‖addr3[0:4]`)
plus a layered **48-bit** extra projection in `addr4` (`tier0::WIFI_WIDE_EXTRA_BLUR`) = **174**, and
`Duration/ID` is 16 further bits sitting at literal zero — `build_dot11` writes `[0x00, 0x00]` in
*both* the base and the wide branch, and #96 measured that stock Wi-Fi does not honour the NAV in our
injected frames — for a possible **190**.

**The wide profile has never been exercised.** `RadioMediumFace::with_wide_bloom` has exactly one
definition (`medium.rs:1010`) and **zero call sites** anywhere in the tree; the only other mentions
are doc-comments and one unit test that constructs the mask set directly. Verified:

```
grep -rn "with_wide_bloom" --include="*.rs" .
```

So the published FP curve, and the conclusion it justifies — `tier1.rs`: *"past ~8–32 prefixes a
relay wants a filter whose FP does not climb with E"* — is the curve of **the filter we ship by
accident, not the filter the design specifies**. That conclusion may not survive the correct width.
This campaign finds out.

### 2.2 It measured discrimination, not benefit

FP(E) says how well the filter separates. It says nothing about whether the filter **pays**. The
benefit is a parse avoided. The cost is `O(E)` mask ANDs on every frame plus the parses wasted on
false positives. Nobody has ever put those on one scale. §5 puts them on one scale, as an equation,
before any number is measured.

---

## 3. Why an offline sweep is valid here — and what it does NOT cover

**Valid.** The false-positive rate is a function of the in-frame filter BITS and the query masks —
*not* of link margin, distance, rate or drift. This is the argument P5(c) made for holding channel
conditions constant by evaluating every arm on one capture; taken one step further it says the
FP/FN half of the question does not need the air at all, provided the bits that reach the receiver
are the bits the sender wrote. **P5(c) established exactly that, on air, at 140 331 frames and zero
false negatives across E** — for the base region. So an offline sweep over the same production code
paths (`PrefixFilter`, `WifiWideBlur`, `NdnNicFilter`, `Tier1`) measures the same quantity the air
would, at sample sizes and widths the bench cannot reach, and holds the traffic identical across
arms by construction.

The cost half is CPU work, which is a property of the code and the host, not of the channel. It is
offline by nature.

**Does NOT cover — declared before the run, not after:**

1. **Whether the WIDE bits survive the air.** A 4-address QoS+HTC frame's `addr4` and HT Control may
   be rewritten, dropped or stripped by a given chip's monitor TX/RX path. That is a hardware
   question owned by `examples/wide_profile_onair.rs`, and **no result from it is recorded anywhere
   in this tree**. Every width ≥ 174 in this campaign is therefore a measurement of the *design*,
   explicitly conditional on an on-air fact that is not yet in hand. Out of scope, and any conclusion
   drawn at 174/190 must carry that condition in the same sentence.
2. **Whether `Duration/ID` is writable in practice.** Some chips compute Duration in hardware and
   will overwrite it; and #96 measured only that stock Wi-Fi *ignores* our NAV, not that no station
   anywhere honours it. The 142 and 190 arms are conditional on this and are labelled so.
3. **The wide profile's airtime.** See §5.3 — it is +12 B/frame of real header, and this campaign
   computes and asserts it but does NOT price it into the equation.
4. **Wake / DMA / interrupt cost avoided on constrained receivers.** Excluded. This biases the result
   **against** the filter, and the bias direction is stated with every result.
5. **Any delivery, latency or throughput effect.** None is measured. This campaign cannot say the
   filter makes a link faster.
6. **Embedded-target cost.** The parse:AND cost ratio is measured on one host CPU. Mitigated, not
   solved, by reporting the crossover as a function of that ratio (§6, M2).
7. **Tier-1's parse-free fingerprint rescue** (`name_gate.rs`, `probe_fingerprint`) is DISABLED in
   the sweep: it is an admit-only path that raises FP without changing FN, and it is a Tier-1
   interaction, not a width effect. Excluded deliberately, named here so it cannot be quietly added
   later to move a number.
8. **Multi-hop / relay behaviour.** One receiver, one registration set.

---

## 4. Arms

### 4.1 Filter widths — the exact construction of each, so none is ambiguous

Each width is a *layered* filter, never a re-modulused one: the base region is bit-identical across
every width (that is the coexistence floor — a base-only receiver must read a wide sender's frame),
and extra regions are independent keyed projections layered on top (`WideBlur::extra_positions`,
`EXTRA_DOMAIN`).

| arm | total bits | construction | wire fields | added airtime vs base |
|---|---|---|---|---|
| **94** | 94 | single projection `positions_m(key, pfx, 94)` | `addr1‖addr2` (96 − 2 reserved) | 0 B |
| **126** | 126 | `PrefixFilter` / `positions` — today's `M_BITS`, the SHIPPED base | `addr1‖addr2‖addr3[0:4]` | 0 B |
| **142** † | 126 + 16 | `WideBlur<2>` — base + 16-bit extra | + `Duration/ID` | **0 B** |
| **174** | 126 + 48 | `WifiWideBlur` = `WideBlur<6>` — the DESIGNED wide profile | + `addr4` | +12 B (4-addr QoS+HTC) |
| **190** | 126 + 64 | `WideBlur<8>`, extra bytes 0..6 → `addr4`, 6..8 → `Duration/ID` | + `addr4` + `Duration/ID` | +12 B |

† **142 is an arm added at pre-registration time**, beyond the audit-specified set {94, 126, 174,
190}, and is labelled as such in every table. Its rationale: it is the only width above the shipped
base that costs **zero** added airtime, because `Duration/ID` is already emitted as `[0x00, 0x00]` on
the base 3-address frame. If it buys a material FP reduction, it is the cheapest available change in
the whole design, and omitting it would be leaving the interesting answer unmeasured.

Note that 190 is deliberately **one contiguous 64-bit extra region**, not a 48-bit region plus a
separate 16-bit region. A 16-bit region receiving up to `MAX_DEPTH × K` = 32 set operations saturates
(~86% fill) and discriminates almost nothing on its own; folded into a 64-bit region the same bits
are worth far more. Both constructions were considered; the contiguous one is registered as primary
and the split one is not run. Stating this now so the choice cannot be made after seeing a number.

### 4.2 Registered-prefix count

`E ∈ {1, 2, 4, 8, 16, 32, 64, 128}` for every width.

### 4.3 Baselines and control (their own budgets, not matched to Tier-0's)

* **ndn-nic** — `NdnNicFilter::paper_default(&key, prefixes_E)`: receiver-side BF-FIB, 16 KB, k = 2.
  **Requires the name parsed.** Its cost is `C_parse + O(depth)` probes, never zero.
* **tier1** — `Tier1::new(...)` with the E prefixes registered, admit iff `lookup(name).fib`.
  Receiver-side, also post-parse. Reported with its `table_bytes`.
* **none** — no filter, parse everything. FP = 100%, FN = 0 by construction. This is the null against
  which net benefit is defined, and it is the arm that wins if the answer is "the design does not
  pay".

---

## 5. The cost model — stated as an equation BEFORE it is measured

### 5.1 The equation

Per frame, at width `w` and registered-prefix count `E`:

```
Net(E, w) = P_reject(E) · C_parse  −  C_filter(E, w)  −  FP(E, w) · P_irrelevant(E) · C_parse
```

where the third term is the parses *wasted* on false positives. Written this way the identity is
easy to check and it does not double-count:

```
Net(E, w) = C_parse · r(E) · (1 − fp(E, w))  −  C_filter(E, w)
```

with `r(E)` = the fraction of all frames that are genuinely irrelevant (not under any registered
prefix) and `fp(E, w)` = the false-positive rate over irrelevant frames. Both forms are reported;
if they disagree the harness is wrong and the run is void.

`Net > 0` ⇒ the filter pays. `Net ≤ 0` ⇒ it does not, at that E and that width.

### 5.2 Every term, and how each is measured

| term | what it is | how measured |
|---|---|---|
| `r(E)` | fraction of frames genuinely irrelevant at this E | **exact ground truth** from the corpus — a name is relevant iff some registered prefix is a component-ancestor of it. Not estimated. Note `r` FALLS with E (registering more makes more traffic genuinely wanted); `tier1.rs` and `ndn_nic.rs` both record that reporting raw reject rate against a moving ceiling is how this was got wrong before. |
| `fp(E, w)` | FP over *irrelevant* frames | counted over the corpus, Wilson 95% CI per cell, averaged over R = 32 independent registration draws (§7.2) |
| `FN` | frames relevant but rejected | counted; must be 0 (H1) |
| `C_parse` | the work the filter AVOIDS: NDNLPv2 + NDN-TLV decode far enough to extract the Name, plus the FIB decision that follows | timed on the real `ndn_packet` decoder over the corpus's own wire encodings, `Instant`-based, `black_box`, median of ≥ 10⁵ iterations, p50 and p99 both reported |
| `C_filter(E, w)` | the `O(E)` mask ANDs: `masks.iter().any(\|m\| frame.may_match(m))` on the production types | timed the same way, per (E, w) cell, on the same frames. **Data-dependent** — `any()` short-circuits on the first match and `may_match` short-circuits on the first mismatched word, and `PrefixFilter::may_match` also runs the `FILL_CAP` popcount test — so it is MEASURED, never modelled as `E × constant` |
| `table_bytes` | receiver state | `NdnNicFilter::table_bytes()` / `Tier1` sizes; Tier-0 = 0 B in frame, `16·|masks|` or `22·|masks|` B of precomputed masks, reported explicitly (this is receiver state and must not be hidden) |
| `|masks|` | masks actually tested after `coverage_antichain` dedup | reported per E — it can be < E, and using E where the code uses `|masks|` would overstate the cost |

### 5.3 Airtime is NOT a term — and the one place that statement needs a caveat

**For widths 94, 126 and 142, airtime is not a term because it is measured to be zero.** The base
802.11 data frame carries `addr1‖addr2‖addr3` and a `Duration/ID` field whether or not a filter is
present; the filter overwrites bytes that are already on the air. That is not an argument, it is
`tier0_wire_cost::the_filter_costs_no_additional_airtime`.

**For widths 174 and 190 that statement is false and this campaign says so up front.** The wide
profile is a 4-address QoS-Data + HT-Control frame. From `build_dot11`: base header = 2 + 2 + 6 + 6 +
6 + 2 = **24 B**; wide header = 2 + 2 + 6 + 6 + 6 + 2 + 6 + 2 + 4 = **36 B**. That is **+12 B per
frame**, on every frame, forever — about 16 µs at legacy 6 Mbit/s. It is exactly the cost the
project wrongly attributed to the *base* profile, and it is real here.

The campaign therefore:

* does **not** put airtime in `Net(E, w)` — the equation is a receiver-work equation and mixing a
  µs-of-air term into a ns-of-CPU term would require an exchange rate nobody has measured, which is
  precisely the failure mode the house rules forbid;
* **asserts** the 24 B / 36 B figures with a length test in the harness, so +12 B is a measurement
  and not arithmetic-from-reading-the-code;
* prints `+12 B/frame` in the same row as every 174 and 190 result, so no reader can take a wide-width
  FP win without seeing what it costs on the air.

If the wide widths win on FP but the reader's link is airtime-bound, the honest reading is that the
174/190 arms are **not free** and 142 is the arm to look at. That reading is registered here, before
the numbers.

---

## 6. Claims — stated so they can FAIL

> These four are the campaign. Each names its refutation condition and, where it makes a directional
> claim, commits a magnitude NOW.

**H1 — Safety (HARD).** Across every width w ∈ {94, 126, 142, 174, 190}, every E ∈ {1, 2, 4, 8, 16,
32, 64, 128}, every one of the R = 32 registration draws, and every frame in the corpus, the number
of false negatives is **exactly zero**, where a false negative is a frame whose name IS under a
registered prefix and whose filter test rejects it. This explicitly includes (a) the mixed-population
case — a base-profile sender's frame arriving at a wide-profile receiver, which must be tested on the
base region alone (`admits_wide`, `addr4 = None`), because testing a base frame's all-zero extra
region against a non-zero extra mask is a false-negative machine; and (b) the `FILL_CAP` admission
path — `PrefixFilter::may_match` rejects any frame whose base popcount exceeds 64, so if a legitimate
corpus name ever trips that cap, that IS a false negative and H1 fails. **Refuted by FN ≥ 1
anywhere.** On refutation the campaign STOPS, the defect becomes a lab property with a regression
test, and no further arm is run or reported as if it were valid. `FILL_CAP`, `K`, `MAX_DEPTH` and
`CLAMP` are NOT re-tuned to make H1 pass.

**H2 — Width buys discrimination.** The per-prefix false-positive probability p̄(w) falls materially
and monotonically along 94 → 126 → 142 → 174 → 190 on one fixed corpus. Because the corpus cancels in
a ratio, the predictions are committed as ratios measured on the same corpus, with bands: p̄(126)/p̄(94)
≈ **0.37** (band 0.20–0.70); p̄(142)/p̄(126) ≈ **0.56** (band 0.35–0.85); p̄(174)/p̄(126) ≈ **0.056**
(band 0.02–0.15); p̄(190)/p̄(174) ≈ **0.43** (band 0.25–0.75). **Refuted** if any ratio lands outside
its band, and refuted hard if any ratio is ≥ 1 — a wider filter that does not discriminate better
would mean the layering is broken (correlated projections), not that width is worthless, and would
send the extra-region construction back to the lab.

**H3 — The filter has a crossover.** For each width there exists a registered-prefix count `E*_net(w)`
— the smallest E at which `Net(E, w) ≤ 0` — beyond which the expected cost of running the filter
exceeds the parse cost it saves. Committed prediction: at the parse:AND cost ratio ρ measured on the
campaign host, `E*_net` for widths 94 and 126 falls **inside** the swept range, point estimate
**32 ≤ E*_net ≤ 128**. **Refuted** if no width crosses anywhere in E ≤ 128 at the measured ρ. Note
that refutation would be a result **in the design's favour** — the filter always paying in range is a
better outcome than a crossover — and it will be reported in exactly those words, not buried.

**H4 — At the DESIGNED width, Tier-1's justification changes; here is the direction and magnitude,
in advance.** Two halves, both committed now, both independently refutable.

*(a) The FP half.* At the designed width 174, FP(E) stays **below the 5% usability bar for every
E ≤ 128**, so the FP-crossover `E*_FP(174)` lies beyond the swept range entirely; and
`E*_FP(174) / E*_FP(94) ≥ 8`, point estimate **25–40×**. If that holds, the sentence in `tier1.rs` —
*"because a 94-bit in-frame filter is tested against E registered masks … past ~8–32 prefixes a relay
wants a filter whose FP does not climb with E"* — is a property of the width we ship **by accident**,
not of the design, and must be rewritten. I additionally predict that on this realistic deep-name
corpus the 94-bit arm will be **worse** than P5(c)'s on-air 94-bit curve at every E ≥ 2 (deeper names
set more bits), with `E*_FP(94)` landing at **E ≈ 4–8** rather than P5(c)'s 64. **Refuted** if FP(174)
crosses 5% at any E ≤ 128, or if the ratio is < 4, or if the deep corpus does not move the 94-bit
curve upward.

*(b) The cost half — and this is the half I expect to survive.* I predict the COST crossover does
**not** move with width the way the FP crossover does: `E*_net(174) ∈ [0.5×, 1.5×] × E*_net(126)`,
because the wide filter's per-mask AND costs roughly 1.5–2× more (three or four 64-bit words plus the
popcount test, versus two) while its FP saving is already near-saturated and cannot buy much more.
**Refuted** if `E*_net(174)` lands outside that band in either direction.

**If both halves of H4 hold, the honest conclusion is that width fixes Tier-0's *discrimination* but
not its *O(E) work*, and Tier-1's justification MOVES — from "FP climbs with E" to "mask ANDs climb
with E" — rather than disappearing.** That is the outcome I currently think most likely, and it is
written here so that it can fail. If instead `E*_net(174)` is far larger than `E*_net(126)`, H4(b) is
refuted and Tier-1's case is genuinely weaker than the project has been claiming; if `E*_net` is
small at every width, the filter does not pay at relay scale at ANY width and §10 applies.

---

## 7. Method

### 7.1 Production code, borrowed corpus

The harness is a new example, `crates/faces/ndn-phy-wifi/examples/filter_cost_benefit.rs`. It

* **reuses `examples/name_filter_eval.rs`'s corpus generator unmodified** (Zipf-popular namespace
  roots, deep versioned/segmented names at modal depth ~10, FIB/PIT/CS registration sets — explicitly
  "not the toy disjoint names"), at a **pinned seed committed in this document: `seed = 1`**, extended
  only in one parameter — `ROOTS` raised from 32 to 256 so that E = 128 registrations can be drawn
  without exhausting the namespace. No other change to the generator, so the traffic cannot be tuned
  to the result;
* but drives the **production filter code**, not the harness's own reimplementation:
  `tier0::PrefixFilter`, `tier0::WideBlur<N>`, `tier0::positions_m`, `ndn_nic::NdnNicFilter`,
  `tier1::Tier1`, and the real `NameGate::admits_wide` decision path. A cost-benefit claim about the
  shipped design that runs a lookalike Bloom filter is not a claim about the shipped design.

P5(c) used toy `/p<i>/<seq>` names at depth 2. Realistic depth is the point of using this corpus, and
it is expected to move the curve — H4(a) commits to the direction.

### 7.2 The lesson P5(c) paid for: never anchor on one prefix

P5(c)'s pre-registered independence prediction was REFUTED because it anchored `FP(1)` on a single
prefix, `/p0`, that turned out to be a 16× low outlier. This campaign does not repeat that:

* every (E, w) cell is the mean over **R = 32 independent registration draws**, each drawing E
  prefixes from the FIB in Zipf-popularity order with an independent offset;
* the **per-prefix FP distribution** (min, p50, mean, p99, max over all registered prefixes) is
  reported at every width, so heterogeneity is visible rather than inferred;
* p̄(w) is fitted from the large-E cells, which P5(c) showed is the stable estimator, and the fit is
  reported alongside the direct measurement.

### 7.3 CPU measurement

One host, named in the results with its CPU model and the `rustc`/opt-level used. `--release`.
`black_box` on every input and output. Medians of ≥ 10⁵ iterations, p50 and p99 both reported.
`C_parse` and `C_filter` are measured **interleaved** in the same process and the same loop nest, so
a thermal or frequency excursion hits both terms rather than one. A run whose `C_parse` p99/p50 ratio
exceeds 3 is discarded as noise-dominated and re-run — that bar is set **here**, before any timing
exists.

### 7.4 Freshness / silent-zero guard (P5(c)'s rule, carried forward)

Every CSV carries N per cell, the corpus seed, the corpus name count, and the number of masks after
`coverage_antichain`. A cell with N = 0, or `|masks|` = 0 where E > 0, or FP exactly 0 across every
draw at a width where the model predicts a nonzero rate, is **instrument-invalid** and is re-run — not
reported as a win.

---

## 8. Pre-named thresholds, and what is a MEASUREMENT with no bar

### 8.1 Pass / fail (fixed here, before the run)

| # | bar | refutation |
|---|---|---|
| T1 | **FN = 0** at every width, every E, every draw, every frame — including base-sender→wide-receiver and the `FILL_CAP` path | any FN ≥ 1 ⇒ H1 refuted, campaign stops, lab property first |
| T2 | every H2 ratio inside its committed band (§6) | outside ⇒ H2 refuted for that pair, reported as such |
| T3 | `E*_net(94)` and `E*_net(126)` inside 32…128 at the measured ρ | outside ⇒ H3 refuted (in either direction) |
| T4 | FP(174, E) < 5% for all E ≤ 128, **and** `E*_FP(174)/E*_FP(94) ≥ 4` | either fails ⇒ H4(a) refuted |
| T5 | `E*_net(174) ∈ [0.5, 1.5] × E*_net(126)` | outside ⇒ H4(b) refuted |
| T6 | the two algebraic forms of `Net` in §5.1 agree to within floating-point tolerance | disagreement ⇒ harness bug, run void |
| T7 | base header 24 B, wide header 36 B, asserted by a length test | mismatch ⇒ the +12 B figure is wrong and every wide row is re-derived |

### 8.2 Reported as MEASUREMENTS, with no pass/fail bar

Following P5(c), which reported its crossover without a directional pre-commitment:

* **`E*_net(w)`** — the net-benefit crossover per width, and **`E*_net(w, ρ)` as a curve over
  ρ ∈ [1, 10⁴]**, so a reader on a different CPU (or on the LR2021/nRF54L15 firmware target, where
  this campaign cannot measure) can read off their own crossover instead of inheriting this host's.
  This is the single most important guard against the result depending on one machine.
* **`E*_FP(w)`** — the 5%-bar crossover per width.
* **ρ = C_parse / c_AND** as measured, with p50 and p99.
* **`r(E)`** — the moving irrelevant-traffic ceiling, per E.
* **Base-region popcount distribution** per width and depth, and whether `FILL_CAP` ever fired.
* **Receiver state**: bytes of masks per (E, w), `NdnNicFilter::table_bytes()`, `Tier1` table bytes.
* **`|masks|` vs E** after `coverage_antichain`.
* **+12 B/frame** on every 174 and 190 row.

---

## 9. Confounders and threats to validity — named before the run

* **C1 — Name-distribution dependence.** FP is a function of the name distribution at least as much
  as of the filter. `tier0.rs` records that at m = 94 two independent harnesses disagreed on the
  k = 4..8 ordering *because the name distribution was dominating*. Mitigation: one fixed corpus at a
  committed seed across every arm, so the distribution cancels in every cross-arm comparison; all H2
  predictions stated as ratios, not absolutes; absolutes reported but never compared to P5(c)'s
  on-air absolutes as if they were the same measurement (they are not — different names).
* **C2 — Per-prefix heterogeneity.** The documented phenomenon that one prefix can carry most of a
  width's FP (P5(c): `/p1` alone contributed ~0.8%). Mitigation: R = 32 draws + the full per-prefix
  distribution reported (§7.2). This is the confounder that refuted the last campaign's prediction; it
  is the one being designed against hardest.
* **C3 — Layer independence.** The whole wide-width case rests on the extra region being an
  *independent* projection (`EXTRA_DOMAIN`-separated key) so combined FP ≈ p̄_base × p̄_extra. If the
  two regions are correlated, H2's 174/126 ratio blows past its band. That is exactly why H2 has a
  band and why a ratio ≥ 1 is called out as a construction defect rather than a null result. The
  campaign reports p̄_base, p̄_extra and p̄_combined **separately** so the independence assumption is
  visible, not assumed.
* **C4 — k is not re-derived per width.** k = 4 was measured at m = 126 (200 names / 400 000 trials).
  It is held at 4 for EVERY width here, including 94, 174 and 190, because changing two variables at
  once would make the width comparison uninterpretable. Consequence, stated up front: the wide widths
  may be reported at a **sub-optimal k**, which biases against them. A per-width k sweep is separate
  work and is NOT done here. Declared, not silently absorbed.
* **C5 — Hash choice.** All widths use the same `siphash24`-under-`GroupKey` pipeline with
  Kirsch–Mitzenmacher double hashing. `tier0.rs` records that splitting one hash instead of using two
  independent keyed evaluations measured 1.3–3.4× worse; that trap is avoided by using the production
  `positions_m` unmodified. But the double-hash construction does correlate positions in small m —
  which is why the measured base FP (0.559% at m = 126) sits ~2× above the naive independence model,
  and why H2's bands are wide.
* **C6 — CPU measurement noise.** Handled by §7.3 (interleaved timing, medians, a pre-set p99/p50
  discard bar) and neutralised as a *conclusion* dependency by reporting `E*_net(ρ)` as a curve.
* **C7 — `coverage_antichain` dedup.** The registered set is deduped before masks are built, so
  `|masks|` can be < E and the cost is `O(|masks|)`, not `O(E)`. Reported explicitly; using E in the
  cost would overstate it, and this is the kind of unmeasured number the house rules forbid.
* **C8 — The wide arms are conditional.** 174 and 190 are measurements of a profile with zero
  production call sites and no recorded on-air survival result. Every conclusion at those widths
  carries that condition in the same sentence, every time.

---

## 10. Reporting rule — what gets reported regardless of outcome

1. **Every cell of the sweep**: five widths × eight E × {FP with Wilson 95% CI, FN, r(E), |masks|,
   C_filter p50/p99, Net}, plus ndn-nic, tier1 and the no-filter control. No arm dropped, no best-of,
   no re-run to get a nicer number. A re-run happens only under the §7.4 instrument-invalid rule or
   the §7.3 noise bar, and every re-run is stated.
2. **Each of H1–H4 marked CONFIRMED or REFUTED against its §8.1 bar, by name**, with the number that
   decided it. A refuted prediction reported honestly is worth more than a confirmed one; P5(c)'s
   most valuable line was its refutation, and this document expects to produce at least one.
3. **Both algebraic forms of `Net`**, so the reader can check the equation was not quietly changed
   after the fact.
4. **The +12 B/frame wide-header cost** printed alongside every 174/190 row, and the 0 B on every
   94/126/142 row.
5. **The §3 "does NOT cover" list, restated in the results**, so no reader takes an offline FP win as
   an on-air fact — particularly the unmeasured survival of `addr4`, HT Control and `Duration/ID`.
6. **The bias directions**: excluding wake/DMA biases against the filter; holding k = 4 at every
   width biases against the wide widths; excluding airtime biases *for* the wide widths. All three
   stated with the verdict, not in a footnote.
7. **If the design does not pay, that is the finding and it is the headline.** If `Net(E, w) ≤ 0`
   across the useful range of E at every width, the conclusion written here in advance is: *Tier-0's
   in-frame filter does not earn its receiver-side work on this traffic, and the correct action is to
   delete it, not to widen it.* If it pays only at small E, the conclusion is that Tier-0 is an
   endpoint mechanism and calling it a MAC-layer primitive overstates it. If it pays at every E at the
   designed width, then §2.1's finding — that the project has been shipping and measuring the wrong
   width — is the headline instead, and `tier1.rs`'s justifying sentence gets rewritten against
   measured numbers rather than remembered ones.
8. **Non-goal, stated so it cannot become a quiet goal:** this campaign does not wire
   `with_wide_bloom` into anything. Its zero call sites are a finding, not a task list; wiring it is
   separate work, gated on the on-air result that §3.1 says does not exist yet.

---

## 11. Deliverables

* `crates/faces/ndn-phy-wifi/examples/filter_cost_benefit.rs` — the harness (does not exist yet; its
  absence at commit time is part of the gate rule).
* `crates/faces/ndn-phy-wifi/docs/data/name-filter/p7-fp.csv`, `p7-cost.csv`,
  `p7-crossover-vs-rho.csv`, `p7-per-prefix.csv`.
* A `## RESULTS` section appended to **this file**, in the P5(c) style: the tables, each claim marked
  against its bar, the refutations first.
