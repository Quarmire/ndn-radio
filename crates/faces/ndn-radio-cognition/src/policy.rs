//! The **decide** plane — `RadioPolicy::decide(name_ctx, medium) -> RadioPlan`.
//!
//! Measured-adaptive (not a static knob table): the inputs are what the forwarder
//! already knows about a named object (PIT fan-out, CCLF score, measured
//! re-Interest rate, pooled rank deficit) crossed with MRMC medium state
//! (per-radio RSSI, occupancy, residual). The single optimand is **airtime per
//! satisfied Interest over the demand set** — every choice (radio selection, rate,
//! redundancy, suppress) trades against it.
//!
//! Three resolved design points baked in here:
//! - **One plane, not two.** Suppress/relay is the same CCLF-style election; the
//!   actuators are just its widened output vocabulary.
//! - **Innovation-aware suppression** unifies CCLF (drop duplicate) and
//!   stop-at-rank-N (transmit only if it adds rank to a rank-deficient downstream).
//! - **Redundancy is ONE budget** sized from the residual left below each layer,
//!   discounted by macrodiversity receiver multiplicity, biased by the measured
//!   re-Interest rate (the real ARQ signal), targeting post-pooling rank deficit.
//!
//! Timescale separation (anti-oscillation): callers run `decide` at the per-Interest
//! cadence for rate/aggregation, but the slow inputs (residual, neighbor set) are
//! EWMA-smoothed in the sense bus and the demand record carries its own `ts_ms`, so
//! a fast decision never reads a slow signal as fresh-per-frame.

use crate::calibrate::{RateThresholds, STATIC_REQ_RSSI, STATIC_REQ_RSSI_SF, SfThresholds};
use crate::phy::{PhyDial, PhyHold};
use crate::plan::{
    AllocRole, Contention, DataPlaneConfig, LoraRate, RadioAllocation, RadioPlan, RateParams,
    TxParams, WifiRate,
};
use crate::sense::{MediumView, PhyMode, RadioCapability, RadioId, RadioKind};
use crate::strategy::RadioStrategy;
use std::sync::Arc;

/// Delivery **class** a name is permitted to reach.
///
/// ⚠ This is a CEILING granted by authority, never a wish carried in a frame. The distinction is
/// the whole design: a class that a sender can simply assert is the DiffServ/802.11e failure — the
/// marking is free, so everyone marks everything urgent and the field stops meaning anything. It is
/// also unverifiable state below the network layer, which fails the §7 test in
/// `ndn-phy-wifi/docs/mac-addressing-doctrine.md`: L2 would be holding something the forwarder
/// cannot recompile.
///
/// So a class is **derived, never asserted**, from two independent inputs that both always apply:
/// * an authority ([`ClassAuthority`]) says how high this NAME may go — the ceiling, this enum;
/// * measured demand ([`DemandRank`]) orders traffic WITHIN whatever ceiling it was granted.
///
/// They are not alternatives and neither substitutes for the other. A fully schematised deployment
/// still needs the rank, because ten prefixes all authorised `Urgent` still compete with each other
/// and the schema says nothing about which of them should go first right now. A deployment with no
/// authority at all still gets useful ordering from demand, capped at `Normal`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default, PartialOrd, Ord)]
pub enum Priority {
    /// Background bulk — favour throughput (high rate, aggregation).
    Bulk,
    #[default]
    Normal,
    /// Latency/robustness-critical — favour reach, may ignore EDCCA.
    Urgent,
}

impl Priority {
    /// Numeric rank (Bulk=0, Normal=1, Urgent=2) for context keying.
    pub fn rank(self) -> u8 {
        match self {
            Priority::Bulk => 0,
            Priority::Normal => 1,
            Priority::Urgent => 2,
        }
    }
}

/// The gate that decides how high a NAME may be classed.
///
/// A trust-schema / LVS evaluation implements this: "may the key that signed this name legitimately
/// claim this class?". There is deliberately **no blanket implementation and no default that returns
/// anything above [`Priority::Normal`]** — a deployment without a trust anchor cannot offer
/// authority-based classes, and the honest response is to say so rather than to offer them and hope
/// nobody lies.
///
/// The signature keys on `prefix_hash` — the compiled form of the name the radio already carries —
/// so an implementation CAN answer from the forwarder's own state with nothing host-shaped entering
/// L2. ⚠ It cannot *enforce* that: an implementor may close over anything, and the one
/// implementation in this tree (`examples/lora_cognition.rs`'s `NameTrusting`) ignores the hash
/// entirely. Implementations are therefore the thing to audit — which is the reason this is a named
/// trait rather than an `if` inside a parser. Grep for `impl ClassAuthority` to enumerate everything
/// a deployment has chosen to trust.
///
/// ⚠ It is also not a capability: a linked crate can write its own permissive impl in four lines.
/// The threat this closes is the REMOTE one — a peer buying priority by marking a frame — plus
/// accidental self-assertion, which was previously a one-line struct literal.
pub trait ClassAuthority {
    /// The highest class this name may reach. Returning more than the schema actually authorises is
    /// the one way to break the invariant, so implementations should fail CLOSED.
    fn ceiling_for(&self, prefix_hash: u64) -> Priority;
}

/// A class ceiling, which can only be **lowered** once held.
///
/// The type exists to make the invariant structural rather than a comment. Before this, `priority`
/// was a public field and `NameContext { priority: Priority::Urgent, .. }` compiled anywhere —
/// which is precisely the hole. Now the only route above `Normal` is [`ClassCeiling::authorised`],
/// which requires a [`ClassAuthority`], and the only operations afterwards are caps.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct ClassCeiling(Priority);

impl ClassCeiling {
    /// What every name gets without an authority to say otherwise: [`Priority::Normal`].
    ///
    /// This is a correct answer, not a degraded one — it is the defined bottom of the lattice.
    pub const fn unauthorised() -> Self {
        Self(Priority::Normal)
    }

    /// Ask an authority. **The only constructor that can exceed [`Priority::Normal`].**
    pub fn authorised(auth: &dyn ClassAuthority, prefix_hash: u64) -> Self {
        Self(auth.ceiling_for(prefix_hash))
    }

    /// Give up privilege. Available without permission — but only **down to `Normal`**.
    ///
    /// ☠ **`Bulk` is not "less than `Normal`", it is DIFFERENT, and that distinction cost a real
    /// hole.** The enum orders `Bulk < Normal < Urgent` as a *privilege* ladder, and the original
    /// rule ("lower never needs permission") read that ordering as if every step down were a
    /// renunciation. It is not: `Bulk` SELECTS behaviour rather than giving it up —
    ///
    /// * `phy::PhyDial` moves the link to the rate PHY on `wants_rate = matches!(p, Bulk)`;
    /// * `RadioPolicy` widens LoRa to 250 kHz on `Bulk` + a strong measured link.
    ///
    /// Both are **rendezvous parameters**, where a mismatch is deafness rather than slowness — the
    /// hazard the code comments at those two sites already name. So an unauthorised caller reaching
    /// `Bulk` through a "cap" was choosing the shared modulation and bandwidth for the link, and on
    /// the dial it was sticky for every later object because `PhyDial` holds shared state.
    ///
    /// The free direction is therefore toward `Normal` — the neutral point — not toward the bottom
    /// of the enum. Reaching `Bulk` needs an authority exactly as `Urgent` does. A ceiling an
    /// authority already placed at `Bulk` is preserved: this only refuses to *introduce* it.
    pub fn capped_to(self, at_most: Priority) -> Self {
        let floor = if at_most > Priority::Normal {
            at_most
        } else {
            Priority::Normal
        };
        Self(if self.0 < floor { self.0 } else { floor })
    }

    /// The class itself.
    pub const fn get(self) -> Priority {
        self.0
    }
}

/// Ordering **within** a class, measured rather than asserted.
///
/// Derived from what the network is actually asking for — PIT fan-out and the re-expression rate.
///
/// ⚠ **Abuse-resistant against a REMOTE peer, not against in-process code — an earlier version of
/// this doc overclaimed it.** `DemandTracker::on_interest(prefix_hash, downstream, ..)` takes a
/// caller-supplied downstream id that nothing checks, so ~200 fabricated ids drive the rank to 0.99
/// with no network at all — measured end to end through the public `RadioControl::on_interest`,
/// where the forged prefix then WON a contended radio. Making `with_demand` crate-private did not
/// change that; the surviving route is the tracker itself. What a rank costs a PEER on the air is
/// real; what it costs a linked crate is nothing — the same boundary [`ClassAuthority`] documents.
///
/// `0.0` = nobody is waiting; `1.0` = many downstreams, all still re-asking.
#[derive(Clone, Copy, Debug, PartialEq, PartialOrd, Default)]
pub struct DemandRank(f32);

impl DemandRank {
    /// Nothing is waiting on this name.
    pub const fn none() -> Self {
        Self(0.0)
    }

    /// Rank from measured demand.
    ///
    /// Two signals, deliberately combined rather than one: **fan-out** says how many downstreams
    /// want it, **re-expression** says they are not getting it. Fan-out alone would rank a
    /// widely-wanted-and-satisfied prefix above an urgent unsatisfied one; re-expression alone would
    /// rank one desperate downstream above fifty content ones. Fan-out saturates (`f/(1+f)`) because
    /// the difference between 1 and 2 downstreams matters far more than between 50 and 51.
    pub fn from_demand(d: &crate::sense::Demand) -> Self {
        let f = d.fanout as f32;
        let want = f / (1.0 + f);
        let miss = d.reinterest_rate.get().unwrap_or(0.0).clamp(0.0, 1.0);
        Self((0.5 * want + 0.5 * miss).clamp(0.0, 1.0))
    }

    /// The scalar, in `0.0..=1.0`.
    pub const fn get(self) -> f32 {
        self.0
    }
}

/// Name-derived context for one transmission decision.
#[derive(Clone, Copy, Debug)]
pub struct NameContext {
    /// Hash of the object's name-prefix (keys demand + consistency).
    pub prefix_hash: u64,
    /// PRIVATE on purpose: see [`Priority`]. Reachable only through [`NameContext::priority`],
    /// settable only from a [`ClassCeiling`], and afterwards only ever lowered.
    ceiling: ClassCeiling,
    /// Measured ordering within [`Self::ceiling`]. Also private: it is a measurement, and a caller
    /// that could write it could forge demand it never observed.
    demand: DemandRank,
    /// Are we the producer/origin (always transmit) vs a relay (innovation-gated)?
    pub is_origin: bool,
    /// Coding generation this object belongs to, if any (enables Split allocation).
    pub generation: Option<u32>,
}

impl NameContext {
    /// We are the origin/producer of this object (always transmit).
    pub fn new(prefix_hash: u64) -> Self {
        Self {
            prefix_hash,
            ceiling: ClassCeiling::unauthorised(),
            demand: DemandRank::none(),
            is_origin: true,
            generation: None,
        }
    }

    /// We are relaying this object for downstream demand (innovation-gated by the
    /// suppress predicate). This is what PIT-driven demand produces.
    pub fn relayed(prefix_hash: u64) -> Self {
        Self {
            prefix_hash,
            ceiling: ClassCeiling::unauthorised(),
            demand: DemandRank::none(),
            is_origin: false,
            generation: None,
        }
    }

    /// The class this name was GRANTED. `Normal` unless an authority said otherwise.
    pub const fn priority(&self) -> Priority {
        self.ceiling.get()
    }

    /// Measured ordering within the class.
    pub const fn demand_rank(&self) -> DemandRank {
        self.demand
    }

    /// Attach an authority's verdict. The only route above `Normal`.
    pub fn with_ceiling(mut self, ceiling: ClassCeiling) -> Self {
        self.ceiling = ceiling;
        self
    }

    /// Attach measured demand. **Crate-private: only [`DemandTracker`](crate::DemandTracker) may
    /// attach a rank**, because the tracker is where the measurement lives.
    ///
    /// The `demand` field has always been private with the right comment on it — "it is a
    /// measurement, and a caller that could write it could forge demand it never observed" — and a
    /// `pub` setter beside it contradicted that comment. `Demand` itself is publicly constructible
    /// (it is the sense-bus record, `Copy`, all-public-fields, pushed across the face boundary in
    /// both directions), so `DemandRank::from_demand(&Demand { fanout: u32::MAX, .. })` yields a
    /// free `1.0`, and `decide_all` now SORTS competing objects by `(class, then rank)` before
    /// last-writer-wins picks the radio.
    ///
    /// ⚠ **Billed as a CONSISTENCY fix, not a security fix**, and for a stricter reason than usual:
    /// forged and measured ranks provably never coexist in one active set today.
    /// `RadioControl::tick_now` is strictly either/or — the tracker's contexts if it has any, the
    /// manually-set ones otherwise — so on a node with live PIT demand the manual path is dead
    /// code, and on a node without it the whole active set belongs to one caller who is only
    /// reordering their own objects. Three further bounds hold independently: class dominates the
    /// sort, `from_demand` clamps to `0.0..=1.0` so a forgery can tie but never exceed a genuinely
    /// maximal rank, and `demand_rank()` has exactly ONE consumer in the tree (that sort).
    ///
    /// What it buys is that the seam cannot BECOME one. The moment anyone writes a producer that
    /// merges contexts from more than one origin — a FIB-backed source alongside PIT demand, a
    /// second face's contexts — a forged rank would start beating a measured one silently, and the
    /// merge point would not look like the place a rule was broken. Crate-private now means that
    /// future producer has to route through `DemandTracker`.
    ///
    /// ⚠ It is also NOT the biggest forgeable surface here, and closing it does not claim to be:
    /// `RadioControl::observe_demand` is `pub` and writes a caller's `Demand` straight into the
    /// sense bus, from where it reaches `effective_receivers` (the broad-vs-unicast MCS split) and
    /// the FEC parity budget — real decisions, not just ordering. That is the sense bus's stated
    /// contract (push-fed by the trusted host) and is left alone deliberately.
    pub(crate) fn with_demand(mut self, demand: DemandRank) -> Self {
        self.demand = demand;
        self
    }

    /// ★ **Lower, never raise** — the rule every cross-node input obeys.
    ///
    /// This is the invariant `ReceptionReport` already embodies and the reason it is safe: a
    /// neighbour advertising `max_rx_mcs` can only make a sender back OFF. A neighbour able to
    /// RAISE our class would be able to buy privilege by lying, and lying would be free. So
    /// anything learned from a peer arrives here, and there is deliberately no inverse.
    pub fn capped_by(mut self, at_most: Priority) -> Self {
        self.ceiling = self.ceiling.capped_to(at_most);
        self
    }
}

/// Tunables for the policy (all measured-adaptive thresholds, not per-feature knobs).
#[derive(Clone, Copy, Debug)]
pub struct PolicyConfig {
    /// Receiver count above which an object is treated as a broad broadcast
    /// (robust low-MCS) rather than near-unicast (high-MCS).
    pub broad_receivers: usize,
    /// Coding generation size `k` the budget sizes parity against.
    pub generation_k: u16,
    /// Replicate across a second radio when post-pooling rank deficit exceeds this.
    pub replicate_deficit: f32,
    /// Default channel busy% above which we prefer a clearer channel / narrow BW.
    pub busy_high: u8,
    /// Emit TX-diversity (CSD / STBC) on weak 1-stream links. **Default off**: on
    /// the RTL8812EU userspace TX path both antenna-B diversity paths are fragile —
    /// they stalled the USB transfer on-air when combined with live actuator
    /// reconfiguration — and their small diversity gain is dominated by LDPC (~2 dB,
    /// always on for robust frames) + rate reduction, which are reliable. Opt in
    /// only where the diversity path is proven.
    pub enable_tx_diversity: bool,
}

impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            broad_receivers: 3,
            generation_k: 8,
            replicate_deficit: 1.0,
            busy_high: 50,
            enable_tx_diversity: false,
        }
    }
}

/// Why a [`RadioPlan`] came out the way it did — the inputs [`RadioPolicy::decide`]
/// read and the key intermediate choices, as plain data. Returned alongside the
/// plan by [`RadioPolicy::decide_traced`] so an observer (the face) can render the
/// decision's *why* to a trace span, while this pure crate stays sans-IO (no
/// tracing/OpenTelemetry dependency — observability is computed as a value here and
/// rendered at the I/O boundary).
#[derive(Clone, Debug, Default, PartialEq)]
pub struct DecisionRationale {
    /// This node originates the content (always transmits — it IS the rank).
    pub is_origin: bool,
    /// Live PIT/demand existed for the prefix (vs the manual active set).
    pub had_demand: bool,
    /// Effective wanted-receiver count driving diversity/redundancy.
    pub receivers: usize,
    /// Neighbours already holding the content (the CCLF suppression input).
    pub holders: usize,
    /// Post-pooling rank deficit — the core "does transmitting add rank?" quantity.
    pub deficit: f32,
    /// Broadcast regime (receivers ≥ threshold) → robust defaults.
    pub broad: bool,
    /// A second radio replicates for diversity (deficit ≥ threshold, ≥2 radios).
    pub replicate: bool,
    /// Set when the plan is a suppression, with the reason it stayed quiet.
    pub suppress: Option<SuppressReason>,
    /// Per chosen radio: the measured inputs behind its allocation.
    pub radios: Vec<RadioRationale>,
}

/// Why a decision suppressed rather than transmitted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SuppressReason {
    /// A relay whose transmission would add no rank downstream (CCLF ∪ stop-at-rank-N).
    RelayAddsNoRank,
    /// No TX-capable radio with a channel and remaining duty budget was available.
    NoTxRadio,
}

/// The measured inputs behind one radio's allocation — the "why this radio, this
/// channel, this rate" a trace consumer needs.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct RadioRationale {
    pub radio: RadioId,
    /// Capability-fit score that ranked this radio (higher = preferred).
    pub score: f32,
    /// Chosen channel (the least-busy one this radio offers).
    pub channel: Option<u8>,
    /// Sensed busy% of the chosen channel — the frame-free occupancy input (#30).
    pub channel_busy_pct: Option<u8>,
    /// Weakest wanted-receiver RSSI (dBm) driving the MCS + power pick.
    pub rssi_dbm: Option<i8>,
    /// The modulation this allocation names, if the PHY axis is in play (`None` = the radio's
    /// current mode is left alone).
    pub phy: Option<PhyMode>,
    /// Why the modulation dial is where it is — a switch, or which brake held it.
    pub phy_hold: Option<PhyHold>,
    // Tombstone: `link_per` removed with its always-empty sensor (`LinkResidual::link_per`).
    /// Replicate vs Split role of this allocation.
    pub role: AllocRole,
}

pub struct RadioPolicy {
    cfg: PolicyConfig,
    /// Learned per-MCS RSSI thresholds (shared with a [`crate::RateCalibrator`]).
    /// `None` ⇒ use the static preset.
    learned: Option<RateThresholds>,
    /// Learned per-SF operating thresholds for LoRa (shared with a [`crate::SfCalibrator`]).
    /// `None` ⇒ use the static preset.
    learned_sf: Option<SfThresholds>,
    /// The **modulation dial** ([`PhyDial`]) — the hysteresis behind the PHY axis, shared so its
    /// state (current mode, confirmation count, cool-down, failed-excursion penalty) survives
    /// across decisions. `None` ⇒ no PHY is ever decided and every plan leaves the radio's
    /// modulation untouched, which is the behaviour of every caller that predates this axis.
    phy_dial: Option<Arc<PhyDial>>,
}

impl Default for RadioPolicy {
    fn default() -> Self {
        Self::new(PolicyConfig::default())
    }
}

impl RadioPolicy {
    pub fn new(cfg: PolicyConfig) -> Self {
        Self {
            cfg,
            learned: None,
            learned_sf: None,
            phy_dial: None,
        }
    }

    /// Drive rate selection from a learned, online-calibrated threshold cell
    /// instead of the static preset.
    pub fn with_learned_thresholds(mut self, thresholds: RateThresholds) -> Self {
        self.learned = Some(thresholds);
        self
    }

    /// Drive LoRa spreading-factor selection from a learned threshold cell (shared with a
    /// [`crate::SfCalibrator`]) instead of the static preset.
    pub fn with_learned_sf_thresholds(mut self, thresholds: SfThresholds) -> Self {
        self.learned_sf = Some(thresholds);
        self
    }

    /// **Decide the modulation too** — attach the [`PhyDial`] that owns the PHY axis.
    ///
    /// Without it the policy decides SF/CR/BW/power exactly as before and never names a
    /// modulation, so attaching this is the whole opt-in. Share ONE dial per radio: its state
    /// *is* the hysteresis (confirmation count, cool-down, failed-excursion penalty), and a
    /// dial rebuilt per decision would have none.
    pub fn with_phy_dial(mut self, dial: Arc<PhyDial>) -> Self {
        self.phy_dial = Some(dial);
        self
    }

    /// The attached dial, for a caller that wants to read the committed mode or the hold reason.
    pub fn phy_dial(&self) -> Option<&Arc<PhyDial>> {
        self.phy_dial.as_ref()
    }

    /// The **anchor** the PHY dial states its crossover against: the operating threshold of the
    /// reach modulation's *fastest* rung (SF7), learned if a calibrator is attached.
    ///
    /// Stated as a relation to this ladder rather than as an absolute FLRC sensitivity because
    /// this ladder is the one this crate actually measures and calibrates — and nobody here has
    /// measured an FLRC threshold. See [`PhyDial`] on why that matters.
    fn phy_anchor_dbm(&self) -> f32 {
        match &self.learned_sf {
            Some(cell) => cell.read().unwrap()[7],
            None => STATIC_REQ_RSSI_SF[7],
        }
    }

    /// Ask the dial for this radio's modulation. `None` (no dial, nothing advertised, or a
    /// radio whose offer holds fewer than two rankable modes) ⇒ the plan names no mode and the
    /// radio stays where it is.
    fn decide_phy(
        &self,
        radio: RadioId,
        cap: &RadioCapability,
        ctx: &NameContext,
        view: &dyn MediumView,
        now_ms: u64,
    ) -> Option<PhyMode> {
        let dial = self.phy_dial.as_ref()?;
        dial.evaluate(
            // The radio's own words: what it advertises and what it says it is running. An
            // empty set means "it has not said", and the dial then names nothing.
            cap.phy_modes,
            cap.phy_current,
            // The MEASURED weakest receiver, never `demand_set_rssi`'s proxy fallback: a
            // modulation is a rendezvous parameter of the strongest kind (a mismatch is
            // deafness, not slowness), so it moves only on a number both ends can see.
            view.weakest_rssi(radio, now_ms),
            self.phy_anchor_dbm(),
            ctx,
            // Heard peers, not wanted receivers: the peer-silence escape hatch asks "did anyone
            // follow us", which only reception can answer.
            view.receiver_count(now_ms) > 0,
            now_ms,
        )
        .0
    }

    /// Highest MCS the current thresholds allow at `rssi` (learned if present), capped by the
    /// demodulation floor implied by `snr_db` when the radio reports one.
    ///
    /// `snr_db = None` reproduces the RSSI-only behaviour exactly.
    fn pick_mcs(&self, rssi: Option<i8>, snr_db: Option<f32>, max_mcs: u8) -> u8 {
        let r = rssi.unwrap_or(-90);
        let t = match &self.learned {
            Some(cell) => *cell.read().unwrap(),
            None => STATIC_REQ_RSSI,
        };
        crate::calibrate::pick_mcs_snr(r, snr_db, max_mcs, &t)
    }

    /// Fastest LoRa spreading factor the current thresholds allow at `rssi` (learned if present).
    fn pick_sf(&self, rssi: i8) -> u8 {
        let t = match &self.learned_sf {
            Some(cell) => *cell.read().unwrap(),
            None => STATIC_REQ_RSSI_SF,
        };
        crate::calibrate::pick_sf(rssi, &t)
    }

    /// The closed loop. Reads demand + MRMC medium state, emits a multi-radio plan
    /// optimizing airtime-per-satisfied-Interest, made cross-node-consistent. This
    /// is the [`RadioStrategy::decide`] implementation; kept inherent too for direct
    /// (monomorphized) use in tests/harness.
    ///
    /// [`RadioStrategy::decide`]: crate::RadioStrategy::decide
    pub fn decide(&self, ctx: &NameContext, view: &dyn MediumView, now_ms: u64) -> RadioPlan {
        self.decide_traced(ctx, view, now_ms).0
    }

    /// Decide the data-centric offload for a face from its capability — the face-level companion to
    /// per-object [`decide`](Self::decide). On a duty-limited broadcast bearer (LoRa sub-GHz, HaLow,
    /// BLE) airtime is THE scarce resource, so both mechanisms earn their keep: dedup keeps a repeated
    /// name off the host link, and CS-serve answers a repeat Interest locally (one hop) instead of
    /// re-fetching it end-to-end — the airtime-per-satisfied-Interest win a flood mesh can't make.
    /// Name-keyed *firmware* hopping is left OFF until the firmware carries its own common-view clock;
    /// the firmware carries the hop function regardless. (#41's clock landed host-side as
    /// `ndn_time::RadioHwClock`, and the host monitor-wifi face already actuates FHSS from it via
    /// `FaceScheduler`/`NDN_SCHED_HOP` — a separate path from this firmware flag.) Mains-powered
    /// always-on Wi-Fi (`duty_cycle_max`
    /// == 1.0, monitor) stays conservative — its host PIT/CS already dedups and airtime is cheap.
    pub fn data_plane(&self, cap: &RadioCapability) -> DataPlaneConfig {
        let duty_limited_broadcast = matches!(
            cap.kind,
            RadioKind::Lora | RadioKind::WifiHaLow | RadioKind::Ble
        ) || cap.duty_cycle_max < 1.0;
        DataPlaneConfig {
            dedup: duty_limited_broadcast,
            cs_serve: duty_limited_broadcast,
            // Still gated on #41 for the FIRMWARE path (its `hop_channel` needs a common-view
            // clock the MCU does not carry). The radio-sequencer path — a name-derived
            // `(carrier, period)` table written with `RadioKnobs::set_hop_plan` — is a separate
            // actuator that needs no such clock, and is installed per face rather than toggled
            // here. See `crate::name_hop_plan`.
            hop: false,
        }
    }

    /// [`decide`](Self::decide) plus a [`DecisionRationale`] — the inputs read and
    /// the key intermediate choices, so an observer can render *why* the plan came
    /// out this way to a trace span. Pure: the rationale is data, not a side effect.
    pub fn decide_traced(
        &self,
        ctx: &NameContext,
        view: &dyn MediumView,
        now_ms: u64,
    ) -> (RadioPlan, DecisionRationale) {
        let demand = view.demand(ctx.prefix_hash);
        let receivers = self.effective_receivers(ctx, view, now_ms);
        let holders = view.neighbors_holding(ctx.prefix_hash, now_ms);
        let deficit = demand
            .map(|d| d.rank_deficit.get_or(receivers as f32))
            .unwrap_or(receivers as f32);
        let mut why = DecisionRationale {
            is_origin: ctx.is_origin,
            had_demand: demand.is_some(),
            receivers,
            holders,
            deficit,
            ..Default::default()
        };

        // --- Innovation-aware suppression (CCLF ∪ stop-at-rank-N) ---
        // A relay stays quiet unless its transmission adds rank to a downstream
        // that still needs it: deficit must be positive AND not already covered by
        // neighbors holding it. The origin always transmits (it IS the rank).
        if !ctx.is_origin {
            let adds_rank = deficit > f32::EPSILON && holders < receivers.max(1);
            if !adds_rank {
                why.suppress = Some(SuppressReason::RelayAddsNoRank);
                return (RadioPlan::suppressed(self.consistency(ctx, &[], 0)), why);
            }
        }

        // --- Radio selection (MRMC: by capability fit to the demand) ---
        let mut tx: Vec<(RadioId, RadioCapability)> = view
            .radios()
            .into_iter()
            .filter(|(id, c)| {
                // TX-capable, has a channel, and hasn't spent its duty-cycle budget (fail-closed:
                // a sub-GHz radio over its ~1% ceiling drops out, so the packet waits rather than
                // breaking the regulatory limit; Wi-Fi's duty_cycle_max = 1.0 never trips).
                !c.rx_only
                    && !c.channels.is_empty()
                    && view.duty_used(*id, now_ms) < c.duty_cycle_max
            })
            .collect();
        if tx.is_empty() {
            why.suppress = Some(SuppressReason::NoTxRadio);
            return (RadioPlan::suppressed(self.consistency(ctx, &[], 0)), why);
        }
        let broad = receivers >= self.cfg.broad_receivers;
        tx.sort_by(|(_, a), (_, b)| {
            self.radio_score(b, ctx, broad)
                .total_cmp(&self.radio_score(a, ctx, broad))
        });

        // Primary radio always; a second radio replicates (diversity) when the post-pooling deficit is
        // high and a TX-capable alternative exists. Replication SPENDS the second radio's airtime/duty
        // budget, so it is gated on a REAL *measured* rank deficit — NOT on `deficit`'s receiver-count
        // fallback (that fallback exists so the suppression gate above assumes work when nothing is
        // measured; reusing it here made replicate fire on every multi-radio TX, `receivers >= 1`).
        // Absent a diversity signal replication stays off; once a pooling producer feeds
        // `observe_rank_deficit` it engages as designed (decided-but-unactuated until that producer exists).
        let measured_deficit = demand.and_then(|d| d.rank_deficit.get());
        let replicate =
            measured_deficit.is_some_and(|md| md >= self.cfg.replicate_deficit) && tx.len() >= 2;
        let chosen = if replicate { 2 } else { 1 };
        why.broad = broad;
        why.replicate = replicate;

        let mut allocations = Vec::with_capacity(chosen);
        for (i, (radio, cap)) in tx.iter().take(chosen).enumerate() {
            let channel = self.pick_channel(*radio, cap, view);
            let params = self.tx_params(
                *radio, cap, ctx, view, receivers, broad, deficit, channel, now_ms,
            );
            // Heterogeneous + coded ⇒ second radio carries a distinct generation
            // subset (Split); otherwise it replicates the same content.
            let role = if i > 0 && ctx.generation.is_some() && cap.bands != tx[0].1.bands {
                AllocRole::Split
            } else {
                AllocRole::Replicate
            };
            // The inputs behind this allocation, for the trace (same view the
            // params were computed from, so the "why" is faithful).
            why.radios.push(RadioRationale {
                radio: *radio,
                score: self.radio_score(cap, ctx, broad),
                channel,
                channel_busy_pct: channel.and_then(|ch| view.busy_pct(*radio, ch)),
                rssi_dbm: self.demand_set_rssi(*radio, view, now_ms),
                // Read back off the params rather than re-asking the dial: a second `evaluate`
                // would advance the confirmation counter and make the trace itself change the
                // decision it is reporting on.
                phy: params.phy,
                phy_hold: self.phy_dial.as_ref().map(|d| d.last_hold()),
                role,
            });
            allocations.push(RadioAllocation {
                radio: *radio,
                channel,
                params,
                role,
            });
        }

        let objective = self.estimate_objective(&allocations, receivers.max(1));
        let consistency = self.consistency(ctx, &allocations, receivers);
        (
            RadioPlan {
                relay: !ctx.is_origin,
                suppress: false,
                allocations,
                objective,
                consistency,
            },
            why,
        )
    }

    // --- effective demand-set size ---
    fn effective_receivers(&self, ctx: &NameContext, view: &dyn MediumView, now_ms: u64) -> usize {
        let fanout = view
            .demand(ctx.prefix_hash)
            .map(|d| d.fanout as usize)
            .unwrap_or(0);
        fanout.max(view.receiver_count(now_ms))
    }

    // --- radio capability fit ---
    fn radio_score(&self, cap: &RadioCapability, ctx: &NameContext, broad: bool) -> f32 {
        // Normalized reach vs rate (both 0..1) so the weighting, not the raw scale,
        // decides. Bulk wants rate; urgent/broad wants reach. Sub-GHz scores high on
        // reach, Wi-Fi high on rate — the homogeneous/heterogeneous switch falls out
        // of the descriptor, no special-casing.
        let reach = cap.range_rank() as f32 / 4.0;
        let rate = cap.rate_rank(); // bearer-agnostic peak-throughput rank
        let (w_reach, w_rate) = match ctx.priority() {
            Priority::Bulk => (0.2, 1.0),
            Priority::Urgent => (1.0, 0.2),
            Priority::Normal if broad => (0.7, 0.5),
            Priority::Normal => (0.5, 0.7),
        };
        w_reach * reach + w_rate * rate
    }

    fn pick_channel(
        &self,
        radio: RadioId,
        cap: &RadioCapability,
        view: &dyn MediumView,
    ) -> Option<u8> {
        // Cognitive channel selection inline: least-busy channel this radio offers
        // (evidence-based when fed by an SDR PSD scan or a neighbour's shared map; coarse
        // CCA otherwise).
        //
        // §9.2: an UNSENSED channel — no local *and* no cooperative view (`busy_pct` now
        // fuses both) — is UNKNOWN, not clear. Treating it as 0 busy biased selection
        // toward channels we cannot see, and `multi_radio.rs` measured the harm: avoidance
        // moving a name ONTO an unseen busy channel. Rank unknown between sensed-clear and
        // sensed-busy, so we prefer known-clear and fall back to unknown only over
        // known-busy.
        const UNSENSED_BUSY: u8 = 50;
        cap.channels
            .iter()
            .min_by_key(|&&ch| view.busy_pct(radio, ch).unwrap_or(UNSENSED_BUSY))
            .copied()
    }

    #[allow(clippy::too_many_arguments)]
    fn tx_params(
        &self,
        radio: RadioId,
        cap: &RadioCapability,
        ctx: &NameContext,
        view: &dyn MediumView,
        receivers: usize,
        broad: bool,
        deficit: f32,
        channel: Option<u8>,
        now_ms: u64,
    ) -> TxParams {
        // LoRa-class radios have no Wi-Fi MCS/BW knobs; their reach/rate dial is the spreading
        // factor. Pick it from the same demand-set RSSI (with the broad/unicast margin) that drives
        // MCS below — a strong link runs low SF (fast), reach pressure runs high SF. Coding rate
        // rises for urgent/broadcast robustness.
        if cap.kind == RadioKind::Lora {
            let base = self.demand_set_rssi(radio, view, now_ms).unwrap_or(-105) as f32;
            let eff = if broad {
                base - BROAD_MARGIN_DB
            } else if receivers <= 1 {
                base + UNICAST_MARGIN_DB
            } else {
                base
            };
            // Clamp the pick to the radio's advertised SF span (from the capability, not a hardcode).
            let sf = self.pick_sf(eff.round().clamp(-128.0, 0.0) as i8);
            let sf = cap.sf_range().map_or(sf, |(lo, hi)| sf.clamp(lo, hi));
            let cr = if matches!(ctx.priority(), Priority::Urgent) || broad {
                2
            } else {
                1
            };
            // Bandwidth is a rendezvous parameter (both ends must match to decode), so it is dialed
            // ONLY from a REAL, shared measurement — the measured weakest RSSI, never the synthetic
            // proxy (which reads strong at low PER and would trip one end into 250 kHz while the other
            // stayed at 125, a decode split). Widen to 250 kHz for Bulk on a genuinely strong, non-
            // reach link: ~2× rate and half the airtime (duty relief) at ~3 dB less sensitivity, which
            // the margin affords. No measured peer ⇒ hold the 125 kHz reach default.
            let strong = !broad && view.weakest_rssi(radio, now_ms).is_some_and(|r| r >= -85);
            let bandwidth_khz = if matches!(ctx.priority(), Priority::Bulk) && strong {
                Some(250)
            } else {
                Some(125)
            };
            return TxParams {
                // The modulation itself — decided one level above SF, from the same measured
                // inputs, and constrained to what this radio advertised.
                phy: self.decide_phy(radio, cap, ctx, view, now_ms),
                rate: RateParams::Lora(LoraRate {
                    spreading_factor: Some(sf),
                    coding_rate: Some(cr),
                    bandwidth_khz,
                }),
                link_fec_redundancy: self
                    .fec_redundancy(radio, ctx, view, channel, receivers, deficit),
                // Minimum-sufficient power (spatial reuse) off the SF operating threshold, same
                // reciprocity as the Wi-Fi path — power is NOT a rendezvous parameter, so each end
                // sets its own freely. Dial off the REAL measured weakest RSSI (not the proxy), so it
                // holds the ceiling until a genuine peer margin is seen, then hands back the surplus.
                tx_power_dbm: self.decide_lora_power_dbm(cap, sf, view.weakest_rssi(radio, now_ms)),
                ..Default::default()
            };
        }

        let busy = channel.and_then(|ch| view.busy_pct(radio, ch)).unwrap_or(0);

        // Rate from RSSI — but the broad/unicast intent is expressed as an RSSI
        // *margin* so it goes through the (learned) thresholds too, rather than a
        // raw ±MCS bump that would bypass calibration. Broad broadcast provisions
        // for weaker/more listeners (margin down); a single good link pushes the
        // rate (margin up).
        let rssi = self.demand_set_rssi(radio, view, now_ms);
        let base = rssi.unwrap_or(-90) as f32;
        let eff = if broad {
            base - BROAD_MARGIN_DB
        } else if receivers <= 1 {
            base + UNICAST_MARGIN_DB
        } else {
            base
        };
        // Worst-overheard-receiver rate cap (doctrine §5): a listener that only brings up one RX
        // chain (e.g. the userspace RTL8812EU, `max_rx_mcs` = 7) cannot decode a 2-stream frame at
        // *any* index — so a neighbour advertising 1..=7 caps both the MCS ceiling and the stream
        // count, not just the MCS. `LEGACY_ONLY_RX` (0) is out of band (the legacy-rate gate handles
        // it); `None`/`FULL_RX_MCS` leave the radio's own ceiling. Without this, cognition happily
        // picks a 2-stream MCS the neighbour can never decode (measured: MCS 9 → a one-way link).
        let neighbor_rx = view.worst_neighbor_rx_mcs(now_ms);
        let mcs_ceiling = match neighbor_rx {
            Some(c) if c >= 1 => cap.max_mcs().min(c),
            _ => cap.max_mcs(),
        };
        let neighbor_single_stream = matches!(neighbor_rx, Some(c) if (1..=crate::report::SINGLE_STREAM_HT_RX_MCS).contains(&c));
        // SNR of the weakest fresh receiver, when the radio reports it: caps the RSSI-chosen rate
        // at what the modulation can actually demodulate. A loud-but-dirty link (contention) reads
        // as strong to RSSI alone, and this is the only input that sees it.
        let snr = view.weakest_snr_db(radio, now_ms);
        let mcs = self.pick_mcs(Some(eff.round().clamp(-110.0, 0.0) as i8), snr, mcs_ceiling);

        // Bandwidth: capability ceiling, narrowed under contention.
        //
        // ☠ This was `bw = bw.saturating_sub(1)` on the raw code. `Bandwidth::code()` is a wire
        // encoding and is NOT ordered by width — `Nb10=3, Nb5=4` sort ABOVE `Bw80=2` — so
        // subtracting one WIDENS a narrowband channel (5 -> 10 MHz) exactly when the medium is
        // busiest. Latent only because no backend declares narrowband, and the axis is why: an
        // honest narrowband declaration would make this pick 5 MHz as the *ceiling* and then
        // "narrow" toward 80. Order by MHz, never by code.
        let mut bw = cap.max_bw();
        // Narrow under contention ONLY when width is an independent actuator. On a coupled-width
        // radio (e.g. MT7612U: ch36 exists solely at 80 MHz as a captured op-stream) "narrowing"
        // means replaying the whole channel program, which storms + fails under live traffic — so
        // hold the channel's single captured width instead (field 2026-09-11).
        if cap.width_actuated
            && busy >= self.cfg.busy_high
            && let Some(n) = ndn_radio_hal::Bandwidth::from_code(bw).narrower()
        {
            bw = n.code();
        }

        let good_snr = rssi.unwrap_or(-90) >= -60;
        let nss = if neighbor_single_stream {
            1 // a 1-RX-chain neighbour cannot decode a 2-stream frame at any MCS
        } else if ctx.priority() == Priority::Bulk && good_snr {
            cap.max_nss()
        } else {
            1
        };

        // Robustness knobs from the situation, not standalone toggles:
        //  - LDPC: better coding gain whenever robustness matters.
        //  - STBC: 2-chain transmit diversity for a 1-stream robust send.
        //  - CSD: 1-stream cyclic-shift diversity to both antennas on a weak link.
        let robust = broad || ctx.priority() == Priority::Urgent || deficit >= 1.0;
        let ldpc = robust;
        let weak = rssi.unwrap_or(-90) < -70;
        let div = self.cfg.enable_tx_diversity;
        let stbc = div && robust && nss == 1 && cap.max_nss() >= 2 && weak;
        let csd = div && nss == 1 && weak && !stbc;

        // 802.11ax reach levers — the strongest single-frame reach an HE radio (e.g. the ESP32-C5) offers,
        // above HT+STBC+LDPC. Reserved for the max-reach corner (robust send on a *weak* link) because HE
        // ER-SU is only decodable by an HE receiver (like VHT vs 11n) and ~halves the rate: exactly the
        // trade a struggling link wants, wrong for a healthy one. The worst-overheard-receiver legacy gate
        // still forces legacy downstream when a legacy-only RX is advertised, so this can't strand one.
        let he = cap.he_cap() && robust && weak;
        let er_su = he; // extended-range single-user: the ~2–4 dB sensitivity lever
        let dcm = he; // dual-carrier modulation: frequency-diversity robustness

        // A-MSDU: aggregate only for bulk on a clean link (and it interleaves with
        // FEC at MSDU granularity downstream — not mutually exclusive).
        let amsdu_msdus = if ctx.priority() == Priority::Bulk && !robust {
            Some(7)
        } else {
            None
        };

        TxParams {
            // 802.11 has no `SetPacketType` axis: HT/VHT/HE and the MCS index below already say
            // everything there is to say about its modulation, so a Wi-Fi radio advertises no
            // PHY set and this stays `None` — the axis is per-radio, not universal.
            phy: None,
            rate: RateParams::Wifi(WifiRate {
                mcs: Some(mcs),
                // HE and VHT are alternative modes — when the HE reach corner fires, the frame is HE, not VHT.
                // ★ Width-based, not code-based: `>= 2` read a 10 MHz channel (code 3) as
                // VHT-capable. This is still an INFERENCE — "80 MHz implies VHT" — and it is the
                // wrong shape: the RTL8733BU has no VHT receiver at all, which no width can
                // express. It belongs in the capability as its own field; until then, at least
                // infer it from real width.
                vht: !he && ndn_radio_hal::Bandwidth::from_code(cap.max_bw()).mhz() >= 80,
                nss: Some(nss),
                short_gi: good_snr,
                bw: Some(bw),
                stbc,
                csd,
                ldpc,
                he,
                dcm,
                er_su,
                amsdu_msdus,
            }),
            link_fec_redundancy: self.fec_redundancy(radio, ctx, view, channel, receivers, deficit),
            // Transmit into a busy channel. TWO independent conditions, and neither is optional:
            // the MEDIUM condition is ours (is it actually busy?), the AUTHORITY condition belongs
            // to `Contention::ignoring_edcca`, which grants only on a ceiling an authority raised
            // to `Urgent`. Written this way round so the class gate is a value the type enforces
            // rather than a `&&` any other construction site could forget.
            contention: if busy >= self.cfg.busy_high {
                Contention::deferring().ignoring_edcca(ctx)
            } else {
                Contention::deferring()
            },
            tx_power: self.decide_power(cap, mcs, rssi),
            tx_power_dbm: self.decide_power_dbm(cap, mcs, rssi),
            rx_gain: self.decide_rx_gain(mcs, rssi),
            edcca_threshold_dbm: self.decide_edcca_threshold_dbm(mcs, rssi),
        }
    }

    /// **Data-centric, cooperative, safe TX-power back-off.** Minimize power to the
    /// least that still serves the named object's demand set — which *maximizes
    /// network spatial reuse* (a smaller footprint frees the medium for concurrent
    /// named-data exchanges elsewhere). It is the one knob with a true externality
    /// (your reach is others' noise), so "minimum sufficient" is the cooperative as
    /// well as the data-centric choice.
    ///
    /// Reciprocity makes this possible from passive overhearing (no handshake): on a
    /// symmetric medium, how weakly we hear the weakest wanted receiver (`rssi`) ≈
    /// how weakly it hears us, so its decode margin ≈ `rssi − required_rssi(mcs)`,
    /// and the learned threshold doubles as the peer's decode floor. We back off by
    /// the surplus margin, keeping a safety margin, and **never exceed the calibrated
    /// max** (returns `None` ⇒ leave the hard-won power alone when there's no margin
    /// to give back).
    fn decide_power(&self, cap: &RadioCapability, mcs: u8, rssi: Option<i8>) -> Option<u8> {
        // ★ `None` here means "no opinion", and the actuator reads it as "leave the radio where it
        // is". So it must mean *only* "no measured peer" — never "no back-off wanted". Conflating
        // the two made this a RATCHET: a node that trimmed 18 dB against a close neighbour, then
        // watched that neighbour walk away, computed a zero back-off, returned `None`, and kept
        // whispering for the rest of the process lifetime. Zero back-off is a real decision, and
        // the decision is *go back to full power*.
        rssi?;
        // No actuator, or no measured scale, means no index opinion. Both used to be papered over
        // — the first by a `set_tx_power` default that returned `Ok(())` without touching silicon,
        // the second by a global constant — and between them a back-off could be decided, recorded
        // and rewarded without any part of it reaching the air.
        if !cap.power_actuated {
            return None;
        }
        let db_per_idx = cap.db_per_power_idx?;
        let backoff_db = self.power_backoff_db(mcs, rssi).unwrap_or(0.0);
        let backoff_idx = (backoff_db / db_per_idx).round() as u32;
        let target = u32::from(cap.max_tx_power).saturating_sub(backoff_idx);
        // Never below the part's monotone floor: past it, the a81a's commanded power INVERTS and
        // climbs ~11 dB above calibrated max — the exact opposite of the decision.
        let floor = u32::from(cap.min_tx_power.unwrap_or(0));
        Some(target.max(floor).min(u32::from(cap.max_tx_power)) as u8)
    }

    /// The same back-off, expressed on the **absolute dBm scale** for a radio that
    /// has one ([`RadioCapability::tx_power_dbm`]).
    ///
    /// This is the more faithful of the two: the policy above reasons natively in
    /// dB and only converts to an index at the end, through a single
    /// chip-independent `DB_PER_POWER_IDX` fudge that no real TXAGC table obeys.
    /// When the radio takes dBm directly, that lossy step is skipped and the
    /// decided margin is what the hardware is actually told.
    ///
    /// `None` when the radio has no absolute control, or there is no surplus
    /// margin to give back — never a guess.
    fn decide_power_dbm(&self, cap: &RadioCapability, mcs: u8, rssi: Option<i8>) -> Option<i8> {
        let range = cap.tx_power_dbm?;
        // See [`Self::decide_power`]: only a missing peer is "no opinion". A zero back-off means
        // restore the ceiling — which is what `decide_lora_power_dbm` has always done, and the
        // reason this path drifted away from it was the `?` on the next line.
        rssi?;
        let backoff_db = self.power_backoff_db(mcs, rssi).unwrap_or(0.0);
        let target = i16::from(range.max) - backoff_db.round() as i16;
        Some(range.clamp(target.clamp(i16::from(i8::MIN), i16::from(i8::MAX)) as i8))
    }

    /// LoRa TX power (absolute dBm): the same minimum-sufficient / spatial-reuse policy as
    /// [`decide_power_dbm`], but the decode threshold comes from the **SF** operating table
    /// ([`STATIC_REQ_RSSI_SF`](crate::calibrate::STATIC_REQ_RSSI_SF)) rather than the Wi-Fi MCS one.
    /// A weak link keeps the ceiling (power-first); surplus margin over what the chosen SF needs is
    /// handed back for reuse, keeping [`POWER_SAFETY_MARGIN_DB`] in hand. `None` ⇒ no measured peer,
    /// leave power alone.
    fn decide_lora_power_dbm(&self, cap: &RadioCapability, sf: u8, rssi: Option<i8>) -> Option<i8> {
        let range = cap.tx_power_dbm?;
        let r = rssi? as f32;
        let req = crate::calibrate::STATIC_REQ_RSSI_SF[sf.clamp(7, 12) as usize];
        let headroom = r - req; // dB the weakest peer has over what this SF needs (reciprocity)
        let backoff = (headroom - POWER_SAFETY_MARGIN_DB).clamp(0.0, MAX_BACKOFF_DB);
        let target = i16::from(range.max) - backoff.round() as i16;
        Some(range.clamp(target.clamp(i16::from(i8::MIN), i16::from(i8::MAX)) as i8))
    }

    /// **The receive half of spatial reuse**: how sensitive this node should be.
    ///
    /// Driven off the same surplus signal as [`decide_power`](Self::decide_power), and deliberately
    /// so — the two are one decision. Backing off transmit power shrinks who *hears* this node;
    /// raising the detection floor shrinks who this node *defers to*. A node that does only the
    /// first has reduced its own reach and bought nothing: it still yields the medium to every
    /// distant transmitter it can hear, so the concurrency the back-off was for never appears.
    ///
    /// * surplus margin (the same condition that licenses a power trim) ⇒ [`RxGain::Reduced`]
    /// * a marginal link ⇒ [`RxGain::Auto`], handing the front end back to the radio. **Never
    ///   `Boosted`**: a struggling link is exactly where the extra gain most often makes things
    ///   worse, and this policy has no measurement saying otherwise on any Wi-Fi part.
    /// * no measured peer ⇒ `None`, no opinion.
    fn decide_rx_gain(&self, mcs: u8, rssi: Option<i8>) -> Option<ndn_radio_hal::RxGain> {
        rssi?;
        Some(match self.power_backoff_db(mcs, rssi) {
            Some(_) => ndn_radio_hal::RxGain::Reduced,
            None => ndn_radio_hal::RxGain::Auto,
        })
    }

    /// The same decision in **true dBm**, for a radio whose defer threshold is denominated in real
    /// units ([`RadioKnobs::set_edcca_threshold_dbm`](ndn_radio_hal::RadioKnobs::set_edcca_threshold_dbm)).
    ///
    /// ★ The floor is raised by **the same dB the power was trimmed by**. That symmetry is the
    /// whole point: trim 10 dB of transmit power and raise the defer floor 10 dB and the node has
    /// actually claimed reuse — it is quieter *and* less deferential by the same amount, so its
    /// share of the medium is preserved while its interference footprint shrinks. Trim only the
    /// power and it has simply made itself smaller.
    ///
    /// Anchored at [`EDCCA_L2H_BASE_DBM`], the vendor default, with the conventional 8 dB
    /// hysteresis between `l2h` and `h2l`. `None` when there is no surplus to claim.
    fn decide_edcca_threshold_dbm(&self, mcs: u8, rssi: Option<i8>) -> Option<(i8, i8)> {
        let backoff = self.power_backoff_db(mcs, rssi)?;
        let l2h = (f32::from(EDCCA_L2H_BASE_DBM) + backoff)
            .round()
            .clamp(-128.0, 127.0) as i8;
        Some((l2h, l2h.saturating_sub(EDCCA_HYSTERESIS_DB)))
    }

    /// dB of power the weakest wanted receiver can spare, after keeping
    /// [`POWER_SAFETY_MARGIN_DB`] in hand and capping at [`MAX_BACKOFF_DB`].
    ///
    /// `None` = no measured peer. ⚠ It ALSO returns `None` for a zero back-off, which is a
    /// different thing entirely — callers must not propagate that with `?`. Both renderers now
    /// check `rssi` themselves and treat `None` from here as 0 dB, because a zero back-off is a
    /// decision to transmit at full power, not an absence of one.
    ///
    /// Shared by both power knobs so the index and dBm paths can never drift into
    /// two different policies.
    fn power_backoff_db(&self, mcs: u8, rssi: Option<i8>) -> Option<f32> {
        let r = rssi? as f32;
        let req = self.threshold_for(mcs);
        let headroom = r - req; // dB of margin the weakest peer has (reciprocity)
        let backoff_db = (headroom - POWER_SAFETY_MARGIN_DB).clamp(0.0, MAX_BACKOFF_DB);
        (backoff_db > 0.0).then_some(backoff_db)
    }

    /// The (learned-or-static) RSSI decode threshold for an MCS.
    fn threshold_for(&self, mcs: u8) -> f32 {
        let t = match &self.learned {
            Some(cell) => *cell.read().unwrap(),
            None => STATIC_REQ_RSSI,
        };
        t[mcs.min(9) as usize]
    }

    /// RSSI representative of the demand set on a radio: provision for the
    /// **weakest fresh receiver** when one is heard (fed from the signal store by
    /// the feature); otherwise fall back to a residual-derived proxy so the policy
    /// still degrades gracefully before any reception is observed.
    fn demand_set_rssi(&self, radio: RadioId, view: &dyn MediumView, now_ms: u64) -> Option<i8> {
        if let Some(weakest) = view.weakest_rssi(radio, now_ms) {
            return Some(weakest);
        }
        // No receiver heard yet: derive a conservative proxy from link residual
        // (high residual ⇒ treat the link as worse).
        let res = view
            .residual(radio)
            .and_then(|r| r.phy_per.get())
            .unwrap_or(0.0);
        let base = -55.0 - res * 40.0; // 0% → -55 dBm, 50% → -75 dBm
        Some(base.round().clamp(-95.0, -40.0) as i8)
    }

    /// THE shared redundancy budget. One number across PHY-LDPC / link-FEC / F1F2:
    /// size parity from the residual left below, **discounted** by macrodiversity
    /// receiver multiplicity (any-of pooling), **biased** by the measured
    /// re-Interest rate (drive ARQ down), targeting post-pooling rank deficit.
    fn fec_redundancy(
        &self,
        radio: RadioId,
        ctx: &NameContext,
        view: &dyn MediumView,
        channel: Option<u8>,
        receivers: usize,
        deficit: f32,
    ) -> Option<u16> {
        // DIRECT broadcast loss (report-seq gaps) — non-circular and measurable even at R=0, where
        // the FEC-residual phy_per is blind (it needs FEC active to measure loss). Size the budget
        // from the WORSE of the two so parity tracks real broadcast loss and engages proactively
        // instead of waiting on a residual that never appears (field 2026-09-14).
        let residual_per = view.residual(radio).and_then(|r| r.phy_per.get()).unwrap_or(0.0);
        let seq_loss = view.broadcast_loss(radio).unwrap_or(0.0);
        let phy = residual_per.max(seq_loss).clamp(0.0, 0.95);
        let reinterest = view
            .demand(ctx.prefix_hash)
            .and_then(|d| d.reinterest_rate.get())
            .unwrap_or(0.0)
            .max(0.0);

        // Pooling discount — DOUBLY GATED (`fec_pooling.rs`). With `n` receivers the
        // chance every one misses a frame is ~phy^n, so parity shrinks as `n` grows.
        // But phy^n silently assumes two things, and applying it blindly (the old
        // `phy.powi(receivers)`) under-provisions when either fails:
        //   1. ANY-OF semantics — the pool wins if *any* receiver catches each frame
        //      (cooperative relay/recode). An ALL-OF name (Urgent: every receiver must
        //      decode — alarm/control) gets NO discount; parity is sized for the single
        //      worst link. Ungated, the discount drops all-of delivery to ~0 at n≥2.
        //   2. INDEPENDENT loss. A shared interferer (a busy/contended channel,
        //      `wifi-loss-is-contention`) correlates loss across receivers, so a pool of
        //      `n` behaves like fewer. Damp the effective count toward 1 as busy rises.
        let all_of = matches!(ctx.priority(), Priority::Urgent);
        let n = receivers.max(1) as f64;
        let n_eff = if all_of {
            1.0
        } else {
            // rho ≈ channel occupancy: at 100% busy the losses fully correlate and the
            // pool collapses to one effective receiver (`fec_pooling.rs` Part C).
            let rho =
                f64::from(channel.and_then(|ch| view.busy_pct(radio, ch)).unwrap_or(0)) / 100.0;
            1.0 + (n - 1.0) * (1.0 - rho.clamp(0.0, 1.0))
        };
        let mut eff = (f64::from(phy).powf(n_eff)) as f32;
        eff = (eff * (1.0 + reinterest)).min(0.95);
        // Engage on measured loss. The rank deficit refines the AMOUNT (diversity discount), but it
        // must NOT be a hard gate when a DIRECT loss signal (report-seq gaps) is present — otherwise
        // FEC stays off until a rank-deficit producer feeds it, which is exactly the gap that left
        // the decided budget at 0 and relied entirely on the floor. With direct loss, size from it;
        // with only the (diversity-discountable) residual, keep the original deficit gate.
        if eff < 1e-3 || (seq_loss < 1e-3 && deficit < f32::EPSILON) {
            return None;
        }
        let k = self.cfg.generation_k as f32;
        let parity = (k * eff / (1.0 - eff)).ceil().clamp(0.0, k);
        if parity < 1.0 {
            None
        } else {
            Some(parity as u16)
        }
    }

    /// Relative airtime per satisfied Interest (lower = better) — the optimand,
    /// for A/B comparison against a fixed-MCS blast. Approximate but monotone.
    fn estimate_objective(&self, allocations: &[RadioAllocation], satisfied: usize) -> f32 {
        if allocations.is_empty() {
            return f32::INFINITY;
        }
        let mut airtime = 0.0f32;
        for a in allocations {
            let rate = phy_rate_proxy(&a.params); // Mbps proxy
            let redundancy = 1.0
                + a.params.link_fec_redundancy.unwrap_or(0) as f32 / self.cfg.generation_k as f32;
            airtime += redundancy / rate;
        }
        airtime / satisfied as f32
    }

    /// Deterministic digest of the salient choices so independent nodes converge
    /// and contradictory re-transmits can be detected/suppressed on the wire.
    fn consistency(
        &self,
        ctx: &NameContext,
        allocations: &[RadioAllocation],
        receivers: usize,
    ) -> u64 {
        let mut h = Fnv::new();
        h.add(ctx.prefix_hash);
        // bucket the demand so small fluctuations don't change the digest
        h.add((receivers / 2) as u64);
        for a in allocations {
            h.add(a.radio.0 as u64);
            h.add(a.channel.unwrap_or(0) as u64);
            h.add(a.params.mcs().unwrap_or(0) as u64); // rate class
        }
        h.0
    }
}

/// **Decide the BLE advertising PHY** — the bearer's reach lever, chosen the same way the Wi-Fi side
/// chooses a data rate: capability floor first, preference second.
///
/// Two inputs, and the order matters:
///
/// 1. **The floor is a capability, not a preference.** Only extended advertising PDUs carry a PHY
///    selection, so an LE 2M or LE Coded advert is invisible to a legacy-only receiver at any range
///    and any power — MEASURED: 20/20 on LE 1M and 0/20 on coded, to the same peer. So the choice is
///    capped at the *least* capable fresh neighbour, and a single legacy-only neighbour pins the whole
///    group to 1M. That is the doctrine's worst-overheard receiver, applied to a PHY instead of a rate.
/// 2. **Within the floor, reach or rate.** Coded (S=8) buys roughly 2–4x range through coding gain,
///    at an eighth of the symbol rate; 2M halves airtime at some cost in range. So `Urgent` (favour
///    reach) takes Coded when the group allows it, `Bulk` (favour throughput) takes 2M, and `Normal`
///    stays on 1M — the universal PHY, and the one with no downside for a group whose composition may
///    change between reports.
///
/// `worst_neighbor` is `None` when nobody has reported: that means an unknown neighbourhood, not an
/// empty one, so it resolves to [`ADV_PHY_1M`](crate::report::ADV_PHY_1M) — the only PHY that is safe
/// against a receiver we have not met.
///
/// Returns one of the `ADV_PHY_*` codes; the BLE bearer maps it to its own PHY type.
pub fn decide_adv_phy(view: &dyn MediumView, ctx: &NameContext, self_cap: u8, now_ms: u64) -> u8 {
    use crate::report::{ADV_PHY_1M, ADV_PHY_2M, ADV_PHY_CODED};
    // ⚠ Takes the CONTEXT, not a bare `Priority`, and that is the point: this used to accept an
    // asserted class, so any caller could write `Priority::Urgent` and buy LE Coded S=8 — the
    // longest-reach, ~8x-airtime-per-bit mode — through the branch below. That is precisely the
    // purchase [`ClassCeiling`] exists to gate, and leaving the door open here would have made the
    // type wall decorative. A class reaches this function only after an authority granted it.
    let floor = self_cap.min(view.worst_neighbor_adv_phy(now_ms).unwrap_or(ADV_PHY_1M));
    match ctx.priority() {
        Priority::Urgent if floor >= ADV_PHY_CODED => ADV_PHY_CODED,
        Priority::Bulk if floor >= ADV_PHY_2M => ADV_PHY_2M,
        _ => ADV_PHY_1M,
    }
}

impl RadioStrategy for RadioPolicy {
    fn decide(&self, ctx: &NameContext, medium: &dyn MediumView, now_ms: u64) -> RadioPlan {
        RadioPolicy::decide(self, ctx, medium, now_ms)
    }
    fn name(&self) -> &'static str {
        "rule-calibrated"
    }
}

// --- helpers ---

/// RSSI margin (dB) subtracted for a broad broadcast — provision the rate for the
/// weaker/more-numerous listeners, not the best single link.
const BROAD_MARGIN_DB: f32 = 6.0;
/// RSSI margin (dB) added for a single-receiver near-unicast — push the rate when
/// there's one good link to serve.
const UNICAST_MARGIN_DB: f32 = 4.0;
/// Decode-margin (dB) kept above the threshold when backing off TX power.
const POWER_SAFETY_MARGIN_DB: f32 = 6.0;
/// The clear-channel (defer) threshold a radio sits at with no reuse claimed, in dBm — the vendor
/// default the Realtek parts boot with. [`RadioPolicy::decide_edcca_threshold_dbm`] raises above
/// this by exactly the dB of transmit power it gave back.
const EDCCA_L2H_BASE_DBM: i8 = crate::plan::DEFER_THRESHOLD_DBM_BAND.0;
/// Hysteresis between the busy (`l2h`) and idle (`h2l`) thresholds, in dB — the kernel default.
const EDCCA_HYSTERESIS_DB: i8 = crate::plan::DEFER_HYSTERESIS_MAX_DB;
/// Most we'll back TX power off, even with huge surplus margin (dB).
const MAX_BACKOFF_DB: f32 = 18.0;
// ☠ `DB_PER_POWER_IDX = 0.5` lived here. It was a single global "approx dB per TXAGC index step"
// applied to every radio in the fleet, and **no part in the fleet obeyed it**: MEASURED 0.22 dB on
// the a81a (2x wrong), 0.111-0.155 on the RTL8733BU (4x wrong), and non-linear on the RTL8812AU
// where no single number can be right. So the policy reasoned correctly in dB and then rendered an
// 18 dB decision as 1.5-5 dB of actual back-off, differently per part, invisibly.
//
// The number now comes from the radio: `RadioCapability::db_per_power_idx`, populated only from a
// measurement. When a part has not been measured this is `None` and `decide_power` returns `None`
// — declining to have an index opinion is strictly better than guessing, because a guess here is
// indistinguishable from a decision and gets rewarded as one.

/// Nominal PHY rate proxy (Mbps) for the objective estimate — monotone in the
/// rate-affecting params, not a calibrated figure.
fn phy_rate_proxy(p: &TxParams) -> f32 {
    // The real HT/VHT ladder (shared, HAL-derived), scaled by bw/nss/SGI — replaces a `(mcs+1)·6.5`
    // approximation that under-rated MCS≥4 (32.5 vs the true 39 at MCS4), which made high-MCS arms
    // look costlier than they are in the airtime objective. Objective is telemetry, not a gate, so
    // this only sharpens the reported number.
    let base = crate::plan::mcs_base_rate_mbps(p.mcs().unwrap_or(0));
    let bw_factor = match p.bw().unwrap_or(0) {
        1 => 2.0,
        2 => 4.0,
        3 => 0.5,
        4 => 0.25,
        _ => 1.0,
    };
    let nss = p.nss().unwrap_or(1).max(1) as f32;
    let sgi = if p.short_gi() { 1.11 } else { 1.0 };
    (base * bw_factor * nss * sgi).max(0.25)
}

// Tiny FNV-1a over u64 words for the consistency digest (no external dep).
struct Fnv(u64);
impl Fnv {
    fn new() -> Self {
        Fnv(0xcbf29ce484222325)
    }
    fn add(&mut self, x: u64) {
        for b in x.to_le_bytes() {
            self.0 ^= b as u64;
            self.0 = self.0.wrapping_mul(0x100000001b3);
        }
    }
}

#[cfg(test)]
mod power_dbm_tests {
    use super::*;
    use ndn_radio_hal::DbmRange;

    /// A radio with absolute control gets an absolute decision, backed off from
    /// its own ceiling — the same margin the index path would have spent.
    #[test]
    fn advertised_range_yields_a_dbm_decision() {
        let p = RadioPolicy::default();
        let cap = RadioCapability {
            db_per_power_idx: Some(0.5),
            power_actuated: true,
            width_actuated: true,
            ..RadioCapability::wifi_halow_s1g(vec![36]).with_tx_power_dbm(DbmRange::new(1, 27))
        };
        // A very strong peer: lots of surplus margin to give back.
        let dbm = p
            .decide_power_dbm(&cap, 0, Some(-30))
            .expect("surplus margin");
        assert!(dbm < 27, "must back off below the ceiling, got {dbm}");
        assert!(dbm >= 1, "must stay inside the advertised range, got {dbm}");
    }

    /// The two scales must express the *same* policy: whenever one backs off, so
    /// does the other. This is what stops them drifting apart.
    #[test]
    fn both_scales_agree_on_when_to_back_off() {
        let p = RadioPolicy::default();
        let cap = RadioCapability {
            db_per_power_idx: Some(0.5),
            power_actuated: true,
            width_actuated: true,
            ..RadioCapability::wifi_halow_s1g(vec![36]).with_tx_power_dbm(DbmRange::new(1, 27))
        };
        for rssi in [-30i8, -50, -70, -90] {
            let idx = p.decide_power(&cap, 0, Some(rssi));
            let dbm = p.decide_power_dbm(&cap, 0, Some(rssi));
            assert_eq!(
                idx.is_some(),
                dbm.is_some(),
                "index and dBm disagreed at rssi {rssi}"
            );
        }
    }

    /// A radio that advertises no dBm range gets no dBm decision — the planner
    /// must not invent absolute power for hardware that cannot take it.
    #[test]
    fn no_advertised_range_means_no_dbm_decision() {
        let p = RadioPolicy::default();
        // Index-only, but with a MEASURED index scale — without one the index path correctly
        // declines too, which is a different property (see
        // `a_radio_with_no_actuator_gets_no_power_decision`).
        let cap = RadioCapability {
            db_per_power_idx: Some(0.5),
            power_actuated: true,
            width_actuated: true,
            ..RadioCapability::wifi_monitor_5ghz(vec![149])
        };
        assert!(cap.tx_power_dbm.is_none());
        assert_eq!(p.decide_power_dbm(&cap, 0, Some(-30)), None);
        // ...but the index path still decides, so such a radio is not left un-actuated.
        assert!(p.decide_power(&cap, 0, Some(-30)).is_some());
    }

    /// No measured peer = no surplus to give back = leave the power alone.
    #[test]
    fn no_rssi_leaves_power_untouched() {
        let p = RadioPolicy::default();
        let cap = RadioCapability {
            db_per_power_idx: Some(0.5),
            power_actuated: true,
            width_actuated: true,
            ..RadioCapability::wifi_halow_s1g(vec![36]).with_tx_power_dbm(DbmRange::new(1, 27))
        };
        assert_eq!(p.decide_power_dbm(&cap, 0, None), None);
    }

    /// The back-off is bounded, so a wildly optimistic RSSI cannot drive power
    /// below what the radio can actually be commanded to.
    #[test]
    fn decision_stays_inside_the_range_under_extreme_margin() {
        let p = RadioPolicy::default();
        let range = DbmRange::new(20, 27); // a narrow-range radio
        let cap = RadioCapability::wifi_halow_s1g(vec![36]).with_tx_power_dbm(range);
        let dbm = p.decide_power_dbm(&cap, 0, Some(0)).expect("huge margin");
        assert!(
            (range.min..=range.max).contains(&dbm),
            "{dbm} escaped {range:?}"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sense::{ChannelOccupancy, MediumState};

    const W: RadioId = RadioId(0);
    const L: RadioId = RadioId(1);

    /// The shared rate ladder is the TRUE HT/VHT ladder (HAL-derived), and `phy_rate_proxy` now uses
    /// it — not the old `(mcs+1)·6.5` that under-rated MCS≥4 (32.5 vs the true 39 at MCS4).
    #[test]
    fn rate_ladder_is_the_true_ht_ladder() {
        let expect = [6.5f32, 13.0, 19.5, 26.0, 39.0, 52.0, 58.5, 65.0];
        for (mcs, &e) in expect.iter().enumerate() {
            assert_eq!(crate::plan::mcs_base_rate_mbps(mcs as u8), e, "MCS{mcs}");
        }
        assert_eq!(crate::plan::mcs_base_rate_mbps(8), 78.0); // VHT
        assert_eq!(crate::plan::mcs_base_rate_mbps(9), 87.75);
        let p = TxParams::wifi(crate::plan::WifiRate {
            mcs: Some(4),
            ..Default::default()
        });
        assert_eq!(
            phy_rate_proxy(&p),
            39.0,
            "MCS4 must rate at the true 39 Mbps, not the old proxy's 32.5"
        );
    }

    fn wifi_only() -> MediumState {
        let mut m = MediumState::new();
        m.register_radio(W, RadioCapability::wifi_monitor_5ghz(vec![149, 161, 165]));
        m
    }

    fn hetero() -> MediumState {
        let mut m = wifi_only();
        m.register_radio(L, RadioCapability::lora(vec![0]));
        m
    }

    /// End-to-end proof that the SNR ceiling reaches the PLAN, not just the selector: same strong
    /// RSSI, once with no SNR reported and once with a poor SNR. The dirty link must plan a lower
    /// MCS. Without this the wiring could be present and unreachable — the failure mode this whole
    /// stack is named for.
    #[test]
    fn poor_snr_caps_the_planned_mcs() {
        let mk = |snr: Option<f32>| {
            let mut m = wifi_only();
            m.observe_rx(W, 0x1234, Some(-40), 1_000); // loud link
            m.observe_rx_snr(W, 0x1234, snr, 1_000);
            RadioPolicy::default()
                .decide(&NameContext::new(0xAA), &m, 1_000)
                .allocations
                .first()
                .and_then(|a| match &a.params.rate {
                    crate::plan::RateParams::Wifi(w) => w.mcs,
                    _ => None,
                })
        };
        let clean = mk(None);
        let dirty = mk(Some(9.0));
        assert!(clean.is_some(), "expected a planned MCS to compare against");
        assert!(
            dirty < clean,
            "SNR ceiling never reached the plan: dirty={dirty:?} clean={clean:?}"
        );
    }

    #[test]
    fn origin_always_transmits_single_radio() {
        let m = wifi_only();
        let p = RadioPolicy::default().decide(&NameContext::new(0xAA), &m, 1_000);
        assert!(!p.suppress);
        assert_eq!(p.allocations.len(), 1);
        assert_eq!(p.allocations[0].radio, W);
    }

    #[test]
    fn relay_suppresses_when_no_rank_to_add() {
        let mut m = wifi_only();
        // downstream already satisfied: deficit ~0
        m.observe_rank_deficit(0xAA, 0.0, 1_000);
        let ctx = NameContext {
            is_origin: false,
            ..NameContext::new(0xAA)
        };
        let p = RadioPolicy::default().decide(&ctx, &m, 1_000);
        assert!(p.suppress);
        assert!(p.allocations.is_empty());
    }

    #[test]
    fn relay_transmits_when_innovative() {
        let mut m = wifi_only();
        m.observe_rx(W, 1, Some(-60), 1_000); // a live receiver
        m.observe_rank_deficit(0xAA, 2.0, 1_000); // still rank-deficient
        let ctx = NameContext {
            is_origin: false,
            ..NameContext::new(0xAA)
        };
        let p = RadioPolicy::default().decide(&ctx, &m, 1_000);
        assert!(!p.suppress);
        assert!(p.relay);
    }

    #[test]
    fn broad_broadcast_lowers_mcs_vs_unicast() {
        let mut m = wifi_only();
        for n in 0..5 {
            m.observe_rx(W, n, Some(-55), 1_000); // 5 receivers ⇒ broad
        }
        let broad = RadioPolicy::default().decide(&NameContext::new(0xAA), &m, 1_000);

        let mut m1 = wifi_only();
        m1.observe_rx(W, 0, Some(-55), 1_000); // single receiver ⇒ unicast
        let uni = RadioPolicy::default().decide(&NameContext::new(0xAA), &m1, 1_000);

        let broad_mcs = broad.allocations[0].params.mcs().unwrap();
        let uni_mcs = uni.allocations[0].params.mcs().unwrap();
        assert!(
            broad_mcs < uni_mcs,
            "broad {broad_mcs} should be < unicast {uni_mcs}"
        );
    }

    /// The worst-overheard-receiver cap: a neighbour that advertises a single-RX-chain capability
    /// (`SINGLE_STREAM_HT_RX_MCS` = 7) forces the transmit down to single-stream ≤ MCS 7 even on a
    /// strong bulk link — because a 1-chain radio cannot decode a 2-stream frame at *any* index. This
    /// is the fix for the field-diagnosed one-way link (a peer TXing 2-stream MCS 9 the drone's
    /// userspace RTL8812EU could never decode).
    #[test]
    fn single_stream_neighbor_caps_mcs_and_stream_count() {
        use crate::report::{FULL_RX_MCS, SINGLE_STREAM_HT_RX_MCS};
        use crate::sense::NeighborReport;

        // A strong single-receiver bulk link: uncapped, cognition provisions a high, 2-stream rate.
        let ctx = ctx_at(0xAA, Priority::Bulk);
        let decide_for = |max_rx: u8| {
            let mut m = wifi_only();
            m.observe_rx(W, 1, Some(-45), 1_000); // strong link ⇒ high uncapped MCS
            m.observe_report(
                1,
                NeighborReport {
                    heard_prefixes: vec![],
                    spectrum: vec![],
                    max_adv_phy: crate::report::ADV_PHY_1M,
                    max_rx_mcs: max_rx,
                    ts_ms: 1_000,
                },
            );
            RadioPolicy::default().decide(&ctx, &m, 1_000).allocations[0].params
        };

        let full = decide_for(FULL_RX_MCS);
        let single = decide_for(SINGLE_STREAM_HT_RX_MCS);

        assert!(
            single.mcs().unwrap() <= 7,
            "1-chain neighbour must cap MCS at 7, got {:?}",
            single.mcs()
        );
        assert_eq!(
            single.nss(),
            Some(1),
            "1-chain neighbour cannot decode 2 streams"
        );
        // And the cap is what changed it: the full-capable neighbour is strictly more aggressive.
        assert!(
            full.mcs().unwrap() > single.mcs().unwrap() || full.nss() > single.nss(),
            "full neighbour ({:?}/{:?} MCS/nss) should out-rate the capped one ({:?}/{:?})",
            full.mcs(),
            full.nss(),
            single.mcs(),
            single.nss(),
        );
    }

    #[test]
    fn budget_scales_with_residual_and_discounts_receivers() {
        // high residual, one receiver ⇒ some parity
        let mut m = wifi_only();
        m.observe_rx(W, 0, Some(-80), 1_000);
        m.observe_phy_per(W, 0.3);
        m.observe_rank_deficit(0xAA, 1.0, 1_000);
        let one = RadioPolicy::default().decide(&NameContext::new(0xAA), &m, 1_000);
        let parity_one = one.allocations[0].params.link_fec_redundancy.unwrap_or(0);
        assert!(parity_one > 0, "expected parity for 30% residual");

        // same residual, many decorrelated receivers ⇒ pooling discounts parity
        let mut m2 = wifi_only();
        for n in 0..6 {
            m2.observe_rx(W, n, Some(-80), 1_000);
        }
        m2.observe_phy_per(W, 0.3);
        m2.observe_rank_deficit(0xAA, 1.0, 1_000);
        let many = RadioPolicy::default().decide(&NameContext::new(0xAA), &m2, 1_000);
        let parity_many = many.allocations[0].params.link_fec_redundancy.unwrap_or(0);
        assert!(
            parity_many < parity_one,
            "pooling should discount: {parity_many} < {parity_one}"
        );
    }

    /// The pooling discount is **doubly gated** (`fec_pooling.rs`): it is legal only for
    /// any-of names on an uncorrelated channel. Ungated `phy^n` under-provisions an all-of
    /// (alarm) name to ~0 delivery at n≥2, and any name on a contended channel.
    #[test]
    fn pooling_discount_is_gated_by_semantics_and_correlation() {
        let base = || {
            let mut m = wifi_only();
            for n in 0..6 {
                m.observe_rx(W, n, Some(-80), 1_000);
            }
            m.observe_phy_per(W, 0.3);
            m.observe_rank_deficit(0xAA, 1.0, 1_000);
            m
        };
        let parity = |pri: Priority, m: &MediumState| {
            RadioPolicy::default()
                .decide(&ctx_at(0xAA, pri), m, 1_000)
                .allocations[0]
                .params
                .link_fec_redundancy
                .unwrap_or(0)
        };

        // Baseline: a Bulk (any-of) name on a clear channel gets the full discount.
        let bulk_clear = parity(Priority::Bulk, &base());

        // SEMANTICS GATE: an Urgent (all-of — every receiver must decode) name gets NO
        // discount, so strictly more parity than the any-of name at the same count.
        let urgent_clear = parity(Priority::Urgent, &base());
        assert!(
            urgent_clear > bulk_clear,
            "all-of must not be discounted: urgent {urgent_clear} > bulk {bulk_clear}"
        );

        // CORRELATION GATE: on a fully-busy (contended) channel the losses correlate, so
        // the pool collapses toward one receiver → more parity even for a Bulk name.
        let mut busy = base();
        for ch in [149u8, 161, 165] {
            busy.observe_occupancy(ChannelOccupancy {
                radio: W,
                channel: ch,
                busy_pct: 100,
                ts_ms: 1_000,
            });
        }
        let bulk_busy = parity(Priority::Bulk, &busy);
        assert!(
            bulk_busy > bulk_clear,
            "correlated (busy) loss must undo the discount: busy {bulk_busy} > clear {bulk_clear}"
        );
    }

    // ── E1: the modulation axis reaches the PLAN ─────────────────────────────────────────

    /// A LoRa-only medium whose radio advertises LoRa **and** FLRC and is running LoRa — the
    /// LR2021 case, and the whole reason this axis exists.
    fn agile_lora(rssi_dbm: i8) -> MediumState {
        let mut m = MediumState::new();
        let cap = RadioCapability::lora_with(
            RadioKind::Lora,
            vec![crate::Band::Sub1GHz],
            vec![65],
            crate::RateCapability::Lora {
                min_sf: 7,
                max_sf: 12,
            },
            200,
            1.0,
        )
        .with_phy(
            crate::PhyModeSet::single(crate::PhyMode::Lora).with(crate::PhyMode::Flrc),
            crate::PhyMode::Lora,
        );
        m.register_radio(L, cap);
        m.observe_rx(L, 0x1234, Some(rssi_dbm), 1_000);
        m
    }

    /// A stub authority for the tests below.
    ///
    /// Deliberately the ONLY way anything here reaches a class above `Normal`: the tests go through
    /// the same gate production does, rather than through a back door that would re-open the hole
    /// this type exists to close. If a future test can set a class without one of these, the
    /// invariant has regressed.
    struct FixedAuthority(Priority);
    impl ClassAuthority for FixedAuthority {
        fn ceiling_for(&self, _prefix_hash: u64) -> Priority {
            self.0
        }
    }

    fn ctx_at(prefix_hash: u64, p: Priority) -> NameContext {
        NameContext::new(prefix_hash)
            .with_ceiling(ClassCeiling::authorised(&FixedAuthority(p), prefix_hash))
    }

    // ---- the class contract: derived, never asserted; lower, never raise -----------------------

    #[test]
    fn a_name_with_no_authority_is_normal_and_that_is_a_correct_answer() {
        // The defined bottom of the lattice, not a degraded state. Both constructors agree, so a
        // relay cannot acquire class merely by relaying.
        assert_eq!(NameContext::new(0xAA).priority(), Priority::Normal);
        assert_eq!(NameContext::relayed(0xAA).priority(), Priority::Normal);
        assert_eq!(ClassCeiling::unauthorised().get(), Priority::Normal);
    }

    #[test]
    fn only_an_authority_can_exceed_normal() {
        // `ctx_at` is the ONLY route above Normal in these tests and it goes through the gate.
        // There is deliberately no `NameContext::set_priority`; if one appears, this contract is
        // gone and the DiffServ failure mode is back.
        assert_eq!(ctx_at(0xAA, Priority::Urgent).priority(), Priority::Urgent);
        // An authority that fails closed yields the bottom, not an error.
        assert_eq!(ctx_at(0xAA, Priority::Normal).priority(), Priority::Normal);
    }

    #[test]
    fn a_peer_may_lower_a_class_and_has_no_way_to_raise_one() {
        // ★ The rule `ReceptionReport` already embodies: anything learned from a neighbour can only
        // make us do LESS. A peer able to raise our class could buy privilege by lying, for free.
        let urgent = ctx_at(0xAA, Priority::Urgent);
        // A cap removes privilege down to the NEUTRAL point, not to the bottom of the enum:
        // `Bulk` selects rendezvous parameters and must be earned. See `ClassCeiling::capped_to`.
        assert_eq!(
            urgent.capped_by(Priority::Bulk).priority(),
            Priority::Normal
        );
        assert_eq!(
            urgent.capped_by(Priority::Normal).priority(),
            Priority::Normal
        );
        // Capping upward is a no-op — the cap is a minimum, never a promotion.
        let bulk_ctx = ctx_at(0xAA, Priority::Bulk);
        assert_eq!(
            bulk_ctx.capped_by(Priority::Urgent).priority(),
            Priority::Bulk
        );
        // ...and it is idempotent, so repeated gossip cannot ratchet anything.
        assert_eq!(
            urgent
                .capped_by(Priority::Bulk)
                .capped_by(Priority::Bulk)
                .priority(),
            Priority::Normal
        );
    }

    /// ☠ The hole an external probe found: `Bulk` sits below `Normal`, so a free "cap" reached it —
    /// and `Bulk` is what MOVES the dial to the rate PHY and widens LoRa to 250 kHz, both rendezvous
    /// parameters. A class that selects behaviour must be earned regardless of where it sits in the
    /// privilege order.
    #[test]
    fn an_unauthorised_caller_cannot_reach_bulk_by_capping() {
        let plain = NameContext::new(0xAA);
        assert_eq!(plain.priority(), Priority::Normal);
        assert_eq!(
            plain.capped_by(Priority::Bulk).priority(),
            Priority::Normal,
            "self-demotion must not buy the rate PHY or 250 kHz"
        );
        // An authority may still grant Bulk, and a later cap does not erase it.
        let granted = ctx_at(0xAA, Priority::Bulk);
        assert_eq!(granted.priority(), Priority::Bulk);
        assert_eq!(granted.capped_by(Priority::Bulk).priority(), Priority::Bulk);
        assert_eq!(
            granted.capped_by(Priority::Normal).priority(),
            Priority::Bulk
        );
    }

    #[test]
    fn demand_rank_is_monotone_in_both_signals_it_measures() {
        let mk = |fanout: u32, reint: f32| {
            let mut e = crate::sense::Ewma::new(1.0);
            e.update(reint);
            crate::sense::Demand {
                fanout,
                reinterest_rate: e,
                rank_deficit: crate::sense::Ewma::new(0.3),
                ts_ms: 0,
            }
        };
        let quiet = DemandRank::from_demand(&mk(0, 0.0));
        let wanted = DemandRank::from_demand(&mk(8, 0.0));
        let missing = DemandRank::from_demand(&mk(0, 1.0));
        let both = DemandRank::from_demand(&mk(8, 1.0));
        assert!(quiet.get() < wanted.get(), "more downstreams ⇒ higher rank");
        assert!(quiet.get() < missing.get(), "re-expression ⇒ higher rank");
        assert!(both.get() > wanted.get() && both.get() > missing.get());
        assert!((0.0..=1.0).contains(&both.get()));
        // Fan-out saturates: 1 -> 2 downstreams matters more than 50 -> 51.
        let d1 = DemandRank::from_demand(&mk(1, 0.0)).get();
        let d2 = DemandRank::from_demand(&mk(2, 0.0)).get();
        let d50 = DemandRank::from_demand(&mk(50, 0.0)).get();
        let d51 = DemandRank::from_demand(&mk(51, 0.0)).get();
        assert!(d2 - d1 > d51 - d50);
    }

    #[test]
    fn the_ceiling_and_the_rank_are_independent_axes() {
        // ★ The correction that shaped this design: they are NOT alternatives. Competing traffic
        // exists at every level, so a schema-authorised deployment still needs the rank to order
        // within a class, and an unauthorised one still gets useful ordering capped at Normal.
        let quiet = {
            let mut e = crate::sense::Ewma::new(1.0);
            e.update(0.0);
            crate::sense::Demand {
                fanout: 1,
                reinterest_rate: e,
                rank_deficit: crate::sense::Ewma::new(0.3),
                ts_ms: 0,
            }
        };
        let busy = {
            let mut e = crate::sense::Ewma::new(1.0);
            e.update(1.0);
            crate::sense::Demand {
                fanout: 9,
                reinterest_rate: e,
                rank_deficit: crate::sense::Ewma::new(0.3),
                ts_ms: 0,
            }
        };
        // Two names at the SAME granted class are still ordered, by measurement.
        let a = ctx_at(0xA, Priority::Urgent).with_demand(DemandRank::from_demand(&quiet));
        let b = ctx_at(0xB, Priority::Urgent).with_demand(DemandRank::from_demand(&busy));
        assert_eq!(a.priority(), b.priority());
        assert!(b.demand_rank().get() > a.demand_rank().get());
        // And high demand never promotes a class: measurement orders, authority gates.
        let c = NameContext::new(0xC).with_demand(DemandRank::from_demand(&busy));
        assert_eq!(
            c.priority(),
            Priority::Normal,
            "demand must not grant class"
        );
        assert!(c.demand_rank().get() > a.demand_rank().get());
    }

    fn bulk(hash: u64) -> NameContext {
        ctx_at(hash, Priority::Bulk)
    }

    /// **The opt-in is total.** With no dial attached the plan names no modulation, so every
    /// caller that predates this axis leaves the radio exactly where it booted.
    #[test]
    fn without_a_dial_no_plan_names_a_modulation() {
        let m = agile_lora(-40);
        let plan = RadioPolicy::default().decide(&bulk(0xAA), &m, 5_000);
        assert_eq!(plan.allocations[0].params.phy(), None);
    }

    /// **E1 end to end** — a strong, measured, bulk link moves the PLAN onto the rate PHY, and
    /// only after the dial's confirmations. The proof the decision is reachable, not just
    /// computable (the failure mode this whole stack is named for).
    #[test]
    fn a_strong_bulk_link_plans_the_rate_phy() {
        let m = agile_lora(-40);
        let dial = Arc::new(PhyDial::new(None));
        let p = RadioPolicy::default().with_phy_dial(dial.clone());

        let first = p.decide(&bulk(0xAA), &m, 5_000);
        assert_eq!(
            first.allocations[0].params.phy(),
            Some(crate::PhyMode::Lora),
            "the first decision must not switch — it names where the radio already is"
        );
        let mut planned = first.allocations[0].params.phy();
        for i in 1..20u64 {
            planned = p.decide(&bulk(0xAA), &m, 5_000 + i).allocations[0]
                .params
                .phy();
        }
        assert_eq!(planned, Some(crate::PhyMode::Flrc));
    }

    /// A weak link keeps the reach PHY however many times it is asked, and an `Urgent` name never
    /// leaves it at all — reach beats rate for the traffic that needs reach.
    #[test]
    fn a_weak_link_and_an_urgent_name_both_stay_on_the_reach_phy() {
        let weak = agile_lora(-105);
        let dial = Arc::new(PhyDial::new(None));
        let p = RadioPolicy::default().with_phy_dial(dial);
        for i in 0..40u64 {
            let plan = p.decide(&bulk(0xAA), &weak, 5_000 + i * 1_000);
            assert_eq!(plan.allocations[0].params.phy(), Some(crate::PhyMode::Lora));
        }

        let strong = agile_lora(-40);
        let p2 = RadioPolicy::default().with_phy_dial(Arc::new(PhyDial::new(None)));
        for i in 0..40u64 {
            let plan = p2.decide(&NameContext::new(0xBB), &strong, 5_000 + i * 1_000);
            assert_eq!(
                plan.allocations[0].params.phy(),
                Some(crate::PhyMode::Lora),
                "a non-bulk name must not spend the switch"
            );
        }
    }

    /// **A radio that has described no modes gets no mode named** — and a Wi-Fi radio, which has
    /// no `SetPacketType` axis at all, never does either.
    #[test]
    fn a_silent_radio_and_a_wifi_radio_are_never_given_a_mode() {
        let mut quiet = MediumState::new();
        quiet.register_radio(
            L,
            RadioCapability::lora_with(
                RadioKind::Lora,
                vec![crate::Band::Sub1GHz],
                vec![65],
                crate::RateCapability::Lora {
                    min_sf: 7,
                    max_sf: 12,
                },
                200,
                1.0,
            ),
        );
        quiet.observe_rx(L, 0x1234, Some(-40), 1_000);
        let p = RadioPolicy::default().with_phy_dial(Arc::new(PhyDial::new(None)));
        for i in 0..20u64 {
            let plan = p.decide(&bulk(0xAA), &quiet, 5_000 + i * 1_000);
            assert_eq!(plan.allocations[0].params.phy(), None);
        }

        let w = wifi_only();
        let plan = RadioPolicy::default()
            .with_phy_dial(Arc::new(PhyDial::new(None)))
            .decide(&bulk(0xAA), &w, 5_000);
        assert_eq!(plan.allocations[0].params.phy(), None);
    }

    /// The rationale carries the mode AND the brake that is holding it, so a trace shows the
    /// *why* of a modulation rather than only the modulation.
    #[test]
    fn the_rationale_carries_the_modulation_and_its_brake() {
        let m = agile_lora(-40);
        let p = RadioPolicy::default().with_phy_dial(Arc::new(PhyDial::new(None)));
        let (_, why) = p.decide_traced(&bulk(0xAA), &m, 5_000);
        assert_eq!(why.radios[0].phy, Some(crate::PhyMode::Lora));
        assert_eq!(why.radios[0].phy_hold, Some(crate::PhyHold::Confirming));

        // With no dial there is no hold to report — the axis is simply not in play.
        let (_, why) = RadioPolicy::default().decide_traced(&bulk(0xAA), &m, 5_000);
        assert_eq!(why.radios[0].phy, None);
        assert_eq!(why.radios[0].phy_hold, None);
    }

    #[test]
    fn heterogeneous_bulk_prefers_wifi_urgent_prefers_lora() {
        let m = hetero();
        let bulk = RadioPolicy::default().decide(&ctx_at(0xAA, Priority::Bulk), &m, 1_000);
        assert_eq!(bulk.allocations[0].radio, W, "bulk → high-rate Wi-Fi");

        let urgent = RadioPolicy::default().decide(&ctx_at(0xAA, Priority::Urgent), &m, 1_000);
        assert_eq!(urgent.allocations[0].radio, L, "urgent → long-range LoRa");
    }

    #[test]
    fn high_deficit_replicates_across_radios_for_diversity() {
        let mut m = hetero();
        m.observe_rank_deficit(0xAA, 3.0, 1_000); // big deficit
        let p = RadioPolicy::default().decide(&NameContext::new(0xAA), &m, 1_000);
        assert_eq!(
            p.allocations.len(),
            2,
            "should replicate across both radios"
        );
    }

    /// Replication must be driven by a MEASURED rank deficit, not by the receiver-count fallback.
    /// With two TX radios and a receiver but NO rank-deficit signal observed, the node must NOT
    /// replicate — the old code read `deficit = receivers` and spent the second radio on every
    /// transmission with a receiver. The moment a real deficit is observed, replication engages.
    #[test]
    fn unmeasured_deficit_does_not_replicate_but_a_measured_one_does() {
        let mut m = hetero();
        m.observe_rx(W, 0x11, Some(-70), 1_000); // a receiver ⇒ the old fallback deficit ≥ 1
        // No observe_rank_deficit: the diversity signal is unmeasured.
        let p = RadioPolicy::default().decide(&NameContext::new(0xAA), &m, 1_000);
        assert_eq!(
            p.allocations.len(),
            1,
            "no measured rank deficit ⇒ one radio, not a wasted second-radio replicate"
        );

        // Contrast: feed a real deficit and the SAME setup replicates as designed.
        m.observe_rank_deficit(0xAA, 2.0, 1_000);
        let p2 = RadioPolicy::default().decide(&NameContext::new(0xAA), &m, 1_000);
        assert_eq!(
            p2.allocations.len(),
            2,
            "a measured deficit engages the second radio"
        );
    }

    #[test]
    fn split_role_when_coded_and_heterogeneous() {
        let mut m = hetero();
        m.observe_rank_deficit(0xAA, 3.0, 1_000);
        let ctx = NameContext {
            generation: Some(7),
            ..NameContext::new(0xAA)
        };
        let p = RadioPolicy::default().decide(&ctx, &m, 1_000);
        assert_eq!(p.allocations.len(), 2);
        assert_eq!(p.allocations[1].role, AllocRole::Split);
    }

    #[test]
    fn consistency_digest_is_deterministic() {
        let m = hetero();
        let a = RadioPolicy::default().decide(&NameContext::new(0xAA), &m, 1_000);
        let b = RadioPolicy::default().decide(&NameContext::new(0xAA), &m, 5_000);
        assert_eq!(
            a.consistency, b.consistency,
            "same name+demand ⇒ same plan digest"
        );
    }

    #[test]
    fn rationale_captures_the_why_of_a_decision() {
        let mut m = wifi_only();
        m.observe_occupancy(ChannelOccupancy {
            radio: W,
            channel: 149,
            busy_pct: 80,
            ts_ms: 1,
        });
        m.observe_occupancy(ChannelOccupancy {
            radio: W,
            channel: 161,
            busy_pct: 10,
            ts_ms: 1,
        });
        m.observe_occupancy(ChannelOccupancy {
            radio: W,
            channel: 165,
            busy_pct: 50,
            ts_ms: 1,
        });

        // Origin transmits: the rationale explains the plan — the picked channel and
        // the occupancy that picked it are both in the "why".
        let (plan, why) = RadioPolicy::default().decide_traced(&NameContext::new(0xAA), &m, 1_000);
        assert_eq!(why.suppress, None);
        assert!(
            why.is_origin,
            "origin transmits regardless of receiver count"
        );
        assert!(!why.radios.is_empty());
        assert_eq!(why.radios.len(), plan.allocations.len());
        let r0 = why.radios[0];
        assert_eq!(r0.channel, Some(161), "chose least-busy");
        assert_eq!(
            r0.channel_busy_pct,
            Some(10),
            "and the trace records why (10% busy)"
        );
        assert_eq!(
            r0.channel, plan.allocations[0].channel,
            "input matches the output"
        );

        // A relay with nothing to add is suppressed — and the trace says *why*.
        let (plan, why) =
            RadioPolicy::default().decide_traced(&NameContext::relayed(0xBB), &m, 1_000);
        assert!(plan.suppress);
        assert_eq!(why.suppress, Some(SuppressReason::RelayAddsNoRank));
    }

    #[test]
    fn picks_least_busy_channel() {
        let mut m = wifi_only();
        m.observe_occupancy(ChannelOccupancy {
            radio: W,
            channel: 149,
            busy_pct: 80,
            ts_ms: 1,
        });
        m.observe_occupancy(ChannelOccupancy {
            radio: W,
            channel: 161,
            busy_pct: 10,
            ts_ms: 1,
        });
        m.observe_occupancy(ChannelOccupancy {
            radio: W,
            channel: 165,
            busy_pct: 50,
            ts_ms: 1,
        });
        let p = RadioPolicy::default().decide(&NameContext::new(0xAA), &m, 1_000);
        assert_eq!(p.allocations[0].channel, Some(161));
    }

    #[test]
    fn coupled_width_radio_holds_its_single_width_under_contention() {
        // MT7612U-class: ch36 exists only at 80 MHz, so width is NOT an independent actuator
        // (`width_actuated=false`). A busy channel must not make cognition "narrow" — on this part
        // that means replaying the whole channel program, which storms and starves RX
        // (field 2026-09-11). A `width_actuated=true` radio still narrows under the same load.
        fn busy_medium(width_actuated: bool) -> MediumState {
            let mut m = MediumState::new();
            let mut cap = RadioCapability::wifi_monitor_5ghz(vec![36]); // max_bw = 2 (Bw80)
            cap.width_actuated = width_actuated;
            m.register_radio(W, cap);
            m.observe_occupancy(ChannelOccupancy {
                radio: W,
                channel: 36,
                busy_pct: 95,
                ts_ms: 1,
            });
            m
        }
        let coupled =
            RadioPolicy::default().decide(&NameContext::new(0xAA), &busy_medium(false), 1_000);
        assert_eq!(
            coupled.allocations[0].params.bw(),
            Some(2),
            "coupled-width radio must HOLD Bw80 under contention, not narrow (a re-tune it cannot do)"
        );
        let agile =
            RadioPolicy::default().decide(&NameContext::new(0xAA), &busy_medium(true), 1_000);
        assert!(
            agile.allocations[0].params.bw().unwrap() < 2,
            "a width-actuated radio still narrows under contention"
        );
    }
}

#[cfg(test)]
mod adv_phy_tests {
    use super::{ClassAuthority, ClassCeiling, NameContext, Priority};

    /// The same gate the production caller uses — see `super::tests::FixedAuthority`. These tests
    /// deliberately cannot assert a class directly, because `decide_adv_phy` no longer accepts one.
    struct Granted(Priority);
    impl ClassAuthority for Granted {
        fn ceiling_for(&self, _prefix_hash: u64) -> Priority {
            self.0
        }
    }
    fn ctx_at(h: u64, p: Priority) -> NameContext {
        NameContext::new(h).with_ceiling(ClassCeiling::authorised(&Granted(p), h))
    }
    use ndn_radio_hal::RxGain;

    /// ★ The power ratchet: a back-off that could never be undone.
    ///
    /// `power_backoff_db` returns `None` both for "no measured peer" and for "zero back-off", and
    /// both renderers used to propagate that with `?`. Since `apply_knobs` reads `None` as "leave
    /// the radio alone", a node that trimmed power against a close neighbour could never restore it
    /// when that neighbour left — it whispered for the rest of the process lifetime. This was live
    /// on HaLow, the one bearer where the dBm axis actually works.
    #[test]
    fn power_recovers_when_the_close_neighbour_leaves() {
        let policy = RadioPolicy::default();
        let mut cap = RadioCapability::wifi_monitor_2ghz_1ss((1..=13).collect());
        cap.tx_power_dbm = Some(ndn_radio_hal::DbmRange::new(2, 20));
        cap.max_tx_power = 63;
        cap.db_per_power_idx = Some(0.5); // the index half needs a declared scale to have an opinion
        cap.power_actuated = true;

        // A very strong peer: plenty of surplus, so both renderers must trim.
        let near_dbm = policy.decide_power_dbm(&cap, 4, Some(-35));
        let near_idx = policy.decide_power(&cap, 4, Some(-35));
        assert!(near_dbm.is_some() && near_idx.is_some());
        assert!(near_dbm.unwrap() < 20, "expected a trim, got {near_dbm:?}");
        assert!(near_idx.unwrap() < cap.max_tx_power);

        // That peer walks away to the edge of decodability: zero surplus. This is a DECISION to
        // transmit at full power, not an absence of one.
        let far_dbm = policy.decide_power_dbm(&cap, 4, Some(-90));
        let far_idx = policy.decide_power(&cap, 4, Some(-90));
        assert_eq!(
            far_dbm,
            Some(20),
            "must climb back to the ceiling, not return None"
        );
        assert_eq!(far_idx, Some(cap.max_tx_power));

        // Genuinely no measurement is still, correctly, no opinion.
        assert_eq!(policy.decide_power_dbm(&cap, 4, None), None);
        assert_eq!(policy.decide_power(&cap, 4, None), None);
    }

    /// ★ The index back-off must be rendered with the RADIO'S measured dB-per-step, not a global
    /// constant. MEASURED: 0.22 dB/step on the a81a and 0.125 on the RTL8733BU, against the old
    /// hardcoded 0.5 — so the same decided back-off is 27 index steps on one part and 48 on
    /// another, and the constant was 2x/4x wrong respectively.
    #[test]
    fn index_backoff_uses_the_parts_own_measured_scale() {
        let policy = RadioPolicy::default();
        let mcs = 4;
        // Pick an RSSI that yields a known back-off through the shared helper, so the test states
        // the CONVERSION property and does not re-encode the threshold table.
        // -70 dBm gives a modest surplus rather than the 18 dB cap, so neither scale saturates.
        let rssi = Some(-70i8);
        let backoff = policy
            .power_backoff_db(mcs, rssi)
            .expect("a mid peer has surplus");

        let mk = |db_per_idx: f32| {
            let mut cap = RadioCapability::wifi_monitor_5ghz(vec![36]);
            // 127, not 63: at 0.125 dB/step an 18 dB back-off is 144 steps, so a 63-index scale
            // saturates and the two parts would look identical. The saturation is real and correct
            // on hardware; it just hides the property under test.
            cap.max_tx_power = 127;
            cap.db_per_power_idx = Some(db_per_idx);
            cap.power_actuated = true;
            cap
        };
        let steps =
            |cap: &RadioCapability| cap.max_tx_power - policy.decide_power(cap, mcs, rssi).unwrap();
        assert!(
            (backoff / 0.125).round() <= 127.0,
            "test must not saturate: {backoff} dB / 0.125 exceeds the scale"
        );

        let a81a = steps(&mk(0.22));
        let rtl8733b = steps(&mk(0.125));
        assert_eq!(a81a as f32, (backoff / 0.22).round());
        assert_eq!(rtl8733b as f32, (backoff / 0.125).round());
        assert!(
            rtl8733b > a81a,
            "a finer scale must take MORE index steps for the same dB: {rtl8733b} vs {a81a}"
        );
        // The plan's acceptance numbers, stated concretely: a 6 dB back-off is 27 index steps on
        // the a81a and 48 on the RTL8733BU. The retired global constant made both 12.
        if (backoff - 6.0).abs() < f32::EPSILON {
            assert_eq!((a81a, rtl8733b), (27, 48));
        }
    }

    /// ☠ A radio whose power knob reaches no silicon must get no power decision at all.
    /// MEASURED true of the MT7612U and MT7921AU. Before `power_actuated` existed they accepted
    /// every back-off, `apply_knobs` recorded it, and the bandit was rewarded for a footprint
    /// reduction that never physically happened.
    #[test]
    fn a_radio_with_no_actuator_gets_no_power_decision() {
        let policy = RadioPolicy::default();
        let mut cap = RadioCapability::wifi_monitor_5ghz(vec![36]);
        cap.max_tx_power = 63;
        cap.db_per_power_idx = Some(0.5);
        cap.power_actuated = false;
        assert_eq!(policy.decide_power(&cap, 4, Some(-40)), None);

        // ...and neither does one whose scale has never been measured: guessing the units is
        // indistinguishable from deciding, and gets rewarded as a decision.
        cap.power_actuated = true;
        cap.db_per_power_idx = None;
        assert_eq!(policy.decide_power(&cap, 4, Some(-40)), None);
    }

    /// ☠ The back-off must never cross the part's monotone floor. MEASURED on the a81a: below
    /// index 20 the commanded power INVERTS and peaks ~11 dB above calibrated max — a "back-off"
    /// that shouts into the channel it was protecting.
    #[test]
    fn backoff_stops_at_the_inversion_floor() {
        let policy = RadioPolicy::default();
        let mut cap = RadioCapability::wifi_monitor_5ghz(vec![36]);
        cap.max_tx_power = 63;
        cap.db_per_power_idx = Some(0.22); // 18 dB max back-off => ~82 steps, well past the floor
        cap.min_tx_power = Some(20);
        cap.power_actuated = true;
        let idx = policy
            .decide_power(&cap, 0, Some(-20))
            .expect("huge surplus");
        assert!(idx >= 20, "walked past the inversion floor to {idx}");
    }

    /// ★ Spatial reuse is ONE decision with two halves. Whenever the policy trims transmit power
    /// it must also make this node less deferential by the same amount — otherwise it has only
    /// made itself smaller: still yielding the medium to every distant transmitter it hears, with
    /// none of the concurrency the trim was for.
    /// ★ **The bound and the decision must not drift.** `DEFER_THRESHOLD_DBM_BAND` is what the
    /// actuator will apply; this asserts it is exactly what `decide_edcca_threshold_dbm` can
    /// produce, so tightening one without the other cannot silently start clamping real decisions
    /// (or stop bounding a forged one).
    ///
    /// Falsified by changing either endpoint of the band, or `MAX_BACKOFF_DB`, on its own.
    #[test]
    fn the_actuator_band_is_exactly_what_the_policy_can_decide() {
        let (lo, hi) = crate::plan::DEFER_THRESHOLD_DBM_BAND;
        assert_eq!(
            lo, EDCCA_L2H_BASE_DBM,
            "the band's floor is the vendor default"
        );
        assert_eq!(
            i16::from(hi) - i16::from(lo),
            MAX_BACKOFF_DB as i16,
            "the band's span is the most power the policy will ever give back"
        );
        // And the emitted values really do land inside it, at both extremes of the input range.
        let policy = RadioPolicy::default();
        for mcs in 0..=9u8 {
            for rssi in -100..=-20i8 {
                if let Some((l2h, h2l)) = policy.decide_edcca_threshold_dbm(mcs, Some(rssi)) {
                    assert!(
                        (lo..=hi).contains(&l2h),
                        "mcs {mcs} rssi {rssi} emitted l2h {l2h} outside {lo}..={hi}"
                    );
                    assert_eq!(
                        crate::plan::clamp_defer_threshold(l2h, h2l),
                        ((l2h, h2l), false),
                        "a real decision must pass the actuator bound untouched"
                    );
                }
            }
        }
    }

    #[test]
    fn the_two_halves_of_spatial_reuse_move_together() {
        let policy = RadioPolicy::default();
        let mcs = 4;

        // Surplus margin: trim power AND stop deferring so readily.
        let strong = Some(-40i8);
        let trim = policy
            .power_backoff_db(mcs, strong)
            .expect("a strong peer has surplus");
        assert_eq!(policy.decide_rx_gain(mcs, strong), Some(RxGain::Reduced));
        let (l2h, h2l) = policy
            .decide_edcca_threshold_dbm(mcs, strong)
            .expect("surplus licenses a higher floor");
        assert_eq!(
            i16::from(l2h) - i16::from(EDCCA_L2H_BASE_DBM),
            trim.round() as i16,
            "the defer floor must rise by exactly the dB the power fell"
        );
        assert_eq!(h2l, l2h - EDCCA_HYSTERESIS_DB);

        // A marginal link: hand the front end back, claim no reuse.
        let weak = Some(-90i8);
        assert_eq!(policy.decide_rx_gain(mcs, weak), Some(RxGain::Auto));
        assert_eq!(policy.decide_edcca_threshold_dbm(mcs, weak), None);

        // No measured peer: no opinion at all, on either half.
        assert_eq!(policy.decide_rx_gain(mcs, None), None);
        assert_eq!(policy.decide_edcca_threshold_dbm(mcs, None), None);
    }

    /// ⚠ A struggling link must never be answered with `Boosted`. Extra front-end gain on a
    /// marginal link is as likely to desense as to help, and nothing in this tree has MEASURED the
    /// delta on any Wi-Fi part — so the policy must not reach for it.
    #[test]
    fn a_weak_link_is_never_boosted() {
        let policy = RadioPolicy::default();
        for rssi in [-70i8, -80, -85, -90, -95] {
            assert_ne!(
                policy.decide_rx_gain(4, Some(rssi)),
                Some(RxGain::Boosted),
                "boosted at rssi {rssi}"
            );
        }
    }

    /// A radio with no dBm axis must still get no dBm opinion, however strong the peer — the
    /// index path is the only one that may speak for it.
    #[test]
    fn no_dbm_axis_means_no_dbm_decision() {
        let policy = RadioPolicy::default();
        let cap = RadioCapability::wifi_monitor_2ghz_1ss((1..=13).collect());
        assert_eq!(cap.tx_power_dbm, None);
        assert_eq!(policy.decide_power_dbm(&cap, 4, Some(-35)), None);
    }
    use super::*;
    use crate::report::{ADV_PHY_1M, ADV_PHY_2M, ADV_PHY_CODED};
    use crate::sense::{MediumState, NeighborReport};

    fn medium_with(caps: &[u8]) -> MediumState {
        let mut m = MediumState::default();
        for (i, c) in caps.iter().enumerate() {
            m.observe_report(
                i as u64 + 1,
                NeighborReport {
                    heard_prefixes: vec![],
                    spectrum: vec![],
                    max_rx_mcs: crate::report::FULL_RX_MCS,
                    max_adv_phy: *c,
                    ts_ms: 100,
                },
            );
        }
        m
    }

    /// One legacy-only neighbour pins the whole group to 1M, however urgent the traffic and however
    /// capable everyone else is. This is the property the whole mechanism exists for: a coded advert
    /// would not reach that neighbour at all.
    #[test]
    fn one_legacy_only_neighbour_pins_the_group_to_1m() {
        let m = medium_with(&[ADV_PHY_CODED, ADV_PHY_CODED, ADV_PHY_1M]);
        for p in [Priority::Bulk, Priority::Normal, Priority::Urgent] {
            assert_eq!(
                decide_adv_phy(&m, &ctx_at(0, p), ADV_PHY_CODED, 100),
                ADV_PHY_1M
            );
        }
    }

    /// With an all-capable group, urgency buys reach and bulk buys airtime.
    #[test]
    fn intent_picks_within_the_group_floor() {
        let m = medium_with(&[ADV_PHY_CODED, ADV_PHY_CODED]);
        assert_eq!(
            decide_adv_phy(&m, &ctx_at(0, Priority::Urgent), ADV_PHY_CODED, 100),
            ADV_PHY_CODED
        );
        assert_eq!(
            decide_adv_phy(&m, &ctx_at(0, Priority::Bulk), ADV_PHY_CODED, 100),
            ADV_PHY_2M
        );
        assert_eq!(
            decide_adv_phy(&m, &ctx_at(0, Priority::Normal), ADV_PHY_CODED, 100),
            ADV_PHY_1M
        );
    }

    /// Our own transmit capability is a floor too — a radio that cannot emit coded must not be told to.
    #[test]
    fn own_capability_bounds_the_choice() {
        let m = medium_with(&[ADV_PHY_CODED]);
        assert_eq!(
            decide_adv_phy(&m, &ctx_at(0, Priority::Urgent), ADV_PHY_1M, 100),
            ADV_PHY_1M
        );
        assert_eq!(
            decide_adv_phy(&m, &ctx_at(0, Priority::Urgent), ADV_PHY_2M, 100),
            ADV_PHY_1M
        );
    }

    /// No reports = an UNKNOWN neighbourhood, not an empty one. Silence must not be read as
    /// permission to use a PHY that would exclude whoever is actually out there.
    #[test]
    fn unknown_neighbourhood_falls_back_to_the_universal_phy() {
        let m = MediumState::default();
        assert_eq!(
            decide_adv_phy(&m, &ctx_at(0, Priority::Urgent), ADV_PHY_CODED, 100),
            ADV_PHY_1M
        );
    }

    /// A neighbour that has gone stale must stop constraining the group — otherwise one departed
    /// legacy node holds everyone at 1M forever.
    #[test]
    fn stale_neighbours_stop_constraining() {
        let m = medium_with(&[ADV_PHY_CODED, ADV_PHY_1M]);
        let long_after = 100 + 10_000_000;
        assert_eq!(
            decide_adv_phy(&m, &ctx_at(0, Priority::Urgent), ADV_PHY_CODED, 100),
            ADV_PHY_1M
        );
        assert_eq!(
            decide_adv_phy(&m, &ctx_at(0, Priority::Urgent), ADV_PHY_CODED, long_after),
            ADV_PHY_1M,
            "with every neighbour stale the fold is None, which must still mean the universal PHY"
        );
    }
}
