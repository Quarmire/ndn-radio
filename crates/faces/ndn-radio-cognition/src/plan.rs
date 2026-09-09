//! The **act** side — what the policy emits and the face applies.
//!
//! MRMC-native: a [`RadioPlan`] is a *per-radio allocation* (which radios carry a
//! named object, on which channels, with what parameters, replicated for
//! diversity or split across a coding generation), **plus** the CCLF-style
//! relay/suppress decision and a cross-node *consistency digest* so overhearers
//! converge on a compatible plan instead of fighting. The single-radio case is
//! the degenerate one-allocation plan.

use crate::policy::{NameContext, Priority};
use crate::sense::RadioId;
use std::sync::atomic::{AtomicU64, Ordering};

/// ★ **The energy-detect carrier-sense override, and the only class privilege that reaches silicon.**
///
/// `edcca_ignore = true` tells the chip to stop deferring to a busy channel and transmit anyway. It
/// is not a hint: it reaches `RadioKnobs::set_edcca_ignore` and lands as real register writes on
/// five parts (`0x520[15]`/`0x524[11]` on the RTL88xx, the RTL8733B and mt76 equivalents, the
/// ath9k_htc path, and the LoRa firmware's LBT toggle). A caller that can set it has taken the
/// medium from every other node in earshot.
///
/// So it is **derived, never asserted**, exactly like [`Priority`] itself. The field is private and
/// the sole route to `true` is [`ignoring_edcca`](Self::ignoring_edcca), which requires a
/// [`NameContext`] a [`ClassAuthority`](crate::ClassAuthority) already raised to
/// [`Priority::Urgent`]. An external crate previously reached the same silicon by writing
/// `TxParams { edcca_ignore: true, .. }` and handing it to a public actuator — SKIPPING the class
/// rather than laundering it — and that literal no longer compiles.
///
/// ⚠ **What this does and does not close.** It closes the struct literal, which is what the audit
/// found. It does NOT make the override a capability: a linked crate can still write its own
/// four-line `ClassAuthority` returning `Urgent` (see [`ClassAuthority`](crate::ClassAuthority)'s
/// own note), and `ndn-radio-drivers` exposes `set_edcca_ignore` as a `pub fn` on a
/// publicly-constructible backend, which nothing in this crate can reach. The threat closed is
/// accidental self-assertion and drift — the same threat, and the same wall, as every other class
/// decision in this tree. Nothing here defends against a hostile in-process crate holding the radio
/// handle, and no honest reading of it should claim otherwise.
///
/// The escalation is COUNTED where it actuates: see [`ledger`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Contention {
    ignore_edcca: bool,
}

impl Contention {
    /// Defer to a busy medium — ordinary carrier sense, and the default for every transmission.
    pub const fn deferring() -> Self {
        Self {
            ignore_edcca: false,
        }
    }

    /// Ask to transmit into a busy channel. **GRANTED only for a [`Priority::Urgent`] ceiling**;
    /// for any other class this leaves carrier sense armed rather than failing, matching
    /// [`ClassCeiling::capped_to`](crate::ClassCeiling::capped_to)'s "lower, never raise" shape.
    ///
    /// The medium condition (is the channel actually busy?) is the POLICY's to decide and is not
    /// checked here — this type owns the authority half only.
    #[must_use]
    pub fn ignoring_edcca(self, ctx: &NameContext) -> Self {
        Self {
            ignore_edcca: ctx.priority() == Priority::Urgent,
        }
    }

    /// Whether this transmission ignores energy-detect carrier sense.
    pub const fn edcca_ignore(self) -> bool {
        self.ignore_edcca
    }
}

/// The band a clear-channel (defer) threshold may occupy, in true dBm, as `(min, max)` for the
/// busy (`l2h`) edge — **the range the policy can actually decide**, and therefore the range an
/// actuator will apply.
///
/// `min` is the vendor default the Realtek parts boot at; `max` is that plus the most transmit
/// power the policy will ever give back
/// (`RadioPolicy::decide_edcca_threshold_dbm` raises the floor by exactly the dB it trimmed).
///
/// ☠ This bound is why sealing [`Contention`] alone would have been theatre. `edcca_threshold_dbm`
/// is the GRADED FORM OF THE SAME DECISION ON THE SAME CHIP, it carried no flag anyone was
/// watching, and `LibUsbRtl88xxBackend::set_edcca_threshold` range-checks nothing — it encodes
/// `((dbm + 110 + 0x80) & 0xff)` straight into `0x84c`, so `Some((17, 9))` writes `0xff`: the
/// highest threshold the register holds, i.e. *the channel is never busy*. That is
/// `edcca_ignore: true` reached through a field with no gate on it. The field is deliberately left
/// public — it is a real number in real units that any class may claim once it has MEASURED the
/// margin — and bounded where it actuates instead. (The `0xff` claim is derived from the encoder
/// arithmetic in the driver, NOT from a register read-back on hardware.)
pub const DEFER_THRESHOLD_DBM_BAND: (i8, i8) = (-75, -57);

/// Clamp a decided `(l2h, h2l)` defer threshold into [`DEFER_THRESHOLD_DBM_BAND`], preserving the
/// downward hysteresis. Returns the pair to apply and whether it had to be moved.
///
/// **The one definition every actuator uses**, so the bound and the decision cannot drift.
pub fn clamp_defer_threshold(l2h: i8, h2l: i8) -> ((i8, i8), bool) {
    let (lo, hi) = DEFER_THRESHOLD_DBM_BAND;
    let cl = l2h.clamp(lo, hi);
    // Hysteresis is downward and bounded by the same span the policy uses; an `h2l` above `l2h`
    // would invert the busy/idle edges.
    let ch = h2l.clamp(cl.saturating_sub(DEFER_HYSTERESIS_MAX_DB), cl);
    ((cl, ch), (cl, ch) != (l2h, h2l))
}

/// Most hysteresis (dB) between the busy and idle edges the policy ever asks for.
pub const DEFER_HYSTERESIS_MAX_DB: i8 = 8;

/// ★ **What actually reached the silicon** — the actuator-side half of the class wall.
///
/// The decision trace already records what cognition DECIDED (`control.rs`'s `decision` span, and
/// `radio.N.edcca_ignore` on `/localhost/nfd/ext/list`). What was missing is the count that would
/// DISAGREE with it: a claim entering an actuator from somewhere other than this node's policy.
///
/// House rule — prefer making a defect detectable over asserting it cannot happen. Nothing here
/// prevents anything; [`Counts::edcca_ignored`](ledger::Counts::edcca_ignored) rising while every plan in the same
/// snapshot reads `edcca_ignore=false` is a claim that did not come from this node's policy, and
/// [`Counts::defer_threshold_clamped`](ledger::Counts::defer_threshold_clamped) is sharper still — a threshold
/// outside [`DEFER_THRESHOLD_DBM_BAND`] cannot have been produced by
/// `decide_edcca_threshold_dbm` at all.
///
/// Process-global and bearer-agnostic on purpose: the Wi-Fi face is not privileged here, and the
/// LoRa face's LBT toggle counts on the same ledger.
///
/// ⚠ NOT MEASURED: no on-air run has been made against these counters; they are wired and unit
/// tested only. The counts are also not a 1:1 audit of decisions — one decision fans out to one
/// allocation per radio, and a knob is re-pushed only when it changes — so read them as "did this
/// move at all", never as an equation.
pub mod ledger {
    use super::{AtomicU64, Ordering};

    static EDCCA_IGNORED: AtomicU64 = AtomicU64::new(0);
    static DEFER_CLAMPED: AtomicU64 = AtomicU64::new(0);
    static FEC_PARITY_OVER_GEN: AtomicU64 = AtomicU64::new(0);
    static TX_POWER_CLAMPED: AtomicU64 = AtomicU64::new(0);

    /// A snapshot of the ledger.
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
    pub struct Counts {
        /// Allocations handed to an actuator carrying `edcca_ignore = true`.
        pub edcca_ignored: u64,
        /// Defer thresholds an actuator had to pull back into [`super::DEFER_THRESHOLD_DBM_BAND`].
        pub defer_threshold_clamped: u64,
        /// Link-FEC generations whose parity budget exceeded the generation size.
        ///
        /// NOT clamped, deliberately: `R > K` is a legitimate high-loss configuration and the codec
        /// already caps `K + R <= 255`.
        ///
        /// ⚠ And NOT evidence of a bypass, which this doc used to claim. `RadioPolicy` clamps to
        /// `PolicyConfig::generation_k`; the faces compare against the generation THEY were built
        /// with, and nothing ties the two. A face built with `with_link_fec(1, ..)` — K=1, i.e.
        /// repetition, which the shipped node binary does deliberately — makes every legitimate
        /// `R >= 2` count here. Read it as "parity exceeded this face's generation", nothing more.
        pub fec_parity_over_generation: u64,
        /// TX-power requests an actuator had to pull back into the radio's DECLARED range.
        ///
        /// `RadioPolicy` already clamps both forms to the capability (the index to
        /// `[min_tx_power, max_tx_power]`, the dBm to the declared `DbmRange`), so a value outside
        /// it cannot have come from cognition — the same reasoning that makes
        /// [`Self::defer_threshold_clamped`] a bypass signal. Without this the loudest escalation on
        /// the chip, "pin the part at maximum power", silently reverted the spatial-reuse back-off
        /// with nothing to disagree with it. ⚠ Counts only where the actuator was GIVEN a
        /// capability; an actuator built without one has no band and cannot bound anything.
        pub tx_power_clamped: u64,
    }

    /// Record that an actuator was handed a transmission that ignores carrier sense.
    pub fn note_edcca_ignored() {
        EDCCA_IGNORED.fetch_add(1, Ordering::Relaxed);
    }
    /// Record that an out-of-band defer threshold arrived at an actuator and was clamped.
    pub fn note_defer_threshold_clamped() {
        DEFER_CLAMPED.fetch_add(1, Ordering::Relaxed);
    }
    /// Record that a parity budget larger than the coding generation reached a FEC consumer.
    pub fn note_fec_parity_over_generation() {
        FEC_PARITY_OVER_GEN.fetch_add(1, Ordering::Relaxed);
    }
    /// Record that a TX-power request outside the radio's declared range was clamped.
    pub fn note_tx_power_clamped() {
        TX_POWER_CLAMPED.fetch_add(1, Ordering::Relaxed);
    }

    /// Read the ledger.
    pub fn counts() -> Counts {
        Counts {
            edcca_ignored: EDCCA_IGNORED.load(Ordering::Relaxed),
            defer_threshold_clamped: DEFER_CLAMPED.load(Ordering::Relaxed),
            fec_parity_over_generation: FEC_PARITY_OVER_GEN.load(Ordering::Relaxed),
            tx_power_clamped: TX_POWER_CLAMPED.load(Ordering::Relaxed),
        }
    }
}

/// Per-transmission actuator settings for **one** radio. The **bearer-agnostic** knobs every radio
/// understands live here directly; the PHY rate/robustness knobs live in [`RateParams`], a sum type
/// keyed by bearer, so a consumer matches on the bearer it is driving and *cannot* read another
/// bearer's fields. No radio's rate model is privileged — Wi-Fi's MCS and LoRa's spreading factor
/// are peer variants, not a base struct with the other bolted on. Read the PHY knobs through the
/// typed accessors ([`TxParams::mcs`], [`TxParams::spreading_factor`], …), which return a value only
/// for the matching variant. `None`/`false` means "leave at the actuator's current value".
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct TxParams {
    /// Link-FEC parity frames per generation (0/None = no link-FEC). Sized by the shared redundancy
    /// budget, discounted by receiver multiplicity. Bearer-agnostic.
    pub link_fec_redundancy: Option<u16>,
    /// ★ **How this transmission treats a busy medium** — see [`Contention`].
    ///
    /// The field is public but its CONTENTS are not: the only way to reach "transmit into a busy
    /// channel" is [`Contention::ignoring_edcca`], which requires a [`NameContext`] an authority
    /// has already raised to [`Priority::Urgent`]. `TxParams { edcca_ignore: true, .. }` — a bare
    /// struct literal that skipped the class entirely and wrote the outcome — no longer compiles.
    pub contention: Contention,
    /// TX-power index (chip TXAGC scale, higher = more power). **`None` = leave the hard-won
    /// calibrated/regulatory/PA-backoff power untouched** — only ever reduced below the calibrated
    /// max for spatial reuse, never exceeded. Bearer-agnostic.
    pub tx_power: Option<u8>,
    /// TX power on the **absolute dBm scale**, for radios that expose one
    /// ([`RadioCapability::tx_power_dbm`](ndn_radio_hal::RadioCapability::tx_power_dbm)).
    /// Same policy and same meaning as [`tx_power`](Self::tx_power) — only ever a
    /// back-off below the radio's ceiling, never an increase above it — but stated in
    /// dB of link budget rather than opaque chip index units, so it actuates
    /// identically on any bearer.
    ///
    /// The two are alternatives, not a pair to reconcile: an actuator applies this
    /// when its radio has absolute control and falls back to the index otherwise.
    /// `None` = leave the radio's current power untouched.
    pub tx_power_dbm: Option<i8>,
    /// ★ **The receive half of spatial reuse**: how sensitive this node should be, as a posture.
    ///
    /// The counterpart to [`tx_power`](Self::tx_power) and the reason a power back-off alone buys
    /// so little. Backing off TX shrinks who *hears* this node; raising the detection floor shrinks
    /// who this node *defers to*. Do only the first and a node in a dense cell still yields to
    /// every distant transmitter it can hear, so the concurrency the back-off was supposed to buy
    /// never materialises — it has simply reduced its own reach.
    ///
    /// `None` = no opinion, leave the front end where it is (including under the radio's own
    /// autonomous gain control). Bearer-agnostic: the per-part dB delta is unknowable here, which
    /// is why this is a posture rather than a number.
    pub rx_gain: Option<ndn_radio_hal::RxGain>,
    /// The clear-channel (defer) threshold in **true dBm**, as `(l2h, h2l)` — above `l2h` the
    /// medium counts as busy, below `h2l` it is idle again.
    ///
    /// The dBm-denominated form of the same decision as [`rx_gain`](Self::rx_gain), for the one
    /// radio in the fleet that expresses it in real units. Preferred where available, exactly as
    /// [`tx_power_dbm`](Self::tx_power_dbm) is preferred over the index: it means the same thing on
    /// every bearer and can be reasoned about in link budget.
    ///
    /// `None` = no opinion.
    ///
    /// ⚠ **Deliberately still a public field, and BOUNDED AT THE ACTUATOR instead** — see
    /// [`DEFER_THRESHOLD_DBM_BAND`] for why sealing [`Contention`] without this would have left an
    /// equivalent bypass wide open. A value outside the band cognition can decide is clamped where
    /// it actuates, and counted on [`ledger`]. Nothing needs permission to *have an opinion* about
    /// its own defer threshold; what needs bounding is how far that opinion may reach.
    pub edcca_threshold_dbm: Option<(i8, i8)>,
    /// Bearer-specific PHY rate/robustness knobs.
    pub rate: RateParams,
    /// **The modulation itself** — the `SetPacketType` mode this transmission wants the radio in.
    ///
    /// One level up from [`rate`](Self::rate): `rate` says how fast to run *within* a modulation,
    /// this says *which* modulation. The two are not independent — an LR2021 in
    /// [`PhyMode::Flrc`](crate::PhyMode) has no spreading factor at all, while the same silicon in
    /// [`PhyMode::Lora`](crate::PhyMode) has SF7..SF12 — which is why a switch replaces the radio's
    /// whole capability rather than patching a field of it.
    ///
    /// `None` = **leave the radio's current modulation untouched**, and that is the default and the
    /// behaviour of every plan that predates this axis. A value here is only ever a mode the radio
    /// ADVERTISED (`EVT_CAP.phy_bitmap`); [`PhyDial`](crate::PhyDial) is what decides it, with the
    /// hysteresis a disruptive, un-negotiated, both-ends-must-move switch demands.
    pub phy: Option<crate::PhyMode>,
}

// NO per-name frame-length / MTU knob lives here, and that is a measured decision
// (2026-07-16, task #27) rather than an omission.
//
// The case for one was a length-dependent PER: if longer frames are likelier to
// die, an `Urgent` name should ask for short frames and a `Bulk` name for long
// ones, and no single MTU serves both. On air, between two OPis at -52 dBm:
//
//   * `burst_fork` fixed the frame size and varied only the inter-frame gap.
//     Every cell landed 26-30/30 — 800 B and 2260 B alike, a 30-frame
//     back-to-back burst as well as one paced 4 ms apart. Per-frame p ~= 0.93
//     with no length term and no burst term.
//   * The object sweep then fit p ~= 0.93-0.98 per frame at BOTH a 1024 B and a
//     2272 B MTU. Delivery is p^n, so the only lever is minimizing n, and a
//     bigger MTU was better-or-equal in every row (4000 B: 24/30 at MTU 1024 ->
//     29/30 at 2272). There is no crossover, so there is no name-dependent
//     optimum: max MTU always wins.
//
// The 0.83 that motivated the knob was an artifact of the bench, which keyed
// reassembly on the raw LP sequence and stitched fragments of different objects
// together (ndn-packet/tests/reassembly_key.rs). Building this knob would have
// been building a control surface to dodge our own bug — the NDP bulk tier again
// (NAMED_RADIO_COURSE_CORRECTION.md §10.1). Add it if a weak-link test ever shows
// a real length term at the margin; the strong-link regime does not have one.
//
// The name-dependent lever that IS real for multi-fragment objects is
// `link_fec_redundancy` above: at 8-17 fragments even p = 0.95 leaves 40-66%
// delivery, and an outer code fixes that with no peer to ACK.

/// The bearer-specific PHY knobs. A radio matches on its own variant; there is no cross-bearer field.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub enum RateParams {
    /// No PHY knobs decided — leave the radio at its current values.
    #[default]
    None,
    /// Wi-Fi (802.11).
    Wifi(WifiRate),
    /// LoRa (sub-GHz).
    Lora(LoraRate),
}

/// Wi-Fi (802.11) PHY knobs — MCS, bandwidth, spatial streams, and robustness coding.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct WifiRate {
    /// Modulation-and-coding-scheme index.
    pub mcs: Option<u8>,
    pub vht: bool,
    pub nss: Option<u8>,
    pub short_gi: bool,
    /// Channel-bandwidth code (0=20,1=40,2=80,3=10,4=5), matching `ChannelBw`.
    pub bw: Option<u8>,
    pub stbc: bool,
    pub csd: bool,
    pub ldpc: bool,
    /// Transmit as 802.11ax (HE) — required for the two HE reach levers below. Only actuated on a radio
    /// that advertises [`RadioCapability::he_cap`](ndn_radio_hal::RadioCapability::he_cap).
    pub he: bool,
    /// HE **Dual-Carrier Modulation** — a frequency-diversity reach lever (halves rate, ~few dB robustness).
    pub dcm: bool,
    /// HE **Extended-Range Single-User** — the strongest single-frame reach lever (~2–4 dB sensitivity).
    pub er_su: bool,
    /// Target A-MSDU size in MSDUs (0/None = no aggregation).
    pub amsdu_msdus: Option<u16>,
}

/// LoRa (sub-GHz) PHY knobs — the reach/rate dial (spreading factor), coding rate, and bandwidth.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct LoraRate {
    /// Spreading factor 7–12 — the reach/rate dial (the peer of Wi-Fi's `mcs`).
    pub spreading_factor: Option<u8>,
    /// Coding rate `1`=4/5 … `4`=4/8 — a robustness/FEC dial.
    pub coding_rate: Option<u8>,
    /// Bandwidth in kHz (125/250/500). Wider = higher rate + shorter airtime (less duty) but ~3 dB
    /// less sensitivity per doubling. Like the SF, it is a **rendezvous** parameter: both ends must
    /// use the same bandwidth to decode, so it is only widened on a decision both peers reach alike.
    pub bandwidth_khz: Option<u32>,
}

/// The 802.11n/ac PHY data rate (Mbps) for a **1×1, 20 MHz, long-GI** stream at MCS `mcs` — the single
/// base ladder every rate/airtime estimate scales from `(× bw × nss × sgi)`. HT indices 0–7 come
/// straight from the canonical [`ndn_radio_hal::mcs_phy_rate_bps`] table so there is ONE source of
/// truth for them; 8–9 are the VHT 256-QAM rates the HT-only HAL table does not carry. This replaced
/// a hand-rolled `(mcs+1)·6.5` proxy that was correct only through MCS3 and under-rated everything
/// above it, and a duplicated `BASE[10]` literal in the phy-wifi scorer.
pub fn mcs_base_rate_mbps(mcs: u8) -> f32 {
    match mcs {
        8 => 78.0,  // VHT MCS8 (256-QAM 3/4), 1SS 20 MHz LGI — beyond the HT-only HAL table
        9 => 87.75, // VHT MCS9 (256-QAM 5/6)
        m => ndn_radio_hal::mcs_phy_rate_bps(m) as f32 / 1_000_000.0, // HT 0–7, canonical
    }
}

impl TxParams {
    /// Bearer-agnostic knobs plus a Wi-Fi rate.
    pub fn wifi(wifi: WifiRate) -> Self {
        Self {
            rate: RateParams::Wifi(wifi),
            ..Default::default()
        }
    }
    /// Bearer-agnostic knobs plus a LoRa rate.
    pub fn lora(lora: LoraRate) -> Self {
        Self {
            rate: RateParams::Lora(lora),
            ..Default::default()
        }
    }

    /// Whether this transmission ignores energy-detect carrier sense — see [`Contention`].
    ///
    /// A read-only view of a decision only a [`Priority::Urgent`] [`NameContext`] can make. There is
    /// deliberately no setter on `TxParams`: the class gate lives on the value, not on this struct.
    pub const fn edcca_ignore(&self) -> bool {
        self.contention.edcca_ignore()
    }

    /// Wi-Fi MCS, or `None` for a non-Wi-Fi radio.
    pub fn mcs(&self) -> Option<u8> {
        if let RateParams::Wifi(w) = &self.rate {
            w.mcs
        } else {
            None
        }
    }
    /// Wi-Fi spatial streams, or `None` for a non-Wi-Fi radio.
    pub fn nss(&self) -> Option<u8> {
        if let RateParams::Wifi(w) = &self.rate {
            w.nss
        } else {
            None
        }
    }
    /// Wi-Fi channel-bandwidth code, or `None` for a non-Wi-Fi radio.
    pub fn bw(&self) -> Option<u8> {
        if let RateParams::Wifi(w) = &self.rate {
            w.bw
        } else {
            None
        }
    }
    /// Wi-Fi VHT flag (false unless a Wi-Fi rate sets it).
    pub fn vht(&self) -> bool {
        matches!(self.rate, RateParams::Wifi(w) if w.vht)
    }
    /// Wi-Fi short-GI flag.
    pub fn short_gi(&self) -> bool {
        matches!(self.rate, RateParams::Wifi(w) if w.short_gi)
    }
    /// Wi-Fi STBC flag.
    pub fn stbc(&self) -> bool {
        matches!(self.rate, RateParams::Wifi(w) if w.stbc)
    }
    /// Wi-Fi cyclic-shift-diversity flag.
    pub fn csd(&self) -> bool {
        matches!(self.rate, RateParams::Wifi(w) if w.csd)
    }
    /// Wi-Fi LDPC flag.
    pub fn ldpc(&self) -> bool {
        matches!(self.rate, RateParams::Wifi(w) if w.ldpc)
    }
    /// Wi-Fi 802.11ax (HE) flag — the gate for the DCM / ER-SU reach levers.
    pub fn he(&self) -> bool {
        matches!(self.rate, RateParams::Wifi(w) if w.he)
    }
    /// Wi-Fi HE Dual-Carrier-Modulation reach lever.
    pub fn dcm(&self) -> bool {
        matches!(self.rate, RateParams::Wifi(w) if w.dcm)
    }
    /// Wi-Fi HE Extended-Range-SU reach lever.
    pub fn er_su(&self) -> bool {
        matches!(self.rate, RateParams::Wifi(w) if w.er_su)
    }
    /// Wi-Fi A-MSDU size, or `None` for a non-Wi-Fi radio.
    pub fn amsdu_msdus(&self) -> Option<u16> {
        if let RateParams::Wifi(w) = &self.rate {
            w.amsdu_msdus
        } else {
            None
        }
    }
    /// LoRa spreading factor, or `None` for a non-LoRa radio.
    pub fn spreading_factor(&self) -> Option<u8> {
        if let RateParams::Lora(l) = &self.rate {
            l.spreading_factor
        } else {
            None
        }
    }
    /// LoRa coding rate, or `None` for a non-LoRa radio.
    pub fn coding_rate(&self) -> Option<u8> {
        if let RateParams::Lora(l) = &self.rate {
            l.coding_rate
        } else {
            None
        }
    }
    /// LoRa bandwidth in kHz, or `None` for a non-LoRa radio.
    pub fn bandwidth_khz(&self) -> Option<u32> {
        if let RateParams::Lora(l) = &self.rate {
            l.bandwidth_khz
        } else {
            None
        }
    }

    /// The decided modulation, if this plan names one. `None` = leave the radio where it is.
    ///
    /// A plain field read rather than a variant match, because this axis is **not** keyed by
    /// bearer: an SX1262 does LoRa + GFSK, an SX1276 does LoRa + FSK + OOK and an LR2021 does
    /// fourteen modes, so "which modulation" is a question every one of them answers, while
    /// "which spreading factor" is a question only some of them have.
    pub fn phy(&self) -> Option<crate::PhyMode> {
        self.phy
    }
    /// Mutable access to the Wi-Fi rate (e.g. for the Minstrel-style probe bump), if this is Wi-Fi.
    pub fn wifi_mut(&mut self) -> Option<&mut WifiRate> {
        if let RateParams::Wifi(w) = &mut self.rate {
            Some(w)
        } else {
            None
        }
    }

    /// The exact [`McsDescriptor`](ndn_radio_hal::McsDescriptor) this decision means, when it carries a
    /// Wi-Fi rate with a decided MCS index. **The single construction site** both the face's `RatePolicy`
    /// and the medium actuator use — the write-once mapping of the decided `WifiRate` onto the HAL rate
    /// descriptor (index + short_gi/vht/nss/stbc/ldpc/he/dcm/er_su). `None` when there is no decided MCS
    /// (leave the radio's current rate) or the bearer is not Wi-Fi.
    pub fn wifi_mcs(&self) -> Option<ndn_radio_hal::McsDescriptor> {
        let index = self.mcs()?;
        Some(ndn_radio_hal::McsDescriptor {
            index,
            short_gi: self.short_gi(),
            vht: self.vht(),
            nss: self.nss().unwrap_or(1),
            stbc: self.stbc(),
            ldpc: self.ldpc(),
            he: self.he(),
            dcm: self.dcm(),
            er_su: self.er_su(),
        })
    }
}

/// How a radio's transmission relates to the others in the plan.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AllocRole {
    /// Same content on this radio too — spatial/frequency macrodiversity.
    Replicate,
    /// A distinct subset of the coding generation (heterogeneous split: e.g. bulk
    /// on Wi-Fi, long-range subset on LoRa). Receivers accumulate rank from any.
    Split,
}

/// One radio's slice of a [`RadioPlan`].
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct RadioAllocation {
    pub radio: RadioId,
    /// Channel to use / hop to before transmitting (None = stay).
    pub channel: Option<u8>,
    pub params: TxParams,
    pub role: AllocRole,
}

/// Data-centric offload directives — the on-device NDN data plane cognition turns on for a face
/// (the firmware `ndn.rs` mechanisms: dedup, Content-Store serve, name-keyed hopping). These are the
/// MECHANISM toggles cognition owns (how to spend duty-limited airtime well); the NAME sets that go
/// with them (filter / relay PREFIXES) come from the forwarder's FIB, merged in by the caller — a
/// clean split of "which mechanism" (radio policy) from "which names" (forwarding table).
///
/// This is a face-level directive (applied once per face / on role change), distinct from the
/// per-object [`RadioPlan`]. FEC/RLNC live in [`RadioPlan`] (redundancy budget + Split generations);
/// named-time lives in the RadioTime plane. See the crate docs for the full offload map.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DataPlaneConfig {
    /// Suppress duplicate names at the antenna — a repeat never crosses the host link twice.
    pub dedup: bool,
    /// Answer a repeat Interest from the on-device Content Store instead of re-fetching it end-to-end
    /// (in-network caching — the airtime-per-content win a flood mesh cannot make).
    pub cs_serve: bool,
    /// Name-keyed frequency hopping (#40) **in the on-device (LoRa/embedded) firmware data plane**: the
    /// carrier for a name is `H(name)`-derived, so both ends compute it with no negotiation. The hop
    /// FUNCTION only — a listener still needs common-view time to know WHEN to sit on a name's channel.
    /// #41's common-view clock landed as the host-side `ndn_time::RadioHwClock`, and the *host*
    /// monitor-wifi face now actuates FHSS from it (`ndn_phy_wifi::FaceScheduler`,
    /// `NDN_SCHED_HOP`). This firmware flag stays off until the *firmware* carries its own common-view
    /// clock (a separate port), not the host's — hence still gated here.
    ///
    /// ★ **This is not the only hop path any more, and it is no longer the interesting one.** A
    /// radio with its own hop sequencer takes a whole `(carrier, period)` TABLE
    /// ([`crate::name_hop_plan`] → [`RadioKnobs::set_hop_plan`](ndn_radio_hal::RadioKnobs)) and
    /// walks it *inside a packet*, at a dwell no host command and no firmware `hop_channel` call
    /// could reach. That path needs no firmware clock at all — the sequencer keeps its own time —
    /// which is why it, and not this flag, is where name-keyed hopping actually landed.
    pub hop: bool,
}

impl DataPlaneConfig {
    /// Everything inert — a plain smart-modem (matches a freshly-flashed dongle).
    pub const OFF: Self = Self {
        dedup: false,
        cs_serve: false,
        hop: false,
    };
}

/// The full cross-layer, multi-radio decision for one named object.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct RadioPlan {
    /// Which radios carry this object (empty ⇒ nothing to do / suppressed).
    pub allocations: Vec<RadioAllocation>,
    /// CCLF: this node is the elected relay for the object.
    pub relay: bool,
    /// CCLF + stop-at-rank-N: stay quiet (a non-innovative duplicate — downstream
    /// demand already satisfied / covered by others).
    pub suppress: bool,
    /// Predicted **airtime per satisfied Interest** (relative; lower is better) —
    /// the optimand, surfaced for comparison/telemetry and A/B against fixed-MCS.
    pub objective: f32,
    /// Cross-node consistency digest over the salient choices (prefix bucket +
    /// radio/channel/rate class). Independent nodes computing from the same
    /// name+demand land on the same digest — the property that would let
    /// overhearers converge and let a mismatch flag a contradictory re-transmit.
    ///
    /// ACTUATED TODAY: telemetry/observability only (surfaced on the decision span)
    /// and a determinism check that two nodes agree. NOT YET WIRED: nothing parses a
    /// peer's digest off the wire to suppress or converge — that RX-path consumer is
    /// the future work this digest is built for (decided-but-unactuated until then).
    pub consistency: u64,
}

impl RadioPlan {
    /// A do-nothing / suppressed plan.
    pub fn suppressed(consistency: u64) -> Self {
        Self {
            suppress: true,
            consistency,
            ..Default::default()
        }
    }

    /// The degenerate single-radio plan.
    pub fn single(radio: RadioId, channel: Option<u8>, params: TxParams) -> Self {
        Self {
            allocations: vec![RadioAllocation {
                radio,
                channel,
                params,
                role: AllocRole::Replicate,
            }],
            ..Default::default()
        }
    }

    pub fn allocation_for(&self, radio: RadioId) -> Option<&RadioAllocation> {
        self.allocations.iter().find(|a| a.radio == radio)
    }
}

/// Applied to one radio by its face (the actuator API the control plane drives).
/// The `WifiPhy`/backend implements this over its knobs; a LoRa/BLE face
/// implements what it can; an RX-only SDR sensor implements none of the TX side.
/// The `LinkServiceFeature` splits a [`RadioPlan`] across the node's face group
/// and calls `apply` on each radio's [`RadioAllocation`] (channel + params).
pub trait RadioActuators {
    fn radio_id(&self) -> RadioId;
    /// Apply this radio's slice of the plan: tune the channel (if set), then set the
    /// per-transmission [`TxParams`]. Implementations apply what they can and ignore
    /// the rest.
    ///
    /// ★ **This is the LAST place a decision can be bounded, and some bounds live only here.**
    /// `apply` takes a `RadioAllocation`, not a [`NameContext`] — deliberately, because it is the
    /// act plane and has no business re-deciding — so an actuator cannot re-check a class. The
    /// division of labour is therefore:
    ///
    /// * **Class privilege** is enforced on the VALUE, before it ever gets here: [`Contention`] is
    ///   sealed and only an authorised `Urgent` name produces the carrier-sense override.
    /// * **Range** is enforced HERE, because a range is a property of the radio and not of the
    ///   name: an implementation MUST bound `edcca_threshold_dbm` with
    ///   [`clamp_defer_threshold`] before it reaches a knob (`ndn-phy-wifi`'s `apply_knobs` is the
    ///   reference, and the LoRa face mirrors it). A driver that range-checks nothing — the
    ///   Realtek EDCCA encoder does not — makes this the only bound there is.
    /// * **Visibility** is enforced here too: a claim on the shared medium is tallied on
    ///   [`ledger`] as it goes past, so it can be compared against what cognition says it decided.
    fn apply(&self, alloc: &RadioAllocation) -> Result<(), RadioError>;
}

#[derive(Debug, Clone)]
pub struct RadioError(pub String);

impl core::fmt::Display for RadioError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "radio actuator error: {}", self.0)
    }
}
impl std::error::Error for RadioError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{ClassAuthority, ClassCeiling};

    struct Grants(Priority);
    impl ClassAuthority for Grants {
        fn ceiling_for(&self, _prefix_hash: u64) -> Priority {
            self.0
        }
    }
    fn granted(p: Priority) -> NameContext {
        NameContext::new(0xAB).with_ceiling(ClassCeiling::authorised(&Grants(p), 0xAB))
    }

    /// ★ **The audit's scenario, as a test.** An external crate compiled
    /// `TxParams { edcca_ignore: true, tx_power: Some(63), .. }` and handed it to a public
    /// actuator — SKIPPING the class rather than laundering it — and energy-detect carrier sense
    /// went off at the chip. That literal no longer exists; this asserts the replacement is the
    /// class gate and not just a rename.
    ///
    /// Falsified by making `ignoring_edcca` set the flag unconditionally: the first three
    /// assertions fail.
    #[test]
    fn only_an_authorised_urgent_name_can_turn_off_carrier_sense() {
        // The default is to defer, and that is what an unauthorised name gets.
        assert!(!TxParams::default().edcca_ignore());
        assert!(
            !Contention::deferring()
                .ignoring_edcca(&NameContext::new(0xAB))
                .edcca_ignore(),
            "a name with no authority cannot buy the override"
        );
        assert!(
            !Contention::deferring()
                .ignoring_edcca(&granted(Priority::Bulk))
                .edcca_ignore(),
            "Bulk SELECTS rendezvous parameters; it is not a route to privilege"
        );
        assert!(
            !Contention::deferring()
                .ignoring_edcca(&granted(Priority::Normal))
                .edcca_ignore()
        );
        assert!(
            Contention::deferring()
                .ignoring_edcca(&granted(Priority::Urgent))
                .edcca_ignore(),
            "an authority's Urgent ceiling is the one thing that grants it"
        );
        // And the grant is not sticky: `capped_by` lowers with no inverse, so a context that has
        // given the class up cannot re-buy the override afterwards.
        assert!(
            !Contention::deferring()
                .ignoring_edcca(&granted(Priority::Urgent).capped_by(Priority::Normal))
                .edcca_ignore(),
            "a capped context must not still reach the override"
        );
    }

    /// ☠ The equivalent bypass with no flag on it: `edcca_threshold_dbm` is the graded form of the
    /// same decision on the same chip, and the Realtek encoder range-checks nothing — `(17, 9)`
    /// writes `0xff`, i.e. the channel is never busy. Bounded to the range the policy can decide.
    ///
    /// Falsified by making `clamp_defer_threshold` return its input unchanged.
    #[test]
    fn a_defer_threshold_outside_what_the_policy_can_decide_is_clamped() {
        let (lo, hi) = DEFER_THRESHOLD_DBM_BAND;

        // The audit's value: "never busy" becomes "the loudest reuse claim the policy could make".
        let ((l2h, h2l), moved) = clamp_defer_threshold(17, 9);
        assert!(moved);
        assert_eq!(l2h, hi, "clamped to the top of the decidable band");
        assert!(h2l <= l2h && h2l >= l2h - DEFER_HYSTERESIS_MAX_DB);

        // The other end: an absurdly low floor would make the node defer to nothing... by deferring
        // to everything, which is self-harm, but it is still not a decision the policy can produce.
        let ((l2h, _), moved) = clamp_defer_threshold(-120, -128);
        assert!(moved);
        assert_eq!(l2h, lo);

        // Everything the policy CAN emit passes through untouched — the bound must not perturb a
        // legitimate decision.
        for backoff in 0..=18i8 {
            let want = (lo + backoff, lo + backoff - DEFER_HYSTERESIS_MAX_DB);
            let (got, moved) = clamp_defer_threshold(want.0, want.1);
            assert_eq!(got, want, "policy-reachable value perturbed: {want:?}");
            assert!(!moved);
        }
    }

    #[test]
    fn single_plan_degenerate() {
        let p = RadioPlan::single(RadioId(0), Some(149), TxParams::default());
        assert_eq!(p.allocations.len(), 1);
        assert!(p.allocation_for(RadioId(0)).is_some());
        assert!(p.allocation_for(RadioId(1)).is_none());
        assert_eq!(p.allocations[0].role, AllocRole::Replicate);
    }

    #[test]
    fn suppressed_plan() {
        let p = RadioPlan::suppressed(42);
        assert!(p.suppress);
        assert!(p.allocations.is_empty());
        assert_eq!(p.consistency, 42);
    }
}
