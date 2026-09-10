//! # ndn-radio-cognition — cross-layer cognitive control plane for the named-data radio
//!
//! The integrating layer that turns the radio's PHY/link **actuators** (MCS, BW,
//! STBC/CSD/LDPC, A-MSDU, EDCCA, link-FEC, channel) and **sensors** (RSSI, PER,
//! occupancy, neighbor reports) into a **system**: a closed-loop, cooperative,
//! name-driven control plane — a *data-centric MAC* — rather than a drawer of
//! static point-to-point knobs (which would make the radio wfb-ng).
//!
//! Design: the note this used to cite
//! (`.claude/notes/named-radio/cross-layer-cognitive-stack-2026-06-15.md`) was never
//! in the workspace — that directory does not exist and the file is not recoverable
//! (checked 2026-07-16). The surviving statement of the argument is
//! `ndn-phy-wifi/docs/RADIO_SUBSYSTEM.md` §2-§3, and the doctrine it
//! answers to is `ndn-face-wifi-aware/docs/NAMED_RADIO_COURSE_CORRECTION.md`.
//!
//! ## The loop
//! - **SENSE** ([`MediumState`]) — the unified, **MRMC-native** cross-layer medium
//!   state, keyed by `(RadioId, Channel)`, fused from our own radios + neighbors'
//!   named/signed reports.
//! - **DECIDE** ([`RadioPolicy::decide`]) — measured-adaptive; reads a
//!   [`MediumView`] + the [`NameContext`] and emits a [`RadioPlan`], optimizing the
//!   single optimand **airtime per satisfied Interest over the demand set**.
//! - **ACT** ([`RadioActuators`]) — the face applies its slice of the plan.
//!
//! ## Resolved doctrine baked into the types
//! - **Multi-radio / multi-channel from day one.** State is `(RadioId, Channel)`-keyed
//!   and a [`RadioPlan`] is a *per-radio allocation*; single-radio is the degenerate
//!   one-entry case. [`RadioCapability`] is the single switch between homogeneous
//!   (NDNPIPES) and heterogeneous (NDN-CRAHNs: LoRa + Wi-Fi) regimes.
//! - **One plane, not two.** The relay/suppress decision is the CCLF-style election;
//!   the actuators are its widened output vocabulary, not a parallel subsystem.
//! - **Innovation-aware suppression** unifies CCLF (drop duplicate) and
//!   stop-at-rank-N (transmit only if it adds rank to a rank-deficient downstream) —
//!   the receive-side (macrodiversity) and transmit-side (medium-sharing) cooperation
//!   are two views of one predicate.
//! - **Redundancy is ONE budget**, sized from the residual left below each layer,
//!   discounted by macrodiversity receiver multiplicity, biased by the measured
//!   re-Interest rate (the real ARQ signal), targeting post-pooling rank deficit.
//! - **SDR is the richest RX-only [`RadioCapability`]** (a spectrum instrument),
//!   not a new PHY: it drops into the sense bus and upgrades the faked occupancy
//!   input. The SDR-as-modem / FHSS-by-name arc stays the frontier.
//!
//! ## Purity
//! Pure / sans-IO / runtime-agnostic (like `ndn-signals-core`). The engine↔face I/O
//! — feeding the bus from PIT/CS/CCLF and driving the face actuators — lives in the
//! `LinkServiceFeature` seam, **not** here, so the logic stays unit-testable and
//! face-agnostic.
//!
//! One documented carve-out: [`spawn_occupancy_sampler`] polls a radio's frame-free
//! activity counter on a background task, so it needs a runtime. It is here rather than in
//! a PHY crate because it is **bearer-agnostic** — it speaks only `RadioKnobs` and the sense
//! bus, and putting it in `ndn-phy-wifi` forced a LoRa PHY to depend on the Wi-Fi crate to
//! sense its own channel. It is gated behind the default `occupancy-sampler` feature; take
//! `default-features = false` for the pure, runtime-free core.

// Clippy release-triage: deferred minor style lints in the radio-face code.
#![allow(clippy::unnecessary_sort_by)]

pub use ndn_radio::mac::{coop, dos, ephemeral_id, name, prefix_hash, schedule};
mod calibrate;
mod contextual;
mod demand;
mod hop;
mod occupancy;
mod phy;
mod plan;
mod policy;
mod report;
mod sense;
mod strategy;

pub use calibrate::{
    RateCalibrator, RateThresholds, STATIC_REQ_RSSI, STATIC_REQ_RSSI_SF, SfCalibrator,
    SfThresholds, default_sf_thresholds, default_thresholds, pick_sf, pick_sf_hysteretic,
};
pub use contextual::{
    ARMS, Arm, ArmChoice, Context, ContextualBandit, FOOTPRINT_LAMBDA, MISS_PENALTY, apply_arm,
    reward,
};
pub use demand::DemandTracker;
/// The name-keyed hop plan (#40) — a `(channel, dwell)` table derived from a name under the
/// shared #44 keyspace, for a radio whose modem walks a hop table itself. See `src/hop.rs`.
pub use hop::{HOP_KEY_DOMAIN, HopPlan, MAX_HOP_COUPLES, carrier_grid, name_hop_plan};
#[cfg(feature = "occupancy-sampler")]
pub use occupancy::spawn_occupancy_sampler;
/// Frame-free occupancy sensing (#30) — bearer-agnostic, so a LoRa/BLE PHY reaches it
/// without depending on the Wi-Fi crate. `spawn_occupancy_sampler` needs the
/// `occupancy-sampler` feature (default on); the pure parts never do.
pub use occupancy::{OccupancySink, activity_rate};
/// The modulation axis — `SetPacketType` as a knob cognition decides, with the hysteresis that
/// makes a PHY switch a rare, deliberate, reversible move. See `src/phy.rs`.
pub use phy::{
    PhyDial, PhyDialConfig, PhyHold, PhyRole, fastest_phy, parse_phy_mode, phy_mode_name,
    phy_peak_bps, phy_role, ranked_phys, rendezvous_phy,
};
pub use plan::{
    AllocRole, Contention, DEFER_HYSTERESIS_MAX_DB, DEFER_THRESHOLD_DBM_BAND, DataPlaneConfig,
    LoraRate, RadioActuators, RadioAllocation, RadioError, RadioPlan, RateParams, TxParams,
    WifiRate, clamp_defer_threshold, ledger, mcs_base_rate_mbps,
};
pub use policy::{
    ClassAuthority, ClassCeiling, DecisionRationale, DemandRank, NameContext, PolicyConfig,
    Priority, RadioPolicy, RadioRationale, SuppressReason, decide_adv_phy,
};
pub use report::{
    ADV_PHY_1M, ADV_PHY_2M, ADV_PHY_CODED, FULL_RX_MCS, LEGACY_ONLY_RX, MAX_ENTRIES, REPORT_MAGIC,
    ReceptionReport, SINGLE_STREAM_HT_RX_MCS, decode_report, encode_report,
};
pub use schedule::{HopSchedule, LeaseClass, SlotSchedule, wifi_airtime_us};
pub use sense::{
    Band, ChannelOccupancy, DEFAULT_SATURATION_FPS, DUTY_WINDOW_MS, Demand, Ewma, HopCapability,
    HopControl, HopPeriodUnit, LinkResidual, MediumState, MediumView, NeighborReport, PhyMode,
    PhyModeSet, RadioCapability, RadioId, RadioKind, RateCapability, lora_airtime_ms,
};
pub use strategy::RadioStrategy;

/// Re-exported so the `LinkServiceFeature` can translate the face's decoded
/// `LinkSignals` into [`MediumState::observe_rx`] inputs.
pub use ndn_signals_core::LinkSignals;
