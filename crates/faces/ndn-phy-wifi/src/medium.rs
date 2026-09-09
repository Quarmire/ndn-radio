//! **The medium is the face.** A single NDN [`Face`] over the *wireless medium*,
//! backed by one or more **radio capabilities** — not one face per radio.
//!
//! Wired connectivity is point-to-point: a UDP/TCP/serial face *is* a link to one
//! peer, so "one face per connection" is right. Wireless is not that. A broadcast
//! transmission reaches every neighbour in range at once, and a node may reach that
//! same neighbourhood through *several* radios (a 5 GHz Wi-Fi monitor NIC, a HaLow
//! sub-GHz NIC, a LoRa modem, …). The medium — the shared air — is the face; each
//! radio is an **added capability** the node has for reaching it, not a separate
//! network face with its own FIB entry and its own PIT.
//!
//! [`RadioMediumFace`] is that: it owns a set of [`RadioBearer`]s (each a
//! [`WifiRadio`] driver + its declared [`RadioCapability`] + the per-radio
//! [`TxParams`] cell the cognitive control plane actuates), and presents them to
//! the engine as **one** face:
//!
//! - **RX is a union.** A reader task per radio feeds one inbound stream, so a
//!   packet heard on *any* capability is delivered once to the engine. Per-frame
//!   RSSI/rate flow to the [`SignalStore`] keyed by the medium face id, closing the
//!   sense→decide loop exactly as the single-radio face does.
//! - **TX fans out.** Each outbound frame is injected on every bearer at that
//!   bearer's decided rate ([`TxParams`] from the control plane, robust default
//!   otherwise). On a broadcast medium, replicating one frame across radios *is*
//!   spatial/frequency diversity. With one bearer this collapses to exactly the
//!   [`WifiPhy`](crate::WifiPhy) behaviour.
//!
//! The cognitive plane ([`RadioControl`](crate::RadioControl)) is already
//! medium-shaped — it holds a `MediumState` of *N* registered radios and decides a
//! `RadioPlan` that allocates a transmission across them. This face is the data
//! plane that matches it. Adding LoRa/BLE/HaLow later is *"register another
//! capability,"* never *"stand up another face."*
//!
//! v1 scope: broadcast addressing and diversity fan-out (every allocated bearer
//! transmits). The plan-driven *primary-vs-replica* refinement (transmit on the
//! subset the `RadioPlan` selects, honouring per-radio channel) remains a follow-up; the
//! abstraction (one face, N capabilities, union RX, fan-out TX) is complete here.
//!
//! The feature gap versus [`WifiPhy`] that this note used to describe is closed (#82): the named
//! airtime lease and link-FEC arrived earlier, and A-MSDU — the last genuinely one-sided feature —
//! landed in part 2. What remains of #82 is the structural half: `WifiPhy` becoming a one-bearer
//! construction of this face rather than a parallel implementation of it.

use portable_atomic::AtomicU64;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU16, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bytes::Bytes;
use ndn_coding::link_fec_bridge::LinkFecBridge;
use tokio::sync::{Mutex as AsyncMutex, mpsc};
use tokio::task::JoinHandle;

use crate::RadioControl;
use ndn_radio_cognition::ephemeral_id::{ClassCommitmentWatch, IdDeconfliction};
use ndn_radio_cognition::{NameContext, RadioActuators, RadioAllocation, RadioError};
use ndn_signals_core::{LinkSignals, NodeSignals, SignalStore, SignalView};
use ndn_transport::link_service::{LinkServiceFeature, LpLinkService};
use ndn_transport::{
    Face, FaceAddr, FaceKind, FacePersistency, LinkType, MtuError, PersistencyError, Transport,
};

use crate::{
    BROADCAST, Bandwidth, DbmRange, EphemeralSource, FaceError, FaceId, FrameIo, InjectFrame,
    MONITOR_MTU, McsDescriptor, OpenRadio, RadioCapability, RadioKnobs, RadioProfile, RadioTime,
    Reliability, TxIntent, mcs_phy_rate_bps,
};

/// Measures **residual** frame loss on the delivered (post-FEC) stream via LP
/// sequence gaps — the signal cognition drives link-FEC redundancy from (raise R
/// until residual → 0, back it off when clean). Cumulative; [`ratio`](Self::ratio)
/// is `gaps / (gaps + delivered)`.
pub struct LossMeter {
    last_seq: AtomicU64, // u64::MAX = unset
    delivered: AtomicU64,
    gaps: AtomicU64,
}

impl Default for LossMeter {
    fn default() -> Self {
        Self {
            last_seq: AtomicU64::new(u64::MAX),
            delivered: AtomicU64::new(0),
            gaps: AtomicU64::new(0),
        }
    }
}

impl LossMeter {
    /// Fold one delivered (post-FEC) LP frame into the residual-loss estimate.
    fn observe(&self, payload: &Bytes) {
        self.delivered.fetch_add(1, Ordering::Relaxed);
        if let Some(h) = ndn_packet::lp::extract_fragment(payload) {
            let seq = h.sequence;
            let last = self.last_seq.swap(seq, Ordering::Relaxed);
            if last != u64::MAX && seq > last.wrapping_add(1) {
                self.gaps.fetch_add(seq - last - 1, Ordering::Relaxed);
            }
        }
    }

    /// Residual loss fraction (0.0–1.0) over all frames delivered so far.
    pub fn ratio(&self) -> f32 {
        let d = self.delivered.load(Ordering::Relaxed);
        let g = self.gaps.load(Ordering::Relaxed);
        if d + g == 0 {
            0.0
        } else {
            g as f32 / (d + g) as f32
        }
    }

    /// The residual loss fraction **since the last call**, resetting the counters —
    /// so the control plane sees *recent* loss (and backs redundancy off when it
    /// clears) rather than a long-run average. `last_seq` is kept so a gap across the
    /// window boundary is not miscounted.
    pub fn take_ratio(&self) -> f32 {
        let d = self.delivered.swap(0, Ordering::Relaxed);
        let g = self.gaps.swap(0, Ordering::Relaxed);
        if d + g == 0 {
            0.0
        } else {
            g as f32 / (d + g) as f32
        }
    }
}

// `RadioId` identifies a radio within the cognitive `MediumState`; re-used here so
// a bearer's id is the same one the control plane registers and actuates against.
pub use ndn_radio_cognition::RadioId;

/// One radio bound into the medium as a capability: its cognition [`RadioId`], the
/// bearer-agnostic data-plane handle, and its declared [`RadioCapability`].
///
/// The data plane is [`FrameIo`] — **any** radio (Wi-Fi, LoRa, BLE, HaLow, …) is a
/// capability, not just Wi-Fi, and the medium face never touches a Wi-Fi type. The
/// transmit **rate is bearer state**, held inside the driver: the control plane's
/// [`MediumActuator`] calls [`FrameIo::set_rate`] each tick, and every `inject` then
/// transmits at that rate — so per-frame TX carries only a [`TxIntent`] and there is
/// no per-bearer rate cell or wrapper.
///
/// `Clone` shares the same radio handle (an `Arc`) — cloning a bearer does not open a
/// second device.
#[derive(Clone)]
pub struct RadioBearer {
    pub id: RadioId,
    /// Bearer-agnostic data plane (inject/recv/set_rate). Every radio kind implements it.
    pub radio: Arc<dyn FrameIo>,
    pub cap: RadioCapability,
    /// Optional stateful control seam (channel / TX power / contention). `None` =
    /// a bearer with no reachable knobs, whose rate is still actuated as driver
    /// state. Attach with [`with_knobs`](Self::with_knobs) so the actuator built
    /// for this bearer can drive it.
    pub knobs: Option<Arc<dyn RadioKnobs>>,
    /// Hardware timestamping / TSF common-view for **this bearer** (#78).
    ///
    /// Per-bearer, not per-face, because that is the shape the MAC needs: a multi-radio node has one
    /// clock per radio, and a slot gate that consults a face-level clock is deciding for the wrong
    /// medium (#89). Absent until now only because the pre-M8 opener could not return it.
    pub time: Option<Arc<dyn RadioTime>>,
    /// The bearer's self-description — declared capability and calibration (#78).
    ///
    /// `cap` above is what the *caller* asserted; this is what the *radio* says. Keeping both makes a
    /// disagreement visible instead of letting a hand-written `RadioCapability` quietly outrank the
    /// hardware (#98 is that failure in miniature: `agile` is asserted and never measured).
    pub profile: Option<Arc<dyn RadioProfile>>,
    /// The channel this bearer was brought up on (its operating channel), when known. Feeds the
    /// scheduler's medium key so two **static** radios on different channels get distinct schedules —
    /// the #89 "one medium, one schedule" property extended to the non-hopping case (§9.3). Before
    /// this, the slot key's channel term was written only by an FHSS retune, so a static radio always
    /// keyed on the `u8::MAX` sentinel and two of them shared one schedule. `None` when unconfigured.
    pub channel: Option<u8>,
}

impl RadioBearer {
    /// A bearer over **any** [`FrameIo`] radio (LoRa, BLE, …).
    pub fn new(id: RadioId, radio: Arc<dyn FrameIo>, cap: RadioCapability) -> Self {
        // ★ **Ask the radio before believing the caller** (2026-08-31).
        //
        // `cap` is an ASSERTION made by whoever built this bearer, and the whole reason
        // [`from_open`](Self::from_open) exists is that the assertion is usually a guess. But
        // `from_open` requires threading four handles through every call site, so it had **zero**
        // production callers while this constructor had all of them — the fix for the unactuated
        // contract was itself unactuated. Concretely: the node opened an RTL8822E and got a
        // placeholder declaring `max_mcs 9 / max_nss 2 / max_bw 2` over a part that receives ONE
        // stream at MCS 7, which is the MEASURED cause of a one-way link.
        //
        // [`FrameIo::radio_capability`] closes that from the handle every caller already holds, so
        // the common path is now correct by construction rather than by remembering to use the
        // other constructor. The caller's `cap` survives only where the radio cannot say — which,
        // among the shipping backends, is nowhere: all 14 implement `RadioProfile`.
        let cap = radio.radio_capability().unwrap_or(cap);
        Self {
            id,
            radio,
            cap,
            knobs: None,
            time: None,
            profile: None,
            channel: None,
        }
    }

    /// **A bearer from the standardized opener** (#78) — the capability-complete path.
    ///
    /// `open_radio` returns everything the backend implements; this carries all of it onto the
    /// bearer in one call. Before this existed, a caller wanting knobs or timing had to bypass the
    /// standardized opener and name a concrete backend, which is precisely the leak the opener was
    /// created to close — it had fixed the on-air FORMAT leak and left the CAPABILITY leak open.
    pub fn from_open(id: RadioId, r: OpenRadio, cap: RadioCapability) -> Self {
        Self {
            id,
            radio: r.io,
            cap,
            knobs: r.knobs,
            time: r.time,
            profile: r.profile,
            channel: None,
        }
    }

    /// **The capability that governs** — the radio's own when it declares one, else the caller's
    /// assertion.
    ///
    /// The [`profile`](Self::profile) field's contract says keeping both "makes a disagreement
    /// visible instead of letting a hand-written `RadioCapability` quietly outrank the hardware".
    /// Nothing read it, so that contract was itself unactuated: every consumer saw the asserted
    /// `cap` and the radio's self-description sat unused on the struct. The hardware wins here, and
    /// [`RunningMedium::spawn`] logs the disagreement rather than resolving it silently.
    pub fn effective_cap(&self) -> RadioCapability {
        match &self.profile {
            Some(p) => p.capability(),
            None => self.cap.clone(),
        }
    }

    /// Attach this bearer's clock. See the [`time`](Self::time) field on why it is per-bearer.
    pub fn with_time(mut self, time: Arc<dyn RadioTime>) -> Self {
        self.time = Some(time);
        self
    }

    /// Attach the radio's self-description.
    pub fn with_profile(mut self, profile: Arc<dyn RadioProfile>) -> Self {
        self.profile = Some(profile);
        self
    }

    /// A **Wi-Fi** bearer — the same thing, upcasting the (now marker) [`WifiRadio`]
    /// handle to the bearer-agnostic data-plane view. Kept as a convenience for
    /// callers holding an `Arc<dyn FrameIo>` from a driver.
    pub fn wifi(id: RadioId, radio: Arc<dyn FrameIo>, cap: RadioCapability) -> Self {
        // Same discovery as [`new`](Self::new): the radio's own answer outranks the caller's.
        let cap = radio.radio_capability().unwrap_or(cap);
        Self {
            id,
            radio,
            cap,
            knobs: None,
            time: None,
            profile: None,
            channel: None,
        }
    }

    /// Attach the radio's control seam, and let it describe itself: a seam that
    /// reports an absolute dBm range publishes it on the capability, which is what
    /// tells cognition to decide power in dB rather than chip index units.
    pub fn with_knobs(mut self, knobs: Arc<dyn RadioKnobs>) -> Self {
        self.knobs = Some(knobs);
        self
    }

    /// Record the channel this bearer was brought up on (§9.3). The scheduler seeds its medium key
    /// with it, so two static radios on different channels get distinct schedules.
    pub fn with_channel(mut self, channel: Option<u8>) -> Self {
        self.channel = channel;
        self
    }

    /// Declare this bearer's absolute TX-power range (from whatever discovered it).
    pub fn with_tx_power_dbm(mut self, range: DbmRange) -> Self {
        self.cap = self.cap.with_tx_power_dbm(range);
        self
    }
}

/// A minimal in-process **link-signal store** keyed by [`FaceId`]: the medium
/// face's readers push each captured frame's RSSI/rate here (via [`SignalStore`]),
/// and the cognitive control plane reads it back (via [`SignalView`]) on every tick
/// to rank the medium by live link quality — the SENSE→DECIDE bridge. Hand the same
/// `Arc` to [`RadioMediumFace::with_signal_sink`] and
/// [`RadioControl::with_signals`](crate::RadioControl::with_signals).
///
/// (`ndn-signals-core` deliberately ships only the traits; concrete stores are
/// per-host adapters. This is the small native one the radio face needs.)
#[derive(Default)]
pub struct LinkSignalStore {
    links: Mutex<HashMap<FaceId, LinkSignals>>,
    /// Per-**neighbour** link signals, keyed by the frame's ephemeral source tag (the rotating nonce
    /// in the 802.11 source field — mac-addressing-doctrine §2). This is the per-neighbour RSSI map
    /// the doctrine wants in place of the ambient per-face scalar `links` holds: two neighbours heard
    /// on one radio get distinct RSSI, which CCLF density and macro-diversity need.
    per_source: Mutex<HashMap<[u8; 6], LinkSignals>>,
}

impl LinkSignalStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Every neighbour currently known, by source nonce → its last link signals. The per-frame
    /// RSSI-per-neighbour map the doctrine's §2 nonce buys (density / macro-diversity input).
    pub fn neighbours(&self) -> Vec<([u8; 6], LinkSignals)> {
        self.per_source
            .lock()
            .unwrap()
            .iter()
            .map(|(k, v)| (*k, *v))
            .collect()
    }
}

impl SignalView<FaceId> for LinkSignalStore {
    fn link(&self, face: FaceId) -> Option<LinkSignals> {
        self.links.lock().unwrap().get(&face).copied()
    }
    fn node(&self) -> NodeSignals {
        NodeSignals::default()
    }
    fn neighbor(&self, _face: FaceId) -> Option<NodeSignals> {
        None
    }
    fn source_link(&self, src: [u8; 6]) -> Option<LinkSignals> {
        self.per_source.lock().unwrap().get(&src).copied()
    }
    fn neighbour_count(&self, fresh_within_ms: u64, now_ms: u64) -> usize {
        // Distinct source nonces heard recently — the per-frame density the doctrine's §2 map buys,
        // catching neighbours that transmit frames but never send a reception report.
        self.per_source
            .lock()
            .unwrap()
            .values()
            .filter(|ls| now_ms.saturating_sub(ls.updated_ms as u64) <= fresh_within_ms)
            .count()
    }
}

impl SignalStore<FaceId> for LinkSignalStore {
    fn set_link(&self, face: FaceId, signals: LinkSignals) {
        self.links.lock().unwrap().insert(face, signals);
    }
    fn set_node(&self, _signals: NodeSignals) {}
    fn set_neighbor(&self, _face: FaceId, _signals: NodeSignals) {}
    fn set_source_link(&self, src: [u8; 6], signals: LinkSignals) {
        self.per_source.lock().unwrap().insert(src, signals);
    }
}

/// The last knob values pushed to a radio, so an unchanged knob is not re-applied
/// every tick (a channel retune is ~16 ms — it would dominate the loop). Shared by
/// BOTH actuator paths ([`MediumActuator`] and `LibUsbActuator`) via [`apply_knobs`],
/// so a knob wired into one is never forgotten in the other — the divergence that once
/// dropped absolute-dBm power on the libusb backend and forced two copies of every dial.
// ⚠ No longer `Copy`: `applied_power` owns an `AppliedPower`, which carries the list of registers
// the driver actually wrote. That list is the thing that distinguishes a fused-base write from a
// raw one, so it is worth the clone.
#[derive(Default, Clone, PartialEq)]
pub(crate) struct AppliedKnobs {
    channel: Option<(u8, u8)>, // (channel, bw_code)
    csd: Option<bool>,
    edcca: Option<bool>,
    power: Option<u8>,
    /// The dBm value last **requested** — the dedupe key, so a firmware clamp does not re-push a
    /// write every tick forever.
    power_dbm: Option<i8>,
    /// ★ The dBm the radio reported it **actually applied**, which a regulatory or firmware clamp
    /// can put below the request. This, not the request, is what a peer must be told: a neighbour
    /// computing path loss from a power we never transmitted at gets a wrong answer and no way to
    /// notice. See `ReceptionReport::tx_power_dbm`.
    pub(crate) applied_dbm: Option<i8>,
    /// ★ What the radio said it APPLIED for `power`, including the resolved `PowerReference`.
    /// Not a dedupe key (that is `power`, the request) — this is the record that tells an operator
    /// which power regime the node is actually in, and it is the field whose absence made the
    /// 2026-09-03 bug invisible from above the driver.
    applied_power: Option<ndn_radio_hal::AppliedPower>,
    rx_gain: Option<ndn_radio_hal::RxGain>,
    edcca_thresh: Option<(i8, i8)>,
    sf: Option<u8>,  // LoRa spreading factor
    cr: Option<u8>,  // LoRa coding rate
    bw: Option<u32>, // LoRa bandwidth (kHz)
}

/// Push a plan's stateful control knobs to `knobs`, applying only values that CHANGED since the
/// last call (tracked in `last`). This is the ONE definition both actuators call: [`MediumActuator`]
/// (loopback/af-packet knobs) and `LibUsbActuator` (libusb chip knobs). Keeping it single is what
/// stops the two paths from drifting — the libusb path used to lack the dBm-power branch entirely,
/// silently dropping every absolute-power decision on a radio that has a dBm scale.
pub(crate) fn apply_knobs(
    last: &mut AppliedKnobs,
    knobs: &dyn RadioKnobs,
    alloc: &RadioAllocation,
    cap: Option<&RadioCapability>,
) -> Result<(), FaceError> {
    let p = &alloc.params;

    // ★ **Bound TX power to the radio's declared range before it reaches a knob.** Both forms are
    // escalations — "pin the part at maximum" is the loudest thing on the chip — and `RadioPolicy`
    // clamps both to this same capability, so anything outside it did not come from cognition.
    // Counted, not merely clamped: `ledger::tx_power_clamped` is what an operator compares the
    // `radio.N.tx_power` reading against. `cap = None` ⇒ no declared band ⇒ no bound and no count,
    // stated rather than faked.
    let mut p = p.clone();
    if let Some(c) = cap {
        if let (Some(dbm), Some(range)) = (p.tx_power_dbm, c.tx_power_dbm) {
            let bounded = range.clamp(dbm);
            if bounded != dbm {
                ndn_radio_cognition::ledger::note_tx_power_clamped();
                tracing::warn!(
                    target: "named_radio",
                    requested = dbm, applied = bounded,
                    "tx power outside the radio's declared dBm range; clamped"
                );
                p.tx_power_dbm = Some(bounded);
            }
        }
        if let (Some(idx), Some(lo)) = (p.tx_power, c.min_tx_power) {
            let bounded = idx.clamp(lo, c.max_tx_power);
            if bounded != idx {
                ndn_radio_cognition::ledger::note_tx_power_clamped();
                tracing::warn!(
                    target: "named_radio",
                    requested = idx, applied = bounded,
                    "tx power index outside the radio's declared range; clamped"
                );
                p.tx_power = Some(bounded);
            }
        }
    }
    let p = &p;

    // ★ **Every knob degrades on its own.** These used to propagate with `?`, so a single knob a
    // radio does not implement aborted the tick and silently disarmed every knob AFTER it — the
    // decided rate, the LoRa dials, everything downstream of the first refusal. The MT7612U
    // documented the consequence: "one impossible width also skipped `set_tx_csd` and
    // `set_edcca_ignore`". A knob a radio lacks is normal and must cost only that knob.
    //
    // `last` is updated ONLY on success, so a knob that failed is retried next tick rather than
    // being recorded as applied — the failure must not become invisible on the second pass.
    fn note(what: &str, r: Result<(), FaceError>) -> bool {
        match r {
            Ok(()) => true,
            Err(e) => {
                tracing::debug!(knob = what, error = %e, "radio refused a knob; continuing");
                false
            }
        }
    }
    // Channel + bandwidth retune together (the ~16 ms cost the change-gating exists for).
    if let Some(ch) = alloc.channel {
        let bw_code = p.bw().unwrap_or(0);
        if last.channel != Some((ch, bw_code))
            && note(
                "set_channel",
                knobs.set_channel(ch, Bandwidth::from_code(bw_code)),
            )
        {
            last.channel = Some((ch, bw_code));
        }
    }
    if last.csd != Some(p.csd()) && note("set_tx_csd", knobs.set_tx_csd(p.csd())) {
        last.csd = Some(p.csd());
    }
    // ★ **Energy-detect carrier sense off at the chip.** The highest-value purchase in the tree:
    // transmit into a busy channel instead of deferring. The value can no longer be asserted by a
    // struct literal — `TxParams::contention` is a sealed `Contention` and only an `Urgent`
    // `NameContext` produces `true` — but this is the line where it becomes register writes, so it
    // is also where the claim is COUNTED. `ledger::edcca_ignored` rising while every plan in the
    // same `/localhost/nfd/ext/list` snapshot reads `edcca_ignore=false` is a claim that did not
    // come from this node's policy. Counted on every arrival, not only on a change, so the count
    // tracks *ticks that claimed the medium* rather than register traffic.
    if p.edcca_ignore() {
        ndn_radio_cognition::ledger::note_edcca_ignored();
    }
    if last.edcca != Some(p.edcca_ignore())
        && note("set_edcca_ignore", knobs.set_edcca_ignore(p.edcca_ignore()))
    {
        last.edcca = Some(p.edcca_ignore());
    }
    // TX power: prefer the absolute dBm scale when the radio has one, since it is what the policy
    // actually decided (the index is a lossy rendering of the same back-off). A radio without dBm
    // control falls back to the index; a radio with it skips the index, so the two never fight over
    // one knob. Dedupe on the REQUEST, not what the radio reported applying — a firmware/regulatory
    // clamp (30 dBm → 27) makes the applied value differ from the request, which would otherwise
    // re-push a write on every tick forever.
    let dbm_applied = match p.tx_power_dbm {
        Some(dbm) if last.power_dbm != Some(dbm) => match knobs.set_tx_power_dbm(dbm) {
            Ok(applied) => {
                last.power_dbm = Some(dbm);
                last.applied_dbm = Some(applied);
                true
            }
            Err(_) => false, // unsupported on this radio — fall through to the index scale
        },
        Some(_) => true, // already applied
        None => false,
    };
    // ⚠⚠ **RE-BASELINE ANY ON-AIR A/B THAT SPANS THIS CHANGE.** As of the bring-up contract's M1
    // this branch records what the radio said it APPLIED, not what cognition requested. Before, a
    // request that the driver clamped, rendered onto a different power reference, or refused after
    // partially writing was indistinguishable from one that landed exactly — which on the RTL8812AU
    // spanned ~18-33 dB. Numbers taken either side of this commit are not comparable.
    if !dbm_applied
        && let Some(idx) = p.tx_power
        && last.power != Some(idx)
    {
        match knobs.set_tx_power(ndn_radio_hal::PowerRequest::index(idx)) {
            Ok(applied) => {
                // ★ Recorded only on success. This previously ran unconditionally after a
                // `?`-propagating call, so on a radio whose `set_tx_power` default was a silent
                // `Ok(())` — the MT7612U and MT7921AU have no power actuator at all — `last.power`
                // recorded a back-off that no silicon ever applied, and the bandit was rewarded for
                // a footprint reduction that did not happen. See `RadioCapability::power_actuated`.
                //
                // Dedupe still keys on the REQUEST: a driver clamp (the a81a's 20..=63 floor) makes
                // the applied index differ from the requested one, and keying on the applied value
                // would re-push the same write every tick forever.
                // ★ **Detection by contrast, at the knob.** If the power REFERENCE changes between
                // two ticks of the same radio, the same index now means a different physical power
                // — which is the 2026-09-03 defect seen from above the driver, and the one thing
                // this layer can notice on its own. It should never happen on a healthy part.
                if let Some(prev) = &last.applied_power
                    && prev.reference != applied.reference
                {
                    tracing::warn!(
                        target: "named_radio",
                        was = prev.reference.tag(),
                        now = applied.reference.tag(),
                        idx,
                        "TX POWER REFERENCE CHANGED under a live radio — the same index now means \
                         a different physical power. Any measurement spanning this tick is invalid."
                    );
                }
                last.power = Some(idx);
                last.applied_power = Some(applied);
            }
            Err(e) => {
                tracing::debug!(knob = "set_tx_power", error = %e, "radio refused a knob; continuing");
            }
        }
    }
    // ★ The RECEIVE half of spatial reuse, actuated beside the power decision rather than after it,
    // because they are one decision: quieter without being less deferential just shrinks this
    // node's reach. The dBm threshold is preferred where a radio has one — same reasoning as
    // dBm-over-index for power — but the two are complementary, not alternatives, so both are
    // pushed when both are decided (the a81a has both).
    // ☠ **BOUND HERE, because this is the same silicon decision as `edcca_ignore` with no flag on
    // it.** `set_edcca_threshold` on the Realtek backend range-checks nothing — it encodes
    // `((dbm + 110 + 0x80) & 0xff)` into `0x84c`, so an arriving `(17, 9)` writes `0xff`: the
    // channel is never busy. Sealing the `Contention` flag while leaving this unbounded would have
    // closed the door everyone was watching and left the window open. The band is the range the
    // policy can actually decide (`DEFER_THRESHOLD_DBM_BAND`, exported from cognition so the bound
    // and the decision cannot drift), and an out-of-band arrival is clamped and counted rather than
    // refused — a threshold outside it cannot have come from `decide_edcca_threshold_dbm` at all,
    // which makes `ledger::defer_threshold_clamped` the sharpest bypass signal we have.
    if let Some((want_l2h, want_h2l)) = p.edcca_threshold_dbm {
        let ((l2h, h2l), moved) =
            ndn_radio_cognition::clamp_defer_threshold(want_l2h, want_h2l);
        if moved {
            ndn_radio_cognition::ledger::note_defer_threshold_clamped();
            tracing::warn!(
                target: "named_radio",
                requested = ?(want_l2h, want_h2l),
                applied = ?(l2h, h2l),
                "defer threshold outside the decidable band; clamped"
            );
        }
        if last.edcca_thresh != Some((l2h, h2l))
            && note(
                "set_edcca_threshold_dbm",
                knobs.set_edcca_threshold_dbm(l2h, h2l),
            )
        {
            last.edcca_thresh = Some((l2h, h2l));
        }
    }
    if let Some(g) = p.rx_gain
        && last.rx_gain != Some(g)
        && note("set_rx_gain", knobs.set_rx_gain(g))
    {
        last.rx_gain = Some(g);
    }
    // LoRa reach/rate dials (no-op on Wi-Fi radios): spreading factor, coding rate, bandwidth. Each
    // is a ~1 s AT retune of the dongle, so gate strictly on a changed value.
    if let Some(sf) = p.spreading_factor()
        && last.sf != Some(sf)
        && note("set_spreading_factor", knobs.set_spreading_factor(sf))
    {
        last.sf = Some(sf);
    }
    if let Some(cr) = p.coding_rate()
        && last.cr != Some(cr)
        && note("set_coding_rate", knobs.set_coding_rate(cr))
    {
        last.cr = Some(cr);
    }
    if let Some(bw) = p.bandwidth_khz()
        && last.bw != Some(bw)
        && note("set_bandwidth_khz", knobs.set_bandwidth_khz(bw))
    {
        last.bw = Some(bw);
    }
    Ok(())
}

/// The medium's **actuator**: applies one radio's slice of a [`RadioPlan`] each tick.
///
/// The transmit **rate is set as driver state** via [`FrameIo::set_rate`] — the
/// decided MCS reaches the air because the driver holds it and every `inject` uses it
/// (no planned cell, no wrapper). The stateful control knobs — channel retune, TX
/// power, CSD, EDCCA, LoRa SF/CR — go through an optional [`RadioKnobs`] handle, gated
/// so an unchanged knob is not re-pushed. A portable bearer (loopback / af-packet)
/// passes `knobs = None`, and only its rate is actuated. Register one per bearer on
/// [`RadioControl`](crate::RadioControl) via `add_actuator`.
pub struct MediumActuator {
    radio: RadioId,
    io: Arc<dyn FrameIo>,
    knobs: Option<Arc<dyn RadioKnobs>>,
    last: Mutex<AppliedKnobs>,
    /// Shared parity count the medium face's FEC bridge reads — written each tick
    /// from the decided `link_fec_redundancy` (the loss-recovery lever).
    fec_redundancy: Option<Arc<AtomicU16>>,
    /// A floor on the actuated parity count — the cognition-decided R is raised to at
    /// least this. Lets an operator pin a minimum redundancy on a known-lossy
    /// broadcast link where the face-level loss signal can't see single-frame loss.
    fec_floor: u16,
    /// What the radio DECLARED about itself, when the caller supplied it — the band this actuator
    /// clamps TX power into. `None` ⇒ no band, so no bound and no `tx_power_clamped` count: an
    /// actuator that was never told the radio's range cannot honestly say a request is out of it.
    cap: Option<RadioCapability>,
}

impl MediumActuator {
    /// Actuate `radio`: set its rate on `io`, and (if `knobs` is given) its
    /// channel/power/etc. `knobs` is `None` for a bearer without a control seam.
    pub fn new(radio: RadioId, io: Arc<dyn FrameIo>, knobs: Option<Arc<dyn RadioKnobs>>) -> Self {
        Self {
            radio,
            io,
            knobs,
            last: Mutex::new(AppliedKnobs::default()),
            fec_redundancy: None,
            fec_floor: 0,
            cap: None,
        }
    }

    /// Bound TX power to what `cap` says the radio can do.
    ///
    /// ★ `RadioPolicy` already clamps BOTH power forms to this same capability (the index to
    /// `[min_tx_power, max_tx_power]`, the dBm to the declared `DbmRange`), so a value outside it
    /// **cannot have come from cognition** — exactly the reasoning that makes a clamp here a bypass
    /// signal rather than a second opinion. Without it, the loudest escalation the chip offers —
    /// pin the part at maximum power — reverted the spatial-reuse back-off silently, and the
    /// operator surface showed the requested value with no counter able to disagree with it.
    /// The LoRa face already did this bound; the Wi-Fi face was the inconsistent one.
    pub fn with_capability(mut self, cap: RadioCapability) -> Self {
        self.cap = Some(cap);
        self
    }

    /// Also actuate **link-FEC redundancy**: on each tick, write the decided
    /// `link_fec_redundancy` (raised to at least `floor`) into `cell`, which the
    /// medium face reads to set the parity count on outbound generations. `floor = 0`
    /// leaves the parity fully cognition-driven.
    pub fn with_fec_redundancy(mut self, cell: Arc<AtomicU16>, floor: u16) -> Self {
        self.fec_redundancy = Some(cell);
        self.fec_floor = floor;
        self
    }
}

impl RadioActuators for MediumActuator {
    fn radio_id(&self) -> RadioId {
        self.radio
    }

    fn apply(&self, alloc: &RadioAllocation) -> Result<(), RadioError> {
        let to_err = |e: FaceError| RadioError(e.to_string());
        let p = &alloc.params;

        // Rate as driver state — the decided MCS every subsequent `inject` transmits at. The
        // TxParams->McsDescriptor mapping is defined once (TxParams::wifi_mcs), shared with RatePolicy.
        if let Some(mcs) = p.wifi_mcs() {
            self.io.set_rate(mcs).map_err(to_err)?;
        }

        // Link-FEC redundancy — the loss-recovery lever, actuated regardless of the
        // knobs seam (a fixed-rate bearer still recovers losses via FEC).
        if let Some(cell) = &self.fec_redundancy {
            cell.store(
                p.link_fec_redundancy.unwrap_or(0).max(self.fec_floor),
                Ordering::Relaxed,
            );
        }

        // The stateful control knobs — only pushed when changed, via the shared `apply_knobs` both
        // actuators use (so no knob is wired here and forgotten on the libusb path).
        let Some(knobs) = &self.knobs else {
            return Ok(());
        };
        let mut last = self.last.lock().unwrap();
        apply_knobs(&mut last, knobs.as_ref(), alloc, self.cap.as_ref()).map_err(to_err)?;
        Ok(())
    }
}

/// Where the cognition loop's active [`NameContext`]s come from on each refresh — the
/// injection point that lets an engine-aware host (with FIB access) feed name-derived
/// contexts while a bare face falls back to a static set. The
/// [`FaceFactory`](ndn_transport::FaceFactory) seam has no engine, so a factory-built
/// face uses [`StaticContexts`]; a forwarder that holds the engine implements this
/// over its FIB and gets the same loop.
pub trait ContextSource: Send + Sync + 'static {
    /// The names the medium is currently transmitting for (what to decide plans for).
    fn active(&self) -> Vec<NameContext>;
}

/// A fixed active set — the default when no engine/FIB is reachable.
pub struct StaticContexts(pub Vec<NameContext>);

impl ContextSource for StaticContexts {
    fn active(&self) -> Vec<NameContext> {
        self.0.clone()
    }
}

/// Spawn the cognition control loop over `control`: refresh the active contexts from
/// `source` every `refresh_every` ticks and decide (`tick_now`) every `tick`. Returns
/// the task handle — hang it on the face via [`RunningMedium::attach_task`] to tie its
/// lifetime to the face. This is the single loop both the factory (with
/// [`StaticContexts`]) and an engine-aware mount (with a FIB-backed source) share.
pub fn spawn_control_loop(
    control: Arc<RadioControl>,
    source: Arc<dyn ContextSource>,
    tick: Duration,
    refresh_every: u32,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let started = Instant::now();
        let mut ticker = tokio::time::interval(tick);
        let mut since = u32::MAX; // force a refresh on the first tick
        loop {
            ticker.tick().await;
            since = since.saturating_add(1);
            if since >= refresh_every.max(1) {
                control.set_active(source.active());
                since = 0;
            }
            control.tick_now(started.elapsed().as_millis() as u64);
        }
    })
}

/// Declarative medium face: a face id, the radio capabilities, and options. Build
/// the running face with [`into_face`](Self::into_face) (or [`build`](Self::build)).
pub struct RadioMediumFace {
    id: FaceId,
    mtu: usize,
    bearers: Vec<RadioBearer>,
    signal_sink: Option<Arc<dyn SignalStore<FaceId> + Send + Sync>>,
    fec: Option<FecConfig>,
    /// When set true (by cognition, on hearing a legacy-only-RX neighbour), the data
    /// path injects at the basic legacy rate ([`TxIntent::ROBUST`]) so it reaches that
    /// neighbour — the worst-overheard-receiver rate cap. `None`/false = decided rate.
    legacy_gate: Option<Arc<AtomicBool>>,
    /// Registered-prefix table for the scheduler's named airtime lease (P1), built by
    /// [`with_group_table`](Self::with_group_table) from the registered prefix set.
    group_table: Option<Arc<crate::GroupTable>>,
    /// **Per-frame rate selection** (#82), when enabled: the cognition-decided [`TxParams`], else an
    /// adaptive/fixed [`McsPolicy`]. `None` ⇒ rate stays pure bearer state set out-of-band, the
    /// historical behaviour.
    rate: Option<Arc<crate::RatePolicy>>,
    /// **A-MSDU bundling** (#82 part 2), when enabled: outbound data frames are coalesced and handed
    /// to the bearer's [`FrameIo::inject_batch`], which the AF_PACKET and RTL/MT7612 backends
    /// override with real aggregation. This was the one genuinely one-sided feature in #82 —
    /// `WifiPhy` had it and the medium did not.
    amsdu: Option<AmsduCfg>,
}

/// A-MSDU bundling parameters for the medium: flush after `max_msdus` frames or `window`, whichever
/// comes first.
#[derive(Clone, Copy)]
struct AmsduCfg {
    max_msdus: usize,
    window: Duration,
}

/// The medium's send-coalescer: one per bearer, submitting whole batches to that bearer's
/// [`FrameIo::inject_batch`].
///
/// It carries no MCS, unlike `WifiPhy`'s batcher. The medium models rate as **bearer state**
/// (the driver holds it; the face sends [`TxIntent`]s), so there is no per-frame descriptor to
/// attach — which is exactly why `ndn-frame-io`'s AF_PACKET backend gained an `inject_batch` that
/// aggregates at the currently-set rate. Aggregating only through the rate-carrying spelling would
/// have made this move silently lose A-MSDU on the S1G path.
struct MediumBatcher {
    tx: mpsc::UnboundedSender<(InjectFrame, Option<McsDescriptor>)>,
    submitted: Arc<AtomicU64>,
}

impl MediumBatcher {
    fn spawn(
        radio: Arc<dyn FrameIo>,
        cfg: AmsduCfg,
        rate: Option<Arc<crate::RatePolicy>>,
    ) -> (Self, JoinHandle<()>) {
        let (tx, mut rx) = mpsc::unbounded_channel::<(InjectFrame, Option<McsDescriptor>)>();
        // TX-wedge diagnostics (#radio-face-wedge): count frames submitted to the
        // batcher vs batches the batcher actually injected + their result, logged
        // every 5s. When the relay wedges this localises it: submitted still
        // rising but injected stalled ⇒ stuck in inject().await; both stalled ⇒
        // nothing upstream is submitting; injected rising but Err ⇒ the backend.
        let submitted = Arc::new(AtomicU64::new(0));
        let injected = Arc::new(AtomicU64::new(0));
        let inject_err = Arc::new(AtomicU64::new(0));
        {
            let (s, i, e) = (submitted.clone(), injected.clone(), inject_err.clone());
            tokio::spawn(async move {
                let mut last = (0u64, 0u64);
                loop {
                    tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                    let (sn, in_, en) = (
                        s.load(Ordering::Relaxed),
                        i.load(Ordering::Relaxed),
                        e.load(Ordering::Relaxed),
                    );
                    let stalled = sn > last.0 && in_ == last.1; // fed but not injecting
                    tracing::info!(
                        target: "face.radio.tx",
                        submitted = sn, injected = in_, inject_err = en,
                        stalled_in_inject = stalled,
                        "radio TX batcher counters"
                    );
                    last = (sn, in_);
                }
            });
        }
        let inj_c = injected.clone();
        let err_c = inject_err.clone();
        let handle = tokio::spawn(async move {
            while let Some(first) = rx.recv().await {
                // **The plan sizes the aggregate, per batch** (#83/`decided-but-unactuated`).
                // `Some(0)` = the plane asking for no aggregation, which is not the same as `None`
                // = no opinion; only the latter falls back to the face's configured cap. Read here
                // rather than at spawn so a re-decided target takes effect on the next flush, the
                // way redundancy already does.
                // `Some(0)` never reaches here — the submit site sends those straight down the
                // direct path, because a 1-frame `inject_batch` would still build a single-subframe
                // A-MSDU on AF_PACKET, i.e. aggregation framing for "do not aggregate".
                let cap = match rate.as_ref().and_then(|r| r.planned_amsdu_msdus()) {
                    Some(n) => (n as usize).max(1),
                    None => cfg.max_msdus,
                };
                let mut batch = vec![first];
                let deadline = tokio::time::Instant::now() + cfg.window;
                while batch.len() < cap {
                    match tokio::time::timeout_at(deadline, rx.recv()).await {
                        Ok(Some(f)) => batch.push(f),
                        _ => break, // window elapsed, or the face was torn down
                    }
                }
                // Two spellings, both aggregating, chosen by whether a rate was decided per frame.
                // Batching used to drop the rate on the floor: the coalescer sat before the rate
                // branch, so turning on A-MSDU turned off every decided MCS. Carrying the rate
                // through the batch is what lets the two features compose.
                let r = if batch.iter().any(|(_, m)| m.is_some()) {
                    let last = batch
                        .iter()
                        .rev()
                        .find_map(|(_, m)| *m)
                        .unwrap_or(McsDescriptor::CONSERVATIVE);
                    radio
                        .inject_batch_at(
                            batch
                                .into_iter()
                                .map(|(f, m)| (f, m.unwrap_or(last)))
                                .collect(),
                        )
                        .await
                } else {
                    radio
                        .inject_batch(batch.into_iter().map(|(f, _)| f).collect())
                        .await
                };
                inj_c.fetch_add(1, Ordering::Relaxed);
                if r.is_err() {
                    err_c.fetch_add(1, Ordering::Relaxed);
                }
            }
        });
        (MediumBatcher { tx, submitted }, handle)
    }

    fn submit(&self, frame: InjectFrame, mcs: Option<McsDescriptor>) -> Result<(), FaceError> {
        self.submitted.fetch_add(1, Ordering::Relaxed);
        self.tx.send((frame, mcs)).map_err(|_| FaceError::Closed)
    }
}

/// Predicate deciding whether an outbound wire is **FEC-eligible** — i.e. wants the
/// last-resort loss-recovery treatment. Given the framed NDN wire (so the host can
/// classify by name via its QoS `PrefixClassifier`/`TrafficClass`). `None` = every
/// frame is eligible (blanket FEC, the pre-gating behaviour).
pub type FecEligible = Arc<dyn Fn(&Bytes) -> bool + Send + Sync>;

/// Link-FEC settings for the medium face: `k` source frames per generation, a tail-
/// flush `window`, the shared parity count the cognition actuator writes, the
/// residual-loss meter the reader feeds, and an optional per-frame eligibility gate.
#[derive(Clone)]
struct FecConfig {
    k: usize,
    window: Duration,
    redundancy: Arc<AtomicU16>,
    loss: Arc<LossMeter>,
    /// Only these frames are coded; the rest bypass FEC even when R>0. `None` = all.
    /// "Retransmit is last resort and appropriate traffic only" — reliable-delivery
    /// names get parity; real-time/best-effort classes do not (a late-recovered frame
    /// is dead weight there).
    eligible: Option<FecEligible>,
}

impl RadioMediumFace {
    /// A medium face `id` reachable through `bearers` (≥1 radio capability).
    pub fn new(id: FaceId, bearers: Vec<RadioBearer>) -> Self {
        Self {
            id,
            mtu: MONITOR_MTU,
            bearers,
            signal_sink: None,
            fec: None,
            legacy_gate: None,
            group_table: None,
            amsdu: None,
            rate: None,
        }
    }

    /// Install the **registered-prefix table** for the scheduler's named airtime lease (P1). The
    /// slot key a name maps to is a pure function of the registered set, so every node computes the
    /// same map. Relevance on RX is decided by parsing the name, not by an in-frame filter.
    /// `registered_prefixes` are `/`-strings; a relay passes several (its forwarding family), a leaf
    /// one.
    pub fn with_group_table(mut self, registered_prefixes: &[impl AsRef<[u8]>]) -> Self {
        self.group_table = Some(Arc::new(crate::GroupTable::new(registered_prefixes)));
        self
    }

    /// [`with_group_table`](Self::with_group_table), with some registered prefixes marked
    /// **latency-class** (#93): those names are placed among the reserved lanes (`NDN_SCHED_RESERVE`),
    /// `L = 1`, never contending with bulk.
    ///
    /// ⚠ **`latency_prefixes` is this node's own assertion — nothing checks it**, which is why the
    /// name says so. The assignment is pinned into `SchedParams::class_digest`, and that pin is
    /// piggybacked on every ordinary data frame (`addr3[5]` bits 2..7 carry one 3-bit slice of
    /// `FaceScheduler::class_commitment()` per frame), so a neighbour that classifies differently is
    /// detected by anyone who hears a round of its traffic. Where a deployment has a trust anchor, use
    /// [`with_lease_latency_authorised`](Self::with_lease_latency_authorised) so the promotion passes
    /// a `ClassAuthority` rather than a slice literal.
    pub fn with_lease_latency_unauthorised(
        mut self,
        registered_prefixes: &[impl AsRef<[u8]>],
        latency_prefixes: &[impl AsRef<[u8]>],
    ) -> Self {
        self.group_table = Some(Arc::new(
            crate::GroupTable::new(registered_prefixes).with_latency_unauthorised(latency_prefixes),
        ));
        self
    }

    /// [`with_lease_latency_unauthorised`](Self::with_lease_latency_unauthorised) with the promotion
    /// gated on a `ClassAuthority`: a prefix reaches the reserved lanes only if the authority puts
    /// its ceiling at `Priority::Urgent`. Not enforcement (a permissive impl is four lines) — it
    /// removes self-assertion as a one-liner and makes `grep impl ClassAuthority` the audit.
    pub fn with_lease_latency_authorised(
        mut self,
        registered_prefixes: &[impl AsRef<[u8]>],
        latency_prefixes: &[impl AsRef<[u8]>],
        auth: &dyn ndn_radio_cognition::ClassAuthority,
    ) -> Self {
        self.group_table = Some(Arc::new(
            crate::GroupTable::new(registered_prefixes)
                .with_latency_authorised(auth, latency_prefixes),
        ));
        self
    }

    /// Bind the shared **legacy-rate gate**: when cognition sets it true (a legacy-only-RX
    /// neighbour is present), every data frame injects at the basic legacy rate so it
    /// reaches that neighbour. Reports already go legacy via [`RunningMedium::send_robust`];
    /// this extends the same worst-receiver reach to the data plane.
    pub fn with_legacy_gate(mut self, gate: Arc<AtomicBool>) -> Self {
        self.legacy_gate = Some(gate);
        self
    }

    /// Enable **link-layer FEC** on every bearer: outbound frames are grouped into
    /// generations of `k` (or flushed after `window`), sent as `k + R` coded frames,
    /// and the receiver recovers up to `R` losses per generation with no ARQ — the
    /// loss-recovery lever for a broadcast medium. `redundancy` is the shared parity
    /// count the cognition [`MediumActuator`] writes (from the decided
    /// `link_fec_redundancy`); `loss` is the residual-loss meter the RX side feeds so
    /// the control plane can raise R until residual loss falls. Both ends must enable
    /// FEC with the same `k`.
    pub fn with_link_fec(
        mut self,
        k: usize,
        window: Duration,
        redundancy: Arc<AtomicU16>,
        loss: Arc<LossMeter>,
    ) -> Self {
        self.fec = Some(FecConfig {
            k: k.max(1),
            window,
            redundancy,
            loss,
            eligible: None,
        });
        self
    }

    /// Gate link-FEC to **appropriate traffic only**: `pred(wire)` decides per frame
    /// whether to add parity (the host classifies by name via its QoS
    /// `PrefixClassifier`). Frames the predicate rejects bypass FEC even when the
    /// cognition-decided redundancy is >0 — so real-time/best-effort classes keep the
    /// low-latency direct path while reliable-delivery names get loss recovery. No-op
    /// unless [`with_link_fec`](Self::with_link_fec) was set.
    pub fn with_fec_eligibility(mut self, pred: FecEligible) -> Self {
        if let Some(fec) = &mut self.fec {
            fec.eligible = Some(pred);
        }
        self
    }

    /// Choose each data frame's **exact rate** rather than leaving it as bearer state: the
    /// cognitive control plane's decided [`TxParams`] when `planned` carries one, else `policy`
    /// (adaptive from observed RSSI, or fixed).
    ///
    /// This closes #82's last one-sided feature. `WifiPhy` could act on a decided MCS and
    /// this face could not, so a `RadioPlan` mounted on a medium face decided a rate that nothing
    /// applied — the quietest kind of gap, because a plan whose rate is never actuated looks exactly
    /// like a plan that chose the rate you were already transmitting at.
    ///
    /// Robust control frames are unaffected: they keep `TxIntent::ROBUST` so the driver puts them on
    /// the basic legacy rate every neighbour can decode. So does anything sent while the legacy gate
    /// is up — the worst-overheard-receiver cap outranks a throughput-chosen rate by design.
    pub fn with_rate_policy(mut self, rate: Arc<crate::RatePolicy>) -> Self {
        self.rate = Some(rate);
        self
    }

    /// Enable **A-MSDU bundling** on every bearer's data path: outbound frames are coalesced into
    /// one batch per up-to-`max_msdus` frames or `window` elapsed, whichever comes first, and handed
    /// to that bearer's [`FrameIo::inject_batch`] — which AF_PACKET, RTL and MT7612 override with
    /// real aggregation (one MPDU carrying many MSDUs, one PHY preamble). Each MSDU stays an
    /// independent NDN packet the receiver de-aggregates, so PIT/FIB semantics are untouched.
    ///
    /// Robust control frames (reports, discovery, time beacons) **bypass** the batcher: they must
    /// reach the worst receiver now, not wait out a flush window. So does link-FEC — a coded
    /// generation already interleaves its own frames, and stacking the two would only add latency.
    ///
    /// How much this buys is the backend's business, not the face's: a driver that does not override
    /// `inject_batch` falls back to individual injection with no airtime change, no error and no
    /// log. Measure the backend before quoting a number.
    pub fn with_amsdu_batching(mut self, max_msdus: usize, window: Duration) -> Self {
        self.amsdu = Some(AmsduCfg {
            max_msdus: max_msdus.max(1),
            window,
        });
        self
    }

    /// Publish each captured frame's RSSI/rate to `sink`, keyed by this face id, so
    /// the cognitive control loop's `SignalView` sees live per-radio link quality.
    pub fn with_signal_sink(mut self, sink: Arc<dyn SignalStore<FaceId> + Send + Sync>) -> Self {
        self.signal_sink = Some(sink);
        self
    }

    /// Override the injected-frame payload budget (defaults to [`MONITOR_MTU`]).
    pub fn with_mtu(mut self, mtu: usize) -> Self {
        self.mtu = mtu;
        self
    }

    /// The declared capabilities of every bearer — hand these to
    /// [`RadioControl::register_radio`](crate::RadioControl::register_radio) so the
    /// medium's decide plane knows what it is allocating across.
    pub fn capabilities(&self) -> Vec<(RadioId, RadioCapability)> {
        self.bearers
            .iter()
            .map(|b| (b.id, b.effective_cap()))
            .collect()
    }

    /// Spawn the per-radio reader tasks and return the running [`Transport`].
    pub fn build(self) -> RunningMedium {
        RunningMedium::spawn(self)
    }

    /// Build a [`Face`] pairing the running medium transport with the engine's
    /// `LpLinkService`, so NDN packets fragment/reassemble across injected frames —
    /// exactly as [`WifiPhy::into_face`](crate::WifiPhy::into_face).
    pub fn into_face(self) -> Face {
        Face::from_transport(self.build())
    }

    /// Build a [`Face`] whose LP link service also runs `feature`. Used to mount the
    /// cognition [`RadioControl`](crate::RadioControl) as a `LinkServiceFeature` so it
    /// observes this face's forwarding events (`on_egress`/`on_ingress`/`tick`) — the
    /// seam that feeds per-name demand into the control plane. Without it, cognition
    /// runs open-loop on demand (the consolidation dropped this). Otherwise identical
    /// to [`into_face`](Self::into_face).
    pub fn into_face_with_feature(self, feature: Arc<dyn LinkServiceFeature>) -> Face {
        let transport = self.build();
        let ls = LpLinkService::new().with_extra_feature(feature);
        Face::from_parts(Arc::new(transport), Arc::new(ls))
    }
}

/// How often the clock master broadcasts its time-beacon (#41 common-view). Frequent enough that a
/// slave's clock never drifts a slot between beacons, cheap enough to be negligible airtime.
const TIME_BEACON_MS: u64 = 100;

/// The send half of one bearer: the bearer-agnostic data plane and, when link-FEC is
/// on, the generation bridge + the shared parity count. The transmit rate is bearer
/// state (held in the driver), so this carries no rate — only the frame.
// ── TX-wedge diagnostics (#radio-face-wedge) ────────────────────────────────
// Process-global stage counters for the face egress path, logged every 5s. When
// the relay wedges these localise where TX stops: `enter` still rising but
// `gated` flat ⇒ stuck in `sched.gate().await`; `gated` rising but `done` flat
// ⇒ stuck in the FEC bridge or `radio.inject().await`; `enter` flat while the
// engine is forwarding ⇒ nothing upstream is calling the face. Gated behind
// target `face.radio.tx` so it's off unless asked for.
static TXD_ENTER: AtomicU64 = AtomicU64::new(0);
/// Frames that reached the addressing stage — the wedge diagnostic's "past the gate" mark.
static TXD_PAST_GATE: AtomicU64 = AtomicU64::new(0);
/// Frames that ACTUALLY went through `FaceScheduler::gate` (or its hardware equivalent).
static TXD_GATED: AtomicU64 = AtomicU64::new(0);
/// ★ Frames that SKIPPED the slot MAC as control traffic (`RunningMedium::send_robust`).
///
/// There was no counter anywhere that said this. `TXD_GATED` sat *after* the `if !robust` block and
/// incremented unconditionally, so the number the egress logger printed as `gated` counted frames
/// that were never gated, and `stuck_in_gate` could never fire for them. A bypass nothing counts is
/// a bypass nobody can see abused: this is the number an operator watches when the schedule is
/// starving and every plan looks correct.
static TXD_BYPASS: AtomicU64 = AtomicU64::new(0);
static TXD_FEC: AtomicU64 = AtomicU64::new(0);

/// **Per-face egress gate accounting** — the same two numbers as `TXD_GATED`/`TXD_BYPASS`, but
/// attributable to one face rather than to the process.
///
/// The process-global statics feed the 5-second wedge log, which has no face handle. This is what a
/// test or an operator asks a specific face, and it is the only form of the number that is
/// deterministic when several faces (or several tests) run in one process.
#[derive(Default, Debug)]
pub struct GateCounts {
    gated: AtomicU64,
    bypassed: AtomicU64,
}

impl GateCounts {
    /// Frames that went through the slot MAC.
    pub fn gated(&self) -> u64 {
        self.gated.load(Ordering::Relaxed)
    }
    /// Frames that SKIPPED the slot MAC as control traffic — see
    /// [`RunningMedium::send_robust`] for what the bypass is for and what bounds it.
    pub fn bypassed(&self) -> u64 {
        self.bypassed.load(Ordering::Relaxed)
    }
}
static TXD_DONE_OK: AtomicU64 = AtomicU64::new(0);
static TXD_DONE_ERR: AtomicU64 = AtomicU64::new(0);
static TXD_LOGGER: std::sync::Once = std::sync::Once::new();
fn txd_start_logger() {
    TXD_LOGGER.call_once(|| {
        tokio::spawn(async move {
            let mut prev = (0u64, 0u64, 0u64);
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                let (e, g, d) = (
                    TXD_ENTER.load(Ordering::Relaxed),
                    TXD_PAST_GATE.load(Ordering::Relaxed),
                    TXD_DONE_OK.load(Ordering::Relaxed) + TXD_DONE_ERR.load(Ordering::Relaxed),
                );
                let stuck_gate = e > prev.0 && g == prev.1;
                let stuck_inject = g > prev.1 && d == prev.2;
                tracing::info!(
                    target: "face.radio.tx",
                    enter = e, past_gate = g,
                    gated = TXD_GATED.load(Ordering::Relaxed),
                    bypassed = TXD_BYPASS.load(Ordering::Relaxed),
                    fec = TXD_FEC.load(Ordering::Relaxed),
                    done_ok = TXD_DONE_OK.load(Ordering::Relaxed),
                    done_err = TXD_DONE_ERR.load(Ordering::Relaxed),
                    stuck_in_gate = stuck_gate, stuck_in_inject = stuck_inject,
                    "radio TX egress counters"
                );
                prev = (e, g, d);
            }
        });
    });
}

struct TxBearer {
    radio: Arc<dyn FrameIo>,
    /// `(bridge, redundancy)` when FEC is enabled: the wire is enqueued into a
    /// generation and the bridge emits `k + R` coded frames on this bearer.
    fec: Option<(Arc<LinkFecBridge<crate::RadioFecPin>>, Arc<AtomicU16>)>,
    /// Per-frame FEC eligibility (appropriate-traffic-only gate); `None` = all frames.
    eligible: Option<FecEligible>,
    /// Shared legacy-rate gate: when true, data injects at the basic legacy rate to reach
    /// a legacy-only-RX neighbour (worst-overheard-receiver cap). `None` = decided rate.
    legacy_gate: Option<Arc<AtomicBool>>,
    /// This node's ephemeral rotating source nonce (mac-addressing-doctrine §2) — stamped into the
    /// 802.11 source field of every frame, replacing the old fixed `DEFAULT_SRC` constant. Shared
    /// (one identity per node) across all bearers.
    source: Arc<EphemeralSource>,
    /// Cooperative 8-bit ephemeral-ID deconfliction (PFS + DAR), shared per node.
    dedup: Arc<Mutex<IdDeconfliction>>,
    /// The data-centric time-slice (#61) + FHSS (#40) transmit scheduler, when configured
    /// (`NDN_SCHED_*`). `None` ⇒ no gating, the historical send path. Per-bearer so a hop retunes its
    /// own radio; the slot timing is identical on every bearer (one common-view clock per node).
    sched: Option<Arc<crate::FaceScheduler>>,
    /// Per-frame rate selection (#82). `None` ⇒ the driver's current rate stands.
    rate: Option<Arc<crate::RatePolicy>>,
    /// A-MSDU coalescer for this bearer's data path (#82 part 2). `None` ⇒ inject each frame
    /// directly. Never used for robust control frames, and never combined with FEC.
    batcher: Option<MediumBatcher>,
    /// Shared across this face's bearers — see [`GateCounts`].
    gate_counts: Arc<GateCounts>,
}

/// `Some(addr3)` only when `addr3` really is the id-carrying `addr3[0..4] ‖ id ‖ flags` shape.
///
/// ⚠ **`addr3` is not always that**, and everything keyed on `addr3[4]`/`addr3[5]` — the ephemeral
/// ID, the DAR collision flag, and now the piggybacked class-commitment slice — inherits the
/// confusion. `build_amsdu` writes `addr3 = addr1`, and the base builder falls back to
/// `addr3 = dst` (`ff × 6` for a legacy broadcast frame). Fed in unconditionally, as they were,
/// every legacy-shaped frame read as a **DAR hint naming ID `0xff`** (`0xff & FLAG_ID_COLLISION`
/// is set), which rotated the ID of any node that happened to hold `0xff`; and every aggregate fed
/// two pseudorandom filter bytes in as an ID and flags.
///
/// `addr3 == addr1` is an EXACT discriminator, not a heuristic: a genuine id-carrying `addr3[0..4]`
/// is nonce-seeded and equals `addr1[0..4]` only by ~2^-32 coincidence, while the two shapes that
/// must be excluded set them equal by construction.
fn ephemeral_id_flags(group: Option<&[u8; 6]>, addr3: Option<&[u8; 6]>) -> Option<[u8; 6]> {
    match (group, addr3) {
        (Some(g), Some(a3)) if g == a3 => None,
        (_, a3) => a3.copied(),
    }
}

impl TxBearer {
    /// Send one already-framed wire on the data plane. Normally at the decided broadcast
    /// rate; but when the shared legacy gate is set (cognition heard a legacy-only-RX
    /// neighbour), inject at the basic legacy rate ([`TxIntent::ROBUST`]) instead, so the
    /// data reaches that neighbour — the doctrine's worst-overheard-receiver rate.
    async fn inject(&self, wire: Bytes) -> Result<(), FaceError> {
        let legacy = self
            .legacy_gate
            .as_ref()
            .is_some_and(|g| g.load(Ordering::Relaxed));
        let intent = if legacy {
            TxIntent::ROBUST
        } else {
            TxIntent::CONSERVATIVE
        };
        // `control = false`: this is DATA. See `inject_with_intent` — the legacy gate picks
        // `TxIntent::ROBUST` for its *rate* and must not thereby take the data plane out of the
        // airtime lease.
        self.inject_with_intent(wire, intent, false).await
    }

    /// Send one wire at an explicit [`TxIntent`]. A `MostRobust` frame (cooperative
    /// report / discovery / control) **bypasses FEC** — it is a standalone control frame,
    /// not part of a data generation — and the driver maps `MostRobust` to the basic
    /// legacy rate every neighbour can decode (the worst-overheard-receiver reach).
    ///
    /// ☠ **`intent` and `control` are two axes, and conflating them handed the whole data plane a
    /// gate bypass.** `robust` below is derived from the intent and correctly suppresses the
    /// throughput-chosen MCS, the FEC generation and A-MSDU batching — a control frame wants none
    /// of those trades. But `TxIntent::ROBUST.reliability == MostRobust`, and
    /// [`TxBearer::inject`] selects `ROBUST` for ordinary data whenever the shared legacy-rate gate
    /// is up (a neighbour advertised legacy-only RX). Testing the intent for the gate decision
    /// therefore meant that ONE such neighbour took this node out of the airtime lease entirely,
    /// at the slowest rate it transmits — the worst possible combination for the shared schedule,
    /// and invisible to the suite because the legacy-gate test binds no scheduler.
    ///
    /// `control` is the second axis: set ONLY by [`RunningMedium::send_robust`], and the only thing
    /// that skips the slot MAC.
    async fn inject_with_intent(
        &self,
        wire: Bytes,
        intent: TxIntent,
        control: bool,
    ) -> Result<(), FaceError> {
        txd_start_logger();
        TXD_ENTER.fetch_add(1, Ordering::Relaxed);
        let robust = intent.reliability == Reliability::MostRobust;
        let legacy = self
            .legacy_gate
            .as_ref()
            .is_some_and(|g| g.load(Ordering::Relaxed));
        // Data-centric time-slice/FHSS gate (#61/#40): wait for this name-group's owned slot and/or
        // retune to its hop channel, from the name + the common-view clock. CONTROL frames
        // (reports / discovery, via `send_robust`) bypass — they must reach the worst receiver now,
        // not wait on a data slot. Keyed on `control`, NOT on the intent: see the doc above. Off
        // unless `NDN_SCHED_*` is set.
        // A ScheduledAt bearer (the C5) with NDN_SCHED_HW_TX=1 places the frame in *hardware* at its owned
        // slot (a delay handed to inject_after below) rather than the host sleeping in the software gate —
        // reconcile-free (the delay is applied on the device's own clock). None ⇒ the software gate, unchanged.
        let mut hw_delay: Option<u64> = None;
        if control {
            TXD_BYPASS.fetch_add(1, Ordering::Relaxed);
            self.gate_counts.bypassed.fetch_add(1, Ordering::Relaxed);
        } else if let Some(sched) = &self.sched {
            // ⚠ REQUIRE THE SEAM, NOT THE LABEL. `hw_slot_wait` keys on `TxDiscipline::ScheduledAt`
            // alone, but a backend can declare that without implementing `inject_after` — and the
            // HAL default for `inject_after` is *inject now*. Taking the hardware path there would
            // skip this software gate AND drop the delay: the frame goes out immediately with no
            // slot discipline at all, strictly worse than never having claimed the discipline.
            // (Measured live case: the AR9271 declares `ScheduledAt{1 µs}` and implements neither
            // seam.) `FrameIo::schedules_tx` is overridden only alongside a real `inject_after`,
            // so requiring it here makes the fallback safe for every present and future backend.
            match sched.hw_slot_wait(&wire) {
                Some(d) if self.radio.schedules_tx() => hw_delay = Some(d),
                _ => sched.gate(&wire).await,
            }
            TXD_GATED.fetch_add(1, Ordering::Relaxed);
            self.gate_counts.gated.fetch_add(1, Ordering::Relaxed);
        }
        TXD_PAST_GATE.fetch_add(1, Ordering::Relaxed);
        // ── Address the frame FIRST, then decide how it goes out ─────────────────────────────
        //
        // Relevance is decided by PARSING the NDN name, not by an in-frame filter, so every frame is
        // broadcast-addressed: addr1 = BROADCAST, and the source field carries this node's ephemeral
        // rotating nonce (doctrine §2 — inert to real networks, no routing meaning, per-frame RSSI
        // key). The 8-bit ephemeral ID + flags + the piggybacked schedule commitment still ride
        // `addr3[4]`/`addr3[5]` (the cooperative ID-deconfliction wire encoding, unchanged).
        //
        // Computing the address before the FEC branch is what keeps the direct, coded and A-MSDU
        // paths incapable of disagreeing (#82) — the FEC path used to return early with a fixed
        // address and a stale nonce.
        let nonce = self.source.current(super::now_ms() as u64);
        // The 8-bit ephemeral ID (+ flags) from the PFS/DAR allocator: normally our own ID with clear
        // flags; when a conflict hint is pending it rides this frame (conflicted ID +
        // FLAG_ID_COLLISION) so the aliasing senders rotate (`ephemeral_id.rs`).
        //
        // **The schedule commitment rides here too** (#93): flags bits 2..7 carry one 3-bit slice of
        // `class_commitment()`, round-robin — the fleet-wide partition detector, read fresh per frame
        // so a map that moves cannot leave a stale commitment on the air.
        let commitment = self.sched.as_ref().map(|s| s.class_commitment());
        let (id, flags) = self.dedup.lock().unwrap().tx_id(commitment);
        // `addr3[0..4]` carry no name meaning; they are seeded from the nonce so the
        // frame's addr3 can never equal its broadcast addr1 (the exact `addr3 == addr1` discriminator
        // `ephemeral_id_flags` uses to tell an id-carrying frame from a legacy filler-addr3 one).
        let a3 = [nonce[0], nonce[1], nonce[2], nonce[3], id, flags];
        let (dst, src, addr3, extra, htc): (
            [u8; 6],
            [u8; 6],
            Option<[u8; 6]>,
            Option<[u8; 8]>,
            Option<[u8; 4]>,
        ) = (BROADCAST, nonce, Some(a3), None, None);

        // The rate this frame should ride, if any is decided. Computed BEFORE the FEC branch so a
        // coded generation can pin it: see the comment at the pin below.
        let decided = (!robust && !legacy)
            .then(|| self.rate.as_ref().map(|r| r.select()))
            .flatten();

        // Only route through the FEC coder when there is parity to add AND this frame
        // is FEC-eligible (appropriate-traffic-only) AND it is not a robust control frame.
        // At R=0 the generation batching would cost the tail-flush latency for no recovery;
        // for an ineligible class (real-time/best-effort) a late-recovered frame is dead
        // weight — all bypass and inject directly. The peer's decoder passes an uncoded
        // frame straight through, so mixing coded/uncoded frames is safe.
        if !robust && let Some((bridge, r)) = &self.fec {
            // The plan is the authority when one is bound; the shared `AtomicU16` is the
            // channel cognition's `MediumActuator` writes when it is not. Reading only the
            // atomic meant a `RadioPlan` could decide `link_fec_redundancy` and have nothing
            // apply it unless a separate actuator happened to be running — the defect this
            // crate is named for in `decided-but-unactuated`.
            let want = self
                .rate
                .as_ref()
                .and_then(|rp| rp.planned_redundancy())
                .unwrap_or_else(|| r.load(Ordering::Relaxed));
            // ★ **`link_fec_redundancy` is an airtime escalation that needs no priority class — and
            // the face is the WRONG place to bound it. Counted, not clamped, and here is why.**
            //
            // Two corrections to the premise. First, it is not unbounded: `LinkFecFeature::set_redundancy`
            // clamps to `min(254, 255 - K)`, with its own test, so `Some(65535)` becomes R=247 at K=8 —
            // a ~31x airtime multiplier, serious, but a bounded one. Second, the obvious tighter bound
            // (R <= K, which is what `RadioPolicy` clamps ITSELF to) is a POLICY choice, not a physical
            // one: R > K is exactly how a broadcast link survives >50% loss, it is reachable through this
            // cell by design, and `planned_redundancy_changes_frames_on_air` asserts a K=2/R=5 generation
            // reaches the air. Enforcing the policy's ceiling here would delete that capability to close
            // an escalation the codec already caps.
            //
            // So this does the thing that is actually the face's business: it makes a parity budget the
            // policy could never have produced VISIBLE. A count moving here is either a cognition bug or a
            // plan that did not come from cognition, and either one is worth a look.
            let parity = want; // counted, never clamped — see above
            // ⚠ **Counted, NOT warned, and the claim it used to make was false.** The old text said
            // "the policy clamps its own R to the generation, so this plan did not come from it".
            // The policy clamps to `PolicyConfig::generation_k` (default 8); this compares against
            // THIS FACE's `generation_size()`, and nothing ties the two. The shipped node binary
            // builds the face with K=1 on purpose (`with_link_fec(1, ..)` — K=1 is repetition), so
            // every legitimate R >= 2 tripped a per-frame `warn!` in production. The two Ks are
            // different quantities, so this comparison cannot distinguish "a plan bypassed
            // cognition" from "this face runs a smaller generation than the policy assumes" — and a
            // detector that cannot tell those apart must not assert the first.
            if want > bridge.generation_size() {
                ndn_radio_cognition::ledger::note_fec_parity_over_generation();
            }
            let eligible = self.eligible.as_ref().is_none_or(|pred| pred(&wire));
            if parity > 0 && eligible {
                // The generation takes the opening frame's address, intent AND rate, so coded
                // traffic keeps the ephemeral-id addressing, the legacy-rate cap, and the decided MCS.
                //
                // `mcs` was `None` here until an on-air run caught it. The reasoning was "this
                // face holds rate as bearer state" — true before `with_rate_policy` existed,
                // false after: with a policy bound and FEC on, EVERY data frame takes this
                // branch, so `inject_at` was never reached and no frame ever carried a decided
                // rate. The old `WifiPhy` pinned `mcs: Some(..)` into its `WifiPin`;
                // unifying the sink dropped that, and the loopback test missed it because it
                // exercised rate and FEC separately, never together.
                //
                // MEASURED (a81a → 881a, ch149, 2684 coded frames): the receiver decoded every
                // `new`-arm frame at the *previous* period's MCS — the rate some other caller
                // had last left in the bearer — while the direct-inject control arm tracked its
                // plan exactly. A decided rate that reaches no frame is this codebase's
                // signature defect, reintroduced by a refactor and invisible to every test that
                // did not put both features on at once.
                TXD_FEC.fetch_add(1, Ordering::Relaxed);
                let r = bridge.send(
                    wire,
                    crate::RadioFecPin {
                        dst,
                        src,
                        addr3,
                        intent,
                        mcs: decided,
                    },
                    Some(parity),
                );
                if r.is_ok() {
                    TXD_DONE_OK.fetch_add(1, Ordering::Relaxed);
                } else {
                    TXD_DONE_ERR.fetch_add(1, Ordering::Relaxed);
                }
                return r;
            }
        }

        let frame = InjectFrame {
            payload: wire,
            tx: intent,
            dst,
            src,
            addr3,
            // No in-frame filter: frames are broadcast-addressed and relevance is decided by parsing
            // the name, so the extended-address / HT-Control slots carry nothing.
            extra,
            htc,
        };
        // A-MSDU bundling (#82 part 2): a non-robust data frame is coalesced instead of injected
        // one at a time. Robust control frames fall through — a report or time beacon must reach the
        // worst receiver *now*, and holding one for a flush window would blunt exactly the
        // worst-overheard-receiver reach the ROBUST intent exists to guarantee.
        //
        // So does a frame the plan has asked not to aggregate (`amsdu_msdus = Some(0)`): the direct
        // path costs it no flush window and gives it a plain MPDU rather than a one-subframe
        // aggregate. `Some(0)` is the plane's way of saying "not this traffic" and is deliberately
        // distinct from `None` = "no opinion, keep the configured cap".
        let no_aggregate = self
            .rate
            .as_ref()
            .and_then(|r| r.planned_amsdu_msdus())
            .is_some_and(|n| n == 0);
        // Hardware slot placement is per-frame (one MPDU at its instant), so it bypasses A-MSDU batching.
        if !robust
            && !no_aggregate
            && hw_delay.is_none()
            && let Some(bat) = &self.batcher
        {
            return bat.submit(frame, decided);
        }
        // Per-frame rate (#82), when a policy is bound. Skipped for robust frames and whenever the
        // legacy gate is up: both mean "reach the worst receiver", which outranks any
        // throughput-chosen rate — actuating a decided MCS there would undo the very cap that was
        // just applied.
        let r = if let Some(delay) = hw_delay {
            // Hardware-scheduled slot placement (C5 T_INJECT_AT). Set the decided rate first (inject_after
            // carries no rate of its own), then place the frame at its owned slot on the device's clock.
            if let Some(mcs) = decided {
                let _ = self.radio.set_rate(mcs);
            }
            self.radio.inject_after(frame, delay).await
        } else if let Some(mcs) = decided {
            self.radio.inject_at(frame, mcs).await
        } else {
            self.radio.inject(frame).await
        };
        if r.is_ok() {
            TXD_DONE_OK.fetch_add(1, Ordering::Relaxed);
        } else {
            TXD_DONE_ERR.fetch_add(1, Ordering::Relaxed);
        }
        r
    }
}

/// The running medium transport: N send-bearers, a unioned inbound channel fed by
/// one reader task per radio, plus any attached background tasks (e.g. a cognition
/// control loop). All task handles are aborted when the transport is dropped — so a
/// face torn down (`engine.remove_face`) stops reading *and* deciding.
pub struct RunningMedium {
    id: FaceId,
    mtu: usize,
    tx: Vec<TxBearer>,
    rx: AsyncMutex<mpsc::UnboundedReceiver<(Bytes, Option<FaceAddr>, u16)>>,
    tasks: Vec<JoinHandle<()>>,
    gate_counts: Arc<GateCounts>,
}

impl RunningMedium {
    /// Attach a background task whose lifetime is tied to this face — aborted when
    /// the transport is dropped. Used to bind a face-owned cognition control loop to
    /// the face (a [`FaceFactory`](ndn_transport::FaceFactory) has no separate
    /// lifetime handle, so it hangs the loop here).
    pub fn attach_task(&mut self, handle: JoinHandle<()>) {
        self.tasks.push(handle);
    }

    /// This face's transmit scheduler, when `NDN_SCHED_*` configured one. Exposed so an experiment
    /// can read what the gate saw — in particular
    /// [`ambient_frames`](crate::FaceScheduler::ambient_frames), which distinguishes "our slots were
    /// busy" from "the channel was busy". Every bearer shares one node clock and one slot map, so the
    /// first bearer's scheduler is the face's.
    pub fn scheduler(&self) -> Option<Arc<crate::FaceScheduler>> {
        self.tx.first().and_then(|b| b.sched.clone())
    }

    /// How many frames this face put through the slot MAC, and how many skipped it.
    ///
    /// The bypass is deliberate and stays (see [`send_robust`](Self::send_robust)); this is the
    /// number that makes it visible. A `bypassed` count climbing with the schedule starving is the
    /// signature of a caller using the control path for data.
    pub fn gate_counts(&self) -> &GateCounts {
        &self.gate_counts
    }

    /// This node's **current §2 source nonce** (rotates every `NONCE_ROTATION_MS`, fresh per
    /// process). Exposed for the claim-C topology instrument: a run prints it at start AND end so
    /// a rotation boundary inside the window self-invalidates, and a peer's `NDN_SCHED_DEAF_SRC`
    /// is set from the printed value rather than guessed.
    pub fn source_nonce(&self) -> Option<[u8; 6]> {
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .ok()?
            .as_millis() as u64;
        self.tx.first().map(|b| b.source.current(now_ms))
    }

    /// Inject a cooperative-broadcast wire (reception report / discovery / control) at
    /// `MostRobust` intent on every bearer — the basic legacy rate every neighbour can
    /// decode, FEC bypassed. Distinct from [`Transport::send_bytes`], which sends data at
    /// the cognition-decided rate: a report must reach the *worst* receiver (e.g. a
    /// legacy-only-RX 8812au), so it never rides the throughput-optimised data rate.
    ///
    /// # ★ This is the one call that SKIPS the named airtime lease, and it is kept that way
    ///
    /// `control = true` below is the only thing in the face that bypasses
    /// [`FaceScheduler::gate`](crate::FaceScheduler::gate): no owned-slot wait, no CCLF jitter.
    /// **What it is for:** a reception report is a Data on `/localhop/radio/report/<node>` — a
    /// *named* object, so the gate would genuinely make it wait for that group's turn — and the
    /// whole point of a report is to tell a sender NOW that it is unreachable at the rate it is
    /// using. Deferring the signal that a link is failing until the failing link's schedule comes
    /// round is the wrong trade. (The time beacon does not use this path at all: it calls
    /// `radio.inject()` directly from the master task, already rate-limited by `TIME_BEACON_MS`.)
    ///
    /// **What bounds it, honestly:**
    /// * *Not a class.* Requiring a `NameContext` here would be theatre — the class does not meter
    ///   the only real cost (airtime), and the medium is not a security boundary anyway: an
    ///   in-process crate holding the `Arc<dyn FrameIo>` bypasses the medium wholesale. Everything
    ///   here is defence against accident and drift, not against a hostile linked crate.
    /// * *Not the Latency lane.* Routing reports through the gate as
    ///   [`LeaseClass::Latency`](ndn_radio_cognition::LeaseClass) looks like the designed answer and
    ///   is currently STRICTLY WORSE: `NDN_SCHED_RESERVE` defaults to 0, and with no reserved lanes
    ///   a Latency frame waits for its owned slot *and* declines to opportunistically claim idle
    ///   ones. It becomes right only once reserved lanes are on by default — a separate decision
    ///   with its own on-air evidence requirement.
    /// * *Not a token bucket — yet.* A leaky airtime budget that falls through to `sched.gate()` on
    ///   exhaustion is the right shape (deferring costs one slot; dropping would break the thing the
    ///   bypass exists for), but its size is the whole design and we have no measurement to set it
    ///   from. An unmeasured budget here would be one more decided-but-unvalidated knob.
    /// * *Counted instead.* Every bypass increments `TXD_BYPASS`, logged as `bypassed` beside
    ///   `gated` under target `face.radio.tx`. Cost per call, from the in-tree airtime model (a
    ///   bound, not a measurement): a 1500 B frame at basic 6 Mbps is ~2060 µs, ~8.4x an MCS7 frame
    ///   and ~69% of the `NDN_SCHED_SLOT=8:3000` example slot — and this fans out over EVERY bearer,
    ///   so an N-radio face pays N x per call.
    ///
    /// ⚠ **NOT MEASURED, and it may buy less than it looks like.** `gate()` holds `REG_TXPAUSE`
    /// (`TxHoldGuard`) while another frame waits for its slot, and TXPAUSE holds *all* transmissions
    /// at the MAC — it holds, it does not drop. So on a part with a TX-hold actuator a bypassing
    /// frame is plausibly stalled inside the chip anyway and released in a burst at the start of a
    /// slot it does not own, turning "reaches the worst receiver now" into "reaches it at an
    /// unpredictable later instant". This is read from the code and the HAL's documented semantics;
    /// no on-air run has been made. Cheap to test: two concurrent senders on one bearer with
    /// `NDN_SCHED_SLOT` set and a `set_tx_hold`-capable backend, timestamping report egress.
    pub async fn send_robust(&self, wire: Bytes) -> Result<(), FaceError> {
        let mut sent = false;
        let mut last_err = None;
        for b in &self.tx {
            match b
                .inject_with_intent(wire.clone(), TxIntent::ROBUST, true)
                .await
            {
                Ok(()) => sent = true,
                Err(e) => last_err = Some(e),
            }
        }
        if sent {
            Ok(())
        } else {
            Err(last_err.unwrap_or(FaceError::Closed))
        }
    }
}

impl RunningMedium {
    fn spawn(cfg: RadioMediumFace) -> Self {
        let RadioMediumFace {
            id,
            mtu,
            group_table,
            bearers,
            signal_sink,
            fec,
            legacy_gate,
            amsdu,
            rate,
        } = cfg;

        let (tx_chan, rx_chan) = mpsc::unbounded_channel();
        let mut tx = Vec::with_capacity(bearers.len());
        // One per FACE, shared by its bearers: `send_robust` fans out over every bearer, so a
        // per-bearer count would report N per call and hide the fan-out cost rather than show it.
        let gate_counts = Arc::new(GateCounts::default());
        let mut tasks = Vec::with_capacity(bearers.len());

        // This node's ephemeral source identity (mac-addressing-doctrine §2): one per-boot random
        // nonce, shared across bearers, rotating every 5 minutes to bound linkability. Seeded from
        // wall-clock nanos ⊕ pid ⊕ face id — non-cryptographic per-boot entropy (a stronger RNG is a
        // drop-in replacement for `boot_seed` without touching anything downstream).
        const NONCE_ROTATION_MS: u64 = 5 * 60 * 1000;
        let boot_seed = {
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos() as u64)
                .unwrap_or(0);
            nanos ^ ((std::process::id() as u64) << 32) ^ id.0.wrapping_mul(0x9E37_79B9)
        };
        let source = Arc::new(EphemeralSource::new(boot_seed, NONCE_ROTATION_MS));
        // The 8-bit ephemeral ID + PFS/DAR deconfliction (wire-format-spec §4), shared per node like
        // the nonce. stale = the rotation period; alias window = 2 s of soft state.
        let dedup = Arc::new(Mutex::new(IdDeconfliction::new(
            boot_seed,
            NONCE_ROTATION_MS,
            2_000,
        )));
        // Per-neighbour accumulation of the piggybacked schedule commitment (#93), shared per node
        // like the ID allocator. Staleness = the ID rotation period: past it the ID no longer names
        // the same transmitter, so its accumulated agreement is not about anyone.
        let commit_watch = Arc::new(Mutex::new(ClassCommitmentWatch::new(NONCE_ROTATION_MS)));

        for b in bearers {
            // #83: the radio's self-description outranks the caller's assertion, and a mismatch is
            // said out loud. A capability that is asserted and never checked against the hardware is
            // how `agile` became decorative (#98); this is the same failure caught one layer up.
            if let Some(p) = &b.profile {
                let declared = p.capability();
                if declared != b.cap {
                    tracing::warn!(
                        target: "monitor-wifi", face = id.0, radio = b.id.0,
                        "capability mismatch: caller asserted {:?}, radio declares {:?} — using the \
                         radio's",
                        b.cap, declared
                    );
                }
            }

            // One link-FEC bridge per bearer (shared TX-encode / RX-decode) when enabled: the sink
            // injects each coded frame on this bearer, and the reader feeds captured frames through
            // the same bridge's decoder.
            //
            // The sink is `crate::RadioFecSink`, shared with `WifiPhy` (#82). It replaced
            // `ndn-coding`'s generic `FrameIoSink`, which took a fixed broadcast dst and **one nonce
            // snapshotted for the bridge's whole lifetime** — so turning link-FEC on turned the
            // ephemeral-id addressing and §2 nonce rotation off. Address, nonce and intent now ride the
            // per-generation pin, resolved by the same code the direct send path uses.
            let bridge = fec.as_ref().map(|fc| {
                Arc::new(LinkFecBridge::spawn(
                    crate::RadioFecSink {
                        radio: b.radio.clone(),
                    },
                    fc.k,
                    0,
                    fc.window,
                ))
            });
            // The data-centric time-slice/FHSS scheduler (#61/#40), per bearer so a hop retunes its own
            // radio via that bearer's knobs. Constructed from `NDN_SCHED_*`; `None` ⇒ send path
            // unchanged. Shared (Arc) with this bearer's RX reader so inbound hardware stamps feed the
            // scheduler's disciplined clock (#41). Bandwidth defaults to 20 MHz for hops across
            // non-overlapping channels.
            let sched =
                crate::FaceScheduler::from_env(b.knobs.clone(), crate::Bandwidth::default(), mtu)
                    .map(|s| {
                        // Give the scheduler this bearer's rate policy so the #84 guard band sizes its
                        // airtime estimate from the rate we will actually transmit at, not from the
                        // conservative worst case (which would defer frames that would have fitted).
                        let s = match &rate {
                            Some(r) => s.with_rate(r.clone()),
                            None => s,
                        };
                        // §9.3: seed the slot key with this bearer's operating channel, so a static radio
                        // no longer keys on the FHSS sentinel and two of them on different channels get
                        // distinct schedules.
                        let s = s.with_operating_channel(b.channel);
                        // P1: slot key = longest registered prefix; RX attribution by parsing the name.
                        match &group_table {
                            Some(t) => s.with_groups(t.clone()),
                            None => s,
                        }
                    })
                    // **Refuse a hop schedule this radio cannot serve** (#97/#98). `set_channel` on the
                    // Wi-Fi monitor parts is a ~16 ms blocking call; against a short dwell the radio
                    // spends most of its life retuning and the "schedule" is thrashing, not frequency
                    // diversity. That was known and written in a comment; now the capability carries the
                    // measured cost and the face acts on it instead of hopping anyway.
                    .map(|s| s.vet_hop(&b.cap))
                    .map(Arc::new);
            if let Some(s) = &sched {
                tracing::info!(target: "monitor-wifi", face = id.0, "{}", s.describe());
                // **What was this run actually configured with?** (#81) 129 NDN_* variables exist
                // and nothing recorded which were set, so a measurement could not be reproduced
                // from its own output and a misspelled name was indistinguishable from an unset
                // one. Printed once per scheduled face, alongside the schedule it produced.
                let env = ndn_env::describe();
                if !env.is_empty() {
                    tracing::info!(target: "monitor-wifi", face = id.0, "{env}");
                }
            }
            // A-MSDU coalescer for this bearer (#82 part 2). Mutually exclusive with link-FEC:
            // the FEC bridge already emits a generation's k+R frames back-to-back, and batching on
            // top of it would only add the flush window to every generation's latency.
            let batcher = match (&amsdu, &fec) {
                (Some(cfg), None) => {
                    let (bat, handle) = MediumBatcher::spawn(b.radio.clone(), *cfg, rate.clone());
                    tasks.push(handle);
                    Some(bat)
                }
                (Some(_), Some(_)) => {
                    tracing::warn!(
                        target: "monitor-wifi", face = id.0, radio = b.id.0,
                        "A-MSDU batching ignored on this bearer: link-FEC is enabled and the two \
                         are mutually exclusive"
                    );
                    None
                }
                _ => None,
            };
            tx.push(TxBearer {
                radio: b.radio.clone(),
                batcher,
                fec: bridge
                    .clone()
                    .zip(fec.as_ref().map(|fc| fc.redundancy.clone())),
                eligible: fec.as_ref().and_then(|fc| fc.eligible.clone()),
                legacy_gate: legacy_gate.clone(),
                source: source.clone(),
                dedup: dedup.clone(),
                sched: sched.clone(),
                rate: rate.clone(),
                gate_counts: gate_counts.clone(),
            });

            // One reader per radio → the RX union. A frame heard on any capability is
            // forwarded once to the engine (after FEC decode when on); its RSSI/rate
            // is published for the sense→decide loop.
            let radio = b.radio.clone();
            let radio_id = b.id.0; // stamp each captured frame with its receiving radio
            let out = tx_chan.clone();
            let sink = signal_sink.clone();
            let rx_bridge = bridge;
            let loss = fec.as_ref().map(|fc| fc.loss.clone());
            let sched_rx = sched.clone();
            // Claim-C topology instrument (see the RX hook below): hex byte prefix of a §2 nonce
            // this node is artificially deaf to, e.g. NDN_SCHED_DEAF_SRC=024e444e0003.
            let deaf_src: Option<Vec<u8>> = std::env::var("NDN_SCHED_DEAF_SRC")
                .ok()
                .map(|h| {
                    (0..h.len() / 2 * 2)
                        .step_by(2)
                        .filter_map(|i| u8::from_str_radix(&h[i..i + 2], 16).ok())
                        .collect()
                })
                .filter(|v: &Vec<u8>| !v.is_empty());
            if let Some(d) = &deaf_src {
                tracing::warn!(target: "monitor-wifi", "TOPOLOGY INSTRUMENT: deaf to src {:02x?}", d);
            }
            let rate_rx = rate.clone();
            let dedup = dedup.clone();
            let commit_watch = commit_watch.clone();
            tasks.push(tokio::spawn(async move {
                let mut last_mesh_cv = 0u64; // last mesh common-view observation count ingested (#74)
                loop {
                    match radio.recv_frame().await {
                        Ok(f) => {
                            // #41: feed the frame's hardware RX timestamp into the scheduler's
                            // disciplined clock — this is the face consuming `.stamp`, the gap the
                            // shared RadioHwClock was built to close. Cheap; only when scheduling is on.
                            if let (Some(sched), Some(stamp)) = (sched_rx.as_ref(), f.stamp.as_ref()) {
                                sched.on_rx_stamp(stamp);
                            }
                            // #88: the busy mark + per-slot evidence, for EVERY captured frame. This
                            // used to ride on the stamp branch above, so a radio whose driver reports
                            // no TSFT never marked the medium busy at all and claimed every slot.
                            if let Some(sched) = sched_rx.as_ref() {
                                // **NDN_SCHED_DEAF_SRC** (claim-C topology instrument, DebugBisect
                                // class): drop frames whose §2 source nonce starts with the given
                                // hex bytes BEFORE they reach the scheduler — a software hearing
                                // matrix on real radios. Exists because hiddenness cannot be
                                // created electronically at bench range (measured: ≥~90 dB link
                                // margin vs 9.6 dB of TXAGC authority, B210 2026-08-13) and
                                // physical options are excluded. The MAC's information topology
                                // becomes hidden-terminal; collisions at the victim stay
                                // physically real. Declared in the prereg; printed in the header.
                                let deaf = deaf_src.as_deref().is_some_and(|d| {
                                    let src = if f.group.as_ref() == Some(&ndn_radio_hal::BROADCAST)
                                    {
                                        f.addr.as_ref()
                                    } else {
                                        f.addr3.as_ref()
                                    };
                                    src.is_some_and(|s| s.starts_with(d))
                                });
                                if !deaf {
                                    sched.observe_rx(
                                        f.group.as_ref(),
                                        f.addr.as_ref(),
                                        f.addr3.as_ref(),
                                        &f.payload,
                                    );
                                }
                            }
                            // #74: the MESH hardware common-view — discipline the scheduler's clock to a
                            // neighbour's HW-TSF-stamped timing beacon (pair (peer_tsf, our_rxtsfl), both
                            // hardware) → self-contained sub-µs `CommonView` epoch, no AP. This is the
                            // face consuming the µs hardware clock (upgrading `cv` mode from the ms
                            // software beacon). Poll the driver's mesh side channel; ingest fresh obs.
                            if let Some(sched) = sched_rx.as_ref()
                                && let Some(mcv) = radio.mesh_common_view()
                                && mcv.count != last_mesh_cv
                            {
                                last_mesh_cv = mcv.count;
                                // #75: if the neighbour advertised a belief, compose multi-hop through it;
                                // otherwise treat it as a direct stratum-0 reference (single-hop, #74).
                                match mcv.belief {
                                    Some(b) => sched.ingest_common_view(mcv.peer_tsf, mcv.our_rxtsfl, b),
                                    None => sched.ingest_mesh_beacon(mcv.peer_tsf, mcv.our_rxtsfl, mcv.bssid),
                                }
                            }
                            // Time-beacon (#41 common-view): discipline the common-view clock to the
                            // master's reference and SUPPRESS the frame — it is a clock signal, not NDN
                            // traffic, so it never reaches the engine.
                            if let Some(sched) = sched_rx.as_ref()
                                && let Some(ref_us) = crate::FaceScheduler::parse_beacon(&f.payload)
                            {
                                // D2: the beacon carries the sender's schedule-map digest. A mismatch
                                // means the medium is partitioned — its slot map differs from ours, so
                                // its evidence lands in different slots. Detected and reported, not
                                // corrected (there is no convergence protocol, by design).
                                if sched.beacon_indicates_partition(&f.payload) {
                                    // The version rides in the clear so this line can say WHICH kind
                                    // of split it is: a neighbour on an older pinned set (every
                                    // v1<->v2 pair reports partitioned by construction — the version
                                    // is the first thing the digest mixes) versus one on our version
                                    // that classifies names differently (#93 class_digest). `None`
                                    // means a pre-v2 beacon, which is itself the first answer.
                                    tracing::warn!(
                                        ours = sched.map_digest(),
                                        theirs = crate::FaceScheduler::parse_beacon_map_digest(&f.payload),
                                        our_params_version = crate::sched::SCHED_PARAMS_VERSION,
                                        their_params_version = crate::FaceScheduler::parse_beacon_params_version(&f.payload),
                                        "schedule-map partition: a neighbour computes a different slot map (mismatched SchedParams)"
                                    );
                                }
                                sched.ingest_time_ref(ref_us);
                                continue;
                            }
                            // Relevance is decided by the engine parsing the NDN name — there is no
                            // in-frame filter to drop on here. Every captured frame is passed up; the
                            // ephemeral-ID / DAR / commitment machinery below reads `addr3[4]/[5]`.
                            // The sender's ephemeral nonce is in addr3 under the id-carrying layout, else
                            // in addr2 (legacy). This one accessor keys per-neighbour signals and the
                            // reassembly stream correctly for both layouts.
                            // Feedback for `McsPolicy::Adaptive` (#82): the RX path is what makes
                            // the TX path adaptive, so the policy is shared across the two.
                            if let (Some(rate), Some(rssi)) = (rate_rx.as_ref(), f.rssi_dbm) {
                                rate.observe_rssi(rssi);
                            }
                            // ⚠ **`addr3` is only `id ‖ flags` under the id-carrying layout.** The A-MSDU
                            // builder writes `addr3 = addr1` (`build_amsdu`) and the base builder
                            // falls back to `addr3 = dst` for a legacy broadcast frame — and both
                            // were fed here unconditionally, so EVERY legacy-shaped frame was read as
                            // a DAR hint naming ID 0xff (`0xff & FLAG_ID_COLLISION != 0`) and every
                            // aggregate fed two pseudorandom filter bytes in as an ID and flags. The
                            // class-commitment slice inherits that byte, so the guard is a
                            // prerequisite, not a tidy-up. `addr3 == addr1` is an exact
                            // discriminator: a real id-carrying `addr3[0..4]` equals `addr1[0..4]` only by
                            // ~2^-32 coincidence.
                            let eph_a3 = ephemeral_id_flags(f.group.as_ref(), f.addr3.as_ref());
                            // Cooperative ID deconfliction (PFS/DAR): feed the received ID + flags +
                            // RSSI. Returns true if this was a DAR *hint* frame — whose addr3[4] is the
                            // conflicted ID, not the sender's, so it keys no neighbour.
                            let is_hint = match eph_a3 {
                                Some(a3) => {
                                    dedup.lock().unwrap().rx(a3[4], a3[5], f.rssi_dbm, super::now_ms() as u64)
                                }
                                None => false,
                            };
                            // **The piggybacked schedule commitment** (#93, wire-format-spec §5.4):
                            // compare the 3-bit slice this frame carries against our own fold. This
                            // is the carrier that made partition detection FLEET-wide — the time
                            // beacon is transmitted only by `is_master()`, so a non-master defector
                            // was previously undetectable by anyone.
                            //
                            // Skipped on a hint frame (its `addr3[4]` is another node's ID, so a
                            // slice would be filed against an innocent neighbour — which is also why
                            // `tx_id` emits no slice on one). The watch reports a half-collected
                            // round as `Unknown`/`Agreeing`, NEVER as a partition, and warns once per
                            // divergence rather than once per frame.
                            //
                            // ⚠ **Scope: this sits BEHIND the RX name gate** (like the DAR path it
                            // rides with, and for the same reason — both key on the ephemeral ID,
                            // and the gate is what says the frame is in our naming domain). So a
                            // neighbour whose traffic shares no registered prefix with us is not
                            // judged by us. That is the same population whose slot placement can
                            // contend with ours, but it is a narrower claim than "every neighbour"
                            // and should be read as such.
                            if let (Some(sched), Some(a3), false) = (sched_rx.as_ref(), eph_a3, is_hint) {
                                let v = commit_watch.lock().unwrap().observe(
                                    a3[4],
                                    a3[5],
                                    sched.class_commitment(),
                                    super::now_ms() as u64,
                                );
                                if v.newly_divergent {
                                    tracing::warn!(
                                        target: "monitor-wifi",
                                        neighbour_id = a3[4],
                                        ours = sched.class_commitment(),
                                        our_params_version = crate::sched::SCHED_PARAMS_VERSION,
                                        "schedule-map partition (piggybacked commitment): a \
                                         neighbour computes a different slot map. This is a 21-bit \
                                         fold — it says the maps DIFFER, not why: an older \
                                         SchedParams version and a different lane policy are \
                                         indistinguishable here. The master's beacon carries the \
                                         version in the clear if one is running."
                                    );
                                }
                            }
                            // Source key = the 8-bit ephemeral ID (addr3[4] under the id-carrying
                            // layout; the full legacy nonce in addr2 otherwise). NOT the whole addr3 —
                            // its first four bytes are pseudo-random, so keying on them would fabricate
                            // a fresh neighbour per frame.
                            let nonce: Option<[u8; 6]> = if is_hint {
                                None
                            } else {
                                match eph_a3 {
                                    Some(a3) => Some([a3[4], 0, 0, 0, 0, 0]),
                                    None => f.addr,
                                }
                            };
                            if (f.rssi_dbm.is_some() || f.mcs_index.is_some())
                                && let Some(sink) = sink.as_ref()
                            {
                                let mut ls = LinkSignals {
                                    rssi_dbm: f.rssi_dbm,
                                    observed_tput_bps: f.mcs_index.map(mcs_phy_rate_bps),
                                    updated_ms: super::now_ms(),
                                    ..LinkSignals::default()
                                };
                                if let Some(mcs) = f.mcs_index {
                                    ls.ext_set("mcs", mcs as f32);
                                }
                                sink.set_link(id, ls);
                                // Doctrine §2: also attribute this RSSI to the *neighbour* by its
                                // ephemeral source nonce (addr3 under the id-carrying layout, addr2 legacy), so the
                                // store is a per-neighbour map, not an ambient per-face scalar.
                                if let Some(src) = nonce {
                                    sink.set_source_link(src, ls);
                                }
                            }
                            let addr = nonce.map(FaceAddr::Ether);
                            match &rx_bridge {
                                // FEC: a captured frame yields 0 (parity, incomplete),
                                // 1 (a source), or several (parity completed a
                                // generation, recovering losses). Each is measured for
                                // residual loss and delivered.
                                Some(bridge) => {
                                    for p in bridge.decode(f.payload) {
                                        if let Some(m) = &loss {
                                            m.observe(&p);
                                        }
                                        if out.send((p, addr.clone(), radio_id)).is_err() {
                                            return;
                                        }
                                    }
                                }
                                None => {
                                    if out.send((f.payload, addr, radio_id)).is_err() {
                                        return; // face dropped — stop reading
                                    }
                                }
                            }
                        }
                        // A transient per-radio RX error must not kill the union.
                        Err(_) => tokio::task::yield_now().await,
                    }
                }
            }));
        }

        // The clock master broadcasts the time-beacon (#41 common-view) on its first bearer, so every
        // `cv` node disciplines its slot clock to one shared timeline — no NTP, no AP. Injected raw
        // (bypasses the slot gate: the clock signal must never wait on a data slot).
        if let Some(first) = tx.first()
            && let Some(sched) = first.sched.clone()
            && sched.is_master()
        {
            let radio = first.radio.clone();
            let src = source.clone();
            tasks.push(tokio::spawn(async move {
                let mut tick =
                    tokio::time::interval(std::time::Duration::from_millis(TIME_BEACON_MS));
                loop {
                    tick.tick().await;
                    // Time beacons are broadcast control, not name-addressed: they must reach every
                    // node regardless of any name relevance, so addr1 stays broadcast (which always
                    // passes) and the nonce rides addr2 as in the legacy layout.
                    let frame = InjectFrame {
                        payload: sched.build_beacon(),
                        tx: TxIntent::ROBUST,
                        dst: BROADCAST,
                        src: src.current(super::now_ms() as u64),
                        addr3: None,
                        extra: None,
                        htc: None,
                    };
                    let _ = radio.inject(frame).await; // transient errors: keep the clock alive
                }
            }));
        }

        Self {
            id,
            mtu,
            tx,
            rx: AsyncMutex::new(rx_chan),
            tasks,
            gate_counts,
        }
    }
}

impl Drop for RunningMedium {
    fn drop(&mut self) {
        for h in &self.tasks {
            h.abort();
        }
    }
}

impl Transport for RunningMedium {
    fn id(&self) -> FaceId {
        self.id
    }

    fn kind(&self) -> FaceKind {
        // `Wfb` is the workspace's connectionless-radio-broadcast kind — despite the
        // Wi-Fi-legacy name it is already shared by non-Wi-Fi radios (ndn-phy-lora
        // reports it too): LP framing on, NonLocal, `AdHoc` link. Renaming it to a
        // neutral `FaceKind::Radio` is a foundational-enum change tracked separately.
        FaceKind::Wfb
    }

    fn remote_uri(&self) -> Option<String> {
        Some("radio-medium://broadcast".to_string())
    }

    fn link_type(&self) -> LinkType {
        LinkType::AdHoc
    }

    fn send_mtu(&self) -> Option<usize> {
        Some(self.mtu)
    }

    async fn send_bytes(&self, wire: Bytes) -> Result<(), FaceError> {
        // Fan out: inject the (already LP-framed) frame on every bearer at its own
        // decided rate. On a broadcast medium this replication is diversity; one
        // bearer collapses to the single-radio path. Succeed if any radio accepted
        // the frame; surface the last error only if all failed.
        let mut sent = false;
        let mut last_err = None;
        for b in &self.tx {
            match b.inject(wire.clone()).await {
                Ok(()) => sent = true,
                Err(e) => last_err = Some(e),
            }
        }
        if sent {
            Ok(())
        } else {
            Err(last_err.unwrap_or(FaceError::Closed))
        }
    }

    async fn recv_bytes(&self) -> Result<Bytes, FaceError> {
        self.recv_bytes_with_meta().await.map(|(b, _, _)| b)
    }

    async fn recv_bytes_with_addr(&self) -> Result<(Bytes, Option<FaceAddr>), FaceError> {
        self.recv_bytes_with_meta().await.map(|(b, a, _)| (b, a))
    }

    async fn recv_bytes_with_meta(
        &self,
    ) -> Result<(Bytes, Option<FaceAddr>, Option<u16>), FaceError> {
        let mut rx = self.rx.lock().await;
        rx.recv()
            .await
            .map(|(b, a, r)| (b, a, Some(r)))
            .ok_or(FaceError::Closed)
    }

    fn set_send_mtu(&self, _mtu: Option<u64>) -> Result<Option<u64>, MtuError> {
        Err(MtuError::Immutable)
    }

    fn set_persistency(&self, _persistency: FacePersistency) -> Result<(), PersistencyError> {
        Err(PersistencyError::Immutable)
    }
}

#[cfg(test)]
mod power_actuation_tests {
    use super::*;
    use crate::LoopbackMonitorBus;
    use ndn_radio_cognition::{LoraRate, RadioPlan, TxParams};
    use std::sync::Mutex as StdMutex;

    /// Records which power scale the actuator reached for.
    #[derive(Default)]
    struct SpyKnobs {
        dbm_calls: StdMutex<Vec<i8>>,
        idx_calls: StdMutex<Vec<u32>>,
        bw_calls: StdMutex<Vec<u32>>,
        /// The `(l2h, h2l)` defer thresholds that actually reached the chip.
        edcca_thresh_calls: StdMutex<Vec<(i8, i8)>>,
        /// Carrier-sense overrides that actually reached the chip.
        edcca_calls: StdMutex<Vec<bool>>,
        /// Simulate a radio with no absolute control.
        dbm_unsupported: bool,
    }

    impl RadioKnobs for SpyKnobs {
        fn set_channel(&self, _c: u8, _bw: Bandwidth) -> Result<(), FaceError> {
            Ok(())
        }
        fn set_tx_power(
            &self,
            req: ndn_radio_hal::PowerRequest,
        ) -> Result<ndn_radio_hal::AppliedPower, FaceError> {
            let idx = req.requested_index().unwrap_or(63);
            self.idx_calls.lock().unwrap().push(idx as u32);
            // A spy on an index-scale part: report a driver reference with no measured slope,
            // which is what every Wi-Fi part in this fleet honestly has.
            Ok(ndn_radio_hal::AppliedPower::from_writes(
                req,
                ndn_radio_hal::PowerReference::DriverReference {
                    source: "spy",
                    slope_db_per_idx: None,
                },
                idx,
                false,
                vec![ndn_radio_hal::PowerWrite {
                    reg: 0,
                    value: idx,
                    group: "spy",
                    path: 0,
                }],
            ))
        }
        fn set_tx_power_dbm(&self, dbm: i8) -> Result<i8, FaceError> {
            if self.dbm_unsupported {
                return Err(FaceError::Io(std::io::Error::from(
                    std::io::ErrorKind::Unsupported,
                )));
            }
            self.dbm_calls.lock().unwrap().push(dbm);
            // Report a clamp, as real firmware does.
            Ok(dbm.min(27))
        }
        fn set_bandwidth_khz(&self, khz: u32) -> Result<(), FaceError> {
            self.bw_calls.lock().unwrap().push(khz);
            Ok(())
        }
        fn set_edcca_threshold_dbm(&self, l2h: i8, h2l: i8) -> Result<(), FaceError> {
            self.edcca_thresh_calls.lock().unwrap().push((l2h, h2l));
            Ok(())
        }
        fn set_edcca_ignore(&self, on: bool) -> Result<(), FaceError> {
            self.edcca_calls.lock().unwrap().push(on);
            Ok(())
        }
    }

    /// ☠ **The loudest escalation on the chip, bounded where it actuates.**
    ///
    /// Sealing `edcca_ignore` and bounding the defer threshold closed the two doors an audit was
    /// watching — and left "pin the part at maximum TX power" wide open, silently reverting the
    /// spatial-reuse back-off with nothing able to disagree: `radio.N.tx_power` shows the operator
    /// the REQUESTED value, so without a counter beside it there is no contradiction to notice.
    ///
    /// `RadioPolicy` clamps both power forms to this same declared capability, so a value outside
    /// it did not come from cognition — the identical reasoning that justifies the threshold clamp.
    ///
    /// Falsified by deleting the clamp block in `apply_knobs`: the spy then records 255 / 127 and
    /// both assertions fire.
    #[test]
    fn tx_power_outside_the_radios_declared_range_is_bounded_and_counted() {
        let before = ndn_radio_cognition::ledger::counts().tx_power_clamped;
        let knobs = Arc::new(SpyKnobs::default());
        let bus = LoopbackMonitorBus::new();
        let io: Arc<dyn FrameIo> = Arc::new(bus.endpoint(1, -55));
        let cap = RadioCapability::wifi_monitor_5ghz(vec![149])
            .with_tx_power_dbm(crate::DbmRange::new(10, 22));
        let act = MediumActuator::new(RadioId(0), io, Some(knobs.clone())).with_capability(cap);
        let plan = RadioPlan::single(
            RadioId(0),
            None,
            TxParams {
                tx_power_dbm: Some(127),
                ..Default::default()
            },
        );
        act.apply(plan.allocation_for(RadioId(0)).unwrap()).unwrap();
        let applied = knobs.dbm_calls.lock().unwrap().clone();
        assert!(
            applied.iter().all(|&d| d <= 22),
            "a request above the declared range must not reach the knob: {applied:?}"
        );
        assert!(
            ndn_radio_cognition::ledger::counts().tx_power_clamped > before,
            "and the clamp must be COUNTED — it is the only thing an operator can compare \
             `radio.N.tx_power` against"
        );
    }

    fn actuate(knobs: Arc<SpyKnobs>, params: TxParams) -> Arc<SpyKnobs> {
        let bus = LoopbackMonitorBus::new();
        let io: Arc<dyn FrameIo> = Arc::new(bus.endpoint(1, -55));
        let act = MediumActuator::new(RadioId(0), io, Some(knobs.clone()));
        let plan = RadioPlan::single(RadioId(0), None, params);
        act.apply(plan.allocation_for(RadioId(0)).unwrap()).unwrap();
        knobs
    }

    /// ★ **The claim reaches silicon only with an authority behind it, and it is COUNTED there.**
    ///
    /// Two halves of surface A in one test. The seal (an unauthorised name cannot produce
    /// `edcca_ignore`) is proved in `ndn-radio-cognition`'s own suite; this is the other end — that
    /// an authorised claim really does reach `set_edcca_ignore`, and that `apply_knobs` tallies it
    /// on the bearer-agnostic ledger the control surface publishes. The ledger is the house rule
    /// applied: a bypass nothing counts is a bypass nobody can see abused. Nothing here PREVENTS a
    /// claim — `ledger` is diagnostics, and the direct-driver-knob path it cannot see is named in
    /// `Contention`'s docs.
    ///
    /// Counted on arrival rather than on a register write, so a claim re-asserted every tick keeps
    /// counting even though the knob is change-gated and pushed once.
    ///
    /// Falsified by moving `note_edcca_ignored()` inside the `last.edcca != ...` change gate (the
    /// second tick then adds nothing), or by deleting it.
    #[test]
    fn an_authorised_medium_claim_reaches_the_chip_and_is_counted() {
        use ndn_radio_cognition::{ClassAuthority, ClassCeiling, Contention, NameContext, Priority};
        struct Urgent;
        impl ClassAuthority for Urgent {
            fn ceiling_for(&self, _h: u64) -> Priority {
                Priority::Urgent
            }
        }
        let ctx = NameContext::new(7).with_ceiling(ClassCeiling::authorised(&Urgent, 7));
        let params = TxParams {
            contention: Contention::deferring().ignoring_edcca(&ctx),
            ..Default::default()
        };
        assert!(params.edcca_ignore(), "the authority granted the claim");

        let before = ndn_radio_cognition::ledger::counts().edcca_ignored;
        let knobs = Arc::new(SpyKnobs::default());
        let bus = LoopbackMonitorBus::new();
        let io: Arc<dyn FrameIo> = Arc::new(bus.endpoint(1, -55));
        let act = MediumActuator::new(RadioId(0), io, Some(knobs.clone()));
        let plan = RadioPlan::single(RadioId(0), None, params);
        let alloc = plan.allocation_for(RadioId(0)).unwrap();
        act.apply(alloc).unwrap();
        act.apply(alloc).unwrap(); // unchanged ⇒ one register write, but two claims

        assert_eq!(
            *knobs.edcca_calls.lock().unwrap(),
            vec![true],
            "the knob is change-gated: one write"
        );
        assert_eq!(
            ndn_radio_cognition::ledger::counts().edcca_ignored - before,
            2,
            "the LEDGER counts claims, not register traffic — otherwise a sustained claim looks \
             like a single event"
        );
    }

    /// ☠ **The equivalent bypass, bounded where it actuates.**
    ///
    /// `edcca_ignore` is now a sealed `Contention` that only an authorised `Urgent` name can set —
    /// but `edcca_threshold_dbm` is the GRADED FORM OF THE SAME DECISION ON THE SAME CHIP, it has
    /// no flag on it, and the Realtek backend range-checks nothing: it encodes
    /// `((dbm + 110 + 0x80) & 0xff)` straight into `0x84c`, so an arriving `(17, 9)` writes `0xff`
    /// — the channel is never busy. Sealing the flag while leaving this open would have closed the
    /// door everyone was watching and left the window beside it.
    ///
    /// The field stays public (any class may have an opinion about its own defer threshold once it
    /// has measured the margin); what is bounded is how far the opinion may reach — to the top of
    /// the range `decide_edcca_threshold_dbm` can actually produce.
    ///
    /// Falsified by deleting the `clamp_defer_threshold` call in `apply_knobs`: the spy then
    /// records `(17, 9)` and the assertion fires.
    ///
    /// ⚠ NOT MEASURED: the `0xff` claim is derived from the driver's encoder arithmetic, not from a
    /// register read-back on hardware. What this test proves is the clamp, not the silicon effect.
    #[test]
    fn a_defer_threshold_the_policy_could_never_decide_is_bounded_at_the_actuator() {
        let before = ndn_radio_cognition::ledger::counts().defer_threshold_clamped;
        let k = actuate(
            Arc::new(SpyKnobs::default()),
            TxParams {
                edcca_threshold_dbm: Some((17, 9)), // "never busy"
                ..Default::default()
            },
        );
        let (hi_lo, hi_hi) = ndn_radio_cognition::DEFER_THRESHOLD_DBM_BAND;
        let got = k.edcca_thresh_calls.lock().unwrap().clone();
        assert_eq!(
            got.len(),
            1,
            "the threshold must still be pushed, just bounded"
        );
        assert_eq!(
            got[0].0, hi_hi,
            "an out-of-band claim lands at the top of the decidable band, not at 0xff"
        );
        assert!(got[0].1 <= got[0].0 && got[0].0 >= hi_lo);
        assert!(
            ndn_radio_cognition::ledger::counts().defer_threshold_clamped > before,
            "and it is COUNTED — a threshold outside the band cannot have come from the policy"
        );
    }

    /// The mirror of the above: a threshold the policy really can decide must pass through
    /// untouched. A bound that perturbs legitimate decisions is worse than no bound.
    #[test]
    fn a_policy_reachable_defer_threshold_passes_through_unchanged() {
        let (lo, _) = ndn_radio_cognition::DEFER_THRESHOLD_DBM_BAND;
        let want = (lo + 10, lo + 10 - ndn_radio_cognition::DEFER_HYSTERESIS_MAX_DB);
        let k = actuate(
            Arc::new(SpyKnobs::default()),
            TxParams {
                edcca_threshold_dbm: Some(want),
                ..Default::default()
            },
        );
        assert_eq!(*k.edcca_thresh_calls.lock().unwrap(), vec![want]);
    }

    /// A radio with dBm control is driven in dBm — and the index knob is left
    /// alone, so the two never fight over one piece of hardware state.
    #[test]
    fn dbm_is_preferred_over_the_index_scale() {
        let k = actuate(
            Arc::new(SpyKnobs::default()),
            TxParams {
                tx_power_dbm: Some(14),
                tx_power: Some(40),
                ..Default::default()
            },
        );
        assert_eq!(*k.dbm_calls.lock().unwrap(), vec![14]);
        assert!(
            k.idx_calls.lock().unwrap().is_empty(),
            "index knob must not also be pushed"
        );
    }

    /// A radio without dBm control still gets actuated: the decision falls back
    /// to the index rather than being silently dropped.
    #[test]
    fn falls_back_to_the_index_when_dbm_is_unsupported() {
        let k = actuate(
            Arc::new(SpyKnobs {
                dbm_unsupported: true,
                ..Default::default()
            }),
            TxParams {
                tx_power_dbm: Some(14),
                tx_power: Some(40),
                ..Default::default()
            },
        );
        assert!(k.dbm_calls.lock().unwrap().is_empty());
        assert_eq!(*k.idx_calls.lock().unwrap(), vec![40]);
    }

    /// An unchanged decision is not re-pushed every tick.
    #[test]
    fn repeated_identical_power_is_pushed_once() {
        let knobs = Arc::new(SpyKnobs::default());
        let bus = LoopbackMonitorBus::new();
        let io: Arc<dyn FrameIo> = Arc::new(bus.endpoint(1, -55));
        let act = MediumActuator::new(RadioId(0), io, Some(knobs.clone()));
        let params = TxParams {
            tx_power_dbm: Some(20),
            ..Default::default()
        };
        let plan = RadioPlan::single(RadioId(0), None, params);
        let alloc = plan.allocation_for(RadioId(0)).unwrap();
        act.apply(alloc).unwrap();
        act.apply(alloc).unwrap();
        assert_eq!(*knobs.dbm_calls.lock().unwrap(), vec![20]);
    }

    /// The decided LoRa **bandwidth** must reach the actuator — it is a real rate/airtime lever
    /// (policy widens to 250 kHz on strong Bulk links) whose `set_bandwidth_khz` actuator existed but
    /// was never called from `apply`, so the width died in the plan. Asserts on the SEAM (the method
    /// call), and that an unchanged value is not re-pushed (each set is a ~1s AT retune).
    #[test]
    fn lora_bandwidth_reaches_the_actuator_once() {
        let knobs = Arc::new(SpyKnobs::default());
        let bus = LoopbackMonitorBus::new();
        let io: Arc<dyn FrameIo> = Arc::new(bus.endpoint(1, -55));
        let act = MediumActuator::new(RadioId(0), io, Some(knobs.clone()));
        let params = TxParams::lora(LoraRate {
            bandwidth_khz: Some(250),
            ..Default::default()
        });
        let plan = RadioPlan::single(RadioId(0), None, params);
        let alloc = plan.allocation_for(RadioId(0)).unwrap();
        act.apply(alloc).unwrap();
        act.apply(alloc).unwrap(); // unchanged ⇒ must not re-push
        assert_eq!(
            *knobs.bw_calls.lock().unwrap(),
            vec![250],
            "decided LoRa bandwidth must reach set_bandwidth_khz exactly once"
        );
    }

    /// A clamped write is remembered as *applied*, not as requested — otherwise a
    /// request the firmware will never grant is re-sent on every single tick.
    #[test]
    fn a_clamped_write_is_not_retried_forever() {
        let knobs = Arc::new(SpyKnobs::default()); // clamps at 27
        let bus = LoopbackMonitorBus::new();
        let io: Arc<dyn FrameIo> = Arc::new(bus.endpoint(1, -55));
        let act = MediumActuator::new(RadioId(0), io, Some(knobs.clone()));
        let params = TxParams {
            tx_power_dbm: Some(30), // will clamp to 27
            ..Default::default()
        };
        let plan = RadioPlan::single(RadioId(0), None, params);
        let alloc = plan.allocation_for(RadioId(0)).unwrap();
        act.apply(alloc).unwrap();
        act.apply(alloc).unwrap();
        act.apply(alloc).unwrap();
        let calls = knobs.dbm_calls.lock().unwrap();
        assert_eq!(
            calls.len(),
            1,
            "a firmware clamp must not cause a write every tick, got {calls:?}"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DEFAULT_SRC, LoopbackMonitorBus, McsPolicy, TxParams};
    use ndn_transport::Transport;
    use std::time::Duration;

    fn cap() -> RadioCapability {
        RadioCapability::wifi_monitor_5ghz(vec![149])
    }

    /// **The `addr3 == addr1` guard** — the prerequisite for reading the ephemeral ID / DAR flags /
    /// commitment slice out of `addr3[4]/[5]`.
    ///
    /// Two builders overwrite `addr3` with an address that is not an ephemeral ID: `build_amsdu`
    /// writes `addr3 = addr1` and the base builder falls back to `addr3 = dst` (`ff × 6` broadcast
    /// on a legacy frame). Both were fed straight into the DAR path, so every legacy-shaped frame
    /// was read as a collision hint naming ID `0xff` — a live defect, and one the commitment slice
    /// would have inherited. An id-carrying frame seeds `addr3[0..4]` from its nonce, so its `addr3`
    /// never equals its broadcast `addr1`.
    #[test]
    fn addr3_is_read_as_an_ephemeral_id_only_in_the_id_carrying_shape() {
        use ndn_radio_cognition::ephemeral_id::FLAG_ID_COLLISION;

        // Legacy broadcast: addr1 = addr3 = ff×6. Read raw, addr3[5] = 0xff sets FLAG_ID_COLLISION.
        let bcast = ndn_radio_hal::BROADCAST;
        assert_eq!(bcast[5] & FLAG_ID_COLLISION, FLAG_ID_COLLISION, "premise");
        assert_eq!(
            ephemeral_id_flags(Some(&bcast), Some(&bcast)),
            None,
            "a legacy broadcast frame is not a DAR hint naming ID 0xff"
        );

        // A-MSDU: addr3 = addr1 — filler, not an ID.
        let ra = [0x03u8, 0x11, 0x22, 0x33, 0x44, 0x55];
        assert_eq!(ephemeral_id_flags(Some(&ra), Some(&ra)), None);

        // The id-carrying shape: addr3[0..4] is nonce-seeded, so it differs from addr1.
        let a3 = [0xde, 0xad, 0xbe, 0xef, 0x5a, 0b0110_0100];
        assert_eq!(ephemeral_id_flags(Some(&ra), Some(&a3)), Some(a3));

        // A capture path that surfaced no addr1 still yields whatever addr3 it did surface.
        assert_eq!(ephemeral_id_flags(None, Some(&a3)), Some(a3));
        assert_eq!(ephemeral_id_flags(Some(&ra), None), None);
    }

    fn name_tlv(comps: &[&[u8]]) -> Vec<u8> {
        let mut inner = Vec::new();
        for c in comps {
            inner.push(0x08);
            inner.push(c.len() as u8);
            inner.extend_from_slice(c);
        }
        let mut t = vec![0x07, inner.len() as u8];
        t.extend_from_slice(&inner);
        t
    }
    fn data_pkt(name: &[u8]) -> Bytes {
        let mut d = vec![0x06, name.len() as u8];
        d.extend_from_slice(name);
        Bytes::from(d)
    }

    /// **The medium's latency seam takes an authority** (#93). `with_lease_latency_unauthorised` is
    /// the name the bare path deserves — it promotes whatever slice literal it is handed, and
    /// `with_lease_latency_unauthorised(mine, mine)` promotes everything this node sends — while
    /// `with_lease_latency_authorised` asks a `ClassAuthority` first. Neither *enforces* anything
    /// (a permissive impl is four lines); what the pair buys is that self-assertion is no longer the
    /// shorter spelling, and that `grep impl ClassAuthority` enumerates what a deployment trusts.
    #[test]
    fn the_medium_latency_seam_takes_an_authority() {
        struct OnlyAlarm;
        impl ndn_radio_cognition::ClassAuthority for OnlyAlarm {
            fn ceiling_for(&self, prefix_hash: u64) -> ndn_radio_cognition::Priority {
                if prefix_hash == ndn_radio_cognition::prefix_hash(&[b"alarm".as_slice()]) {
                    ndn_radio_cognition::Priority::Urgent
                } else {
                    ndn_radio_cognition::Priority::Normal
                }
            }
        }
        let bus = LoopbackMonitorBus::new();
        let regs = [
            b"/bulk".as_slice(),
            b"/alarm".as_slice(),
            b"/light".as_slice(),
        ];
        // Both prefixes ASKED for the lanes; only one of them is the campaign's lane policy.
        let asked = [b"/alarm".as_slice(), b"/bulk".as_slice()];

        let bare = RadioMediumFace::new(
            FaceId(1),
            vec![RadioBearer::new(
                RadioId(1),
                Arc::new(bus.endpoint(1, -50)),
                cap(),
            )],
        )
        .with_lease_latency_unauthorised(&regs, &asked);
        let gated = RadioMediumFace::new(
            FaceId(2),
            vec![RadioBearer::new(
                RadioId(2),
                Arc::new(bus.endpoint(2, -50)),
                cap(),
            )],
        )
        .with_lease_latency_authorised(&regs, &asked, &OnlyAlarm);

        let table = |f: &RadioMediumFace| f.group_table.clone().expect("a lease face has a table");
        assert_ne!(
            table(&bare).class_digest(true),
            table(&gated).class_digest(true),
            "the authority refused /bulk, and the class commitment records the difference — which is \
             what a neighbour reads off the slices these two nodes piggyback on their data frames \
             (and, if either is the clock master, off its beacon)"
        );
    }

    /// Two radios on two disjoint media, one medium face spanning both: a frame put
    /// on *either* medium is delivered once by the union, and a frame the face
    /// *sends* fans out onto *both* media. This is the whole "one face, N
    /// capabilities" contract — RX union + TX fan-out — with no hardware.
    #[tokio::test]
    async fn medium_face_unions_rx_and_fans_out_tx() {
        let bus_a = LoopbackMonitorBus::new();
        let bus_b = LoopbackMonitorBus::new();

        // Peers: a lone radio on each bus that we inject from / listen on.
        let peer_a: Arc<dyn FrameIo> = Arc::new(bus_a.endpoint(10, -50));
        let peer_b: Arc<dyn FrameIo> = Arc::new(bus_b.endpoint(20, -50));

        // The medium face: capability 1 on bus A, capability 2 on bus B.
        let bearers = vec![
            RadioBearer::new(RadioId(1), Arc::new(bus_a.endpoint(1, -55)), cap()),
            RadioBearer::new(RadioId(2), Arc::new(bus_b.endpoint(2, -55)), cap()),
        ];
        let medium = RadioMediumFace::new(FaceId(7), bearers).build();

        // RX union: a frame on bus A and a frame on bus B both arrive at the face.
        let inject = |radio: Arc<dyn FrameIo>, byte: u8| async move {
            let frame = InjectFrame {
                payload: Bytes::from(vec![byte; 16]),
                tx: TxIntent::CONSERVATIVE,
                dst: BROADCAST,
                src: DEFAULT_SRC,
                addr3: None,
                extra: None,
                htc: None,
            };
            radio.inject_at(frame, McsDescriptor::ht(0)).await.unwrap();
        };
        inject(peer_a.clone(), 0xAA).await;
        inject(peer_b.clone(), 0xBB).await;

        let mut got = Vec::new();
        for _ in 0..2 {
            let (b, _) =
                tokio::time::timeout(Duration::from_secs(2), medium.recv_bytes_with_addr())
                    .await
                    .expect("union should deliver frames from both media")
                    .unwrap();
            got.push(b[0]);
        }
        got.sort();
        assert_eq!(got, vec![0xAA, 0xBB], "RX unions both radio capabilities");

        // TX fan-out: one send reaches a listener on *each* medium.
        medium
            .send_bytes(Bytes::from(vec![0xCC; 16]))
            .await
            .unwrap();
        for peer in [peer_a, peer_b] {
            let f = tokio::time::timeout(Duration::from_secs(2), peer.recv_frame())
                .await
                .expect("send must fan out onto every medium")
                .unwrap();
            assert_eq!(f.payload[0], 0xCC);
        }
    }

    /// The cognition loop closes through the driver's native rate state: a
    /// `RadioControl` with a [`MediumActuator`] over a loopback radio, fed a strong
    /// link, decides on `tick` and calls [`FrameIo::set_rate`] on that radio — so a
    /// subsequent plain `inject` puts the decided MCS on the air, observed by a peer.
    /// No USB, no hardware, no planned cell; this is the ACT the `ndn-fwd` radio face
    /// runs (proving `RateBearer`'s retirement is sound).
    #[tokio::test]
    async fn cognition_tick_sets_the_driver_rate() {
        use crate::{FrameIo, RadioControl};
        use ndn_radio_cognition::{NameContext, RadioPolicy, prefix_hash};

        let bus = LoopbackMonitorBus::new();
        let radio: Arc<dyn FrameIo> = Arc::new(bus.endpoint(1, -50));
        let peer: Arc<dyn FrameIo> = Arc::new(bus.endpoint(2, -50));
        let face_id = FaceId(5);
        let rid = RadioId(0);

        let signals = Arc::new(LinkSignalStore::new());
        let mut control = RadioControl::new(RadioPolicy::default()).with_signals(signals.clone());
        control.register_radio(rid, face_id, cap());
        control.add_actuator(Arc::new(MediumActuator::new(rid, radio.clone(), None)));
        control.set_active(vec![NameContext::new(prefix_hash(&[b"radio"]))]);

        // A strong link so the policy picks a real (non-suppressed) rate.
        signals.set_link(
            face_id,
            LinkSignals {
                rssi_dbm: Some(-50),
                updated_ms: crate::now_ms(),
                ..LinkSignals::default()
            },
        );

        let plans = control.tick_now(1_000);
        let decided = plans
            .first()
            .and_then(|p| p.allocations.first())
            .and_then(|a| a.params.mcs())
            .expect("the tick decided a concrete MCS");

        // The actuator set that rate on the driver → a plain inject transmits at it.
        radio
            .inject(InjectFrame {
                payload: Bytes::from_static(b"x"),
                tx: TxIntent::CONSERVATIVE,
                dst: BROADCAST,
                src: DEFAULT_SRC,
                addr3: None,
                extra: None,
                htc: None,
            })
            .await
            .unwrap();
        let got = tokio::time::timeout(Duration::from_secs(2), peer.recv_frame())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            got.mcs_index,
            Some(decided),
            "the decided MCS reached the air as driver rate state"
        );
    }

    /// Link-FEC on the medium face round-trips: frames sent through a FEC-enabled
    /// medium are generation-coded, cross the bus, and the peer's FEC-enabled medium
    /// decodes them back to the originals — proving the TX-encode / RX-decode plumbing
    /// end to end (erasure *recovery* is covered by `ndn_coding`'s own tests). This is
    /// the loss-recovery lever the cognition loop actuates.
    #[tokio::test]
    async fn link_fec_round_trips_through_the_medium() {
        let bus = LoopbackMonitorBus::new();
        let tx = RadioMediumFace::new(
            FaceId(1),
            vec![RadioBearer::wifi(
                RadioId(0),
                Arc::new(bus.endpoint(1, -50)),
                cap(),
            )],
        )
        .with_link_fec(
            3,
            Duration::from_millis(20),
            Arc::new(AtomicU16::new(2)),
            Arc::new(LossMeter::default()),
        )
        .build();
        let rx = RadioMediumFace::new(
            FaceId(2),
            vec![RadioBearer::wifi(
                RadioId(0),
                Arc::new(bus.endpoint(2, -50)),
                cap(),
            )],
        )
        .with_link_fec(
            3,
            Duration::from_millis(20),
            Arc::new(AtomicU16::new(0)),
            Arc::new(LossMeter::default()),
        )
        .build();

        let sent: Vec<Bytes> = (0..3u8).map(|i| Bytes::from(vec![i; 12])).collect();
        for w in &sent {
            tx.send_bytes(w.clone()).await.unwrap();
        }
        let mut got = Vec::new();
        for _ in 0..3 {
            let (b, _) = tokio::time::timeout(Duration::from_secs(2), rx.recv_bytes_with_addr())
                .await
                .expect("FEC medium delivers the generation")
                .unwrap();
            got.push(b);
        }
        got.sort();
        let mut want = sent;
        want.sort();
        assert_eq!(
            got, want,
            "link-FEC round-trips the generation through the medium face"
        );
    }

    /// One bearer ⇒ the medium face is exactly the single-radio path: send on the
    /// bus, the peer hears it; peer sends, the face receives it.
    #[tokio::test]
    async fn single_bearer_is_the_degenerate_medium() {
        let bus = LoopbackMonitorBus::new();
        let peer: Arc<dyn FrameIo> = Arc::new(bus.endpoint(9, -50));
        let medium = RadioMediumFace::new(
            FaceId(3),
            vec![RadioBearer::new(
                RadioId(1),
                Arc::new(bus.endpoint(1, -55)),
                cap(),
            )],
        )
        .build();

        medium
            .send_bytes(Bytes::from(vec![0x42; 16]))
            .await
            .unwrap();
        let f = tokio::time::timeout(Duration::from_secs(2), peer.recv_frame())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(f.payload[0], 0x42);
    }

    /// **The medium's A-MSDU batcher must reach `FrameIo::inject_batch`, and robust frames must
    /// bypass it.**
    ///
    /// A-MSDU was the one feature #82 listed that `RadioMediumFace` genuinely lacked rather than
    /// duplicated. Moving it down is only worth anything if the batch arrives at the method the
    /// backends override — the medium sends `TxIntent`s and holds rate as bearer state, so it can
    /// only use the rate-free `inject_batch` spelling, and `AfPacketBackend` had to grow one.
    ///
    /// The bypass half matters just as much: a reception report or time beacon held for a flush
    /// window is a report that arrives late to the receiver it exists to reach.
    #[tokio::test]
    async fn medium_amsdu_batches_data_and_never_delays_robust_frames() {
        struct BatchSpy {
            batches: std::sync::Mutex<Vec<usize>>,
            singles: std::sync::Mutex<Vec<TxIntent>>,
        }

        #[async_trait::async_trait]
        impl FrameIo for BatchSpy {
            async fn inject(&self, frame: InjectFrame) -> Result<(), FaceError> {
                self.singles.lock().unwrap().push(frame.tx);
                Ok(())
            }
            async fn inject_batch(&self, frames: Vec<InjectFrame>) -> Result<(), FaceError> {
                self.batches.lock().unwrap().push(frames.len());
                Ok(())
            }
            async fn recv_frame(&self) -> Result<crate::CapturedFrame, FaceError> {
                std::future::pending().await
            }
        }

        let spy = Arc::new(BatchSpy {
            batches: std::sync::Mutex::new(Vec::new()),
            singles: std::sync::Mutex::new(Vec::new()),
        });
        let medium = RadioMediumFace::new(
            FaceId(7),
            vec![RadioBearer::new(RadioId(0), spy.clone(), cap())],
        )
        .with_amsdu_batching(8, Duration::from_millis(5))
        .build();

        for i in 0..4u8 {
            medium
                .send_bytes(data_pkt(&name_tlv(&[b"x", &[i]])))
                .await
                .unwrap();
        }
        // A cooperative report — must go out immediately, not into the batch.
        medium
            .send_robust(Bytes::from_static(b"report"))
            .await
            .unwrap();

        tokio::time::sleep(Duration::from_millis(60)).await;

        let batches = spy.batches.lock().unwrap().clone();
        let singles = spy.singles.lock().unwrap().clone();
        assert_eq!(
            batches.iter().sum::<usize>(),
            4,
            "all four data frames must arrive via inject_batch (the backends' aggregation hook), \
             got batches={batches:?} singles={singles:?}"
        );
        assert_eq!(
            singles.len(),
            1,
            "exactly the robust frame bypasses the batcher: {singles:?}"
        );
        assert_eq!(
            singles[0].reliability,
            Reliability::MostRobust,
            "the frame that bypassed must be the robust one"
        );
    }
    /// **A rate the plan decides must change what the medium transmits — and must still lose to the
    /// worst-receiver cap.**
    ///
    /// `WifiPhy` could act on a decided MCS; this face could not, so a `RadioPlan` mounted
    /// on a medium face chose a rate that nothing applied (#82's last one-sided feature). That gap
    /// is invisible from the decision side, so this asserts on which call the backend received.
    ///
    /// The second half matters as much: when cognition raises the legacy gate because a
    /// legacy-only-RX neighbour is present, the frame must go out at the basic legacy rate. The
    /// medium expresses that as `TxIntent::ROBUST` on the plain `inject` path, which every driver
    /// maps to the basic rate — *not* by picking a low MCS itself.
    ///
    /// Recording `set_rate` state alone was not enough to see this: the rate a driver holds is
    /// sticky, so after one `inject_at(.., MCS7)` the spy reported MCS 7 for the *next* frame too,
    /// even though the medium never asked for it. Asserting on the call that was made, rather than
    /// on leftover state, is what makes the distinction visible.
    #[tokio::test]
    async fn medium_actuates_the_planned_rate_but_the_legacy_gate_outranks_it() {
        #[derive(Debug, PartialEq)]
        enum Call {
            /// `inject_at` — an exact rate was demanded for this frame.
            At(u8),
            /// Plain `inject` — the rate is whatever the bearer holds; the intent carries the
            /// robustness the driver maps to a rate.
            Plain(Reliability),
        }

        struct RateSpy {
            calls: std::sync::Mutex<Vec<Call>>,
        }

        #[async_trait::async_trait]
        impl FrameIo for RateSpy {
            async fn inject(&self, f: InjectFrame) -> Result<(), FaceError> {
                self.calls
                    .lock()
                    .unwrap()
                    .push(Call::Plain(f.tx.reliability));
                Ok(())
            }
            async fn inject_at(
                &self,
                _f: InjectFrame,
                mcs: McsDescriptor,
            ) -> Result<(), FaceError> {
                self.calls.lock().unwrap().push(Call::At(mcs.index));
                Ok(())
            }
            async fn recv_frame(&self) -> Result<crate::CapturedFrame, FaceError> {
                std::future::pending().await
            }
        }

        let spy = Arc::new(RateSpy {
            calls: std::sync::Mutex::new(Vec::new()),
        });
        let gate = Arc::new(AtomicBool::new(false));
        let plan = Arc::new(std::sync::RwLock::new(Some(TxParams {
            rate: ndn_radio_cognition::RateParams::Wifi(ndn_radio_cognition::WifiRate {
                mcs: Some(7),
                ..Default::default()
            }),
            ..Default::default()
        })));

        let medium = RadioMediumFace::new(
            FaceId(8),
            vec![RadioBearer::new(RadioId(0), spy.clone(), cap())],
        )
        .with_legacy_gate(gate.clone())
        .with_rate_policy(Arc::new(
            crate::RatePolicy::new(McsPolicy::Fixed(McsDescriptor::CONSERVATIVE))
                .with_planned(plan),
        ))
        .build();

        medium
            .send_bytes(Bytes::from_static(b"planned"))
            .await
            .unwrap();
        // A legacy-only-RX neighbour appears: reach beats throughput.
        gate.store(true, Ordering::Relaxed);
        medium
            .send_bytes(Bytes::from_static(b"capped"))
            .await
            .unwrap();

        let calls = spy.calls.lock().unwrap();
        assert_eq!(
            calls[0],
            Call::At(7),
            "the plan's decided MCS must reach the radio, not just the decision plane: {calls:?}"
        );
        assert_eq!(
            calls[1],
            Call::Plain(Reliability::MostRobust),
            "with the legacy gate up the frame must go out MostRobust on the plain path, so the \
             driver drops it to the basic rate — never at the planned MCS: {calls:?}"
        );
    }

    /// ★ **The in-tree defect behind surface B: the legacy-rate gate silently switched the whole
    /// data plane out of the slot MAC.**
    ///
    /// `TxBearer::inject` selects [`TxIntent::ROBUST`] when the shared legacy gate is up — purely to
    /// get the basic rate for a legacy-only-RX neighbour. But `TxIntent::ROBUST.reliability ==
    /// MostRobust`, and `inject_with_intent` derived its GATE decision from that same field. So one
    /// neighbour advertising legacy-only RX took this node out of the airtime lease entirely, at the
    /// slowest rate it transmits — the worst possible combination for a shared schedule, and
    /// invisible to the suite because `medium_actuates_the_planned_rate_but_the_legacy_gate_outranks_it`
    /// binds no scheduler.
    ///
    /// The fix separates the two axes: `robust` still decides rate/FEC/A-MSDU, `control` alone
    /// decides the gate, and only [`RunningMedium::send_robust`] sets it.
    ///
    /// `bypassed` is the faithful proxy for "skipped the slot MAC": it is incremented in the very
    /// branch that skips `sched.gate`, so it cannot drift from it. Per-face rather than the
    /// process-global `TXD_BYPASS`, so this is deterministic with other tests running.
    ///
    /// Falsified by restoring the old condition (`if robust` instead of `if control`): the
    /// legacy-gated data frame is then counted as a bypass and the first assertion fires.
    #[tokio::test]
    async fn the_legacy_rate_gate_must_not_take_data_out_of_the_airtime_lease() {
        struct Sink;
        #[async_trait::async_trait]
        impl FrameIo for Sink {
            async fn inject(&self, _f: InjectFrame) -> Result<(), FaceError> {
                Ok(())
            }
            async fn recv_frame(&self) -> Result<crate::CapturedFrame, FaceError> {
                std::future::pending().await
            }
        }

        let gate = Arc::new(AtomicBool::new(true)); // a legacy-only-RX neighbour is present
        let medium = RadioMediumFace::new(
            FaceId(21),
            vec![RadioBearer::new(RadioId(0), Arc::new(Sink), cap())],
        )
        .with_legacy_gate(gate.clone())
        .build();

        // DATA, under the legacy gate. It rides the basic rate (that part is correct and tested
        // elsewhere) — but it must remain subject to the slot MAC.
        medium.send_bytes(Bytes::from_static(b"data")).await.unwrap();
        assert_eq!(
            medium.gate_counts().bypassed(),
            0,
            "a legacy-rate data frame must NOT skip the slot MAC: the intent picks the rate, it \
             does not buy an exemption from the airtime lease"
        );

        // CONTROL. This one bypasses on purpose, and is counted so the bypass is visible.
        medium
            .send_robust(Bytes::from_static(b"report"))
            .await
            .unwrap();
        assert_eq!(
            medium.gate_counts().bypassed(),
            1,
            "send_robust is the only caller that skips the gate, and every skip is counted"
        );
    }

    /// **A decided rate must reach FEC-CODED frames too** — the combination, not each feature alone.
    ///
    /// Found on air, not here. `medium_actuates_the_planned_rate_but_the_legacy_gate_outranks_it`
    /// tests rate with FEC off; other tests exercise FEC with no rate
    /// policy. Both passed while the intersection was broken: with a policy bound *and* FEC on,
    /// every data frame takes the FEC branch, which pinned `mcs: None`, so `inject_at` was never
    /// reached and coded frames rode whatever rate happened to be left in the bearer.
    ///
    /// The on-air A/B (a81a → 881a, ch149) showed it plainly: 2684 coded frames all decoded at the
    /// *previous* period's MCS, while a direct-inject control arm on the same radio tracked its plan
    /// exactly. Two features that are individually correct can still be jointly wrong, and a suite
    /// that only tests them apart will report success.
    #[tokio::test]
    async fn medium_actuates_the_planned_rate_on_fec_coded_frames() {
        struct RateSpy {
            at: std::sync::Mutex<Vec<u8>>,
            plain: std::sync::Mutex<usize>,
        }

        #[async_trait::async_trait]
        impl FrameIo for RateSpy {
            async fn inject(&self, _f: InjectFrame) -> Result<(), FaceError> {
                *self.plain.lock().unwrap() += 1;
                Ok(())
            }
            async fn inject_at(
                &self,
                _f: InjectFrame,
                mcs: McsDescriptor,
            ) -> Result<(), FaceError> {
                self.at.lock().unwrap().push(mcs.index);
                Ok(())
            }
            async fn recv_frame(&self) -> Result<crate::CapturedFrame, FaceError> {
                std::future::pending().await
            }
        }

        const K: usize = 2;
        let spy = Arc::new(RateSpy {
            at: std::sync::Mutex::new(Vec::new()),
            plain: std::sync::Mutex::new(0),
        });
        let plan = Arc::new(std::sync::RwLock::new(Some(TxParams {
            rate: ndn_radio_cognition::RateParams::Wifi(ndn_radio_cognition::WifiRate {
                mcs: Some(7),
                ..Default::default()
            }),
            ..Default::default()
        })));

        let medium = RadioMediumFace::new(
            FaceId(9),
            vec![RadioBearer::new(RadioId(0), spy.clone(), cap())],
        )
        .with_rate_policy(Arc::new(
            crate::RatePolicy::new(McsPolicy::Fixed(McsDescriptor::CONSERVATIVE))
                .with_planned(plan),
        ))
        // Parity > 0, so every data frame goes through the coder.
        .with_link_fec(
            K,
            Duration::from_millis(20),
            Arc::new(AtomicU16::new(2)),
            Arc::new(LossMeter::default()),
        )
        .build();

        for i in 0..K as u8 {
            medium.send_bytes(Bytes::from(vec![i; 24])).await.unwrap();
        }
        tokio::time::sleep(Duration::from_millis(80)).await;

        let at = spy.at.lock().unwrap().clone();
        let plain = *spy.plain.lock().unwrap();
        assert!(
            !at.is_empty(),
            "coded frames must be injected AT the decided rate; {plain} went out on the plain \
             path, which rides whatever rate the bearer happens to hold"
        );
        assert!(
            at.iter().all(|m| *m == 7),
            "every coded frame must carry the plan's MCS 7, got {at:?}"
        );
        assert_eq!(plain, 0, "no coded frame may bypass the decided rate");
    }

    /// **The plan must size the aggregate.** `TxParams::amsdu_msdus` had an accessor and *zero*
    /// callers: cognition decided an A-MSDU target that reached no actuator. It survived even the
    /// session that built this batcher, because the batcher took a static bound from its builder
    /// and never asked the plan — the decided-but-unactuated defect, produced fresh while fixing
    /// two other instances of it.
    ///
    /// Three states, all distinct and all asserted on the frames the backend actually received:
    ///   * `None`    — no opinion: the face's configured cap stands.
    ///   * `Some(n)` — aggregate to n.
    ///   * `Some(0)` — do not aggregate: bypass the batcher entirely, so the frame takes the direct
    ///                 path (no flush window, plain MPDU) rather than a one-subframe A-MSDU.
    #[tokio::test]
    async fn medium_sizes_the_amsdu_from_the_plan() {
        struct Spy {
            batches: std::sync::Mutex<Vec<usize>>,
            singles: std::sync::Mutex<usize>,
        }

        #[async_trait::async_trait]
        impl FrameIo for Spy {
            async fn inject(&self, _f: InjectFrame) -> Result<(), FaceError> {
                *self.singles.lock().unwrap() += 1;
                Ok(())
            }
            async fn inject_at(&self, _f: InjectFrame, _m: McsDescriptor) -> Result<(), FaceError> {
                *self.singles.lock().unwrap() += 1;
                Ok(())
            }
            async fn inject_batch(&self, frames: Vec<InjectFrame>) -> Result<(), FaceError> {
                self.batches.lock().unwrap().push(frames.len());
                Ok(())
            }
            async fn inject_batch_at(
                &self,
                frames: Vec<(InjectFrame, McsDescriptor)>,
            ) -> Result<(), FaceError> {
                self.batches.lock().unwrap().push(frames.len());
                Ok(())
            }
            async fn recv_frame(&self) -> Result<crate::CapturedFrame, FaceError> {
                std::future::pending().await
            }
        }

        /// Send `n` frames through a medium whose plan carries `target`, and report
        /// `(batch sizes, direct injects)`.
        async fn run(target: Option<u16>, n: usize) -> (Vec<usize>, usize) {
            let spy = Arc::new(Spy {
                batches: std::sync::Mutex::new(Vec::new()),
                singles: std::sync::Mutex::new(0),
            });
            let plan = Arc::new(std::sync::RwLock::new(target.map(|t| TxParams {
                rate: ndn_radio_cognition::RateParams::Wifi(ndn_radio_cognition::WifiRate {
                    amsdu_msdus: Some(t),
                    ..Default::default()
                }),
                ..Default::default()
            })));
            let medium = RadioMediumFace::new(
                FaceId(11),
                vec![RadioBearer::new(RadioId(0), spy.clone(), cap())],
            )
            .with_rate_policy(Arc::new(
                crate::RatePolicy::new(McsPolicy::default()).with_planned(plan),
            ))
            // Configured cap of 8 — what `None` must fall back to.
            .with_amsdu_batching(8, Duration::from_millis(5))
            .build();

            for i in 0..n {
                medium
                    .send_bytes(Bytes::from(vec![i as u8; 16]))
                    .await
                    .unwrap();
            }
            tokio::time::sleep(Duration::from_millis(60)).await;
            let b = spy.batches.lock().unwrap().clone();
            let s = *spy.singles.lock().unwrap();
            (b, s)
        }

        // No opinion → the configured cap of 8 governs: 8 frames land in one batch.
        let (batches, singles) = run(None, 8).await;
        assert_eq!(
            batches,
            vec![8],
            "None must keep the configured cap (singles={singles})"
        );

        // The plan asks for 2 → batches cap at 2, so 8 frames become four of them.
        let (batches, singles) = run(Some(2), 8).await;
        assert!(
            !batches.is_empty() && batches.iter().all(|n| *n <= 2),
            "the plan's target must bound every batch, got {batches:?} (singles={singles})"
        );
        assert_eq!(
            batches.iter().sum::<usize>(),
            8,
            "and every frame still goes out"
        );

        // The plan asks for no aggregation → nothing is batched at all.
        let (batches, singles) = run(Some(0), 4).await;
        assert!(
            batches.is_empty(),
            "amsdu_msdus=0 means do not aggregate; a one-subframe A-MSDU is not that: {batches:?}"
        );
        assert_eq!(singles, 4, "all four take the direct path");
    }

    /// **The radio's self-description must outrank the caller's assertion.** `RadioBearer::profile`
    /// documented exactly this — "keeping both makes a disagreement visible instead of letting a
    /// hand-written `RadioCapability` quietly outrank the hardware" — and then nothing read the
    /// field. #78 landed the plumbing; the contract it carried stayed unactuated, so every consumer
    /// saw the asserted `cap` while the radio's own capability sat unused on the struct. Same shape
    /// as `agile` (#98): a capability asserted and never checked against hardware.
    /// ★ **A bearer built from a bare `dyn FrameIo` must take the RADIO's capability, not the
    /// caller's guess.**
    ///
    /// This is the regression test for the leak that shipped: the production node opened an
    /// RTL8822E and built its face with `WifiPhy::new`, which had to invent
    /// `wifi_monitor_5ghz` (`max_mcs 9 / max_nss 2 / max_bw 2`) over a part that receives ONE
    /// stream at MCS 7. Advertising streams a radio cannot receive is the MEASURED cause of a
    /// one-way link. The capability-complete constructor existed and had zero production callers.
    ///
    /// The invariant is now enforced at the common constructor, so it cannot be bypassed by
    /// forgetting to use the other one.
    #[test]
    fn bearer_takes_the_radios_capability_over_the_callers_guess() {
        // A radio that knows it is 1x1 / MCS7 — the a81a's real shape.
        struct Honest;
        #[async_trait::async_trait]
        impl FrameIo for Honest {
            async fn inject(&self, _f: InjectFrame) -> Result<(), FaceError> {
                Ok(())
            }
            async fn recv_frame(&self) -> Result<crate::CapturedFrame, FaceError> {
                std::future::pending().await
            }
            fn radio_capability(&self) -> Option<RadioCapability> {
                Some(RadioCapability::wifi_monitor_5ghz_1ss(vec![36]))
            }
        }
        // A radio that cannot describe itself: the caller's assertion must survive.
        struct Mute;
        #[async_trait::async_trait]
        impl FrameIo for Mute {
            async fn inject(&self, _f: InjectFrame) -> Result<(), FaceError> {
                Ok(())
            }
            async fn recv_frame(&self) -> Result<crate::CapturedFrame, FaceError> {
                std::future::pending().await
            }
        }

        let guess = RadioCapability::wifi_monitor_5ghz(vec![36]);
        assert_eq!(guess.max_nss(), 2, "the placeholder really does claim 2 streams");

        let b = RadioBearer::new(RadioId(0), Arc::new(Honest), guess.clone());
        assert_eq!(
            b.cap.max_nss(),
            1,
            "the radio says 1 stream; a bearer that still advertises 2 is the one-way-link bug"
        );
        assert_eq!(b.effective_cap().max_nss(), 1, "and effective_cap must agree");

        let b2 = RadioBearer::new(RadioId(0), Arc::new(Mute), guess.clone());
        assert_eq!(
            b2.cap.max_nss(),
            guess.max_nss(),
            "a radio that cannot say must not silently downgrade the caller's assertion"
        );
    }

    #[test]
    fn the_radios_own_capability_outranks_the_callers_assertion() {
        struct Truthful(RadioCapability);
        impl RadioProfile for Truthful {
            fn capability(&self) -> RadioCapability {
                self.0.clone()
            }
        }

        struct Dummy;
        #[async_trait::async_trait]
        impl FrameIo for Dummy {
            async fn inject(&self, _f: InjectFrame) -> Result<(), FaceError> {
                Ok(())
            }
            async fn recv_frame(&self) -> Result<crate::CapturedFrame, FaceError> {
                std::future::pending().await
            }
        }

        // The caller guesses 5 GHz ch149; the radio knows it is really S1G on ch1/2.
        let asserted = RadioCapability::wifi_monitor_5ghz(vec![149]);
        let real = RadioCapability::wifi_halow_s1g(vec![1, 2]);
        assert_ne!(
            real, asserted,
            "the two must actually differ or this proves nothing"
        );

        let guessed = RadioBearer::new(RadioId(0), Arc::new(Dummy), asserted.clone());
        assert_eq!(
            guessed.effective_cap(),
            asserted,
            "with no profile the caller's assertion is all there is"
        );

        let known = RadioBearer::new(RadioId(0), Arc::new(Dummy), asserted.clone())
            .with_profile(Arc::new(Truthful(real.clone())));
        assert_eq!(
            known.effective_cap(),
            real,
            "the radio wins; believing the assertion is how a planner budgets for a band the \
             hardware does not have"
        );

        // And the medium reports the governing one, not the asserted one.
        let medium = RadioMediumFace::new(FaceId(12), vec![known]);
        assert_eq!(
            medium.capabilities(),
            vec![(RadioId(0), real)],
            "capabilities() is what a control plane registers — it must carry the radio's truth"
        );
    }
}
