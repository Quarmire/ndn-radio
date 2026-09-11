//! Connectionless **LoRa-family** face for ndn-rs — a named-radio bearer over any
//! [`FrameIo`] sub-GHz radio (the serial-bridged SX126x `LoraSerialBackend`, the
//! nRF54L15+LR2021 FLRC bridge, a Heltec SX1276), with **plan-driven link FEC**.
//!
//! Sub-GHz is the bearer where redundancy matters *most*: half-duplex, no ARQ, and
//! airtime measured in the hundreds of milliseconds per frame, so a lost frame is
//! expensive to notice and expensive to re-request. Its rate knobs are *bearer
//! state*, not per-frame arguments — spreading factor / coding rate / bandwidth are
//! set out-of-band through [`RadioKnobs`] — which makes
//! it the textbook case for the bearer-agnostic
//! [`LinkFecBridge`](ndn_coding::link_fec_bridge): the face mounts the bridge with a
//! plain-inject sink (no per-generation pin) and the cognitive plane's
//! [`TxParams::link_fec_redundancy`] actuates the parity count per name, exactly as
//! it does on Wi-Fi (tasks #32-#34), with none of the MCS machinery.
//!
//! **The control plane travels with the data plane.** A radio is not just an
//! `Arc<dyn FrameIo>`: [`from_open`](LoraPhy::from_open) takes the HAL's
//! [`OpenRadio`] aggregate so the radio's *knobs* (channel / SF / CR / BW / power),
//! its *clock* ([`RadioTime`]) and its *self-description* ([`RadioProfile`]) reach
//! the face instead of being erased at the construction site. That is what lets
//! this face actuate a decided [`TxParams`] on the radio (the LoRa peer of the
//! Wi-Fi rate actuator) and lets a caller attach an occupancy sampler to
//! [`knobs`](LoraPhy::knobs) — see [`with_planned_params`](LoraPhy::with_planned_params).
//!
//! **Nothing here assumes "LoRa".** The MTU comes from the radio's declared
//! [`RadioCapability::max_payload`], not a constant, and the spreading-factor knob
//! is actuated only where the radio declares a [`RateCapability::Lora`] span — so an
//! FLRC node (which has no SF at all) mounts through this same PHY and is simply
//! never handed a knob it does not have.
//!
//! Like [`ndn-phy-ble`] and the Wi-Fi monitor face, this is an
//! `AdHoc` broadcast bearer: the NDN *name* is the addressing, there is no
//! association, and every receiver in range hears every frame and evaluates
//! it against its own PIT/FIB/CS. Pair it with the engine's `LpLinkService` via
//! [`into_face`](LoraPhy::into_face) so NDN packets larger than one frame
//! fragment across frames (NDNLPv2) — and, when FEC is on, ride generations.
//!
//! [`TxParams::link_fec_redundancy`]: ndn_radio_cognition::TxParams::link_fec_redundancy
//! [`ndn-phy-ble`]: https://docs.rs/ndn-phy-ble

use std::collections::VecDeque;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use bytes::Bytes;
use ndn_coding::link_fec_bridge::{GenerationSink, LinkFecBridge};
pub use ndn_radio_cognition::TxParams;
/// The bearer-agnostic frame-free occupancy sampler (#30), re-exported so a wiring site can
/// attach one to this face without naming the cognition crate. It used to live in
/// `ndn-phy-wifi`, which made a LoRa node depend on the *Wi-Fi* crate to sense its own
/// channel; see [`LoraPhy::start_occupancy_sampling`].
pub use ndn_radio_cognition::{OccupancySink, RadioId, activity_rate, spawn_occupancy_sampler};
use ndn_radio_hal::{
    Bandwidth, ClockDomainId, FaceError, FrameIo, HopControl, InjectFrame, PhyMode, RadioKnobs,
    RadioProfile, RadioTime, RadioTimeSource, RateCapability, TxDiscipline, TxIntent,
};
pub use ndn_radio_hal::{OpenRadio, RadioCapability};
use ndn_transport::{
    Face, FaceAddr, FaceId, FaceKind, FacePersistency, LinkType, MtuError, PersistencyError,
    Transport,
};

/// The name-keyed hop plan (#40). Re-exported so a wiring site can build and read one without
/// naming the cognition crate — see [`LoraPhy::install_name_hop_plan`].
pub use ndn_radio_cognition::{HopPlan, carrier_grid, name_hop_plan};
/// The plan types this face's public API speaks. Re-exported so a wiring site can build a
/// [`TxParams`] cell for [`with_planned_params`](LoraPhy::with_planned_params) without taking a
/// direct dependency on the cognition crate (which depends, in turn, on `ndn-radio` — the wiring
/// site is usually inside it).
pub use ndn_radio_cognition::{LoraRate, RateParams};
/// The modulation axis a plan can name: the HAL's [`PhyMode`] vocabulary plus cognition's
/// name↔mode mapping, re-exported for the same reason — a wiring site sets `TxParams::phy`
/// without depending on either crate directly.
pub use ndn_radio_cognition::{parse_phy_mode, phy_mode_name};

/// The face's own **frame-payload ceiling** — the most this bearer will ever put in one
/// frame, whatever a radio declares.
///
/// It is a ceiling, not the MTU: the MTU is
/// `min(LORA_MTU, capability().max_payload)` (see
/// [`LoraPhy::send_mtu`]). Deliberately conservative — a serial-bridged sub-GHz
/// radio caps a frame well under 255 B and the driver rejects an oversize `inject`,
/// while the `RadioCapability::lora` preset optimistically declares 256. Taking the
/// **min** means a radio that knows its real cap is smaller (an FLRC node, or a
/// firmware that truncates RX) is respected, and one that over-declares cannot push
/// us past a budget measured on the wire.
pub const LORA_MTU: usize = 200;

/// Source frames per FEC generation (K). Deliberately small for sub-GHz: at high
/// spreading factors one frame is hundreds of ms of airtime, so a large K would
/// make a generation span many seconds and stall everything behind it. K=2 keeps
/// the generation short while still letting one lost frame be recovered (with R≥1).
const LORA_FEC_K: usize = 2;

/// How long a partial generation waits before a tail-flush. Generous for sub-GHz —
/// a frame can take ~1 s at SF12, so a tight window would flush half-empty
/// generations constantly. The face's caller can override via [`with_link_fec`].
const LORA_FEC_WINDOW: Duration = Duration::from_secs(3);

/// **When** a frame is allowed on air — the output of a slot gate, and the one thing a
/// hardware-scheduling radio needs in order to place the frame itself.
///
/// Two shapes because the two `FrameIo` scheduling seams are genuinely different:
///
/// * [`After`](Self::After) is a *delay against the device's own timebase*, which is what
///   makes it **reconcile-free**: the offset between the scheduler's clock and the radio's TX
///   clock cancels, so no cross-domain mapping has to be learned first. Prefer it.
/// * [`AtClock`](Self::AtClock) is an *absolute instant in a named clock domain*, for a caller
///   that already holds a disciplined mapping into that domain (`ndn-time`).
///
/// The face never invents one of these — a caller supplies it through
/// [`LoraPhy::with_slot_gate`], from whatever lease/schedule it runs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SlotTiming {
    /// Transmit `delay_us` microseconds from now, on the radio's own clock. `0` = now.
    After {
        /// Microseconds from now.
        delay_us: u64,
    },
    /// Transmit at absolute `tick` in `domain`. Requires a radio that schedules TX in
    /// hardware — the host cannot honour a foreign clock domain's instant by sleeping.
    AtClock {
        /// The target counter value, in `domain`'s own units/epoch.
        tick: u64,
        /// Which counter `tick` is expressed in.
        domain: ClockDomainId,
    },
}

/// A slot gate: given the outbound wire, when may it go on air? `None` ⇒ not slot-schedulable
/// (no name-group, no schedule, a control frame) — transmit now, which is the pre-existing
/// behaviour and the default for a face with no gate installed.
pub type SlotGate = dyn Fn(&[u8]) -> Option<SlotTiming> + Send + Sync;

/// The LoRa injection specifics the bearer-agnostic [`LinkFecBridge`] delegates:
/// put each coded frame of a generation on the air via the serial radio. LoRa has
/// no per-generation pin (its SF/CR are set out-of-band), so `Pin = ()` — this is
/// the plain-inject case, sharing the same [`FrameIo`] handle the face uses for RX.
struct LoraFecSink {
    radio: Arc<dyn FrameIo>,
}

impl GenerationSink for LoraFecSink {
    type Pin = ();

    async fn emit(&self, coded: Vec<Bytes>, _pin: &()) {
        for f in coded {
            // Broadcast: LoRa carries no link addressing here (the name is the
            // addressing), so dst/src are advisory and the driver ignores them.
            let _ = self
                .radio
                .inject(InjectFrame {
                    payload: f,
                    tx: TxIntent::CONSERVATIVE,
                    dst: [0xff; 6],
                    src: [0x02, b'l', b'o', b'r', b'a', 0x00],
                    addr3: None,
                    extra: None,
                    htc: None,
                })
                .await;
        }
    }
}

enum Egress {
    /// Plain: each `send_bytes` is one LoRa frame (the `LpLinkService` already
    /// fragmented). No redundancy.
    Direct,
    /// Link FEC: frames batch into generations; the plan's parity count actuates
    /// per generation. The bridge owns the batching/decode; this face reads the
    /// plan and feeds it in.
    Fec(LinkFecBridge<()>),
}

/// What the radio says about its own rate axis — the read that keeps this PHY
/// bearer-agnostic across the LoRa family.
///
/// A spreading factor is a *LoRa* concept. An LR2021 running FLRC has none, and
/// pushing one at it is a category error the radio can only answer with a lie or an
/// error. So SF/CR are actuated on evidence, not on the crate's name.
#[derive(Clone, Copy)]
enum SfPolicy {
    /// The radio declares a LoRa SF span — clamp the plan into it and actuate.
    Span(u8, u8),
    /// The radio declares a *non*-LoRa rate capability (or none at all): it has no
    /// spreading factor, so the knob is skipped entirely.
    NotLora,
    /// No [`RadioProfile`] attached, so the radio has said nothing. Pass the plan
    /// through unclamped and let the driver be the authority — the pre-#78
    /// behaviour, preserved for a face built from a bare `FrameIo`.
    Unknown,
}

/// The rate/power knobs this face has already pushed at the radio. Knobs are
/// *bearer state* (one call, not a per-frame argument), so re-sending an unchanged
/// value is pure cost — on a serial bridge, a blocking command round-trip per frame.
#[derive(Default, Clone, Copy, PartialEq)]
struct AppliedRate {
    /// The modulation last commanded — and, on success, the one the radio REPORTED back, not the
    /// one we asked for (a chip may refuse a mode the node advertises).
    phy: Option<PhyMode>,
    sf: Option<u8>,
    cr: Option<u8>,
    bw_khz: Option<u32>,
    dbm: Option<i8>,
    power_idx: Option<u8>,
    edcca_ignore: Option<bool>,
    /// Knobs the radio has answered `Unsupported` for. A refusal is a **property of the
    /// radio**, not of the value, so re-asking on the next frame can only produce the same
    /// answer — and because the cache only advances on success, an un-latched refusal would
    /// re-fire on every single send and bury the log. Latched here so each unreachable knob
    /// is asked exactly once and warned about exactly once.
    refused: Refused,
}

/// See [`AppliedRate::refused`].
#[derive(Default, Clone, Copy, PartialEq)]
struct Refused {
    /// The modulation the radio refused, if one has been. **A mode, not a flag**: unlike every
    /// other knob here, a refusal is a property of the `(radio, mode)` pair rather than of the
    /// radio, and latching a bare boolean would take the whole axis out of service after one
    /// unreachable mode. Latched at all because the alternative is a blocking serial round trip
    /// on every single send, for an answer that cannot change.
    phy: Option<PhyMode>,
    sf: bool,
    cr: bool,
    bw: bool,
    dbm: bool,
    power_idx: bool,
    edcca: bool,
}

/// Is this the radio saying "I do not have that knob", as opposed to a transient failure?
///
/// The distinction matters because only the first is safely permanent: a serial hiccup must
/// stay retryable. [`RadioKnobs`]'s default methods and every explicit refusal in this stack
/// use `ErrorKind::Unsupported` for exactly this.
fn is_unsupported(e: &FaceError) -> bool {
    matches!(e, FaceError::Io(io) if io.kind() == std::io::ErrorKind::Unsupported)
}

/// A connectionless sub-GHz broadcast face. Build a [`Face`] with
/// [`into_face`](Self::into_face); the engine treats it as an ad-hoc bearer.
pub struct LoraPhy {
    id: FaceId,
    radio: Arc<dyn FrameIo>,
    /// Channel / SF / CR / bandwidth / power / occupancy — the control plane, when the
    /// radio has one. `None` ⇒ a bearer whose knobs are unreachable (a loopback bus, a
    /// backend that only sends and receives); every actuation is then skipped, never faked.
    knobs: Option<Arc<dyn RadioKnobs>>,
    /// This radio's link clocks (#78). Held so a caller can reach them through
    /// [`time`](Self::time) — the face itself has no use for a clock yet, but erasing it
    /// at construction is what made it unreachable everywhere else.
    time: Option<Arc<dyn RadioTime>>,
    /// The radio's self-description. Governs the MTU and the SF policy.
    profile: Option<Arc<dyn RadioProfile>>,
    /// The capability read from `profile`: `send_mtu` and the per-frame actuator both consult
    /// it, and a per-send `capability()` call would be a lock (or a device round-trip) on the
    /// hot path, so it is cached here.
    ///
    /// Behind a lock rather than plain, because of ONE event: a successful
    /// [`RadioKnobs::set_phy`] **invalidates the whole capability** — payload cap, rate model,
    /// SF span, scheduling granularity and even the band are per-PHY. So the actuator re-reads
    /// the profile and replaces this wholesale ([`refresh_capability`](Self::refresh_capability)),
    /// which it cannot do through a plain field on `&self`. Without that, a face that switched
    /// modulation would go on fragmenting to the *old* MTU and hand the driver frames it now
    /// rejects — invisible loss rather than an error.
    cap: RwLock<Option<RadioCapability>>,
    /// Derived from `cap` — see [`LORA_MTU`]. Recomputed whenever `cap` is,
    /// so the two can never disagree about the frame size.
    mtu: AtomicUsize,
    egress: Egress,
    /// Recovered payloads awaiting `recv_bytes` (FEC decode can yield 0/1/many).
    pending: Mutex<VecDeque<Bytes>>,
    /// Control-plane [`TxParams`] cell — written by the cognitive actuator, read per send.
    /// `link_fec_redundancy` drives the FEC bridge; the LoRa `rate` block and the power
    /// fields drive [`RadioKnobs`] when one is attached.
    planned: Option<Arc<RwLock<Option<TxParams>>>>,
    /// Last values pushed through `knobs`, so an unchanged plan costs nothing.
    applied: Mutex<AppliedRate>,
    /// The named airtime lease's reach into this bearer: when may this wire go on air?
    /// `None` ⇒ ungated (transmit on call), which is the default and the historical behaviour.
    /// See [`with_slot_gate`](LoraPhy::with_slot_gate).
    slot_gate: Option<Arc<SlotGate>>,
}

impl LoraPhy {
    /// A plain face over `radio` (no link FEC, **no control plane**). Every `send_bytes`
    /// is one frame; the paired `LpLinkService` fragments larger packets.
    ///
    /// A bare `Arc<dyn FrameIo>` cannot be asked what it is or told what to do, so this
    /// constructor declares the conservative [`LORA_MTU`] and actuates nothing. Prefer
    /// [`from_open`](Self::from_open) wherever the opener gives you the whole radio.
    pub fn new(id: FaceId, radio: Arc<dyn FrameIo>) -> Self {
        Self {
            id,
            radio,
            knobs: None,
            time: None,
            profile: None,
            cap: RwLock::new(None),
            mtu: AtomicUsize::new(LORA_MTU),
            egress: Egress::Direct,
            pending: Mutex::new(VecDeque::new()),
            planned: None,
            applied: Mutex::new(AppliedRate::default()),
            slot_gate: None,
        }
    }

    /// **A face from the whole radio** — the capability-complete path (#78).
    ///
    /// [`OpenRadio`] carries the four handles a backend implements; this keeps all of
    /// them. Without it, a wiring site that writes
    /// `let io: Arc<dyn FrameIo> = backend; LoraPhy::new(id, io)` throws the radio's
    /// knobs, clock and profile away at the one place they were available, and every
    /// downstream consumer — the rate actuator, an occupancy sampler, the MTU — silently
    /// gets a default instead of the hardware.
    pub fn from_open(id: FaceId, r: OpenRadio) -> Self {
        let mut me = Self::new(id, r.io);
        me.knobs = r.knobs;
        me.time = r.time;
        if let Some(p) = r.profile {
            *me.cap.get_mut().unwrap() = Some(p.capability());
            me.profile = Some(p);
        }
        me.recompute_mtu();
        me
    }

    /// Attach the radio's control seam (channel / SF / CR / bandwidth / power / occupancy).
    pub fn with_knobs(mut self, knobs: Arc<dyn RadioKnobs>) -> Self {
        self.knobs = Some(knobs);
        self
    }

    /// Attach this radio's link clocks. Per-radio, not per-face: a multi-radio node has
    /// one clock per radio and a gate consulting a face-level clock is timing the wrong
    /// medium (#89).
    pub fn with_time(mut self, time: Arc<dyn RadioTime>) -> Self {
        self.time = Some(time);
        self
    }

    /// Attach the radio's self-description — and take the MTU and the SF policy from it.
    pub fn with_profile(mut self, profile: Arc<dyn RadioProfile>) -> Self {
        *self.cap.get_mut().unwrap() = Some(profile.capability());
        self.profile = Some(profile);
        self.recompute_mtu();
        self
    }

    /// The control seam, for a caller wiring something this face does not do itself — a
    /// frame-free occupancy sampler (`read_channel_activity`), or a channel/hop plan. `None` when
    /// the radio has no reachable knobs.
    pub fn knobs(&self) -> Option<Arc<dyn RadioKnobs>> {
        self.knobs.clone()
    }

    /// **Start frame-free occupancy sensing on this radio** (#30) — the LoRa end of the
    /// sampler that used to be reachable only through `ndn-phy-wifi`.
    ///
    /// Spawns [`spawn_occupancy_sampler`] over this face's own [`knobs`](Self::knobs), so the
    /// same radio that ACTs also SENSEs its medium; the readings land in `sink` (a shared
    /// `Mutex<MediumState>`, or any [`OccupancySink`]) and the policy then decides on measured
    /// channel load instead of a guess. On the 7E-A5 fleet this is the `CMD_SENSE` opcode, and
    /// a node whose `cmd_bitmap` lacks it answers `Ok(None)` — the sampler then polls once and
    /// exits, so an incapable radio costs one round-trip, not a permanent task.
    ///
    /// `None` when this face has no reachable knobs (built from a bare `FrameIo`): there is
    /// nothing to poll, and returning a handle to a task that can never sample would be the
    /// fake success this stack refuses.
    pub fn start_occupancy_sampling<S>(
        &self,
        sink: Arc<S>,
        radio: RadioId,
        channel: u8,
        interval: Duration,
        now_ms: impl Fn() -> u64 + Send + 'static,
    ) -> Option<tokio::task::JoinHandle<()>>
    where
        S: OccupancySink + ?Sized,
    {
        let knobs = self.knobs.clone()?;
        Some(spawn_occupancy_sampler(
            sink, radio, channel, knobs, interval, now_ms,
        ))
    }

    /// **Install the named airtime lease's gate on this bearer** (#61/#40).
    ///
    /// `gate` answers *when* an outbound wire may go on air; the face then answers *how* that
    /// is enforced, and that is the whole point of this seam:
    ///
    /// * a radio that really schedules TX (`FrameIo::schedules_tx` **and**
    ///   [`TxDiscipline::ScheduledAt`]) gets the timing handed to `inject_after` /
    ///   `inject_at_clock`, so the MCU places the frame and the host never sleeps;
    /// * every other radio gets the software gate — the host sleeps out the delay and then
    ///   injects, exactly as before.
    ///
    /// With no gate installed the face is byte-for-byte unchanged: every `send_bytes` injects
    /// on call. See [`schedules_tx_in_hardware`](Self::schedules_tx_in_hardware).
    pub fn with_slot_gate<F>(mut self, gate: F) -> Self
    where
        F: Fn(&[u8]) -> Option<SlotTiming> + Send + Sync + 'static,
    {
        self.slot_gate = Some(Arc::new(gate));
        self
    }

    /// **Does this radio place TX in time itself?** Both halves are required, and the second is
    /// the one that bites: `TxDiscipline::ScheduledAt` is a *label* a backend can declare
    /// without implementing the seam, and the HAL default for `inject_after` is *inject now*.
    /// Trusting the label alone would skip the software gate AND drop the delay — the frame
    /// leaves immediately with no slot discipline at all, strictly worse than never having
    /// claimed the discipline. (Measured live case on Wi-Fi: the AR9271 declares
    /// `ScheduledAt{1 µs}` and implements neither seam.) `FrameIo::schedules_tx` is overridden
    /// only alongside a real `inject_after`, so requiring both makes the fallback safe for
    /// every present and future backend.
    ///
    /// A face with no knobs attached cannot read a discipline, so it reports `false` and takes
    /// the software gate — an honest answer, not a guess.
    pub fn schedules_tx_in_hardware(&self) -> bool {
        self.radio.schedules_tx()
            && self
                .knobs
                .as_ref()
                .is_some_and(|k| matches!(k.tx_discipline(), TxDiscipline::ScheduledAt { .. }))
    }

    /// **A clock this face could name an absolute transmit instant in** — the best link clock the
    /// radio exposes that can be *read now*, monotonically.
    ///
    /// Both properties are required and neither is cosmetic. Without `read_now` there is no way to
    /// relate an instant to the present at all; without `monotonic` (a beacon-resynced port TSF,
    /// say) the counter can step backwards between the arm and the deadline, and a schedule built
    /// on it places frames at times that never arrive.
    ///
    /// ⚠ **This is a hint for a caller building a gate, not the gate's own capability test.** A
    /// radio may be able to *schedule* in a domain it does not advertise a source for — MEASURED
    /// in this fleet: the Waveshare SX1262 stamps with a firmware software counter, which the
    /// backend rightly refuses to advertise as a link clock (promoting it would make two nodes
    /// difference their firmware main-loop latencies and call it a clock offset), yet
    /// `CMD_READ_CLOCK` reads that same counter and `CMD_TX_AT` schedules against it. Judging the
    /// scheduling path by this list would refuse a radio that works.
    pub fn tx_clock_domain(&self) -> Option<ClockDomainId> {
        self.best_clock().map(|s| s.domain)
    }

    /// The best read-now monotonic source, if any. `time_sources()` is best-first.
    fn best_clock(&self) -> Option<RadioTimeSource> {
        self.time
            .as_ref()?
            .time_sources()
            .into_iter()
            .find(|s| s.read_now && s.monotonic)
    }

    /// The advertised source for `domain`, if the radio has one — needed to convert ticks into a
    /// wall-clock wait, and therefore required by the **software** absolute gate (and only by it).
    fn clock_for(&self, domain: ClockDomainId) -> Option<RadioTimeSource> {
        self.time
            .as_ref()?
            .time_sources()
            .into_iter()
            .find(|s| s.domain == domain && s.read_now && s.monotonic)
    }

    /// This radio's link clocks, for a timekeeping consumer. `None` when it has none.
    pub fn time(&self) -> Option<Arc<dyn RadioTime>> {
        self.time.clone()
    }

    /// The radio's self-description handle. `None` when it does not describe itself.
    pub fn profile(&self) -> Option<Arc<dyn RadioProfile>> {
        self.profile.clone()
    }

    /// What the radio declared about itself at construction (`None` = it declared
    /// nothing). This is what governs the MTU and the SF policy — the *radio's* claim,
    /// not an assertion made on its behalf here.
    pub fn capability(&self) -> Option<RadioCapability> {
        self.cap.read().ok().and_then(|c| c.clone())
    }

    /// The data plane, for a caller that needs to share the radio (a second reader, a
    /// probe). Cloning the handle does not open a second device.
    pub fn frame_io(&self) -> Arc<dyn FrameIo> {
        Arc::clone(&self.radio)
    }

    /// Tune the radio to `channel`. A convenience over [`knobs`](Self::knobs) for the
    /// commonest control call; `Ok(())` with no knobs attached would be a lie, so it is
    /// an error instead.
    pub fn set_channel(&self, channel: u8) -> Result<(), FaceError> {
        match self.knobs.as_ref() {
            // LoRa is a single-carrier bearer: the width comes from `set_bandwidth_khz`,
            // and every LoRa-family backend ignores this argument.
            Some(k) => k.set_channel(channel, Bandwidth::default()),
            None => Err(FaceError::Io(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "this LoRa face has no RadioKnobs attached (built from a bare FrameIo)",
            ))),
        }
    }

    /// MTU = the radio's declared payload cap, never above this face's own measured
    /// ceiling, less the room a body-prefix filter needs. See [`LORA_MTU`].
    fn recompute_mtu(&self) {
        let declared = self
            .cap
            .read()
            .ok()
            .and_then(|c| c.as_ref().map(|c| c.max_payload))
            .unwrap_or(LORA_MTU);
        self.mtu
            .store(LORA_MTU.min(declared).max(1), Ordering::Relaxed);
    }

    /// **Re-read the radio's self-description and replace what we hold** — the mandatory
    /// follow-up to a successful modulation change.
    ///
    /// `EVT_CAP` describes the CURRENT PHY, so a switch does not change one field of the
    /// capability, it replaces all of them: an LR2021 in FLRC carries 47 bytes and has no
    /// spreading factor, while the same silicon in LoRa carries far more and spans SF7..SF12.
    /// Patching the field we think moved would leave the rest quietly describing a radio that no
    /// longer exists — so this takes the profile's word wholesale and recomputes the MTU from it.
    ///
    /// A face with no [`RadioProfile`] has nothing to re-read and keeps what it had, which is the
    /// same (conservative) answer it started with.
    fn refresh_capability(&self) {
        let Some(profile) = self.profile.as_ref() else {
            return;
        };
        if let Ok(mut slot) = self.cap.write() {
            *slot = Some(profile.capability());
        }
        self.recompute_mtu();
    }

    /// Enable **plan-driven link FEC**: source frames batch into generations of `k`
    /// (or `LORA_FEC_K`), transmitted as `k + R` coded frames where `R` is the
    /// plan's [`link_fec_redundancy`], recoverable from any `k` of the `n`. `window`
    /// bounds a partial generation's tail-flush (default `LORA_FEC_WINDOW`).
    ///
    /// The initial `R` is 0 — the real value comes from the plan per frame, so a
    /// face with no plan cell transmits plain (no parity) until one is attached.
    ///
    /// [`link_fec_redundancy`]: ndn_radio_cognition::TxParams::link_fec_redundancy
    pub fn with_link_fec(mut self, k: Option<usize>, window: Option<Duration>) -> Self {
        let sink = LoraFecSink {
            radio: Arc::clone(&self.radio),
        };
        let bridge = LinkFecBridge::spawn(
            sink,
            k.unwrap_or(LORA_FEC_K),
            0,
            window.unwrap_or(LORA_FEC_WINDOW),
        );
        self.egress = Egress::Fec(bridge);
        self
    }

    /// Let the cognitive control plane drive this bearer: its actuator writes the decided
    /// [`TxParams`] into `cell`, and this face reads it on each send.
    ///
    /// Two things are actuated from that one cell:
    /// * `link_fec_redundancy` → the FEC bridge's parity count (needs
    ///   [`with_link_fec`](Self::with_link_fec)).
    /// * the LoRa `rate` block (SF / CR / bandwidth) and the power fields → the radio,
    ///   through [`RadioKnobs`] (needs a radio with knobs; see
    ///   [`from_open`](Self::from_open)). Values are pushed only when they *change*,
    ///   because a knob is bearer state, and SF/CR are skipped entirely on a radio whose
    ///   capability says it has no spreading factor.
    ///
    /// With neither a FEC bridge nor knobs attached this is inert — which is exactly what
    /// a plain face should do with a plan it cannot act on.
    pub fn with_planned_params(mut self, cell: Arc<RwLock<Option<TxParams>>>) -> Self {
        self.planned = Some(cell);
        self
    }

    /// Build a [`Face`] pairing this transport with the engine's `LpLinkService`,
    /// so NDN packets fragment/reassemble across frames (and, under FEC, ride
    /// generations).
    pub fn into_face(self) -> Face {
        Face::from_transport(self)
    }

    /// The decided plan, if a control plane is attached and has written one.
    fn planned_params(&self) -> Option<TxParams> {
        self.planned
            .as_ref()
            .and_then(|c| c.read().ok().and_then(|g| *g))
    }

    /// Parity the plan wants on the next generation (`None` = leave the bridge's
    /// current R). The actuator for [`TxParams::link_fec_redundancy`] on LoRa.
    fn planned_redundancy(&self) -> Option<u16> {
        self.planned_params().and_then(|tp| tp.link_fec_redundancy)
    }

    /// Does this radio *have* a spreading factor, and over what span? Read from the
    /// declared capability, never assumed from the crate's name.
    fn sf_policy(&self) -> SfPolicy {
        match self.capability().map(|c| c.rate) {
            None => SfPolicy::Unknown,
            Some(RateCapability::Lora { min_sf, max_sf }) => SfPolicy::Span(min_sf, max_sf),
            Some(_) => SfPolicy::NotLora,
        }
    }

    /// May this face command `want`? The guard in front of [`RadioKnobs::set_phy`].
    ///
    /// **A plan must never name a mode the node did not offer**, so the check is against the
    /// radio's own [`RadioCapability::phy_modes`] — not against what the crate is called, and not
    /// against a table keyed on a part number. Three refusals, each a different mistake:
    ///
    /// * the radio has described no modes at all (`is_empty`) — "I cannot say" is not "yes";
    /// * it described exactly one (`!is_agile`) — modulation is a *fact* about that radio, and
    ///   commanding it is at best a no-op round trip;
    /// * it described several and `want` is not among them — the plan is wrong, and finding that
    ///   out on the air (as a dead link) is the expensive way.
    ///
    /// A face with no capability at all refuses too: this is the one knob where "let the driver
    /// be the authority" is not safe, because a wrong answer costs the whole link rather than
    /// one frame.
    fn phy_switch_allowed(&self, want: PhyMode) -> Result<(), &'static str> {
        let Some(cap) = self.capability() else {
            return Err("no declared capability: this face cannot know which modes exist");
        };
        if cap.phy_modes.is_empty() {
            return Err("the radio has not described its modulations");
        }
        if !cap.phy_modes.is_agile() {
            return Err("the radio runs a single modulation — it is not a knob here");
        }
        if !cap.phy_modes.contains(want) {
            return Err("the radio did not advertise this modulation");
        }
        Ok(())
    }

    /// **Install a name-keyed hop plan on the radio's own sequencer** (#40) — the actuator the
    /// hop derivation has never had.
    ///
    /// Derives the plan from `name` under the shared #44 `key` over `carriers_hz` (the group's
    /// band plan), truncates it to what this radio's sequencer accepts, and arms it. Returns the
    /// plan that was installed, so a caller can log or cross-check what the peer should derive.
    ///
    /// Both ends compute the SAME list from the same name + key + band plan and nothing is
    /// negotiated, which is what makes this work on a broadcast bearer — see
    /// [`name_hop_plan`] for the inputs that may and may not
    /// enter that derivation (local occupancy may not).
    ///
    /// `period` is in the radio's own unit
    /// ([`HopCapability::period_unit`](ndn_radio_hal::HopCapability)): **LoRa symbols** on a
    /// LoRa-modulation radio, microseconds elsewhere. It is passed through untouched rather than
    /// converted, because a wall-clock dwell in symbols moves with SF and bandwidth.
    ///
    /// Errors — never a quiet success — when this face has no knobs, when the radio declares no
    /// hop sequencer (`RadioCapability::hop == None`), or when the plan derives empty. A silent
    /// "ok" on a radio that cannot hop would leave a planner believing a name's frames are spread
    /// across a band they never left, which is exactly the co-band problem this exists to fix.
    pub fn install_name_hop_plan(
        &self,
        key: &[u8; 16],
        name: &[u8],
        carriers_hz: &[u32],
        period: u16,
    ) -> Result<HopPlan, FaceError> {
        let unsupported = |m: &str| {
            FaceError::Io(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                m.to_string(),
            ))
        };
        let knobs = self
            .knobs
            .as_ref()
            .ok_or_else(|| unsupported("this LoRa face has no RadioKnobs attached"))?;
        let hop = self
            .capability()
            .and_then(|c| c.hop)
            .ok_or_else(|| unsupported("this radio declares no autonomous hop sequencer"))?;
        let plan = name_hop_plan(key, name, carriers_hz, period, hop.max_list_len as usize);
        if plan.is_empty() {
            return Err(unsupported(
                "the derived hop plan is empty (no carriers declared)",
            ));
        }
        knobs.set_hop_plan(HopControl::On, plan.period(), plan.freqs_hz())?;
        tracing::info!(
            target: "named_radio",
            face = self.id.0,
            hops = plan.len(),
            period = plan.period(),
            intra_packet = hop.intra_packet,
            "installed a name-keyed hop plan"
        );
        Ok(plan)
    }

    /// Disarm hopping and return the radio to its tuned carrier. The installed list stays loaded
    /// (that is [`HopControl::Off`]'s contract), so re-arming does not need a re-derivation.
    pub fn clear_hop_plan(&self) -> Result<(), FaceError> {
        match self.knobs.as_ref() {
            Some(k) => k.set_hop_plan(HopControl::Off, 0, &[]),
            None => Err(FaceError::Io(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "this LoRa face has no RadioKnobs attached",
            ))),
        }
    }

    /// **ACT** — push the decided [`TxParams`] at the radio before the frame goes out.
    ///
    /// The LoRa peer of the Wi-Fi rate actuator, and the reason the control handles have
    /// to survive construction: without knobs there is nothing to push to, so a plan is
    /// decided, logged, and thrown away (this stack's characteristic defect). Every knob
    /// is written only on change, and a failure is reported rather than swallowed — a knob
    /// that did not land must not look like one that did.
    fn actuate_planned(&self) {
        let (Some(knobs), Some(tp)) = (self.knobs.as_ref(), self.planned_params()) else {
            return;
        };
        let mut cur = self.applied.lock().unwrap();

        // ── The modulation, BEFORE anything else ──────────────────────────────────────────
        // Order is load-bearing, not stylistic: `set_phy` resets the modem, so a spreading
        // factor or a power pushed before it would be wiped by it. The HAL says so outright —
        // "it must re-assert its intended channel/rate/power: none of them survives a
        // modulation change" — so on a switch we clear the whole applied-knob cache and let the
        // rest of this function push everything again against the new PHY.
        if let Some(want) = tp.phy
            && cur.phy != Some(want)
            && cur.refused.phy != Some(want)
        {
            match self.phy_switch_allowed(want) {
                Err(reason) => {
                    // A mode the radio never advertised is a plan bug, not a radio failure:
                    // refuse it here rather than commanding it and finding out on the air.
                    cur.refused.phy = Some(want);
                    tracing::warn!(target: "named_radio", face = self.id.0, phy = ?want, reason, "lora set_phy refused before it reached the radio");
                }
                Ok(()) => match knobs.set_phy(want) {
                    // Believe the APPLIED mode, not the request: a chip may refuse a mode its
                    // node advertises (a band/PA combination it cannot serve).
                    Ok(applied) => {
                        let changed = cur.phy != Some(applied);
                        cur.phy = Some(applied);
                        if changed {
                            // Every other knob is now unset as far as the radio is concerned.
                            let phy = cur.phy;
                            *cur = AppliedRate {
                                phy,
                                ..Default::default()
                            };
                            // And the capability we hold describes the PHY we just left.
                            drop(cur);
                            self.refresh_capability();
                            cur = self.applied.lock().unwrap();
                        }
                        if applied != want {
                            // The chip would not go where the node said it could. Latch THAT
                            // mode so the next frame does not buy the same refusal again.
                            cur.refused.phy = Some(want);
                            tracing::warn!(target: "named_radio", face = self.id.0, wanted = ?want, applied = ?applied, "lora set_phy landed on a different mode");
                        }
                    }
                    Err(e) => {
                        if is_unsupported(&e) {
                            cur.refused.phy = Some(want);
                        }
                        tracing::warn!(target: "named_radio", face = self.id.0, phy = ?want, error = %e, "lora set_phy failed")
                    }
                },
            }
        }

        // Spreading factor + coding rate: LoRa's reach/rate dial. Only on a radio that
        // declares an SF span (or one that has declared nothing, where the driver is the
        // authority); an FLRC node declaring a non-LoRa rate is skipped, not lied to.
        let policy = self.sf_policy();
        if !matches!(policy, SfPolicy::NotLora) {
            if let Some(sf) = tp.spreading_factor() {
                let sf = match policy {
                    SfPolicy::Span(lo, hi) => sf.clamp(lo, hi),
                    _ => sf, // undeclared: the driver is the authority on its own range
                };
                if cur.sf != Some(sf) && !cur.refused.sf {
                    match knobs.set_spreading_factor(sf) {
                        Ok(()) => cur.sf = Some(sf),
                        Err(e) => {
                            cur.refused.sf = is_unsupported(&e);
                            tracing::warn!(target: "named_radio", face = self.id.0, sf, error = %e, "lora set_spreading_factor failed")
                        }
                    }
                }
            }
            if let Some(cr) = tp.coding_rate()
                && cur.cr != Some(cr)
                && !cur.refused.cr
            {
                match knobs.set_coding_rate(cr) {
                    Ok(()) => cur.cr = Some(cr),
                    Err(e) => {
                        cur.refused.cr = is_unsupported(&e);
                        tracing::warn!(target: "named_radio", face = self.id.0, cr, error = %e, "lora set_coding_rate failed")
                    }
                }
            }
        }

        // Bandwidth: a rate/range axis every sub-GHz bearer here has, LoRa or not.
        if let Some(khz) = tp.bandwidth_khz()
            && cur.bw_khz != Some(khz)
            && !cur.refused.bw
        {
            match knobs.set_bandwidth_khz(khz) {
                Ok(()) => cur.bw_khz = Some(khz),
                Err(e) => {
                    cur.refused.bw = is_unsupported(&e);
                    tracing::warn!(target: "named_radio", face = self.id.0, khz, error = %e, "lora set_bandwidth_khz failed")
                }
            }
        }

        // Power: prefer the portable dBm scale when the radio advertises a range (clamped
        // into it — the plan only ever backs OFF below the ceiling), else the opaque index.
        if let Some(dbm) = tp.tx_power_dbm {
            let dbm = self
                .capability()
                .and_then(|c| c.tx_power_dbm)
                .map_or(dbm, |r| r.clamp(dbm));
            if cur.dbm != Some(dbm) && !cur.refused.dbm {
                match knobs.set_tx_power_dbm(dbm) {
                    // Believe the APPLIED value, not the request: a driver/regulatory table
                    // may clamp further, and caching the request would make us think a power
                    // we never reached is already set.
                    Ok(applied) => cur.dbm = Some(applied),
                    Err(e) => {
                        cur.refused.dbm = is_unsupported(&e);
                        tracing::warn!(target: "named_radio", face = self.id.0, dbm, error = %e, "lora set_tx_power_dbm failed")
                    }
                }
            }
        } else if let Some(idx) = tp.tx_power
            && cur.power_idx != Some(idx)
            && !cur.refused.power_idx
        {
            match knobs.set_tx_power(ndn_radio_hal::PowerRequest::index(idx)) {
                // ⚠ Dedupe on the REQUEST (`idx`), not on what the radio reported applying: on
                // this bearer the "index" is dBm in disguise and the node clamps it into its
                // declared range, so the applied value routinely differs and caching it would
                // re-push a write every tick forever.
                Ok(_applied) => cur.power_idx = Some(idx),
                Err(e) => {
                    cur.refused.power_idx = is_unsupported(&e);
                    tracing::warn!(target: "named_radio", face = self.id.0, idx, error = %e, "lora set_tx_power failed")
                }
            }
        }

        // Listen-before-talk: on this bearer `edcca_ignore` maps to the firmware LBT toggle.
        if tp.edcca_ignore() {
            ndn_radio_cognition::ledger::note_edcca_ignored();
        }
        if cur.edcca_ignore != Some(tp.edcca_ignore()) && !cur.refused.edcca {
            match knobs.set_edcca_ignore(tp.edcca_ignore()) {
                Ok(()) => cur.edcca_ignore = Some(tp.edcca_ignore()),
                Err(e) => {
                    cur.refused.edcca = is_unsupported(&e);
                    tracing::warn!(target: "named_radio", face = self.id.0, error = %e, "lora set_edcca_ignore failed")
                }
            }
        }
    }

    /// **Put one frame on air, honouring `timing`.**
    ///
    /// `None` (no gate, or a wire the gate does not schedule) is plain `inject` — the unchanged
    /// default path, and the whole behaviour of a face with no gate installed.
    ///
    /// ## Absolute beats relative, and that is a measurement
    ///
    /// [`SlotTiming::AtClock`] goes to [`FrameIo::inject_at_clock`] whenever the radio really
    /// schedules **and** owns the clock the instant is named in. Preferring it is not taste:
    ///
    /// * MEASURED on the LR2021 absolute-boundary slot train — 45/45 slots fired, mean gap
    ///   2 399 818 ticks against 2 400 000 nominal (within 11 µs over 44 slots). **Accuracy is
    ///   excellent.** But **jitter came out at sd 553 µs / p2p 1875 µs** against a declared 50 µs
    ///   `sched_gran_ns`, because the *relative* arm counts its delay from the moment the
    ///   FIRMWARE processes the command — so the whole host→device serial latency lands inside
    ///   the placement. The corroboration is exact: that node's `CMD_GET_INFO` round trip is p2p
    ///   **550 µs**, the same number.
    /// * As exercised that way, host-armed scheduled TX is *worse* than the software gate
    ///   (sd 553 µs vs 155 µs) because it pays an extra round trip for the privilege. An
    ///   **absolute** instant has no such term: the deadline is a value on the device's own
    ///   timebase, so serial latency only has to be *smaller than the lead time*, not stable.
    ///
    /// Relative timing is still exactly right when the *caller* thinks in delays — it is
    /// reconcile-free (the clock offset cancels) — so [`SlotTiming::After`] is passed through as
    /// a delay and never silently converted. Converting one to the other would mean reading the
    /// device clock per frame, which re-introduces the very round trip the absolute path exists
    /// to remove.
    ///
    /// ## When the radio cannot schedule
    ///
    /// A delay falls back to the host's own sleep, exactly as before — unchanged for every
    /// non-scheduling radio. An **absolute** instant falls back to the software gate too, but
    /// only where it can be honoured honestly: the radio must expose that clock domain
    /// `read_now`, so the host can ask what time it is *there* and sleep the difference. That is
    /// coarse (it costs one clock round trip and the sleep's own jitter) but it is real.
    ///
    /// The one case that still ERRORS rather than degrading: a non-scheduling radio handed an
    /// absolute instant in a domain it does not describe. The host holds no mapping into it and
    /// the radio cannot honour it, so transmitting now would silently discard the discipline —
    /// and this stack's rule is that a knob the hardware cannot do must error, never quietly
    /// succeed. Callers with no disciplined domain should emit [`SlotTiming::After`], which
    /// always works.
    async fn inject_scheduled(
        &self,
        frame: InjectFrame,
        timing: Option<SlotTiming>,
    ) -> Result<(), FaceError> {
        let Some(t) = timing else {
            return self.radio.inject(frame).await;
        };
        match t {
            SlotTiming::After { delay_us } => {
                if self.schedules_tx_in_hardware() {
                    self.radio.inject_after(frame, delay_us).await
                } else {
                    if delay_us > 0 {
                        tokio::time::sleep(Duration::from_micros(delay_us)).await;
                    }
                    self.radio.inject(frame).await
                }
            }
            SlotTiming::AtClock { tick, domain } => {
                if self.schedules_tx_in_hardware() {
                    // ★ The BACKEND owns the domain check, and must: only it knows which counter
                    // is its own. The LoRa family's `inject_at_clock` compares against its device
                    // domain and falls back to plain injection for a foreign tick, and it accepts
                    // instants in counters it deliberately does not advertise as *link clocks*
                    // (the Waveshare's firmware software counter — readable and schedulable, but
                    // not a common-view source). Re-deciding that here from `time_sources()` would
                    // refuse radios that work; see `tx_clock_domain`.
                    return self.radio.inject_at_clock(frame, tick, domain).await;
                }
                // The radio cannot place it at all — but if the host can READ that domain, and the
                // radio has described its tick, the instant can still be honoured by sleeping the
                // remainder on the radio's own clock. Coarse (a clock round trip plus the sleep's
                // own jitter), and strictly better than the error this used to be.
                let Some(src) = self.clock_for(domain) else {
                    return Err(FaceError::Io(std::io::Error::new(
                        std::io::ErrorKind::Unsupported,
                        "SlotTiming::AtClock names a clock domain this radio does not expose as a \
                         readable monotonic counter, so neither the radio nor the host can honour \
                         it — use SlotTiming::After for a reconcile-free delay, or name the domain \
                         from LoraPhy::tx_clock_domain()",
                    )));
                };
                let now = self
                    .time
                    .as_ref()
                    .and_then(|t| t.read_clock(domain).ok().flatten());
                if let Some(now) = now
                    && tick > now
                {
                    let ticks = tick - now;
                    let us = ticks.saturating_mul(src.tick_ns.max(1) as u64) / 1_000;
                    if us > 0 {
                        tokio::time::sleep(Duration::from_micros(us)).await;
                    }
                }
                // A deadline already past (or a clock read that failed) transmits now, which is
                // what a software gate can do about a slot it is already inside.
                self.radio.inject(frame).await
            }
        }
    }
}

impl Transport for LoraPhy {
    fn id(&self) -> FaceId {
        self.id
    }

    fn kind(&self) -> FaceKind {
        // A wire kind (LP framing on), NonLocal scope; `link_type() == AdHoc`
        // marks the connectionless broadcast bearer, as for BLE-adv / monitor-wifi.
        FaceKind::Wfb
    }

    fn remote_uri(&self) -> Option<String> {
        Some("lora://broadcast".to_string())
    }

    fn link_type(&self) -> LinkType {
        LinkType::AdHoc
    }

    /// The radio's declared payload cap, capped by this face's own ceiling and less the
    /// body-prefix headroom — **not** a constant. See [`LORA_MTU`].
    fn send_mtu(&self) -> Option<usize> {
        Some(self.mtu.load(Ordering::Relaxed))
    }

    async fn send_bytes(&self, wire: Bytes) -> Result<(), FaceError> {
        // ACT before the frame leaves: rate/power are bearer state, so the knob must be
        // set for the frame that follows it.
        self.actuate_planned();
        match &self.egress {
            Egress::Direct => {
                // WHEN before WHAT: the slot gate reads the *wire* (where the NDN name is), so the
                // lease keys on the frame's own name.
                let timing = self.slot_gate.as_ref().and_then(|g| g(&wire));
                self.inject_scheduled(
                    InjectFrame {
                        payload: wire,
                        tx: TxIntent::CONSERVATIVE,
                        dst: [0xff; 6],
                        src: [0x02, b'l', b'o', b'r', b'a', 0x00],
                        addr3: None,
                        extra: None,
                        htc: None,
                    },
                    timing,
                )
                .await
            }
            // The plan's redundancy rides in with the frame (same pattern as the
            // Wi-Fi face's MCS): the bridge applies it at the next generation
            // boundary, because R is a whole-generation property.
            //
            // Deliberately NOT slot-gated: `send` here only *enqueues* into the open
            // generation, and the coded frames leave later, from the bridge's own task, at the
            // generation boundary. Gating this call would delay the enqueue and leave the
            // actual transmission ungated — a lease that looks enforced and is not. Gating a
            // FEC generation belongs in the sink, and is not claimed here.
            // A parity budget larger than the generation is COUNTED, not clamped — the same
            // decision, for the same reason, as the Wi-Fi face's `inject_with_intent`: R > K is a
            // legitimate high-loss configuration, the codec already caps `K + R <= 255`, and the
            // tighter `R <= K` is the POLICY's own ceiling rather than a physical one. What the
            // face can honestly do is make a budget cognition could not have produced visible.
            Egress::Fec(bridge) => {
                let parity = self.planned_redundancy().inspect(|&want| {
                    // Counted, not warned: the policy's ceiling is `PolicyConfig::generation_k`,
                    // this is THIS face's generation, and nothing ties them — a face built with a
                    // smaller K (K=1 is repetition) makes every legitimate plan trip it. See the
                    // same site in `ndn-phy-wifi/src/medium.rs` for the full reasoning.
                    if want > bridge.generation_size() {
                        ndn_radio_cognition::ledger::note_fec_parity_over_generation();
                    }
                });
                bridge.send(wire, (), parity)
            }
        }
    }

    async fn recv_bytes(&self) -> Result<Bytes, FaceError> {
        self.recv_bytes_with_addr().await.map(|(b, _)| b)
    }

    async fn recv_bytes_with_addr(&self) -> Result<(Bytes, Option<FaceAddr>), FaceError> {
        match &self.egress {
            // Deliver every captured frame; relevance is decided by parsing the NDN name upstream
            // (the in-frame body-prefix filter is retired — see firmware/NDR_MAC_SPEC.md).
            Egress::Direct => {
                let cf = self.radio.recv_frame().await?;
                Ok((cf.payload, cf.addr.map(FaceAddr::Ether)))
            }
            // Feed each captured frame through the FEC decoder; source frames come
            // back immediately, parity recovers missing ones (0/1/many per frame).
            // Buffer the extras and drain across calls.
            Egress::Fec(bridge) => loop {
                if let Some(p) = self.pending.lock().unwrap().pop_front() {
                    return Ok((p, None));
                }
                let cf = self.radio.recv_frame().await?;
                let addr = cf.addr;
                let delivered = bridge.decode(cf.payload);
                if delivered.is_empty() {
                    continue;
                }
                let mut q = self.pending.lock().unwrap();
                q.extend(delivered);
                if let Some(p) = q.pop_front() {
                    return Ok((p, addr.map(FaceAddr::Ether)));
                }
            },
        }
    }

    /// The frame size is fixed by the radio's declared capability + this face's ceiling,
    /// not by the engine — rebuild the face against a radio that declares a different cap.
    fn set_send_mtu(&self, _mtu: Option<u64>) -> Result<Option<u64>, MtuError> {
        Err(MtuError::Immutable)
    }

    /// A broadcast medium has no per-peer connection to keep alive.
    fn set_persistency(&self, _p: FacePersistency) -> Result<(), PersistencyError> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ndn_frame_io::LoopbackMonitorBus;
    use ndn_radio_cognition::{LoraRate, RateParams};
    use ndn_radio_hal::{
        Band, CsiSupport, DbmRange, HopCapability, HopPeriodUnit, PhyModeSet, RadioKind,
    };
    use ndn_transport::Transport;

    /// A K=2 generation with the plan forcing R=2 must put 4 frames on air, and the
    /// peer's FEC face must decode the 2 source frames back out — proving the
    /// plan-driven link-FEC path end to end over a `FrameIo` bearer (the LoRa case,
    /// on the loopback bus since real LoRa needs a serial dongle). Mirrors the
    /// Wi-Fi face's regression test; erasure recovery itself is covered by
    /// `ndn_coding::link_fec` unit tests.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn plan_driven_fec_round_trips_over_a_frameio_bearer() {
        let bus = LoopbackMonitorBus::new();
        let cell = Arc::new(RwLock::new(Some(TxParams {
            link_fec_redundancy: Some(2),
            ..Default::default()
        })));
        let tx = LoraPhy::new(FaceId(1), Arc::new(bus.endpoint(1, -60)))
            .with_link_fec(Some(2), Some(Duration::from_millis(50)))
            .with_planned_params(cell);
        let rx = LoraPhy::new(FaceId(2), Arc::new(bus.endpoint(2, -60)))
            .with_link_fec(Some(2), Some(Duration::from_millis(50)));

        let sent: Vec<Bytes> = (0..2u8).map(|i| Bytes::from(vec![i; 16])).collect();
        for w in &sent {
            tx.send_bytes(w.clone()).await.unwrap();
        }
        let mut got = Vec::new();
        for _ in 0..2 {
            let (b, _) = tokio::time::timeout(Duration::from_secs(2), rx.recv_bytes_with_addr())
                .await
                .expect("FEC face should deliver the generation")
                .unwrap();
            got.push(b);
        }
        got.sort();
        let mut want = sent;
        want.sort();
        assert_eq!(
            got, want,
            "plan-driven LoRa FEC face round-trips the generation"
        );
    }

    /// A plain (no-FEC) face is a straight passthrough: one send, one frame, one
    /// recv — the fragmentation-only path when the plan asks for no redundancy.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn plain_face_passes_frames_through() {
        let bus = LoopbackMonitorBus::new();
        let tx = LoraPhy::new(FaceId(1), Arc::new(bus.endpoint(1, -60)));
        let rx = LoraPhy::new(FaceId(2), Arc::new(bus.endpoint(2, -60)));
        tx.send_bytes(Bytes::from_static(b"hello-lora"))
            .await
            .unwrap();
        let (b, _) = tokio::time::timeout(Duration::from_secs(2), rx.recv_bytes_with_addr())
            .await
            .expect("plain face delivers")
            .unwrap();
        assert_eq!(&b[..], b"hello-lora");
    }

    /// A radio that declares itself and records every knob it is handed.
    #[derive(Default)]
    struct SpyRadio {
        cap: Mutex<Option<RadioCapability>>,
        sf: Mutex<Vec<u8>>,
        cr: Mutex<Vec<u8>>,
        bw: Mutex<Vec<u32>>,
        dbm: Mutex<Vec<i8>>,
        ch: Mutex<Vec<u8>>,
        /// When set, `set_bandwidth_khz` answers `Unsupported` — what the LoRa serial backend
        /// now does on a node whose `CMD_SET_MOD` triple is not a LoRa one (an FLRC LR2021).
        refuse_bw: bool,
        /// Modulations commanded through `set_phy`, in order.
        phy: Mutex<Vec<PhyMode>>,
        /// Hop plans installed through `set_hop_plan`: `(ctrl, period, carriers)`.
        hops: Mutex<Vec<(HopControl, u16, Vec<u32>)>>,
        /// The capability this radio reports **after** a successful `set_phy` — the wholesale
        /// replacement a real node's `EVT_CAP` performs on a mode change.
        cap_after_phy: Mutex<Option<RadioCapability>>,
        /// A mode the CHIP refuses even though the node advertises it (a band/PA combination it
        /// cannot serve) — the case the per-mode refusal latch exists for.
        refuse_phy: Mutex<Option<PhyMode>>,
    }

    impl SpyRadio {
        fn with_cap(cap: RadioCapability) -> Arc<Self> {
            let s = Self::default();
            *s.cap.lock().unwrap() = Some(cap);
            Arc::new(s)
        }
    }

    impl RadioProfile for SpyRadio {
        fn capability(&self) -> RadioCapability {
            self.cap.lock().unwrap().clone().unwrap()
        }
    }

    impl RadioKnobs for SpyRadio {
        fn set_channel(&self, channel: u8, _bw: Bandwidth) -> Result<(), FaceError> {
            self.ch.lock().unwrap().push(channel);
            Ok(())
        }
        fn set_phy(&self, mode: PhyMode) -> Result<PhyMode, FaceError> {
            self.phy.lock().unwrap().push(mode);
            if *self.refuse_phy.lock().unwrap() == Some(mode) {
                return Err(FaceError::Io(std::io::Error::new(
                    std::io::ErrorKind::Unsupported,
                    "this chip cannot serve that mode on this band",
                )));
            }
            // A real node re-describes itself after a switch; mimic that so the face's
            // capability-refresh path is genuinely exercised.
            if let Some(next) = self.cap_after_phy.lock().unwrap().clone() {
                *self.cap.lock().unwrap() = Some(next);
            }
            Ok(mode)
        }
        fn set_hop_plan(
            &self,
            ctrl: HopControl,
            period: u16,
            freqs_hz: &[u32],
        ) -> Result<(), FaceError> {
            self.hops
                .lock()
                .unwrap()
                .push((ctrl, period, freqs_hz.to_vec()));
            Ok(())
        }
        fn set_spreading_factor(&self, sf: u8) -> Result<(), FaceError> {
            self.sf.lock().unwrap().push(sf);
            Ok(())
        }
        fn set_coding_rate(&self, cr: u8) -> Result<(), FaceError> {
            self.cr.lock().unwrap().push(cr);
            Ok(())
        }
        fn set_bandwidth_khz(&self, khz: u32) -> Result<(), FaceError> {
            if self.refuse_bw {
                return Err(FaceError::Io(std::io::Error::new(
                    std::io::ErrorKind::Unsupported,
                    "no portable bandwidth byte on this node",
                )));
            }
            self.bw.lock().unwrap().push(khz);
            Ok(())
        }
        fn set_tx_power_dbm(&self, dbm: i8) -> Result<i8, FaceError> {
            self.dbm.lock().unwrap().push(dbm);
            Ok(dbm)
        }
    }

    /// A capability declaring a payload cap of `max_payload` and (optionally) a LoRa SF span.
    fn cap_with(max_payload: usize, rate: RateCapability) -> RadioCapability {
        RadioCapability {
            kind: RadioKind::Lora,
            he_cap: false,
            bands: vec![Band::Sub1GHz],
            rate,
            channels: vec![65],
            max_tx_power: 22,
            // A LoRa part drives the dBm knob directly, so the index scale is never rendered here.
            min_tx_power: None,
            db_per_power_idx: None,
            power_actuated: true,
            width_actuated: true,
            tx_power_dbm: Some(DbmRange::new(10, 22)),
            retune_us: None,
            rx_only: false,
            duty_cycle_max: 0.01,
            max_payload,
            half_duplex: true,
            csi: CsiSupport::None,
            // The modulation axis: a radio that has said nothing about its modes, which is the
            // right default for a fixture — `phy_switch_allowed` must refuse it.
            phy_modes: PhyModeSet::empty(),
            phy_current: None,
            hop: None,
        }
    }

    fn lora_cap(max_payload: usize) -> RadioCapability {
        cap_with(
            max_payload,
            RateCapability::Lora {
                min_sf: 7,
                max_sf: 12,
            },
        )
    }

    /// **G3** — the MTU is the radio's declared cap, not a constant. A node whose firmware
    /// truncates at 64 B is respected; a radio that over-declares (the `lora` preset says
    /// 256) cannot push the face past its own measured frame ceiling; and switching the
    /// body-prefix filter on reserves the TLV's worst case so a full fragment plus filter
    /// still fits one frame.
    #[test]
    fn mtu_comes_from_the_radios_declared_capability() {
        let bus = LoopbackMonitorBus::new();
        let io: Arc<dyn FrameIo> = Arc::new(bus.endpoint(1, -60));

        let bare = LoraPhy::new(FaceId(1), io.clone());
        assert_eq!(
            bare.send_mtu(),
            Some(LORA_MTU),
            "a radio that declares nothing gets the conservative default"
        );

        let small =
            LoraPhy::new(FaceId(2), io.clone()).with_profile(SpyRadio::with_cap(lora_cap(64)));
        assert_eq!(
            small.send_mtu(),
            Some(64),
            "a smaller REAL cap governs — this is the whole point"
        );

        let big =
            LoraPhy::new(FaceId(3), io.clone()).with_profile(SpyRadio::with_cap(lora_cap(256)));
        assert_eq!(
            big.send_mtu(),
            Some(LORA_MTU),
            "an over-declared 256 is capped to the face's measured ceiling, not believed"
        );
    }

    /// **A knob the radio refuses is asked once, not once per frame.**
    ///
    /// The applied-value cache only advances on success, so a knob that answers
    /// `Unsupported` never matches the plan and would be re-attempted — and re-warned about —
    /// on every single send. That is now reachable in practice: the LoRa serial backend
    /// refuses `set_bandwidth_khz` / `set_coding_rate` on a node whose `CMD_SET_MOD` bytes are
    /// not the LoRa ones (an FLRC LR2021), because the same three positions there mean
    /// `[bitrate_rung, _, flrc_cr]`. A refusal is a property of the radio, so it latches;
    /// transient errors do not carry `ErrorKind::Unsupported` and stay retryable.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_refused_knob_is_not_re_asked_every_frame() {
        let bus = LoopbackMonitorBus::new();
        let mut spy_inner = SpyRadio::default();
        spy_inner.refuse_bw = true;
        *spy_inner.cap.lock().unwrap() = Some(lora_cap(200));
        let spy = Arc::new(spy_inner);

        let cell = Arc::new(RwLock::new(Some(TxParams {
            rate: RateParams::Lora(LoraRate {
                spreading_factor: Some(9),
                coding_rate: None,
                bandwidth_khz: Some(250),
            }),
            ..Default::default()
        })));
        let face = LoraPhy::new(FaceId(1), Arc::new(bus.endpoint(1, -60)))
            .with_knobs(spy.clone())
            .with_profile(spy.clone())
            .with_planned_params(cell);

        for _ in 0..5 {
            face.send_bytes(Bytes::from_static(b"x")).await.unwrap();
        }
        assert!(
            spy.bw.lock().unwrap().is_empty(),
            "a refused knob never records a value"
        );
        // The knob that DOES work is still pushed, exactly once — the latch is per-knob, not a
        // global "stop actuating".
        assert_eq!(*spy.sf.lock().unwrap(), vec![9]);
    }

    /// **G1/G2** — a plan reaches the radio. SF/CR/BW/power are pushed through
    /// `RadioKnobs` on send, clamped into the declared span, and pushed only on change.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_decided_plan_actuates_the_radios_knobs() {
        let bus = LoopbackMonitorBus::new();
        let spy = SpyRadio::with_cap(lora_cap(200));
        let cell = Arc::new(RwLock::new(Some(TxParams {
            // SF20 does not exist; the declared span clamps it to 12.
            rate: RateParams::Lora(LoraRate {
                spreading_factor: Some(20),
                coding_rate: Some(3),
                bandwidth_khz: Some(250),
            }),
            // 30 dBm is above the declared 22 ceiling — a plan only ever backs OFF.
            tx_power_dbm: Some(30),
            ..Default::default()
        })));
        let face = LoraPhy::new(FaceId(1), Arc::new(bus.endpoint(1, -60)))
            .with_knobs(spy.clone())
            .with_profile(spy.clone())
            .with_planned_params(cell.clone());

        face.send_bytes(Bytes::from_static(b"one")).await.unwrap();
        assert_eq!(*spy.sf.lock().unwrap(), vec![12], "SF clamped to the span");
        assert_eq!(*spy.cr.lock().unwrap(), vec![3]);
        assert_eq!(*spy.bw.lock().unwrap(), vec![250]);
        assert_eq!(*spy.dbm.lock().unwrap(), vec![22], "clamped to the ceiling");

        // A knob is bearer STATE: an unchanged plan must not re-push it (on a serial
        // bridge each push is a blocking command round-trip per frame).
        face.send_bytes(Bytes::from_static(b"two")).await.unwrap();
        assert_eq!(
            spy.sf.lock().unwrap().len(),
            1,
            "unchanged SF is not re-sent"
        );
        assert_eq!(spy.dbm.lock().unwrap().len(), 1);

        // A changed plan does land.
        *cell.write().unwrap() = Some(TxParams {
            rate: RateParams::Lora(LoraRate {
                spreading_factor: Some(7),
                ..Default::default()
            }),
            ..Default::default()
        });
        face.send_bytes(Bytes::from_static(b"three")).await.unwrap();
        assert_eq!(*spy.sf.lock().unwrap(), vec![12, 7]);

        // And the channel knob is reachable at all, which it was not before (#G1).
        face.set_channel(65).unwrap();
        assert_eq!(*spy.ch.lock().unwrap(), vec![65]);
    }

    /// **G5** — the PHY does not assume LoRa. A radio that declares a *non*-LoRa rate
    /// capability (an LR2021 in FLRC, which has no spreading factor at all) mounts through
    /// this same PHY and is never handed an SF — the knob is skipped on the radio's own
    /// evidence, not on the crate's name. Bandwidth, which FLRC does have, still lands.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_non_lora_radio_is_never_handed_a_spreading_factor() {
        let bus = LoopbackMonitorBus::new();
        let spy = SpyRadio::with_cap(cap_with(160, RateCapability::None));
        let cell = Arc::new(RwLock::new(Some(TxParams {
            rate: RateParams::Lora(LoraRate {
                spreading_factor: Some(9),
                coding_rate: Some(2),
                bandwidth_khz: Some(500),
            }),
            ..Default::default()
        })));
        let face = LoraPhy::new(FaceId(1), Arc::new(bus.endpoint(1, -60)))
            .with_knobs(spy.clone())
            .with_profile(spy.clone())
            .with_planned_params(cell);

        face.send_bytes(Bytes::from_static(b"flrc")).await.unwrap();
        assert!(
            spy.sf.lock().unwrap().is_empty(),
            "no spreading factor exists on this radio — do not push one"
        );
        assert!(spy.cr.lock().unwrap().is_empty(), "nor a LoRa coding rate");
        assert_eq!(
            *spy.bw.lock().unwrap(),
            vec![500],
            "bandwidth is bearer-agnostic and still actuates"
        );
        assert_eq!(
            face.send_mtu(),
            Some(160),
            "and its own payload cap governs"
        );
    }

    /// A face built from a bare `FrameIo` (no knobs) with a plan attached must be inert,
    /// not panic and not pretend: `set_channel` fails loudly rather than reporting a tune
    /// that never happened.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_face_without_knobs_actuates_nothing_and_says_so() {
        let bus = LoopbackMonitorBus::new();
        let cell = Arc::new(RwLock::new(Some(TxParams::lora(LoraRate {
            spreading_factor: Some(10),
            ..Default::default()
        }))));
        let face =
            LoraPhy::new(FaceId(1), Arc::new(bus.endpoint(1, -60))).with_planned_params(cell);
        face.send_bytes(Bytes::from_static(b"x")).await.unwrap();
        assert!(
            face.set_channel(65).is_err(),
            "a tune with no knobs must be an error, never a silent Ok"
        );
        assert!(face.knobs().is_none() && face.capability().is_none());
    }

    // ── E1: frame-free occupancy sensing reaches this bearer ──────────────────────────────

    /// A radio that can sense its channel (`CMD_SENSE` on the 7E-A5 fleet) and counts up
    /// every time it is asked. `read_channel_activity` is the only knob under test.
    #[derive(Default)]
    struct SenseRadio {
        counter: Mutex<u16>,
        /// `false` ⇒ the honest "this radio has no such counter" answer.
        can_sense: bool,
    }

    impl RadioKnobs for SenseRadio {
        fn set_channel(&self, _c: u8, _bw: Bandwidth) -> Result<(), FaceError> {
            Ok(())
        }
        fn read_channel_activity(&self) -> Result<Option<u16>, FaceError> {
            if !self.can_sense {
                return Ok(None); // exactly what a node without CMD_SENSE reports
            }
            let mut c = self.counter.lock().unwrap();
            *c = c.wrapping_add(25); // 25 frames per 100 ms window ⇒ 250 fps ⇒ saturated
            Ok(Some(*c))
        }
    }

    /// **E1** — a LoRa face samples its own channel into the shared sense bus, with no Wi-Fi
    /// type anywhere in the path. Before the move this was impossible without depending on
    /// `ndn-phy-wifi`; the sink here is a bare `Mutex<MediumState>`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_lora_face_samples_occupancy_into_the_shared_sense_bus() {
        let bus_io = LoopbackMonitorBus::new();
        let radio = Arc::new(SenseRadio {
            can_sense: true,
            ..Default::default()
        });
        let face = LoraPhy::new(FaceId(1), Arc::new(bus_io.endpoint(1, -60))).with_knobs(radio);

        let sense: Arc<Mutex<ndn_radio_cognition::MediumState>> =
            Arc::new(Mutex::new(ndn_radio_cognition::MediumState::new()));
        let handle = face
            .start_occupancy_sampling(
                sense.clone(),
                RadioId(0),
                65,
                Duration::from_millis(20),
                || 0,
            )
            .expect("a face with knobs can sample");

        // Two ticks are needed before a rate exists (a rate is a difference of two reads).
        let mut busy = None;
        for _ in 0..100 {
            tokio::time::sleep(Duration::from_millis(20)).await;
            busy = OccupancySink::busy_pct(sense.as_ref(), RadioId(0), 65);
            if busy.is_some() {
                break;
            }
        }
        handle.abort();
        assert!(
            busy.is_some_and(|b| b > 0),
            "the sampled activity rate must reach the sense bus as busy% (got {busy:?})"
        );
    }

    /// A radio that answers `Ok(None)` is polled once and the sampler exits — an incapable
    /// node costs one round-trip, never a permanent task feeding the bus fabricated zeros.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_radio_that_cannot_sense_stops_the_sampler_and_reports_nothing() {
        let bus_io = LoopbackMonitorBus::new();
        let face = LoraPhy::new(FaceId(1), Arc::new(bus_io.endpoint(1, -60)))
            .with_knobs(Arc::new(SenseRadio::default()));
        let sense: Arc<Mutex<ndn_radio_cognition::MediumState>> =
            Arc::new(Mutex::new(ndn_radio_cognition::MediumState::new()));
        let handle = face
            .start_occupancy_sampling(
                sense.clone(),
                RadioId(0),
                65,
                Duration::from_millis(5),
                || 0,
            )
            .unwrap();
        tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .expect("the sampler must exit, not spin")
            .unwrap();
        assert_eq!(
            OccupancySink::busy_pct(sense.as_ref(), RadioId(0), 65),
            None,
            "no counter ⇒ no occupancy claim at all (None, never a plausible 0)"
        );
    }

    /// No knobs ⇒ nothing to poll ⇒ `None`, not a handle to a task that can never sample.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn occupancy_sampling_without_knobs_is_refused_not_faked() {
        let bus_io = LoopbackMonitorBus::new();
        let face = LoraPhy::new(FaceId(1), Arc::new(bus_io.endpoint(1, -60)));
        let sense: Arc<Mutex<ndn_radio_cognition::MediumState>> =
            Arc::new(Mutex::new(ndn_radio_cognition::MediumState::new()));
        assert!(
            face.start_occupancy_sampling(sense, RadioId(0), 65, Duration::from_millis(5), || 0)
                .is_none()
        );
    }

    // ── E1: the modulation is a knob, and only where the radio said so ────────────────────

    /// A capability for an **agile** node: it advertises `modes`, runs `current`, and (when
    /// `hop` is set) has a sequencer of its own.
    fn agile_cap(
        modes: PhyModeSet,
        current: PhyMode,
        hop: Option<HopCapability>,
    ) -> RadioCapability {
        let mut c = lora_cap(200);
        c.phy_modes = modes;
        c.phy_current = Some(current);
        c.hop = hop;
        c
    }

    fn lora_flrc() -> PhyModeSet {
        PhyModeSet::single(PhyMode::Lora).with(PhyMode::Flrc)
    }

    fn plan_with_phy(phy: Option<PhyMode>) -> Arc<RwLock<Option<TxParams>>> {
        Arc::new(RwLock::new(Some(TxParams {
            phy,
            rate: RateParams::Lora(LoraRate {
                spreading_factor: Some(9),
                ..Default::default()
            }),
            ..Default::default()
        })))
    }

    /// **E1** — a decided modulation reaches `RadioKnobs::set_phy`, once, and is not re-pushed
    /// while it is unchanged (a knob is bearer state, and on a serial bridge every push is a
    /// blocking round trip).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_decided_modulation_reaches_the_radio_once() {
        let bus = LoopbackMonitorBus::new();
        let io: Arc<dyn FrameIo> = Arc::new(bus.endpoint(1, -60));
        let spy = SpyRadio::with_cap(agile_cap(lora_flrc(), PhyMode::Lora, None));
        let face = LoraPhy::new(FaceId(1), io)
            .with_knobs(spy.clone())
            .with_profile(spy.clone())
            .with_planned_params(plan_with_phy(Some(PhyMode::Flrc)));

        for _ in 0..4 {
            face.send_bytes(Bytes::from_static(b"x")).await.unwrap();
        }
        assert_eq!(*spy.phy.lock().unwrap(), vec![PhyMode::Flrc], "pushed once");
    }

    /// **The rule.** A mode the radio never advertised is refused *before* it reaches the
    /// hardware — as is a radio that advertised nothing, and one that runs a single modulation
    /// (where modulation is a fact, not a knob). Finding this out on the air, as a dead link, is
    /// the expensive way.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_modulation_the_radio_never_advertised_is_never_commanded() {
        let bus = LoopbackMonitorBus::new();
        for cap in [
            // advertises LoRa + FLRC, asked for BLE
            agile_cap(lora_flrc(), PhyMode::Lora, None),
            // advertises nothing at all
            lora_cap(200),
            // advertises exactly one mode
            agile_cap(PhyModeSet::single(PhyMode::Lora), PhyMode::Lora, None),
        ] {
            let io: Arc<dyn FrameIo> = Arc::new(bus.endpoint(1, -60));
            let spy = SpyRadio::with_cap(cap);
            let face = LoraPhy::new(FaceId(1), io)
                .with_knobs(spy.clone())
                .with_profile(spy.clone())
                .with_planned_params(plan_with_phy(Some(PhyMode::Ble)));
            face.send_bytes(Bytes::from_static(b"x")).await.unwrap();
            assert!(
                spy.phy.lock().unwrap().is_empty(),
                "an unadvertised mode must never be commanded"
            );
        }
    }

    /// **A switch replaces the capability wholesale.** The same silicon in FLRC carries 47 bytes
    /// and has no spreading factor; in LoRa it carries far more and spans SF7..SF12. So after a
    /// successful `set_phy` the face re-reads the profile and the MTU follows — without this it
    /// would keep fragmenting to the OLD payload cap and hand the driver frames it now rejects,
    /// which is invisible loss rather than an error.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_phy_switch_replaces_the_capability_and_the_mtu() {
        let bus = LoopbackMonitorBus::new();
        let io: Arc<dyn FrameIo> = Arc::new(bus.endpoint(1, -60));
        let spy = SpyRadio::with_cap(agile_cap(lora_flrc(), PhyMode::Lora, None));
        // What the node reports once it is in FLRC: a 47-byte frame and no spreading factor.
        let mut flrc = agile_cap(lora_flrc(), PhyMode::Flrc, None);
        flrc.max_payload = 47;
        flrc.rate = RateCapability::None;
        *spy.cap_after_phy.lock().unwrap() = Some(flrc);

        let face = LoraPhy::new(FaceId(1), io)
            .with_knobs(spy.clone())
            .with_profile(spy.clone())
            .with_planned_params(plan_with_phy(Some(PhyMode::Flrc)));
        assert_eq!(face.send_mtu(), Some(200), "the LoRa-mode payload cap");

        face.send_bytes(Bytes::from_static(b"x")).await.unwrap();
        assert_eq!(*spy.phy.lock().unwrap(), vec![PhyMode::Flrc]);
        assert_eq!(
            face.send_mtu(),
            Some(47),
            "the MTU must follow the capability the switch replaced"
        );
        assert_eq!(
            face.capability().map(|c| c.rate),
            Some(RateCapability::None),
            "and so must the rate model — an FLRC node has no spreading factor"
        );
        // Nothing survives a modulation change, so the SF the plan asks for is re-asserted
        // against the new PHY rather than being assumed still set. (It is skipped here because
        // the replacement capability declares no SF span at all — which is the point.)
        assert!(
            spy.sf.lock().unwrap().len() <= 1,
            "SF must not be pushed at a radio that no longer has one"
        );
    }

    /// A chip that refuses a mode its node advertises is asked **once**, and the refusal is
    /// latched against THAT MODE — not against the axis. A bare boolean here would take
    /// modulation out of service for the rest of the face's life after one unreachable mode;
    /// re-asking every frame would buy a blocking serial round trip for an answer that cannot
    /// change.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_refused_mode_is_asked_once_and_does_not_disable_the_axis() {
        let bus = LoopbackMonitorBus::new();
        let io: Arc<dyn FrameIo> = Arc::new(bus.endpoint(1, -60));
        let modes = lora_flrc().with(PhyMode::Fsk);
        let spy = SpyRadio::with_cap(agile_cap(modes, PhyMode::Lora, None));
        *spy.refuse_phy.lock().unwrap() = Some(PhyMode::Flrc);

        let plan = plan_with_phy(Some(PhyMode::Flrc));
        let face = LoraPhy::new(FaceId(1), io)
            .with_knobs(spy.clone())
            .with_profile(spy.clone())
            .with_planned_params(plan.clone());
        for _ in 0..5 {
            face.send_bytes(Bytes::from_static(b"x")).await.unwrap();
        }
        assert_eq!(
            *spy.phy.lock().unwrap(),
            vec![PhyMode::Flrc],
            "a refusal must be latched, not re-bought every frame"
        );

        // A DIFFERENT advertised mode is still reachable.
        *plan.write().unwrap() = Some(TxParams {
            phy: Some(PhyMode::Fsk),
            ..Default::default()
        });
        face.send_bytes(Bytes::from_static(b"x")).await.unwrap();
        assert_eq!(
            *spy.phy.lock().unwrap(),
            vec![PhyMode::Flrc, PhyMode::Fsk],
            "one unreachable mode must not disable the whole axis"
        );
    }

    // ── E2: the name-keyed hop plan reaches the radio's sequencer ─────────────────────────

    fn hop_cap() -> HopCapability {
        HopCapability {
            intra_packet: true,
            max_list_len: 40,
            period_unit: HopPeriodUnit::LoraSymbols,
        }
    }

    /// **E2** — a name's hop plan is derived under the shared #44 key and written to the radio's
    /// own sequencer, armed, truncated to what that sequencer accepts.
    #[test]
    fn a_name_keyed_hop_plan_reaches_the_sequencer() {
        let bus = LoopbackMonitorBus::new();
        let io: Arc<dyn FrameIo> = Arc::new(bus.endpoint(1, -60));
        let spy = SpyRadio::with_cap(agile_cap(lora_flrc(), PhyMode::Lora, Some(hop_cap())));
        let face = LoraPhy::new(FaceId(1), io)
            .with_knobs(spy.clone())
            .with_profile(spy.clone());

        let key = *b"ndn/wl-lora-key1";
        let carriers = carrier_grid(902_000_000, 928_000_000, 1_000_000);
        let plan = face
            .install_name_hop_plan(&key, b"/ndn/wl/svc", &carriers, 12)
            .expect("a radio with a sequencer installs a plan");

        let installed = spy.hops.lock().unwrap().clone();
        assert_eq!(installed.len(), 1);
        let (ctrl, period, freqs) = &installed[0];
        assert_eq!(
            *ctrl,
            HopControl::On,
            "the plan must be armed, not just loaded"
        );
        assert_eq!(*period, 12);
        assert_eq!(freqs, plan.freqs_hz());
        assert_eq!(
            freqs.len(),
            27,
            "the whole declared band plan fits in 40 slots"
        );
        for f in freqs {
            assert!(carriers.contains(f), "invented carrier {f}");
        }
        // ★ The property both ends depend on: the peer derives the same list from the same name
        // and key, with nothing negotiated on air.
        assert_eq!(
            plan.freqs_hz(),
            name_hop_plan(&key, b"/ndn/wl/svc", &carriers, 12, 40).freqs_hz(),
            "the peer must derive a byte-identical list"
        );

        face.clear_hop_plan().unwrap();
        assert_eq!(spy.hops.lock().unwrap()[1].0, HopControl::Off);
    }

    /// A radio with no sequencer ERRORS rather than reporting a plan it never installed — a
    /// silent success would leave a planner believing a name's frames are spread across a band
    /// they never left, which is exactly the co-band problem hopping exists to fix.
    #[test]
    fn a_radio_with_no_sequencer_refuses_a_hop_plan() {
        let bus = LoopbackMonitorBus::new();
        let io: Arc<dyn FrameIo> = Arc::new(bus.endpoint(1, -60));
        let spy = SpyRadio::with_cap(agile_cap(lora_flrc(), PhyMode::Lora, None));
        let face = LoraPhy::new(FaceId(1), io)
            .with_knobs(spy.clone())
            .with_profile(spy.clone());
        let carriers = carrier_grid(902_000_000, 928_000_000, 1_000_000);
        assert!(
            face.install_name_hop_plan(b"0123456789abcdef", b"/a", &carriers, 8)
                .is_err()
        );
        assert!(spy.hops.lock().unwrap().is_empty());

        // …and so does a face with no knobs at all, and one handed no carriers.
        let bare = LoraPhy::new(FaceId(2), Arc::new(bus.endpoint(2, -60)));
        assert!(
            bare.install_name_hop_plan(b"0123456789abcdef", b"/a", &carriers, 8)
                .is_err()
        );
        let spy2 = SpyRadio::with_cap(agile_cap(lora_flrc(), PhyMode::Lora, Some(hop_cap())));
        let face2 = LoraPhy::new(FaceId(3), Arc::new(bus.endpoint(3, -60)))
            .with_knobs(spy2.clone())
            .with_profile(spy2.clone());
        assert!(
            face2
                .install_name_hop_plan(b"0123456789abcdef", b"/a", &[], 8)
                .is_err(),
            "no carriers declared is not a plan"
        );
    }

    /// A shorter sequencer gets a PREFIX of the same derived sequence, so two nodes that agree
    /// on the length still agree on the hops.
    #[test]
    fn a_short_sequencer_gets_a_prefix_of_the_same_sequence() {
        let bus = LoopbackMonitorBus::new();
        let mut hop = hop_cap();
        hop.max_list_len = 8;
        let spy = SpyRadio::with_cap(agile_cap(lora_flrc(), PhyMode::Lora, Some(hop)));
        let face = LoraPhy::new(FaceId(1), Arc::new(bus.endpoint(1, -60)))
            .with_knobs(spy.clone())
            .with_profile(spy.clone());
        let key = *b"ndn/wl-lora-key1";
        let carriers = carrier_grid(902_000_000, 928_000_000, 1_000_000);
        let short = face
            .install_name_hop_plan(&key, b"/ndn/wl/svc", &carriers, 12)
            .unwrap();
        assert_eq!(short.len(), 8);
        let full = name_hop_plan(&key, b"/ndn/wl/svc", &carriers, 12, 40);
        assert_eq!(short.freqs_hz(), &full.freqs_hz()[..8]);
    }

    // ── E3: a slot-scheduled send reaches the hardware scheduler ──────────────────────────

    /// Which injection seam a frame actually left through.
    #[derive(Debug, PartialEq, Eq)]
    enum Sent {
        Now,
        After(u64),
        AtClock(u64, u32),
    }

    /// A radio whose scheduling *seam* and declared *discipline* are set independently — the
    /// two are separate on real hardware, and the gap is the bug this dispatch guards against.
    struct SchedRadio {
        seam: bool,
        discipline: TxDiscipline,
        sent: Mutex<Vec<Sent>>,
        /// The clock this radio owns, if any — an absolute instant may only be named in it.
        clock: Option<(ClockDomainId, u64)>,
    }

    const SCHED_DOMAIN: ClockDomainId = ClockDomainId(9);

    impl SchedRadio {
        /// A radio that owns [`SCHED_DOMAIN`], reading `now` ticks (1 µs each).
        fn new(seam: bool, discipline: TxDiscipline) -> Arc<Self> {
            Arc::new(Self {
                seam,
                discipline,
                sent: Mutex::new(Vec::new()),
                clock: Some((SCHED_DOMAIN, 0)),
            })
        }
        /// A radio with a clock of its own at `now`, for the software-gate path.
        fn with_clock(seam: bool, discipline: TxDiscipline, now: u64) -> Arc<Self> {
            Arc::new(Self {
                seam,
                discipline,
                sent: Mutex::new(Vec::new()),
                clock: Some((SCHED_DOMAIN, now)),
            })
        }
        /// A radio that exposes no readable clock at all.
        fn clockless(seam: bool, discipline: TxDiscipline) -> Arc<Self> {
            Arc::new(Self {
                seam,
                discipline,
                sent: Mutex::new(Vec::new()),
                clock: None,
            })
        }
    }

    impl RadioTime for SchedRadio {
        fn time_sources(&self) -> Vec<RadioTimeSource> {
            self.clock
                .iter()
                .map(|(d, _)| RadioTimeSource {
                    kind: ndn_radio_hal::RadioClockKind::FreeRunRxStamp,
                    domain: *d,
                    latch: ndn_radio_hal::LatchPoint::MacDone,
                    precision_ns: 1_000,
                    tick_ns: 1_000,
                    monotonic: true,
                    read_now: true,
                    // A scheduling fixture, not a radio: these tests exercise `tx_clock_domain`
                    // and the absolute-TX gate, which key on `read_now`/`monotonic` and never on
                    // the reference. `unknown()` keeps the fixture from asserting a fact it has no
                    // business having.
                    reference: ndn_radio_hal::ClockReference::unknown(),
                })
                .collect()
        }
        fn read_clock(&self, domain: ClockDomainId) -> Result<Option<u64>, FaceError> {
            Ok(self.clock.filter(|(d, _)| *d == domain).map(|(_, now)| now))
        }
    }

    #[async_trait::async_trait]
    impl FrameIo for SchedRadio {
        async fn inject(&self, _f: InjectFrame) -> Result<(), FaceError> {
            self.sent.lock().unwrap().push(Sent::Now);
            Ok(())
        }
        async fn inject_after(&self, _f: InjectFrame, delay_us: u64) -> Result<(), FaceError> {
            self.sent.lock().unwrap().push(Sent::After(delay_us));
            Ok(())
        }
        async fn inject_at_clock(
            &self,
            _f: InjectFrame,
            target_tick: u64,
            domain: ClockDomainId,
        ) -> Result<(), FaceError> {
            self.sent
                .lock()
                .unwrap()
                .push(Sent::AtClock(target_tick, domain.0));
            Ok(())
        }
        fn schedules_tx(&self) -> bool {
            self.seam
        }
        async fn recv_frame(&self) -> Result<ndn_radio_hal::CapturedFrame, FaceError> {
            std::future::pending().await
        }
    }

    impl RadioKnobs for SchedRadio {
        fn set_channel(&self, _c: u8, _bw: Bandwidth) -> Result<(), FaceError> {
            Ok(())
        }
        fn tx_discipline(&self) -> TxDiscipline {
            self.discipline
        }
    }

    const SCHEDULED: TxDiscipline = TxDiscipline::ScheduledAt {
        granularity_ns: 1_000,
    };

    /// **E3** — on a radio that really schedules (seam + declared discipline), a slot-gated
    /// send goes out through `inject_after` with the delay intact, and the host does **not**
    /// sleep: the MCU places the frame. This is the path that was unreachable from the face.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_scheduling_radio_places_the_frame_in_hardware() {
        let r = SchedRadio::new(true, SCHEDULED);
        let face = LoraPhy::new(FaceId(1), r.clone())
            .with_knobs(r.clone())
            .with_slot_gate(|_| Some(SlotTiming::After { delay_us: 750_000 }));
        assert!(face.schedules_tx_in_hardware());

        let t0 = std::time::Instant::now();
        face.send_bytes(Bytes::from_static(b"slot")).await.unwrap();
        assert_eq!(*r.sent.lock().unwrap(), vec![Sent::After(750_000)]);
        assert!(
            t0.elapsed() < Duration::from_millis(300),
            "the host must not sleep out a delay the hardware is placing"
        );
    }

    /// An absolute instant reaches `inject_at_clock` with its domain intact.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_absolute_slot_reaches_inject_at_clock() {
        let r = SchedRadio::new(true, SCHEDULED);
        let face = LoraPhy::new(FaceId(1), r.clone())
            .with_knobs(r.clone())
            .with_time(r.clone())
            .with_slot_gate(|_| {
                Some(SlotTiming::AtClock {
                    tick: 0xDEAD_BEEF,
                    domain: SCHED_DOMAIN,
                })
            });
        assert_eq!(face.tx_clock_domain(), Some(SCHED_DOMAIN));
        face.send_bytes(Bytes::from_static(b"slot")).await.unwrap();
        assert_eq!(*r.sent.lock().unwrap(), vec![Sent::AtClock(0xDEAD_BEEF, 9)]);
    }

    /// **The domain belongs to the BACKEND to check.** `inject_at_clock` takes a tick in a named
    /// domain, and only the backend knows which counter is its own — the LoRa family's compares
    /// against its device domain and falls back to plain injection for a foreign tick. It also
    /// schedules against counters it deliberately does not advertise as *link clocks* (the
    /// Waveshare's firmware software counter is readable and schedulable but is not a common-view
    /// source), so a face that re-decided this from `time_sources()` would refuse radios that
    /// work. The domain is therefore passed through intact rather than vetted here.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_scheduling_radio_is_handed_the_domain_intact() {
        let r = SchedRadio::new(true, SCHEDULED);
        let face = LoraPhy::new(FaceId(1), r.clone())
            .with_knobs(r.clone())
            .with_time(r.clone())
            .with_slot_gate(|_| {
                Some(SlotTiming::AtClock {
                    tick: 1_000,
                    domain: ClockDomainId(77), // a domain this face never advertised
                })
            });
        face.send_bytes(Bytes::from_static(b"slot")).await.unwrap();
        assert_eq!(*r.sent.lock().unwrap(), vec![Sent::AtClock(1_000, 77)]);
    }

    /// A **non-scheduling** radio handed an instant in a domain it does not describe still errors:
    /// nothing here can honour it, and transmitting now would silently discard the discipline the
    /// caller asked for.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_non_scheduling_radio_refuses_an_undescribed_domain() {
        let r = SchedRadio::with_clock(false, TxDiscipline::BestEffort, 1_000);
        let face = LoraPhy::new(FaceId(1), r.clone())
            .with_knobs(r.clone())
            .with_time(r.clone())
            .with_slot_gate(|_| {
                Some(SlotTiming::AtClock {
                    tick: 9_000,
                    domain: ClockDomainId(77), // the OTHER dongle's counter
                })
            });
        assert!(face.send_bytes(Bytes::from_static(b"slot")).await.is_err());
        assert!(
            r.sent.lock().unwrap().is_empty(),
            "nothing may go on air on a discipline nobody can honour"
        );
    }

    /// **E3, the software gate for an absolute instant.** A radio that cannot place the frame
    /// but CAN be read in that domain is still honoured: the host asks what time it is *there*
    /// and sleeps the difference. Coarse (a clock round trip plus the sleep's own jitter), but
    /// real — and strictly better than the error this used to be.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_absolute_slot_falls_back_to_the_software_gate_when_the_clock_is_readable() {
        // No seam: the radio cannot schedule. Its clock reads 1_000_000 ticks (1 µs each), and
        // the slot is 120 ms later.
        let r = SchedRadio::with_clock(false, TxDiscipline::BestEffort, 1_000_000);
        let face = LoraPhy::new(FaceId(1), r.clone())
            .with_knobs(r.clone())
            .with_time(r.clone())
            .with_slot_gate(|_| {
                Some(SlotTiming::AtClock {
                    tick: 1_120_000,
                    domain: SCHED_DOMAIN,
                })
            });
        assert!(!face.schedules_tx_in_hardware());
        let t0 = std::time::Instant::now();
        face.send_bytes(Bytes::from_static(b"slot")).await.unwrap();
        assert_eq!(*r.sent.lock().unwrap(), vec![Sent::Now]);
        assert!(
            t0.elapsed() >= Duration::from_millis(90),
            "the host must wait out the instant on the radio's own clock"
        );
    }

    /// A deadline already in the past transmits now — a software gate cannot un-miss a slot it
    /// is already inside, and pretending otherwise would stall the face forever.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_absolute_slot_already_past_transmits_now() {
        let r = SchedRadio::with_clock(false, TxDiscipline::BestEffort, 5_000_000);
        let face = LoraPhy::new(FaceId(1), r.clone())
            .with_knobs(r.clone())
            .with_time(r.clone())
            .with_slot_gate(|_| {
                Some(SlotTiming::AtClock {
                    tick: 1_000,
                    domain: SCHED_DOMAIN,
                })
            });
        let t0 = std::time::Instant::now();
        face.send_bytes(Bytes::from_static(b"slot")).await.unwrap();
        assert_eq!(*r.sent.lock().unwrap(), vec![Sent::Now]);
        assert!(t0.elapsed() < Duration::from_millis(200));
    }

    /// A radio with no readable clock at all keeps the old behaviour: an absolute instant is an
    /// error, because nothing here can honour it.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_absolute_slot_on_a_clockless_radio_still_errors() {
        let r = SchedRadio::clockless(false, TxDiscipline::BestEffort);
        let face = LoraPhy::new(FaceId(1), r.clone())
            .with_knobs(r.clone())
            .with_time(r.clone())
            .with_slot_gate(|_| {
                Some(SlotTiming::AtClock {
                    tick: 1_000,
                    domain: SCHED_DOMAIN,
                })
            });
        assert_eq!(face.tx_clock_domain(), None);
        assert!(face.send_bytes(Bytes::from_static(b"slot")).await.is_err());
        assert!(r.sent.lock().unwrap().is_empty());
    }

    /// **The trap this dispatch exists to avoid.** A backend may declare `ScheduledAt` and not
    /// implement the seam (measured live on Wi-Fi: the AR9271). Believing the label would skip
    /// the software gate AND drop the delay — the frame leaves immediately, ungated. So the
    /// seam is required, and this radio software-gates: the delay is really waited out, then a
    /// plain `inject`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_declared_discipline_without_the_seam_still_software_gates() {
        let r = SchedRadio::new(false, SCHEDULED); // says ScheduledAt, implements nothing
        let face = LoraPhy::new(FaceId(1), r.clone())
            .with_knobs(r.clone())
            .with_slot_gate(|_| Some(SlotTiming::After { delay_us: 120_000 }));
        assert!(
            !face.schedules_tx_in_hardware(),
            "the label is not the seam"
        );

        let t0 = std::time::Instant::now();
        face.send_bytes(Bytes::from_static(b"slot")).await.unwrap();
        assert_eq!(*r.sent.lock().unwrap(), vec![Sent::Now]);
        assert!(
            t0.elapsed() >= Duration::from_millis(90),
            "the host must actually wait out the slot when the radio will not"
        );
    }

    /// A best-effort radio (the Waveshare SX1262 today) keeps the software gate — same lease
    /// decision, enforced by the host.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_best_effort_radio_keeps_the_software_gate() {
        let r = SchedRadio::new(false, TxDiscipline::BestEffort);
        let face = LoraPhy::new(FaceId(1), r.clone())
            .with_knobs(r.clone())
            .with_slot_gate(|_| Some(SlotTiming::After { delay_us: 0 }));
        face.send_bytes(Bytes::from_static(b"slot")).await.unwrap();
        assert_eq!(*r.sent.lock().unwrap(), vec![Sent::Now]);
    }

    /// An absolute device-clock instant on a radio that cannot schedule must ERROR: the host
    /// holds no mapping into that domain, and transmitting now would silently discard the
    /// discipline. A knob the hardware cannot do fails loudly.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_absolute_slot_on_an_unscheduled_radio_errors_instead_of_transmitting_now() {
        let r = SchedRadio::new(false, TxDiscipline::BestEffort);
        let face = LoraPhy::new(FaceId(1), r.clone())
            .with_knobs(r.clone())
            .with_slot_gate(|_| {
                Some(SlotTiming::AtClock {
                    tick: 42,
                    domain: ClockDomainId(1),
                })
            });
        assert!(face.send_bytes(Bytes::from_static(b"slot")).await.is_err());
        assert!(
            r.sent.lock().unwrap().is_empty(),
            "nothing may go on air when the requested discipline is unreachable"
        );
    }

    /// **Default behaviour is untouched.** No gate installed, or a gate that declines to
    /// schedule this wire (a control frame, no name-group), is a plain `inject` on call — on a
    /// scheduling radio too, so installing hardware never changes ungated traffic.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_ungated_send_is_a_plain_inject_on_every_radio() {
        for seam in [false, true] {
            let r = SchedRadio::new(seam, SCHEDULED);
            let none = LoraPhy::new(FaceId(1), r.clone()).with_knobs(r.clone());
            none.send_bytes(Bytes::from_static(b"a")).await.unwrap();

            let declines = LoraPhy::new(FaceId(2), r.clone())
                .with_knobs(r.clone())
                .with_slot_gate(|_| None);
            declines.send_bytes(Bytes::from_static(b"b")).await.unwrap();

            assert_eq!(*r.sent.lock().unwrap(), vec![Sent::Now, Sent::Now]);
        }
    }
}
