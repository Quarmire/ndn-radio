//! Connectionless **LoRa-family** face for ndn-rs — a named-radio bearer over any
//! [`FrameIo`] sub-GHz radio (the serial-bridged SX126x `LoraSerialBackend`, the
//! nRF54L15+LR2021 FLRC bridge, a Heltec SX1276), with **plan-driven link FEC**.
//!
//! Sub-GHz is the bearer where redundancy matters *most*: half-duplex, no ARQ, and
//! airtime measured in the hundreds of milliseconds per frame, so a lost frame is
//! expensive to notice and expensive to re-request. Its rate knobs are *bearer
//! state*, not per-frame arguments — spreading factor / coding rate / bandwidth are
//! set out-of-band through [`RadioKnobs`](ndn_radio_hal::RadioKnobs) — which makes
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
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use bytes::Bytes;
use ndn_coding::link_fec_bridge::{GenerationSink, LinkFecBridge};
pub use ndn_radio_cognition::TxParams;
use ndn_radio_cognition::gcs::{BODY_PREFIX_TLV, GCS_MAX_BYTES, GcsFilter};
use ndn_radio_cognition::name::{inner_name, ndn_name_to_slash};
use ndn_radio_hal::{
    Bandwidth, FaceError, FrameIo, InjectFrame, RadioKnobs, RadioProfile, RadioTime,
    RateCapability, TxIntent,
};
pub use ndn_radio_hal::{OpenRadio, RadioCapability};
use ndn_transport::{
    Face, FaceAddr, FaceId, FaceKind, FacePersistency, LinkType, MtuError, PersistencyError,
    Transport,
};

/// The plan types this face's public API speaks. Re-exported so a wiring site can build a
/// [`TxParams`] cell for [`with_planned_params`](LoraPhy::with_planned_params) without taking a
/// direct dependency on the cognition crate (which depends, in turn, on `ndn-radio` — the wiring
/// site is usually inside it).
pub use ndn_radio_cognition::{LoraRate, RateParams};

/// The face's own **frame-payload ceiling** — the most this bearer will ever put in one
/// frame, whatever a radio declares.
///
/// It is a ceiling, not the MTU: the MTU is
/// `min(LORA_MTU, capability().max_payload) - gcs headroom` (see
/// [`LoraPhy::send_mtu`]). Deliberately conservative — a serial-bridged sub-GHz
/// radio caps a frame well under 255 B and the driver rejects an oversize `inject`,
/// while the `RadioCapability::lora` preset optimistically declares 256. Taking the
/// **min** means a radio that knows its real cap is smaller (an FLRC node, or a
/// firmware that truncates RX) is respected, and one that over-declares cannot push
/// us past a budget measured on the wire.
pub const LORA_MTU: usize = 200;

/// Bytes the body-prefix GCS TLV puts *in front of* the packet (`[type][len][gcs]`).
/// Reserved out of the MTU whenever [`with_gcs`](LoraPhy::with_gcs) is on, so a
/// full-MTU LP fragment plus its filter still fits one frame — without this the
/// largest fragments would be built to the un-reserved MTU and then rejected by the
/// driver as oversize, which is invisible loss rather than an error.
const GCS_HEADROOM: usize = 2 + GCS_MAX_BYTES;

/// Source frames per FEC generation (K). Deliberately small for sub-GHz: at high
/// spreading factors one frame is hundreds of ms of airtime, so a large K would
/// make a generation span many seconds and stall everything behind it. K=2 keeps
/// the generation short while still letting one lost frame be recovered (with R≥1).
const LORA_FEC_K: usize = 2;

/// How long a partial generation waits before a tail-flush. Generous for sub-GHz —
/// a frame can take ~1 s at SF12, so a tight window would flush half-empty
/// generations constantly. The face's caller can override via [`with_link_fec`].
const LORA_FEC_WINDOW: Duration = Duration::from_secs(3);

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
                    addr4: None,
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

/// Config for the in-frame **body-prefix GCS** filter — the `FLAG_BODY_PREFIX` tier of the shared
/// named-radio name-filter cascade (`wire-format-spec.md` §2a). The cascade places the prefix-set
/// filter wherever a bearer has room: an **address-field** bearer packs a random-access Bloom into
/// its address bytes; a **body-field** bearer with no address fields (LoRa, FLRC) carries a
/// sequential-decode GCS in the frame body as a self-signaling TLV (`[BODY_PREFIX_TLV][len][gcs]`)
/// prepended to the first LP fragment. Same #44 keyspace and zero-false-negative guarantee across
/// both — only the encoding differs, chosen by what the bearer affords.
///
/// `key` is the shared SipHash key; `prefixes` are the `/`-joined names this face serves. The RX
/// gate drops an incoming frame **only** when its GCS admits *none* of these — a `false` from
/// [`GcsFilter::may_match`] is exact (zero false negatives), so a wanted frame is never dropped.
pub struct GcsCfg {
    /// Shared filter key (same keyspace as the Wi-Fi Blur and the receiver's BF-FIB).
    pub key: [u8; 16],
    /// `/`-joined prefixes this face serves; empty ⇒ the gate keeps everything (filter-off).
    pub prefixes: Vec<Vec<u8>>,
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
    /// The capability read from `profile` **once**, at construction: `send_mtu` and the
    /// per-frame actuator both consult it, and a per-send `capability()` call would be a
    /// lock (or a device round-trip) on the hot path. Re-read by rebuilding the face.
    cap: Option<RadioCapability>,
    /// Derived from `cap` + the GCS headroom — see [`LORA_MTU`].
    mtu: usize,
    egress: Egress,
    /// Recovered payloads awaiting `recv_bytes` (FEC decode can yield 0/1/many).
    pending: Mutex<VecDeque<Bytes>>,
    /// Control-plane [`TxParams`] cell — written by the cognitive actuator, read per send.
    /// `link_fec_redundancy` drives the FEC bridge; the LoRa `rate` block and the power
    /// fields drive [`RadioKnobs`] when one is attached.
    planned: Option<Arc<RwLock<Option<TxParams>>>>,
    /// In-frame body-prefix GCS (`FLAG_BODY_PREFIX`). `None` ⇒ no filter framing on this bearer.
    /// Applies to the plain (`Egress::Direct`) path only — a FEC generation's coded frames carry
    /// no parseable name, so there is nothing to filter on before decode.
    gcs: Option<GcsCfg>,
    /// Last values pushed through `knobs`, so an unchanged plan costs nothing.
    applied: Mutex<AppliedRate>,
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
            cap: None,
            mtu: LORA_MTU,
            egress: Egress::Direct,
            pending: Mutex::new(VecDeque::new()),
            planned: None,
            gcs: None,
            applied: Mutex::new(AppliedRate::default()),
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
            me.cap = Some(p.capability());
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
        self.cap = Some(profile.capability());
        self.profile = Some(profile);
        self.recompute_mtu();
        self
    }

    /// The control seam, for a caller wiring something this face does not do itself — a
    /// frame-free occupancy sampler (`read_channel_activity`), a channel plan, a Tier-0
    /// on-device name filter. `None` when the radio has no reachable knobs.
    pub fn knobs(&self) -> Option<Arc<dyn RadioKnobs>> {
        self.knobs.clone()
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
        self.cap.clone()
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
    fn recompute_mtu(&mut self) {
        let declared = self.cap.as_ref().map_or(LORA_MTU, |c| c.max_payload);
        let head = if self.gcs.is_some() { GCS_HEADROOM } else { 0 };
        self.mtu = LORA_MTU.min(declared).saturating_sub(head).max(1);
    }

    /// Enable **plan-driven link FEC**: source frames batch into generations of `k`
    /// (or [`LORA_FEC_K`]), transmitted as `k + R` coded frames where `R` is the
    /// plan's [`link_fec_redundancy`], recoverable from any `k` of the `n`. `window`
    /// bounds a partial generation's tail-flush (default [`LORA_FEC_WINDOW`]).
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

    /// Enable the in-frame **body-prefix GCS** filter (`FLAG_BODY_PREFIX`). On TX, the first LP
    /// fragment's name is compiled into a GCS and prepended as a self-signaling TLV; on RX, a frame
    /// carrying one is dropped iff its filter admits *none* of `prefixes` (exact — zero false
    /// negatives). `key` is the shared #44 SipHash key. Applies to the plain (`Egress::Direct`)
    /// path only — see [`GcsCfg`].
    ///
    /// Lowers the MTU by the filter's worst-case width so a full fragment plus its TLV
    /// still fits one frame.
    pub fn with_gcs(mut self, key: [u8; 16], prefixes: Vec<Vec<u8>>) -> Self {
        self.gcs = Some(GcsCfg { key, prefixes });
        self.recompute_mtu();
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
        match self.cap.as_ref().map(|c| c.rate) {
            None => SfPolicy::Unknown,
            Some(RateCapability::Lora { min_sf, max_sf }) => SfPolicy::Span(min_sf, max_sf),
            Some(_) => SfPolicy::NotLora,
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
                .cap
                .as_ref()
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
            match knobs.set_tx_power(idx as u32) {
                Ok(()) => cur.power_idx = Some(idx),
                Err(e) => {
                    cur.refused.power_idx = is_unsupported(&e);
                    tracing::warn!(target: "named_radio", face = self.id.0, idx, error = %e, "lora set_tx_power failed")
                }
            }
        }

        // Listen-before-talk: on this bearer `edcca_ignore` maps to the firmware LBT toggle.
        if cur.edcca_ignore != Some(tp.edcca_ignore) && !cur.refused.edcca {
            match knobs.set_edcca_ignore(tp.edcca_ignore) {
                Ok(()) => cur.edcca_ignore = Some(tp.edcca_ignore),
                Err(e) => {
                    cur.refused.edcca = is_unsupported(&e);
                    tracing::warn!(target: "named_radio", face = self.id.0, error = %e, "lora set_edcca_ignore failed")
                }
            }
        }
    }

    /// TX: if a GCS is configured and `wire` is a first fragment carrying a name, prepend the
    /// self-signaling `[BODY_PREFIX_TLV][len][gcs]` header; otherwise pass the wire through
    /// untouched (a continuation fragment or nameless frame carries no filter — and must not, or a
    /// receiver would gate it against a filter it can't recompute).
    fn body_prefix_prepend(&self, wire: Bytes) -> Bytes {
        let Some(cfg) = self.gcs.as_ref() else {
            return wire;
        };
        let Some(name_tlv) = inner_name(&wire) else {
            return wire;
        };
        let name = ndn_name_to_slash(name_tlv);
        let filter = GcsFilter::from_name(&cfg.key, &name);
        let mut gcs = [0u8; GCS_MAX_BYTES + 1];
        let n = filter.to_wire(&mut gcs);
        let mut out = Vec::with_capacity(2 + n + wire.len());
        out.push(BODY_PREFIX_TLV);
        out.push(n as u8);
        out.extend_from_slice(&gcs[..n]);
        out.extend_from_slice(&wire);
        Bytes::from(out)
    }

    /// RX: the body-prefix gate. Returns `Some(inner)` to deliver (TLV stripped if present), `None`
    /// to drop. Fail-open at every ambiguity — no GCS configured, no TLV on the frame, or a
    /// malformed TLV header all deliver the frame unchanged; a frame is dropped **only** on a
    /// well-formed filter that provably admits none of the registered prefixes, so a parse slip can
    /// never manufacture a false negative (the forbidden failure).
    fn body_prefix_gate(&self, payload: Bytes) -> Option<Bytes> {
        let Some(cfg) = self.gcs.as_ref() else {
            return Some(payload);
        };
        if payload.first() != Some(&BODY_PREFIX_TLV) {
            return Some(payload); // no filter on this frame — keep it
        }
        // Parse [type][len][gcs]; on any malformed header, fail OPEN (keep the frame).
        let parsed = (|| {
            let len = *payload.get(1)? as usize;
            let gcs = payload.get(2..2 + len)?;
            Some((GcsFilter::from_wire(gcs), 2 + len))
        })();
        let Some((filter, off)) = parsed else {
            return Some(payload);
        };
        if cfg.prefixes.is_empty() || cfg.prefixes.iter().any(|p| filter.may_match(&cfg.key, p)) {
            Some(payload.slice(off..))
        } else {
            None // provably none of our prefixes — safe to drop
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
        Some(self.mtu)
    }

    async fn send_bytes(&self, wire: Bytes) -> Result<(), FaceError> {
        // ACT before the frame leaves: rate/power are bearer state, so the knob must be
        // set for the frame that follows it.
        self.actuate_planned();
        match &self.egress {
            Egress::Direct => {
                self.radio
                    .inject(InjectFrame {
                        payload: self.body_prefix_prepend(wire),
                        tx: TxIntent::CONSERVATIVE,
                        dst: [0xff; 6],
                        src: [0x02, b'l', b'o', b'r', b'a', 0x00],
                        addr3: None,
                        addr4: None,
                        htc: None,
                    })
                    .await
            }
            // The plan's redundancy rides in with the frame (same pattern as the
            // Wi-Fi face's MCS): the bridge applies it at the next generation
            // boundary, because R is a whole-generation property.
            Egress::Fec(bridge) => bridge.send(wire, (), self.planned_redundancy()),
        }
    }

    async fn recv_bytes(&self) -> Result<Bytes, FaceError> {
        self.recv_bytes_with_addr().await.map(|(b, _)| b)
    }

    async fn recv_bytes_with_addr(&self) -> Result<(Bytes, Option<FaceAddr>), FaceError> {
        match &self.egress {
            // Read until a frame passes the body-prefix gate. A frame provably not under any
            // registered prefix is dropped here (before the engine sees it); a frame with no filter
            // TLV, or one that may match, is delivered with its TLV stripped.
            Egress::Direct => loop {
                let cf = self.radio.recv_frame().await?;
                let addr = cf.addr;
                if let Some(inner) = self.body_prefix_gate(cf.payload) {
                    return Ok((inner, addr.map(FaceAddr::Ether)));
                }
            },
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
    use ndn_radio_hal::{Band, CsiSupport, DbmRange, RadioKind};
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

    /// The body-prefix GCS gate (`FLAG_BODY_PREFIX`): TX prepends the self-signaling TLV; RX keeps a
    /// frame whose filter admits a registered prefix (zero-FN ⇒ a true prefix always matches),
    /// drops one that admits none, and strips the TLV on delivery. A frame with no TLV is never
    /// dropped (fail-open). Proves the filter derives the name through the shared cognition
    /// primitive and agrees with the address-Blur keyspace (#44) without re-registration.
    #[test]
    fn body_prefix_gcs_gates_by_registered_prefix() {
        // A bare Interest wire `0x05 { 0x07 { 0x08 comp … } }` for name `/a/b/c`; `inner_name` uses a
        // headerless packet as-is, so no LP framing is needed to exercise the name path.
        let key = *b"ndn/gcs-test-key";
        let bus = LoopbackMonitorBus::new();
        let radio = Arc::new(bus.endpoint(1, -60));

        let wire = interest(&["a", "b", "c"]); // name /a/b/c
        let sender = LoraPhy::new(FaceId(1), radio.clone()).with_gcs(key, vec![]);
        let framed = sender.body_prefix_prepend(wire.clone());
        assert_eq!(
            framed.first(),
            Some(&BODY_PREFIX_TLV),
            "TX prepends the body-prefix TLV"
        );
        assert!(
            framed.len() > wire.len(),
            "the filter adds bytes ahead of the packet"
        );

        // A receiver serving /a/b keeps it (true prefix ⇒ match) and gets the packet TLV-stripped.
        let keep = LoraPhy::new(FaceId(2), radio.clone()).with_gcs(key, vec![b"/a/b".to_vec()]);
        assert_eq!(
            keep.body_prefix_gate(framed.clone()),
            Some(wire.clone()),
            "a registered true prefix passes the gate; the TLV is stripped back to the packet"
        );

        // A receiver serving only /z/y drops it (provably not under any registered prefix).
        let reject = LoraPhy::new(FaceId(3), radio.clone()).with_gcs(key, vec![b"/z/y".to_vec()]);
        assert!(
            reject.body_prefix_gate(framed).is_none(),
            "no registered prefix can be under the carried name — the frame is dropped"
        );

        // A frame WITHOUT the TLV is always delivered (an un-filtered sender), never dropped.
        assert_eq!(
            keep.body_prefix_gate(wire.clone()),
            Some(wire),
            "a frame carrying no body-prefix TLV is never dropped (fail-open)"
        );
    }

    /// A bare Interest wire for `comps` — no LP framing needed to exercise the name path.
    fn interest(comps: &[&str]) -> Bytes {
        let mut name = Vec::new();
        for c in comps {
            name.push(0x08u8);
            name.push(c.len() as u8);
            name.extend_from_slice(c.as_bytes());
        }
        let mut nt = vec![0x07u8, name.len() as u8];
        nt.extend_from_slice(&name);
        let mut it = vec![0x05u8, nt.len() as u8];
        it.extend_from_slice(&nt);
        Bytes::from(it)
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
            tx_power_dbm: Some(DbmRange::new(10, 22)),
            retune_us: None,
            rx_only: false,
            duty_cycle_max: 0.01,
            max_payload,
            half_duplex: true,
            csi: CsiSupport::None,
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

        let filtered = LoraPhy::new(FaceId(4), io)
            .with_profile(SpyRadio::with_cap(lora_cap(256)))
            .with_gcs([7u8; 16], vec![b"/a".to_vec()]);
        assert_eq!(
            filtered.send_mtu(),
            Some(LORA_MTU - GCS_HEADROOM),
            "the body-prefix TLV's worst case is reserved out of the MTU"
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
}
