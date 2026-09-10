//! [`RadioMediumFaceFactory`] — stand the wireless-medium face up from **data**.
//!
//! This is the [`FaceFactory`] for `FaceKind::Wfb`: a connectivity resolver (or a
//! forwarder reading a config row / a signed `BearerRecord`) holding
//! `(FaceKind::Wfb, FaceParams{..})` can build a live [`RadioMediumFace`] via
//! `ForwarderEngine::add_face_of_kind` with no per-kind code — the same
//! delegate-don't-dial seam UDP/serial/etc. use. It is what lets the "medium is the
//! face" model participate in *automatic*, trust-driven face management: faces
//! become the reconciled projection of verified fabric data, not hand-wired calls.
//!
//! # Params grammar
//! A radio medium is *N* capabilities, so each radio is one `("radio", "<spec>")`
//! option; a lone radio may instead ride [`FaceParams::remote`]. A `<spec>` is
//! `driver[;channel=N][;iface=NAME][;tx-power=N]`, e.g.:
//! ```text
//! opts = [("radio","rtl8822e;channel=149;tx-power=40"),
//!         ("radio","halow;iface=halow0;channel=161")]
//! ```
//! Drivers: `rtl8822e` (USB, needs `libusb-backend`, Linux), `af-packet` / `halow`
//! (Linux monitor iface), `loopback` (in-process, for tests).
//!
//! # The seam limit this sketch surfaces (API-quality finding)
//! `FaceFactory::create(id, params)` receives **no engine handle, no FIB, and no
//! cancellation token** — by design it builds a *transport*, not a subsystem. That
//! is a clean fit for the medium's **data plane** (bearers, RX union, TX fan-out),
//! which this factory builds fully. But the cognition **control plane** wants two
//! things the seam does not offer:
//!  1. **FIB-derived active name-contexts** — needs `engine.fib()`; unreachable
//!     here, so a factory-built face decides for a single static root context
//!     (`ndn-fwd`'s engine-aware `mount_radio_face` is the superset that derives
//!     them from the FIB).
//!  2. **A lifetime handle** — there is none, so the control loop is hung on the
//!     transport itself ([`RunningMedium::attach_task`]) to die with the face.
//!
//! So the factory ships a working, self-contained rate-adaptation loop and is honest
//! that name-aware decisions need engine access `create` cannot give. Closing that
//! cleanly would mean a richer factory variant that also receives an engine/context
//! handle (or a post-create "face-ready" hook) — the concrete place ndn-workspace's
//! face-construction API could better support control-bearing faces.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use ndn_transport::{ErasedTransport, FaceError, FaceFactory, FaceId, FaceKind, FaceParams};

use ndn_radio_cognition::{NameContext, RadioPolicy, prefix_hash};

use crate::{
    ContextSource, LinkSignalStore, MediumActuator, RadioBearer, RadioCapability, RadioControl,
    RadioId, RadioMediumFace, StaticContexts, spawn_control_loop,
};

/// Control-loop re-decide cadence (mirrors the engine-aware mount).
const TICK: Duration = Duration::from_millis(500);

/// Builds a [`ContextSource`] for a given face id — the **engine-aware hook**. The
/// host that holds the engine (which `FaceFactory::create` cannot reach) supplies a
/// closure that captures it and yields, per face, a FIB-backed source; `ndn-ext`
/// never names the engine type. `None` ⇒ a static root context.
type ContextBuilder = Arc<dyn Fn(FaceId) -> Arc<dyn ContextSource> + Send + Sync>;

/// [`FaceFactory`] that builds the wireless-medium face from [`FaceParams`].
///
/// By default a factory-built face decides for a static root context (the seam gives
/// `create` no `engine.fib()`). Inject FIB-awareness with
/// [`with_context_source`](Self::with_context_source): the forwarder passes a builder
/// capturing the engine, so the *same* face — built by data — derives its active
/// name-contexts from routes, exactly like `ndn-fwd`'s hand mount.
#[derive(Clone, Default)]
pub struct RadioMediumFaceFactory {
    context_builder: Option<ContextBuilder>,
}

impl RadioMediumFaceFactory {
    /// A bare factory (static contexts — no engine access).
    pub fn new() -> Self {
        Self::default()
    }

    /// Inject a per-face [`ContextSource`] builder — the engine-aware hook. A
    /// forwarder holding the engine passes a closure that captures its FIB, so
    /// factory-built faces get name-derived contexts.
    pub fn with_context_source(mut self, builder: ContextBuilder) -> Self {
        self.context_builder = Some(builder);
        self
    }
}

fn invalid(msg: impl Into<String>) -> FaceError {
    FaceError::Io(std::io::Error::new(
        std::io::ErrorKind::InvalidInput,
        msg.into(),
    ))
}

/// One parsed radio capability from a params spec.
#[derive(Clone, Debug, PartialEq, Eq)]
struct RadioSpec {
    driver: String,
    channel: Option<u8>,
    iface: Option<String>,
    tx_power: Option<u8>,
}

/// Parse `driver[;channel=N][;iface=NAME][;tx-power=N]`.
fn parse_spec(s: &str) -> Result<RadioSpec, FaceError> {
    let mut parts = s.split(';');
    let driver = parts.next().unwrap_or("").trim().to_string();
    if driver.is_empty() {
        return Err(invalid("radio spec: driver is required"));
    }
    let mut spec = RadioSpec {
        driver,
        channel: None,
        iface: None,
        tx_power: None,
    };
    for kv in parts {
        let kv = kv.trim();
        if kv.is_empty() {
            continue;
        }
        let (k, v) = kv
            .split_once('=')
            .ok_or_else(|| invalid(format!("radio spec: expected key=value, got {kv:?}")))?;
        match k.trim() {
            "channel" => {
                spec.channel = Some(
                    v.trim()
                        .parse()
                        .map_err(|_| invalid("radio spec: bad channel"))?,
                )
            }
            "iface" => spec.iface = Some(v.trim().to_string()),
            "tx-power" => {
                spec.tx_power = Some(
                    v.trim()
                        .parse()
                        .map_err(|_| invalid("radio spec: bad tx-power"))?,
                )
            }
            other => return Err(invalid(format!("radio spec: unknown option {other:?}"))),
        }
    }
    Ok(spec)
}

/// Collect every radio capability from the params: each `("radio", spec)` option,
/// or `remote` as a lone-radio shorthand.
fn parse_specs(params: &FaceParams) -> Result<Vec<RadioSpec>, FaceError> {
    let mut specs: Vec<RadioSpec> = params
        .opts
        .iter()
        .filter(|(k, _)| k == "radio")
        .map(|(_, v)| parse_spec(v))
        .collect::<Result<_, _>>()?;
    if specs.is_empty()
        && let Some(remote) = params.remote.as_deref()
    {
        specs.push(parse_spec(remote)?);
    }
    if specs.is_empty() {
        return Err(invalid(
            "radio face: at least one radio required (a 'radio' opt or remote)",
        ));
    }
    Ok(specs)
}

impl FaceFactory for RadioMediumFaceFactory {
    fn kind(&self) -> FaceKind {
        FaceKind::Wfb
    }

    fn create<'a>(
        &'a self,
        id: FaceId,
        params: &'a FaceParams,
    ) -> Pin<Box<dyn Future<Output = Result<Box<dyn ErasedTransport>, FaceError>> + Send + 'a>>
    {
        let context_builder = self.context_builder.clone();
        Box::pin(async move {
            let specs = parse_specs(params)?;

            // 1. Bring up each capability as a bearer.
            let mut bearers = Vec::with_capacity(specs.len());
            for (i, spec) in specs.iter().enumerate() {
                match build_bearer(RadioId(i as u16), spec)? {
                    Some(b) => bearers.push(b),
                    None => {
                        return Err(invalid(format!(
                            "radio driver {:?} not available on this build/platform",
                            spec.driver
                        )));
                    }
                }
            }

            // 2. SENSE→DECIDE bridge + the cognition control plane (rate-only; see the
            //    module note on why channel/power/FIB-contexts need engine access).
            let signals = Arc::new(LinkSignalStore::new());
            let mut control = RadioControl::new(RadioPolicy::default())
                .with_signals(signals.clone())
                .with_tick_interval(TICK);
            for b in &bearers {
                control.register_radio(b.id, id, b.cap.clone());
                // Rate as driver state, plus whatever control seam the bearer found
                // for itself (see `build_afpacket`) — `None` stays rate-only.
                control.add_actuator(Arc::new(MediumActuator::new(
                    b.id,
                    b.radio.clone(),
                    b.knobs.clone(),
                )));
            }

            // 3. Data plane, with the shared control loop hung on the transport so it
            //    dies with the face (the seam gives no separate lifetime handle). The
            //    active-context source is engine-injected when available (FIB-derived),
            //    else a static root context — the same loop either way.
            let mut running = RadioMediumFace::new(id, bearers)
                .with_signal_sink(signals)
                .build();
            let source: Arc<dyn ContextSource> = match &context_builder {
                Some(build) => build(id),
                None => Arc::new(StaticContexts(vec![NameContext::new(prefix_hash(&[b"/"]))])),
            };
            let handle = spawn_control_loop(Arc::new(control), source, TICK, 4);
            running.attach_task(handle);

            Ok(Box::new(running) as Box<dyn ErasedTransport>)
        })
    }
}

// ---- bearer construction (driver-dispatched, build/platform-gated) ----

fn build_bearer(rid: RadioId, spec: &RadioSpec) -> Result<Option<RadioBearer>, FaceError> {
    match spec.driver.as_str() {
        "loopback" => Ok(Some(build_loopback(rid, spec))),
        "rtl8822e" => build_rtl8822e(rid, spec),
        "af-packet" | "halow" => build_afpacket(rid, spec),
        "esp32c5" | "c5" => build_esp32c5(rid, spec),
        _ => Ok(None),
    }
}

/// In-process bearer over a fresh loopback bus (no hardware) — the testable path and
/// the reference for what a real backend plugs in as.
fn build_loopback(rid: RadioId, spec: &RadioSpec) -> RadioBearer {
    use crate::{FrameIo, LoopbackMonitorBus};
    let bus = LoopbackMonitorBus::new();
    let radio: Arc<dyn FrameIo> = Arc::new(bus.endpoint(1, -55));
    let cap = RadioCapability::wifi_monitor_5ghz(spec.channel.into_iter().collect());
    RadioBearer::wifi(rid, radio, cap).with_channel(spec.channel)
}

#[cfg(feature = "libusb-backend")]
fn build_rtl8822e(rid: RadioId, spec: &RadioSpec) -> Result<Option<RadioBearer>, FaceError> {
    use crate::FrameIo;
    use ndn_radio_drivers::{BringUpRequest, DeviceSelect, open_radio};
    let ch = spec
        .channel
        .ok_or_else(|| invalid("rtl8822e requires channel="))?;
    // ★ **M8: ONE door.** This arm used to be `open_monitor_pid(0xa81a, ch)` — a two-call ladder
    // that discarded the `BringUpReport` and, because it bypassed `open_named_radio`, silently
    // had **no RX pump, no `NDN_RADIO_BW`, no `NDN_TX_PWR` and no `NDN_CCA_OFF`**. It now gets all
    // four, and a bearer whose regime is on the record. That is a real behaviour change on a
    // deployed node; it is written out in `open_radio`'s own doc comment.
    //
    // Target `0bda:a81a` (RTL8812EU / 8822E-halmac) specifically — an 8812AU is also in
    // `RTL88XX_PIDS`, so a plain `open()` can claim the wrong Realtek device.
    let mut req = BringUpRequest::from_env(ch);
    if let Some(p) = spec.tx_power {
        // The spec's `tx-power=` now rides INTO the open, so the applied value lands in the
        // report (and a refusal lands in `report.warnings`) instead of being a separate call whose
        // result an earlier revision of this function discarded outright.
        req.power = ndn_radio_hal::PowerRequest::index(p);
    }
    let open = open_radio(0xa81a, &DeviceSelect::from_env(), &req)?;
    tracing::info!(
        target: "named_radio", radio = rid.0, plan = %open.report().plan,
        plan_digest = format_args!("{:#018x}", open.report().plan_digest),
        power = %open.report().state.power.render(),
        "rtl8822e bearer opened"
    );
    // ★ **`with_knobs`, and the radio's OWN capability.** Without the first, this bearer had no
    // control seam at all: the one-shot `spec.tx_power` was the only power this radio ever saw,
    // and every runtime decision — power, channel, EDCCA, CSD — was computed, recorded as applied,
    // and dropped.
    //
    // The capability swap matters independently: `wifi_monitor_5ghz` is a generic preset claiming
    // **2x2 / MCS9 / 80 MHz**, while this part's own `RadioProfile` reports 1SS / MCS7 / 40 MHz
    // (its userspace path has one RX chain). Advertising two streams to a peer that then rates its
    // replies for two is exactly the mismatch MEASURED as a one-way link. The capability now comes
    // out of the REPORT, which is where the plan put it — one fact, one place.
    let cap = open
        .report()
        .capability
        .clone()
        .ok_or_else(|| invalid("rtl8822e: the bring-up report carries no capability"))?;
    let radio: Arc<dyn FrameIo> = open.io.clone();
    let mut bearer = RadioBearer::wifi(rid, radio, cap).with_channel(Some(ch));
    if let Some(k) = open.knobs.clone() {
        bearer = bearer.with_knobs(k);
    }
    Ok(Some(bearer))
}

#[cfg(not(feature = "libusb-backend"))]
fn build_rtl8822e(_rid: RadioId, _spec: &RadioSpec) -> Result<Option<RadioBearer>, FaceError> {
    Ok(None) // needs the `libusb-backend` feature (Linux userspace USB driver)
}

/// **ESP32-C5 over its serial bridge** — `esp32c5;iface=/dev/cu.usbmodemXXX[;channel=N][;tx-power=N]`.
///
/// This exists because the C5 was the most instrumented radio in the fleet and *not a radio cognition
/// could actuate*: it had a rate knob, a calibrated dBm power knob, per-frame PHY metadata, hardware
/// receive counters and channel profiling, but no arm here — so it only ever appeared in examples, and
/// every decision the policy makes about MCS, power and channel landed on nothing.
///
/// Unlike the libusb arms this attaches the full capability set, not just `FrameIo`: `with_knobs` is
/// what makes the policy's channel/power/rate decisions actuate, and `with_profile` carries the real
/// dual-band capability so the planner can choose 5 GHz.
#[cfg(feature = "serial-radio")]
fn build_esp32c5(rid: RadioId, spec: &RadioSpec) -> Result<Option<RadioBearer>, FaceError> {
    use ndn_radio_hal::Bandwidth;
    let port = spec
        .iface
        .as_deref()
        .ok_or_else(|| invalid("esp32c5 requires iface=<serial port>"))?;
    // ★ M6: the channel travels INTO the bring-up instead of being applied just after it. Same
    // bytes on the wire — `PLAN_SERIAL_BRIDGE`'s `set_channel` rung is the same
    // `RadioKnobs::set_channel(ch, Bw20)` this arm used to make itself — but now the tune is a
    // reported rung and part of the plan digest, instead of an off-the-books call whose failure
    // this function turned into a bare `?`. `spec.channel == None` sends nothing, as before.
    let open = ndn_radio_drivers::Esp32SerialBackend::open_c5_radio_on(
        port,
        spec.channel.unwrap_or(0),
        Bandwidth::Bw20,
    )?;
    let knobs = open
        .knobs
        .clone()
        .ok_or_else(|| invalid("esp32c5 opened without knobs"))?;
    if let Some(p) = spec.tx_power {
        // The C5's power really is an absolute scale, so prefer the dBm knob and let the driver
        // report what it actually applied — and then SAY what it applied. MEASURED: the IDF
        // quantises to 11 discrete steps and 21 dBm applies as 20, so the requested value is not
        // the transmitted one, and `let _ =` here discarded the only place that difference was
        // visible. Same class as the 8812au's discarded `AppliedPower`, one bearer over.
        match knobs.set_tx_power_dbm(p as i8) {
            Ok(applied) => tracing::info!(
                target: "named_radio", radio = rid.0, requested = p, applied,
                "esp32c5: spec tx_power applied (dBm readback)"
            ),
            Err(e) => tracing::warn!(
                target: "named_radio", radio = rid.0, requested = p, error = %e,
                "esp32c5: spec tx_power refused — the radio is at whatever its bring-up left"
            ),
        }
    }
    let cap = open
        .profile
        .as_ref()
        .map(|p| p.capability())
        .unwrap_or_else(|| {
            RadioCapability::wifi_monitor_dual_1ss(spec.channel.into_iter().collect())
        });
    let mut bearer = RadioBearer::wifi(rid, open.io, cap).with_knobs(knobs);
    if let Some(t) = open.time {
        bearer = bearer.with_time(t);
    }
    if let Some(pr) = open.profile {
        bearer = bearer.with_profile(pr);
    }
    Ok(Some(bearer.with_channel(spec.channel)))
}

#[cfg(not(feature = "serial-radio"))]
fn build_esp32c5(_rid: RadioId, _spec: &RadioSpec) -> Result<Option<RadioBearer>, FaceError> {
    Ok(None) // needs the `serial-radio` feature
}

#[cfg(target_os = "linux")]
fn build_afpacket(rid: RadioId, spec: &RadioSpec) -> Result<Option<RadioBearer>, FaceError> {
    use crate::{AfPacketBackend, FrameFormat, FrameIo};
    let iface = spec
        .iface
        .as_deref()
        .ok_or_else(|| invalid(format!("{} requires iface=", spec.driver)))?;
    let channels: Vec<u8> = spec.channel.into_iter().collect();
    let (fmt, cap) = if spec.driver == "halow" {
        (
            FrameFormat::RawNdnS1g {
                ethertype: crate::NDN_ETHERTYPE,
            },
            RadioCapability::wifi_halow_s1g(channels),
        )
    } else {
        (
            FrameFormat::RawNdn {
                ethertype: crate::NDN_ETHERTYPE,
            },
            RadioCapability::wifi_monitor_5ghz(channels),
        )
    };
    let backend = AfPacketBackend::new(iface, fmt)
        .map_err(|e| invalid(format!("{e:?}")))?
        .with_capability(cap.clone());
    let radio: Arc<dyn FrameIo> = Arc::new(backend);

    // Probe the interface for a control seam. This is driver-agnostic: whatever
    // absolute-dBm mechanism exists (a driver knob, else nl80211) is found by
    // `Mac80211Knobs`, and only a range it actually established is published on the
    // capability — which is the signal that makes cognition decide power in dB.
    // Nothing found leaves the bearer exactly as it was: rate-only.
    let knobs = crate::dbm_power::Mac80211Knobs::discover(iface);
    let range = knobs.tx_power_range();
    let mut bearer = RadioBearer::wifi(rid, radio, cap)
        .with_knobs(Arc::new(knobs))
        .with_channel(spec.channel);
    if let Some(r) = range {
        bearer = bearer.with_tx_power_dbm(r);
    }
    Ok(Some(bearer))
}

#[cfg(not(target_os = "linux"))]
fn build_afpacket(_rid: RadioId, _spec: &RadioSpec) -> Result<Option<RadioBearer>, FaceError> {
    Ok(None) // af-packet / HaLow monitor bearers are Linux-only
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_multi_capability_medium() {
        let params = FaceParams::default()
            .with_opt("radio", "rtl8822e;channel=149;tx-power=40")
            .with_opt("radio", "halow;iface=halow0;channel=161");
        let specs = parse_specs(&params).unwrap();
        assert_eq!(specs.len(), 2);
        assert_eq!(specs[0].driver, "rtl8822e");
        assert_eq!(specs[0].channel, Some(149));
        assert_eq!(specs[0].tx_power, Some(40));
        assert_eq!(specs[1].driver, "halow");
        assert_eq!(specs[1].iface.as_deref(), Some("halow0"));
    }

    #[test]
    fn remote_is_a_lone_radio_shorthand() {
        let params = FaceParams::remote("loopback;channel=149");
        let specs = parse_specs(&params).unwrap();
        assert_eq!(specs.len(), 1);
        assert_eq!(specs[0].driver, "loopback");
    }

    #[test]
    fn empty_params_are_rejected() {
        assert!(parse_specs(&FaceParams::default()).is_err());
    }

    #[test]
    fn factory_reports_the_wfb_medium_kind() {
        assert_eq!(RadioMediumFaceFactory::new().kind(), FaceKind::Wfb);
    }

    /// End to end with no hardware: the factory stands a live medium transport up
    /// from a `loopback` params row — the same call an `add_face_of_kind` resolver
    /// makes — and it is a working `Transport` (id + kind), with its cognition loop
    /// attached. Proves the data-driven construction path.
    #[tokio::test]
    async fn factory_builds_a_live_medium_from_data() {
        let params = FaceParams::default().with_opt("radio", "loopback;channel=149");
        let transport = RadioMediumFaceFactory::new()
            .create(FaceId(42), &params)
            .await
            .expect("loopback medium builds");
        assert_eq!(transport.id(), FaceId(42));
        assert_eq!(transport.kind(), FaceKind::Wfb);
    }
}

// ⚠ **Gated on the feature the arm itself is gated on.** `build_esp32c5` is
// `#[cfg(feature = "serial-radio")]`; without it `build_bearer` falls to `_ => Ok(None)` and
// `esp32c5_is_routed_and_requires_a_port` asserted against a routing arm that is not compiled —
// it failed on `cargo test -p ndn-phy-wifi --lib` and passed under `--features serial-radio`.
// (Not part of the bring-up-contract work; a red test in the tree, fixed where it was found.)
#[cfg(all(test, feature = "serial-radio"))]
mod c5_bearer_tests {
    use super::*;

    /// The C5 must be routed, not silently ignored. Before this arm existed `build_bearer` fell
    /// through to `_ => Ok(None)` for every serial radio, so the most instrumented radio in the
    /// fleet could never be a face cognition actuated — its rate, power and channel decisions all
    /// landed on nothing.
    #[test]
    fn esp32c5_is_routed_and_requires_a_port() {
        let spec = parse_spec("esp32c5").expect("spec parses");
        assert_eq!(spec.driver, "esp32c5");
        match build_bearer(RadioId(1), &spec) {
            Err(e) => assert!(
                format!("{e}").contains("iface"),
                "the error should name the missing parameter, got: {e}"
            ),
            Ok(_) => panic!("esp32c5 without a port must not build a bearer"),
        }
    }

    /// An unknown driver still falls through quietly — routing the C5 must not have turned the
    /// catch-all into an error path for everything else.
    #[test]
    fn unknown_driver_still_falls_through() {
        let spec = parse_spec("not-a-radio").expect("spec parses");
        assert!(matches!(build_bearer(RadioId(1), &spec), Ok(None)));
    }
}
