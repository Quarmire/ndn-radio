//! **The LoRa FACE path, end to end** — real NDN Interest/Data through [`LoraPhy`] → `Face` →
//! `ForwarderEngine`, with the radio's control plane attached.
//!
//! Every other LoRa example in this workspace drives `LoraSerialBackend` directly and hand-builds
//! ASCII payloads (`"I|A|/ndn/…"`). That exercises the *dongle*, never the *face*: no NDNLPv2
//! fragmentation, no PIT/FIB/CS, no link-FEC generation, no body-prefix GCS gate, and no
//! capability-derived MTU. This example runs the path the forwarder actually uses.
//!
//! Two modes, one binary:
//!
//! ```sh
//! # SELF-TEST — no hardware. Two engines over a loopback bus, each with its own LoraPhy;
//! # the consumer fetches names the producer serves. Proves the whole face path, including the
//! # control plane (the sim radio records every knob the plan actuates).
//! cargo run -p ndn-phy-lora --example lora_face_node
//! # ...with a radio that declares a SMALL real payload cap (the Waveshare RX truncation):
//! LORA_SIM_MAX_PAYLOAD=64 LORA_PAYLOAD_BYTES=400 cargo run -p ndn-phy-lora --example lora_face_node
//!
//! # ON AIR — a real dongle per node. Producer on one host, consumer on the other.
//! LORA_PORT=/dev/ttyACM0 LORA_ROLE=producer cargo run -p ndn-phy-lora --example lora_face_node
//! LORA_PORT=/dev/ttyACM0 LORA_ROLE=consumer cargo run -p ndn-phy-lora --example lora_face_node
//! ```
//!
//! Both modes take the same face options, all defaulting OFF so the baseline is today's behaviour:
//!
//! | env | effect |
//! |---|---|
//! | `LORA_CHANNEL` | tune the radio through `RadioKnobs::set_channel` before the engine starts |
//! | `LORA_SF` / `LORA_CR` / `LORA_BW` / `LORA_DBM` | seed the plan cell; the face actuates them on send |
//! | `LORA_FEC` | link-FEC parity per generation (`R`); `LORA_FEC_K`, `LORA_FEC_WINDOW_MS` size it |
//! | `LORA_GCS` | body-prefix GCS filter on, registered for the served prefix |
//! | `LORA_SIM_MAX_PAYLOAD` | self-test only: the payload cap the sim radio DECLARES (drives the MTU) |
//!
//! The plan cell here is a static seed rather than a live policy — the point is to prove the
//! actuation path reaches the hardware. `ndn-radio-cognition`'s `lora_cognition` example is the
//! live sense→decide→act loop; wire its decided `TxParams` into this same cell to join them.

use std::env;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use ndn_app::{EngineAppExt, EngineBuilder};
use ndn_engine::builder::EngineConfig;
use ndn_frame_io::LoopbackMonitorBus;
use ndn_packet::Name;
use ndn_packet::encode::DataBuilder;
use ndn_phy_lora::LoraPhy;
use ndn_radio_cognition::{LoraRate, RateParams, TxParams};
use ndn_radio_hal::{
    Bandwidth, ClockDomainId, FaceError, FrameIo, OpenRadio, RadioCapability, RadioKnobs,
    RadioProfile, RadioTime, RadioTimeSource,
};
use ndn_transport::{FaceId, Transport};
use tokio_util::sync::CancellationToken;

/// The plan cell the cognitive actuator would write; here it is seeded from env.
type PlanCell = Arc<RwLock<Option<TxParams>>>;

fn env_or(k: &str, d: &str) -> String {
    env::var(k).unwrap_or_else(|_| d.into())
}

fn env_num<T: std::str::FromStr>(k: &str) -> Option<T> {
    env::var(k).ok().and_then(|s| s.parse().ok())
}

// ---------------------------------------------------------------------------
// A hardware-free radio for the self-test: a loopback data plane plus a control
// plane that DECLARES a capability and RECORDS every knob the face pushes at it.
// ---------------------------------------------------------------------------

/// The knobs/profile/clock half of a simulated LoRa radio. Deliberately separate from the
/// data plane (a `LoopbackEndpoint`) — `OpenRadio`'s four handles need not be one object,
/// which is the whole reason it is four `Option`s rather than a supertrait.
struct SimRadio {
    cap: RadioCapability,
    log: Mutex<Vec<String>>,
}

impl SimRadio {
    fn new(max_payload: usize, channel: u8) -> Self {
        let mut cap = RadioCapability::lora(vec![channel]);
        // The one number this example is here to prove travels: a node that reports a
        // SMALLER real cap than the preset's optimistic 256 must be respected by the face.
        cap.max_payload = max_payload;
        Self {
            cap,
            log: Mutex::new(Vec::new()),
        }
    }
    fn note(&self, s: String) {
        self.log.lock().unwrap().push(s);
    }
    fn actuated(&self) -> Vec<String> {
        self.log.lock().unwrap().clone()
    }
}

impl RadioProfile for SimRadio {
    fn capability(&self) -> RadioCapability {
        self.cap.clone()
    }
}

impl RadioTime for SimRadio {
    fn time_sources(&self) -> Vec<RadioTimeSource> {
        vec![RadioTimeSource::host_recv(ClockDomainId(0))]
    }
}

impl RadioKnobs for SimRadio {
    fn set_channel(&self, channel: u8, _bw: Bandwidth) -> Result<(), FaceError> {
        self.note(format!("channel={channel}"));
        Ok(())
    }
    fn set_spreading_factor(&self, sf: u8) -> Result<(), FaceError> {
        self.note(format!("sf={sf}"));
        Ok(())
    }
    fn set_coding_rate(&self, cr: u8) -> Result<(), FaceError> {
        self.note(format!("cr=4/{}", cr + 4));
        Ok(())
    }
    fn set_bandwidth_khz(&self, khz: u32) -> Result<(), FaceError> {
        self.note(format!("bw={khz}kHz"));
        Ok(())
    }
    fn set_tx_power_dbm(&self, dbm: i8) -> Result<i8, FaceError> {
        self.note(format!("power={dbm}dBm"));
        Ok(dbm)
    }
    fn set_edcca_ignore(&self, on: bool) -> Result<(), FaceError> {
        self.note(format!("lbt_ignore={on}"));
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Face assembly — the wiring site this example exists to keep honest.
// ---------------------------------------------------------------------------

/// The plan a control plane would decide, seeded from env. `None` fields leave the radio alone.
fn seed_plan() -> Option<PlanCell> {
    let lora = LoraRate {
        spreading_factor: env_num("LORA_SF"),
        coding_rate: env_num("LORA_CR"),
        bandwidth_khz: env_num("LORA_BW"),
    };
    let fec: Option<u16> = env_num("LORA_FEC");
    let dbm: Option<i8> = env_num("LORA_DBM");
    if lora == LoraRate::default() && fec.is_none() && dbm.is_none() {
        return None; // nothing decided — leave the face plan-less, exactly as before
    }
    Some(Arc::new(RwLock::new(Some(TxParams {
        link_fec_redundancy: fec,
        tx_power_dbm: dbm,
        rate: RateParams::Lora(lora),
        ..Default::default()
    }))))
}

/// Mount `radio` — **the whole radio**, not just its data plane — as a LoRa face.
///
/// This is the shape the fix is about: `OpenRadio` in, every optional handle carried onto the
/// face, and the face's MTU read back from what the radio declared rather than assumed.
fn mount(id: FaceId, radio: OpenRadio, prefix: &Name) -> LoraPhy {
    // Tune first: the channel is bearer state and must be right before the reader starts.
    if let Some(ch) = env_num::<u8>("LORA_CHANNEL")
        && let Some(k) = radio.knobs.as_ref()
        && let Err(e) = k.set_channel(ch, Bandwidth::default())
    {
        eprintln!("  ! set_channel({ch}) failed: {e} (continuing on the radio's current channel)");
    }

    let mut phy = LoraPhy::from_open(id, radio);
    if let Some(cell) = seed_plan() {
        phy = phy.with_planned_params(cell);
    }
    if let Some(r) = env_num::<u16>("LORA_FEC") {
        let k = env_num::<usize>("LORA_FEC_K");
        let w = env_num::<u64>("LORA_FEC_WINDOW_MS").map(Duration::from_millis);
        phy = phy.with_link_fec(k, w);
        println!(
            "  link-FEC on (R={r} from the plan, K={:?})",
            k.unwrap_or(2)
        );
    }
    if env_or("LORA_GCS", "0") != "0" {
        // The #44 keyspace key is shared by every node on the medium; a demo constant here.
        phy = phy.with_gcs(*b"ndn/lora-face-k1", vec![prefix.to_string().into_bytes()]);
        println!("  body-prefix GCS on for {prefix}");
    }

    let cap = phy.capability();
    println!(
        "  face {} mounted: mtu={:?} declared_max_payload={:?} knobs={} clock={}",
        id.0,
        phy.send_mtu(),
        cap.as_ref().map(|c| c.max_payload),
        phy.knobs().is_some(),
        phy.time()
            .map(|t| t.time_sources().len())
            .unwrap_or_default(),
    );
    phy
}

// ---------------------------------------------------------------------------
// Roles
// ---------------------------------------------------------------------------

async fn run_producer(
    phy: LoraPhy,
    prefix: Name,
    secs: u64,
    body: Vec<u8>,
) -> Result<(), Box<dyn std::error::Error>> {
    let (engine, _shutdown) = EngineBuilder::new(EngineConfig::default())
        .face_composed(phy.into_face())
        .build()
        .await?;
    let cancel = CancellationToken::new();
    let producer = engine.register_producer(prefix.clone(), cancel.child_token());
    println!(
        "producer: serving {prefix} for {secs}s ({} B objects)",
        body.len()
    );
    let task = tokio::spawn(async move {
        let _ = producer
            .serve(move |i, r| {
                let name = (*i.name).clone();
                let body = body.clone();
                async move {
                    r.respond_bytes(DataBuilder::new(name, &body).build())
                        .await
                        .ok();
                }
            })
            .await;
    });
    tokio::time::sleep(Duration::from_secs(secs)).await;
    cancel.cancel();
    task.abort();
    Ok(())
}

async fn run_consumer(
    phy: LoraPhy,
    face: FaceId,
    prefix: Name,
    rounds: u32,
    gap: Duration,
) -> Result<u32, Box<dyn std::error::Error>> {
    let (engine, _shutdown) = EngineBuilder::new(EngineConfig::default())
        .face_composed(phy.into_face())
        .build()
        .await?;
    engine.fib().add_nexthop(&prefix, face, 0);
    let cancel = CancellationToken::new();
    let mut consumer = engine.app_consumer(cancel.child_token());
    let mut delivered = 0u32;
    println!("consumer: fetching {rounds} names under {prefix} ...");
    for r in 0..rounds {
        let name: Name = format!("{prefix}/{r}").parse()?;
        if let Ok(v) = consumer.fetch_unverified(name).await
            && v.trust_unchecked().content().is_some()
        {
            delivered += 1;
        }
        tokio::time::sleep(gap).await;
    }
    cancel.cancel();
    Ok(delivered)
}

#[tokio::main(flavor = "multi_thread", worker_threads = 4)]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let prefix: Name = env_or("LORA_PREFIX", "/ndn/lora/face").parse()?;
    let rounds: u32 = env_num("LORA_ROUNDS").unwrap_or(8);
    let payload_bytes: usize = env_num("LORA_PAYLOAD_BYTES").unwrap_or(64);
    let body = vec![b'L'; payload_bytes];

    let ok = match env::var("LORA_PORT") {
        // ---- On air: one real dongle, one role. ----
        Ok(port) => {
            let role = env_or("LORA_ROLE", "consumer");
            println!("lora_face_node: role={role} port={port} prefix={prefix}");
            // The wiring site. `LoraSerialBackend` implements all four HAL traits, so the whole
            // radio travels to the face — NOT `let io: Arc<dyn FrameIo> = be;`, which is where
            // the knobs, clock and profile used to be thrown away.
            let be = Arc::new(ndn_radio_drivers::LoraSerialBackend::open(&port)?);
            let radio = OpenRadio {
                io: be.clone() as Arc<dyn FrameIo>,
                knobs: Some(be.clone() as Arc<dyn RadioKnobs>),
                time: Some(be.clone() as Arc<dyn RadioTime>),
                profile: Some(be as Arc<dyn RadioProfile>),
            };
            let id = FaceId(2);
            let phy = mount(id, radio, &prefix);
            tokio::time::sleep(Duration::from_millis(1500)).await; // reader spin-up / radio settle
            if role == "producer" {
                run_producer(phy, prefix, env_num("LORA_SECS").unwrap_or(120), body).await?;
                true
            } else {
                let n = run_consumer(
                    phy,
                    id,
                    prefix,
                    rounds,
                    Duration::from_millis(env_num("LORA_GAP_MS").unwrap_or(1500)),
                )
                .await?;
                println!("\nconsumer: delivered {n}/{rounds}");
                n > 0
            }
        }
        // ---- Self-test: no hardware. Two faces, one simulated medium, two engines. ----
        Err(_) => {
            let ch: u8 = env_num("LORA_CHANNEL").unwrap_or(65);
            let declared: usize = env_num("LORA_SIM_MAX_PAYLOAD").unwrap_or(200);
            println!(
                "lora_face_node: SELF-TEST (no LORA_PORT) prefix={prefix} \
                 sim_declared_max_payload={declared} object={payload_bytes}B"
            );
            let bus = LoopbackMonitorBus::new();
            let sim_p = Arc::new(SimRadio::new(declared, ch));
            let sim_c = Arc::new(SimRadio::new(declared, ch));
            let open = |node: u64, sim: &Arc<SimRadio>| OpenRadio {
                io: Arc::new(bus.endpoint(node, -70)) as Arc<dyn FrameIo>,
                knobs: Some(sim.clone() as Arc<dyn RadioKnobs>),
                time: Some(sim.clone() as Arc<dyn RadioTime>),
                profile: Some(sim.clone() as Arc<dyn RadioProfile>),
            };
            let phy_p = mount(FaceId(101), open(1, &sim_p), &prefix);
            let phy_c = mount(FaceId(201), open(2, &sim_c), &prefix);

            let p_prefix = prefix.clone();
            let p_body = body.clone();
            let producer = tokio::spawn(async move {
                if let Err(e) = run_producer(phy_p, p_prefix, 30, p_body).await {
                    eprintln!("self-test producer failed: {e}");
                }
            });
            tokio::time::sleep(Duration::from_millis(200)).await;
            let n = run_consumer(
                phy_c,
                FaceId(201),
                prefix,
                rounds,
                Duration::from_millis(env_num("LORA_GAP_MS").unwrap_or(50)),
            )
            .await?;
            producer.abort();

            println!("\nself-test: delivered {n}/{rounds}");
            // What the plan actually pushed at the radio — empty when no LORA_SF/CR/BW/DBM was
            // set, which is the honest report for "nothing was decided", not "nothing landed".
            println!("producer radio actuated: {:?}", sim_p.actuated());
            n == rounds
        }
    };

    // Exit immediately: a graceful engine+serial shutdown blocks on the blocking reader threads
    // and wedges the USB port (the C5/CYD/LoRa serial-thread gotcha).
    std::process::exit(if ok { 0 } else { 1 });
}
