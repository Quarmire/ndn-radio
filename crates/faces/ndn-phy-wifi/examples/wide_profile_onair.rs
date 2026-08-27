//! **On-air per-chip validation for the wide profile (#39).**
//!
//! The wide profile rides a 4-address QoS-Data + HT-Control frame. Whether that survives a given
//! chip's monitor TX/RX path is a *hardware* question, not a software one: some Realtek/Atheros
//! firmwares rewrite address fields, drop the 4th address, or strip HT Control on injection or
//! capture. This harness answers it directly — a TX node emits wide frames with a known fingerprint
//! and extra Blur, an RX node captures and reports whether `addr4` and HT Control came through intact
//! (and whether the base 126-bit Blur is byte-identical, i.e. a commodity receiver would still match).
//!
//! It exercises the real path built for #39: `WideFrame::to_fields` → `InjectFrame{addr4,htc}` →
//! `build_dot11` (4-addr QoS+HTC) on TX, and `parse_dot11` surfacing `addr4`/`htc` on RX.
//!
//! Run on two OPis on the same channel (needs CAP_NET_RAW → sudo):
//!   TX:  sudo RADIO_IFACE=wlu1 WIDE_MODE=tx ./wide_profile_onair
//!   RX:  sudo RADIO_IFACE=wlu1 WIDE_MODE=rx ./wide_profile_onair
//! Env: RADIO_IFACE (default wlu1), WIDE_MODE (tx|rx, default rx),
//!      WIDE_NAME (default /ndn/wide/onair/v1), WIDE_TX_MS (TX cadence, default 200).

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("wide_profile_onair is Linux-only (AF_PACKET monitor) — run it on the OPi");
}

#[cfg(target_os = "linux")]
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    use std::time::Duration;

    use ndn_phy_wifi::{
        FrameFormat, FrameIo, InjectFrame, OPEN_GROUP_KEY, TxIntent, tier0::WideFrame,
    };

    let iface = std::env::var("RADIO_IFACE").unwrap_or_else(|_| "wlu1".into());
    let mode = std::env::var("WIDE_MODE").unwrap_or_else(|_| "rx".into());
    let name = std::env::var("WIDE_NAME").unwrap_or_else(|_| "/ndn/wide/onair/v1".into());
    let fmt = FrameFormat::RawNdn { ethertype: 0x8624 };
    let key = OPEN_GROUP_KEY;

    // The 4-address QoS+HTC frame is a DATA frame; the AF_PACKET backend injects the exact bytes
    // `build_dot11` produced (radiotap ++ 802.11), so what reaches the air is what we asked for.
    let backend = ndn_phy_wifi::AfPacketBackend::new(&iface, fmt)?;

    if mode == "tx" {
        let cadence: u64 = std::env::var("WIDE_TX_MS").ok().and_then(|s| s.parse().ok()).unwrap_or(200);
        let wf = WideFrame::of_name(&key.0, name.as_bytes(), 0x37, 0x00);
        let f = wf.to_fields();
        eprintln!(
            "TX wide '{name}' on {iface}: fp={:06x} addr4={:02x?} htc={:02x?} (base addr1={:02x?})",
            wf.fingerprint, f.addr4, f.htc, f.addr1
        );
        let mut n: u64 = 0;
        loop {
            let payload = format!("\x06\x08wide#{n}").into_bytes();
            let frame = InjectFrame {
                payload: payload.into(),
                tx: TxIntent::CONSERVATIVE,
                dst: f.addr1,
                src: f.addr2,
                addr3: Some(f.addr3),
                addr4: Some(f.addr4),
                htc: Some(f.htc),
            };
            if let Err(e) = backend.inject(frame).await {
                eprintln!("inject error: {e}");
            }
            n += 1;
            if n % 20 == 0 {
                eprintln!("  … {n} wide frames sent");
            }
            tokio::time::sleep(Duration::from_millis(cadence)).await;
        }
    }

    // RX: the verdict node. Expected fields for the advertised name, to compare against the air.
    let want = WideFrame::of_name(&key.0, name.as_bytes(), 0x37, 0x00).to_fields();
    eprintln!(
        "RX on {iface}: expecting wide '{name}' → addr4={:02x?} htc={:02x?}. Ctrl-C to stop.",
        want.addr4, want.htc
    );
    let (mut seen, mut wide_ok, mut addr4_lost, mut htc_lost) = (0u64, 0u64, 0u64, 0u64);
    loop {
        match tokio::time::timeout(Duration::from_millis(500), backend.recv_frame()).await {
            Ok(Ok(cap)) => {
                seen += 1;
                let has_a4 = cap.addr4.is_some();
                let has_htc = cap.htc.is_some();
                let a4_match = cap.addr4 == Some(want.addr4);
                let htc_match = cap.htc == Some(want.htc);
                if has_a4 && has_htc && a4_match && htc_match {
                    wide_ok += 1;
                } else {
                    if !has_a4 {
                        addr4_lost += 1;
                    }
                    if !has_htc {
                        htc_lost += 1;
                    }
                }
                if seen <= 5 || seen % 20 == 0 {
                    eprintln!(
                        "  frame #{seen}: addr4={:02x?} ({}) htc={:02x?} ({}) base_group={:02x?}",
                        cap.addr4,
                        if a4_match { "MATCH" } else if has_a4 { "differs" } else { "LOST" },
                        cap.htc,
                        if htc_match { "MATCH" } else if has_htc { "differs" } else { "LOST" },
                        cap.group,
                    );
                }
                if seen % 50 == 0 {
                    eprintln!(
                        "── VERDICT so far: {seen} frames, wide preserved {wide_ok}, addr4 lost \
                         {addr4_lost}, htc lost {htc_lost} → {}",
                        if wide_ok == seen {
                            "this chip PRESERVES the wide profile"
                        } else if wide_ok == 0 {
                            "this chip does NOT carry the wide profile (base-only path)"
                        } else {
                            "PARTIAL — intermittent; inspect the driver"
                        }
                    );
                }
            }
            Ok(Err(e)) => eprintln!("recv error: {e}"),
            Err(_) => {} // timeout: keep waiting
        }
    }
}
