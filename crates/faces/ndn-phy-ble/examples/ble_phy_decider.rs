//! **The advertising-PHY decider, end to end** — neighbour reports in, radio PHY out, delivery measured.
//!
//! The BLE bearer has a reach lever (LE Coded, S=8) that is not free: only extended advertising PDUs
//! carry a PHY selection, so a coded advert is invisible to a legacy-only controller at *any* range.
//! Choosing it is therefore a worst-receiver decision, exactly like dropping to a legacy Wi-Fi rate
//! for a legacy-only neighbour — so the decision lives in cognition
//! (`ndn_radio_cognition::policy::decide_adv_phy`), fed by the `max_adv_phy` each neighbour advertises
//! in its reception report, and this example just closes the loop onto real hardware.
//!
//! Two rounds, and the point is the contrast:
//!
//! * **all-capable group** — every fresh neighbour reports `ADV_PHY_CODED`, urgency asks for reach,
//!   the decider returns Coded, and both capable receivers hear it.
//! * **one legacy-only neighbour** — a single peer reports `ADV_PHY_1M` and the whole group drops to
//!   1M, even for urgent traffic. The measurement that matters is the *third* column: what the
//!   legacy-only peer receives. Under the decider it gets everything; had we ignored it and kept
//!   Coded it would get nothing at all.
//!
//! ```sh
//! C5_TX=/dev/cu.usbmodem101 C5_RX=/dev/cu.usbmodem111401 BW16=/dev/cu.usbserial-11110 \
//!   cargo run --example ble_phy_decider --features shared-mux -p ndn-phy-ble
//! ```
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use ndn_phy_ble::{AdvBackend, AdvPhy, SharedBleBackend};
use ndn_radio_cognition::{
    ADV_PHY_1M, ADV_PHY_CODED, ClassAuthority, ClassCeiling, MediumState, NameContext,
    NeighborReport, Priority, decide_adv_phy,
};
use ndn_radio_drivers::{Esp32SerialBackend, SerialRadioBackend};

/// Build the medium model a node would hold after hearing these neighbours' reports.
fn medium_hearing(caps: &[(u64, u8)], now_ms: u64) -> MediumState {
    let mut m = MediumState::default();
    for (id, cap) in caps {
        m.observe_report(
            *id,
            NeighborReport {
                heard_prefixes: vec![],
                spectrum: vec![],
                max_rx_mcs: ndn_radio_cognition::FULL_RX_MCS,
                max_adv_phy: *cap,
                ts_ms: now_ms,
            },
        );
    }
    m
}

async fn deliver(
    tx: &Arc<dyn AdvBackend>,
    c5_rx: &Arc<dyn AdvBackend>,
    bw16: &Arc<SerialRadioBackend>,
    tag: &str,
    n: u32,
) -> (usize, usize) {
    let c5_seen: Arc<tokio::sync::Mutex<std::collections::HashSet<Vec<u8>>>> = Arc::default();
    {
        let (rx, seen) = (c5_rx.clone(), c5_seen.clone());
        tokio::spawn(async move {
            while let Ok(sf) = rx.next_scanned().await {
                seen.lock().await.insert(sf.frame.to_vec());
            }
        });
    }
    let bw_seen: Arc<tokio::sync::Mutex<std::collections::HashSet<Vec<u8>>>> = Arc::default();
    {
        let (mux, seen) = (bw16.clone(), bw_seen.clone());
        tokio::spawn(async move {
            while let Ok((_, _, f)) = mux.ble_next_scanned().await {
                seen.lock().await.insert(f.to_vec());
            }
        });
    }
    tokio::time::sleep(Duration::from_millis(400)).await;
    for i in 0..n {
        tx.broadcast(Bytes::from(format!("{tag}{i:02}").into_bytes()))
            .await
            .ok();
        tokio::time::sleep(Duration::from_millis(220)).await;
    }
    tokio::time::sleep(Duration::from_millis(2500)).await;
    let c = c5_seen.lock().await.iter().filter(|p| p.starts_with(tag.as_bytes())).count();
    let b = bw_seen.lock().await.iter().filter(|p| p.starts_with(tag.as_bytes())).count();
    (c, b)
}

/// `decide_adv_phy` now takes the GRANTED class rather than an asserted `Priority`: an asserted one
/// could buy LE Coded S=8 (~8x airtime per bit) for free, which is the purchase `ClassCeiling`
/// exists to gate. This demo therefore mints a ceiling through the same gate production uses.
struct Demo(Priority);
impl ClassAuthority for Demo {
    fn ceiling_for(&self, _prefix_hash: u64) -> Priority {
        self.0
    }
}
fn granted(p: Priority) -> NameContext {
    NameContext::new(0).with_ceiling(ClassCeiling::authorised(&Demo(p), 0))
}

#[tokio::main(flavor = "multi_thread", worker_threads = 4)]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let tx_port = std::env::var("C5_TX").unwrap_or_else(|_| "/dev/cu.usbmodem101".into());
    let rx_port = std::env::var("C5_RX").unwrap_or_else(|_| "/dev/cu.usbmodem111401".into());
    let bw_port = std::env::var("BW16").unwrap_or_else(|_| "/dev/cu.usbserial-11110".into());

    let tx_wifi = Esp32SerialBackend::open_c5(&tx_port)?;
    let rx_wifi = Esp32SerialBackend::open_c5(&rx_port)?;
    let tx: Arc<dyn AdvBackend> = Arc::new(SharedBleBackend::new_esp32(tx_wifi.shared_mux()));
    let c5_rx: Arc<dyn AdvBackend> = Arc::new(SharedBleBackend::new_esp32(rx_wifi.shared_mux()));
    let bw16 = Arc::new(SerialRadioBackend::open(&bw_port)?);
    tokio::time::sleep(Duration::from_secs(6)).await; // the BW16 reboots on open

    // Give both receivers a wide scan so the measurement is about the PHY, not the duty cycle.
    for m in [&tx_wifi.shared_mux(), &rx_wifi.shared_mux()] {
        m.set_ble_share(0.75, 160).ok();
    }
    bw16.set_ble_share(0.75, 160).ok();
    tokio::time::sleep(Duration::from_secs(2)).await;

    let now = 1_000u64;
    println!("neighbourhood                       decided PHY   C5 rx    BW16 rx");

    // Round 1: every neighbour reports extended+coded capability.
    let all_capable = medium_hearing(&[(1, ADV_PHY_CODED), (2, ADV_PHY_CODED)], now);
    let code = decide_adv_phy(&all_capable, &granted(Priority::Urgent), ADV_PHY_CODED, now);
    let phy = AdvPhy::from_code(code);
    tx.set_adv_phy(phy)?;
    tokio::time::sleep(Duration::from_millis(800)).await;
    let (c, b) = deliver(&tx, &c5_rx, &bw16, "ALLCAP", 20).await;
    println!("  all neighbours coded-capable      {phy:?}   {c:2}/20    {b:2}/20");

    // Round 2: one legacy-only neighbour joins. Nothing else changes.
    let mixed = medium_hearing(
        &[(1, ADV_PHY_CODED), (2, ADV_PHY_CODED), (3, ADV_PHY_1M)],
        now,
    );
    let code = decide_adv_phy(&mixed, &granted(Priority::Urgent), ADV_PHY_CODED, now);
    let phy = AdvPhy::from_code(code);
    tx.set_adv_phy(phy)?;
    tokio::time::sleep(Duration::from_millis(800)).await;
    let (c, b) = deliver(&tx, &c5_rx, &bw16, "MIXED", 20).await;
    println!("  one legacy-only neighbour joins   {phy:?}   {c:2}/20    {b:2}/20");

    println!(
        "\nthe third column is the point: the legacy-only peer is served only because the decider\n\
         gave up the reach lever for it. Holding Coded would have delivered it nothing."
    );
    tx.set_adv_phy(AdvPhy::Le1M)?;
    Ok(())
}
