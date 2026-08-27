//! **ESP32-C6 BLE PHY → the Mac's own Bluetooth.** Two real named-radio BLE PHYs across two different
//! stacks: the **C6** (Espressif NimBLE, driven over its serial bridge) advertises named data via the ND
//! manufacturer AD (company `0x4E44`), and the **Mac's built-in Bluetooth** ([`MacBleBackend`], Apple
//! CoreBluetooth via btleplug) scans and decodes it. This is how we validate a C6 BLE PHY on air without
//! a second ESP board — the peer is the host radio itself.
//!
//! The Mac PHY is receive-only on the adv bearer (CoreBluetooth won't broadcast manufacturer data — see
//! [`MacBleBackend`]), so the direction is fixed: C6 transmits, Mac receives. We broadcast a distinct
//! payload per round and count how many the Mac hears.
//!
//! ```sh
//! WL_C6=/dev/cu.usbmodem2101 NDR_ROUNDS=20 \
//!   cargo run --example ble_c6_mac --features shared-mux,mac -p ndn-phy-ble
//! ```
//! The C6 must run the unified `firmware/esp32c5-ndn` (built for esp32c6). macOS will ask for Bluetooth
//! permission for the terminal the first time — grant it, or scanning yields nothing.
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use ndn_phy_ble::{AdvBackend, MacBleBackend, SharedBleBackend};
use ndn_radio_drivers::Esp32SerialBackend;

#[tokio::main(flavor = "multi_thread", worker_threads = 4)]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let port = std::env::var("WL_C6").unwrap_or_else(|_| "/dev/cu.usbmodem2101".into());
    let rounds: u32 = std::env::var("NDR_ROUNDS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(20);

    // The C6 as a BLE advertiser (TX), over its serial bridge (unified firmware, shared Wi-Fi/BLE mux).
    let wifi = Arc::new(Esp32SerialBackend::open_c5(&port)?);
    let c6: Arc<dyn AdvBackend> = Arc::new(SharedBleBackend::new(wifi.shared_mux()));

    // The Mac's own Bluetooth as the receiver (RX): CoreBluetooth scan for ND manufacturer adverts.
    let mac = Arc::new(MacBleBackend::open().await?);

    // Drain ALL scanned adverts in the background into a set. Decoupling reception from the send loop is
    // the honest way to measure: CoreBluetooth batches/delays advert callbacks, so a tight per-round
    // window under-counts (a late-delivered advert looks like the "wrong round" and gets discarded).
    let received: Arc<tokio::sync::Mutex<std::collections::HashSet<Vec<u8>>>> = Arc::default();
    {
        let (mac, received) = (mac.clone(), received.clone());
        tokio::spawn(async move {
            while let Ok(sf) = mac.next_scanned().await {
                received.lock().await.insert(sf.frame.to_vec());
            }
        });
    }

    let reps: u32 = std::env::var("NDR_REPS").ok().and_then(|v| v.parse().ok()).unwrap_or(3);
    println!("C6 (serial {port}) advertises → the Mac's Bluetooth scans. {rounds} names × {reps} reps.");
    tokio::time::sleep(Duration::from_millis(1500)).await; // NimBLE ext-adv + CoreBluetooth spin-up

    // Each Data is re-advertised `reps` times — the firmware burst is only ~90 ms, so a single broadcast
    // easily falls between CoreBluetooth scan windows. A real producer keeps a Data advertised until it is
    // fetched or expires; this mimics that briefly.
    for r in 0..rounds {
        let payload = format!("C6-BLE->MAC #{r}").into_bytes();
        for _ in 0..reps {
            c6.broadcast(Bytes::from(payload.clone())).await.ok();
            tokio::time::sleep(Duration::from_millis(60)).await;
        }
        tokio::time::sleep(Duration::from_millis(120)).await;
    }
    tokio::time::sleep(Duration::from_millis(1500)).await; // let the last adverts drain

    let got = received.lock().await;
    let hits = (0..rounds).filter(|r| got.contains(format!("C6-BLE->MAC #{r}").as_bytes())).count();
    println!("\n  Mac Bluetooth received {hits}/{rounds} distinct named Data from the C6 BLE PHY.");
    println!("  → C6 (NimBLE) TX ↔ Mac (CoreBluetooth) RX: named data over BLE across two stacks.");
    std::process::exit(if hits > 0 { 0 } else { 1 });
}
