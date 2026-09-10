//! **The register surface**: enumerate USB, identify the silicon, dump and compare register
//! blocks, poke, and drive the RF test tones. The other half of the `usb_probe` split
//! (bring-up contract §5-M8); the plan half is `bringup_probe.rs`.
//!
//! ```text
//!   regs                         # enumerate USB + read identity registers (no bring-up)
//!   regs --all                   # ... including non-Realtek devices
//!   regs --power-domain          # the post-power-on power/clock block (was --regs)
//!   regs --macdump               # 0x0000..0x2000 as dwords, for diffing against a capture
//!   regs --txstate               # the TX-engine control regs vs the golden kernel values
//!   regs --efuse                 # physical EFUSE -> logical map -> MAC (was --mac)
//!   regs --tone [--carrier] [--maxgain] [--chan N] [--secs N]
//!   regs --poke ADDR=VAL ...     # write, after a canonical bring-up
//!   regs --qsel N  --ep N        # TX queue selector / bulk-OUT endpoint overrides
//! ```
//!
//! ## What is NOT here
//!
//! Anything that composed its own bring-up. Every arm below that needs a live radio runs
//! `bring_up_planned` — the ONE plan for the part — because a register read taken after a
//! *different* sequence is a reading of a different radio, and that is precisely how sixteen
//! private ladders came to be compared with each other.
//!
//! Five flags from `usb_probe` are deleted rather than ported, because their hypotheses are
//! refuted: `--txfix`, `--forcemac`, `--bbfix`, `--replayh2c`, `--replayinit`/`--useinit`
//! (and `--forcebb`, which additionally crashed the dongle off USB). Each refutation is written
//! into the `why` of the plan step it was testing, in `ndn-radio-drivers/src/libusb_rtl88xx.rs`.
#[cfg(feature = "libusb-backend")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use ndn_phy_wifi::{LibUsbRtl88xxBackend, REG_SYS_CFG};
    use ndn_radio_drivers::bringup::{ProofRequirement, Role};
    use rusb::UsbContext;

    let args: Vec<String> = std::env::args().skip(1).collect();
    let has = |f: &str| args.iter().any(|a| a == f);
    let val = |f: &str| -> Option<String> {
        args.iter()
            .position(|a| a == f)
            .and_then(|i| args.get(i + 1).cloned())
    };
    let all = |f: &str| -> Vec<String> {
        args.iter()
            .enumerate()
            .filter(|(_, a)| a.as_str() == f)
            .filter_map(|(i, _)| args.get(i + 1).cloned())
            .collect()
    };
    let hex = |s: &str| u32::from_str_radix(s.trim().trim_start_matches("0x"), 16);

    // ── 1. Enumerate, with no hardware claimed ───────────────────────────────────────────────
    let ctx = rusb::Context::new()?;
    for dev in ctx.devices()?.iter() {
        let d = dev.device_descriptor()?;
        let realtek = d.vendor_id() == 0x0bda;
        if realtek || has("--all") {
            println!(
                "bus {:03} addr {:03}  {:04x}:{:04x}  class {:#04x}{}",
                dev.bus_number(),
                dev.address(),
                d.vendor_id(),
                d.product_id(),
                d.class_code(),
                if realtek { "  <-- Realtek" } else { "" }
            );
        }
        if realtek {
            match dev.open() {
                Ok(_h) => match dev.active_config_descriptor() {
                    Ok(cfg) => {
                        for iface in cfg.interfaces() {
                            for id in iface.descriptors() {
                                for ep in id.endpoint_descriptors() {
                                    println!(
                                        "    iface {} ep {:#04x} {:?} {:?} mps {}",
                                        id.interface_number(),
                                        ep.address(),
                                        ep.direction(),
                                        ep.transfer_type(),
                                        ep.max_packet_size(),
                                    );
                                }
                            }
                        }
                    }
                    Err(e) => println!("    (no active config: {e})"),
                },
                Err(e) => println!("    (cannot open: {e})"),
            }
        }
    }

    // ── 2. Claim the backend and read identity — still no bring-up ───────────────────────────
    let mut radio = match LibUsbRtl88xxBackend::open() {
        Ok(r) => std::sync::Arc::new(r),
        Err(e) => {
            println!("\nbackend open failed: {e}");
            return Ok(());
        }
    };
    println!("\nbackend opened; identity registers (no bring-up has run):");
    for (name, addr) in [
        ("REG_SYS_ISO_CTRL(0x00)", 0x0000u16),
        ("REG_SYS_FUNC_EN(0x02)", 0x0002),
        ("REG_SYS_CFG(0xF0)", REG_SYS_CFG),
        ("REG_SYS_CFG2(0xFC)", 0x00fc),
    ] {
        match radio.read32(addr) {
            Ok(v) => println!("  {name:24} = {v:#010x}"),
            Err(e) => println!("  {name:24} = ERR {e}"),
        }
    }
    match radio.chip_info() {
        Ok(i) => println!(
            "  chip_id {:#04x} cut {}  sys_cfg {:#010x}",
            i.chip_id, i.cut, i.sys_cfg
        ),
        Err(e) => println!("  chip_info ERR {e}"),
    }

    // Anything past here needs a live radio, so it needs THE plan.
    let needs_radio = has("--power-domain")
        || has("--macdump")
        || has("--txstate")
        || has("--efuse")
        || has("--tone")
        || !all("--poke").is_empty();
    if !needs_radio {
        return Ok(());
    }

    let chan: u8 = val("--chan").and_then(|s| s.parse().ok()).unwrap_or(6);
    // ★ ONE call, the canonical `PLAN_A81A`. Every readback below is therefore a reading of the
    // SAME radio the shipped node runs — which is the only way a "golden vs ours" table means
    // anything at all.
    let (report, _guards) = radio.bring_up_planned(
        chan,
        Role::TransmitAndReceive,
        ndn_radio_drivers::a81a_env_deviation(),
        ProofRequirement::BestAvailable,
    )?;
    println!("\n{}", report.render());

    if has("--power-domain") {
        // The power/clock-domain registers, in the same set read live from the working kernel
        // driver on OPi-0 (debugfs read_reg) — diff these to find an enable this init still misses.
        println!("\npower/clock-domain block:");
        for addr in [
            0x0000u16, 0x0004, 0x0008, 0x0010, 0x001c, 0x0028, 0x0030, 0x0034, 0x0040, 0x004c,
            0x0064, 0x00ec, 0x00f0, 0x00f4, 0x00fc, 0x0100, 0x1018, 0x1044, 0x1064, 0x1080, 0x1100,
        ] {
            match radio.read32(addr) {
                Ok(v) => println!("  {addr:#06x} = {v:#010x}"),
                Err(e) => println!("  {addr:#06x} = ERR {e}"),
            }
        }
    }

    // Pokes: the write half of `bringup_probe --poke`, which only DECLARES them (the runner cannot
    // name a register bus). Declare there, write here, and the digest of the run says a poke
    // happened either way.
    for kv in all("--poke") {
        let Some((a, v)) = kv.split_once('=') else {
            continue;
        };
        let (addr, val32) = (hex(a)? as u16, hex(v)?);
        radio.write32(addr, val32)?;
        println!("poked {addr:#06x} = {val32:#010x}");
    }

    if let Some(q) = val("--qsel").and_then(|s| hex(&s).ok()) {
        // The TX queue selector (default MGT 0x12; BE = 0x00 is a normal EDCA data queue).
        radio.set_tx_qsel(q as u8);
        println!("TX qsel = {q:#x}");
    }
    if let Some(ep) = val("--ep").and_then(|s| hex(&s).ok()) {
        // ☠ The bulk-OUT endpoint is NOT a live question on the RTL8812AU: all three of its OUT
        // endpoints were swept against a witness and all three put 0 frames on the air. It stays
        // reachable here for the 88xx, whose HIGH/NORMAL/LOW queues map to different hardware DMA
        // queues, but a result from it is "which queue", never "which endpoint radiates".
        //
        // The one `&mut self` call in this file. Sound because this is the only `Arc` to the
        // backend, and it fails loudly rather than silently skipping if that stops being true.
        std::sync::Arc::get_mut(&mut radio)
            .expect("regs holds the only Arc to the backend")
            .set_bulk_out(ep as u8);
        println!("bulk-OUT endpoint = {ep:#x}");
    }

    if has("--txstate") {
        // The TX-engine control registers vs the working kernel driver's end-of-init values — the
        // master TX state machine, where a GLOBAL stall lives (a per-queue one does not).
        println!("\nTX-engine control (golden = working kernel driver):");
        for (name, addr, golden) in [
            ("REG_CR(0x100)", 0x0100u16, 0x0000_06ffu32),
            ("REG_PTCL(0x520)", 0x0520, 0x0000_2f0f),
            ("REG_TXBUF(0x600)", 0x0600, 0x0400_4000),
            ("REG_TCR(0x604)", 0x0604, 0x0030_3000),
            ("REG_RCR(0x608)", 0x0608, 0x9000_0001),
            ("REG_TX_RPT(0x60c)", 0x060c, 0x8500_0418),
        ] {
            let v = radio.read32(addr).unwrap_or(0);
            let flag = if v == golden { "==golden" } else { "DIFF" };
            println!("  {name:18} = {v:#010x}  (golden {golden:#010x}) {flag}");
        }
        // ⚠ Real TX-activity registers, verified to change on the WORKING OPi when it transmits.
        // 0x2de0 is NOT one of them — it stays 0 there mid-transmit, and an example once printed
        // it as "TX activity". Queue pages (FIFOPAGE_INFO_1/2/3 [27:16]) drop if frames pile up
        // unTX'd.
        let txregs = [0x2d00u16, 0x2d04, 0x2d08, 0x2d20, 0x2d24, 0x2de4];
        let txstat = || {
            txregs
                .iter()
                .map(|&a| format!("{a:#06x}={:#x}", radio.read32(a).unwrap_or(0)))
                .collect::<Vec<_>>()
                .join(" ")
        };
        let pages = || {
            let r = |a: u16| (radio.read32(a).unwrap_or(0) >> 16) & 0xfff;
            format!("HQ={} LQ={} NQ={}", r(0x230), r(0x234), r(0x238))
        };
        println!("  TX-activity: {}", txstat());
        println!("  queue pages: {}", pages());
    }

    if has("--macdump") {
        // The whole MAC register space as dwords, so it can be diffed against a capture to find a
        // TX-scheduler/EDCA gate that is not in the golden value dump.
        for addr in (0x0u16..0x2000).step_by(4) {
            let v = radio.read32(addr).unwrap_or(0xdead_beef);
            println!("MACDUMP {addr:#06x} {v:#010x}");
        }
    }

    if has("--tone") {
        // A continuous carrier so an SDR can confirm the PA radiates at all. The bring-up above
        // already configured RF and set the channel — this file no longer runs its own.
        let secs: u64 = val("--secs").and_then(|s| s.parse().ok()).unwrap_or(8);
        match radio.single_tone(true) {
            Ok(()) => println!("single_tone ON — carrier {secs}s on ch{chan}"),
            Err(e) => println!("single_tone FAILED: {e}"),
        }
        if has("--maxgain") {
            // Crank the digital TX gain: OFDM TX-AGC reference (0x18e8/0x41e8 [16:10]) plus the BB
            // TX scaling (0x81c [20:14]). If the single carrier strengthens in the FFT, digital
            // gain is the lever for a weak modulated output.
            for reg in [0x18e8u16, 0x41e8] {
                let v = radio.read32(reg).unwrap_or(0) & !0x0001_fc00;
                let _ = radio.write32(reg, v | (0x3f << 10));
            }
            let v = radio.read32(0x81c).unwrap_or(0) & !0x001f_c000;
            let _ = radio.write32(0x81c, v | (0x3f << 14));
            println!("  cranked digital TX gain (0x18e8/0x41e8/0x81c)");
        }
        if has("--carrier") {
            // Also drive the BB OFDM modulator. If the SDR spectrum gains an offset subcarrier vs
            // the bare tone, the BB -> DAC -> RF datapath works.
            match radio.single_carrier(true) {
                Ok(()) => println!("single_carrier ON (BB modulator)"),
                Err(e) => println!("single_carrier FAILED: {e}"),
            }
        }
        std::thread::sleep(std::time::Duration::from_secs(secs));
        let _ = radio.single_carrier(false);
        let _ = radio.single_tone(false);
        println!("tone/carrier OFF");
    }

    if has("--efuse") {
        // Full physical EFUSE dump -> logical map decode -> MAC. Diff the logical rows against the
        // golden kernel-driver dump in `golden/opi0-2026-06-12/efuse_map.txt` (MAC = logical
        // 0x157, 78:22:88:d9:93:e6 on the testbed dongle).
        match radio.efuse_dump_physical() {
            Ok(physical) => {
                println!("physical EFUSE: {} bytes read", physical.len());
                match LibUsbRtl88xxBackend::efuse_decode_logical(&physical) {
                    Ok(logical) => {
                        for base in (0x000..0x0d0).step_by(16).chain((0x100..0x180).step_by(16)) {
                            print!("logical[{base:#05x}] =");
                            for b in &logical[base..base + 16] {
                                print!(" {b:02x}");
                            }
                            println!();
                        }
                        let m = &logical[0x157..0x15d];
                        println!(
                            "MAC @0x157 = {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                            m[0], m[1], m[2], m[3], m[4], m[5]
                        );
                    }
                    Err(e) => println!("logical decode ERR {e}"),
                }
            }
            Err(e) => println!("physical dump ERR {e}"),
        }
    }

    Ok(())
}

#[cfg(not(feature = "libusb-backend"))]
fn main() {
    eprintln!("build with --features libusb-backend");
    std::process::exit(1);
}
