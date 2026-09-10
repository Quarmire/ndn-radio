//! **Run any part's canonical bring-up plan, on the record.** The replacement for `usb_probe`'s
//! bring-up half (bring-up contract §5-M8).
//!
//! ```text
//!   bringup_probe [--pid 0xa81a] [--chan N] [--role rx|txrx]
//!                 [--skip <step-id>]... [--stop-after <stage>] [--poke ADDR=VAL]...
//!                 [--raw IDX] [--report json]
//! ```
//!
//! ## Why this file exists, and what it replaces
//!
//! `usb_probe.rs` was 1084 lines with ~27 flags under the doc comment *"List USB devices"*. It was
//! **27 deviations wearing a trench coat**, and it was already a hand-written plan interpreter:
//! `--power-on --fw --mac-init --phy --cal --rx --inject` was the stage list, `--noiqk --nobbtx
//! --nocca --clearcal --txblock` was `--skip`, and `--forcemac --forcebb --txpwr --qsel --ep
//! --tone --maxgain` was `--poke`. §5-M8 splits it three ways:
//!
//! * a flag encoding a **measured fact** became a plan step, with that fact as its `why`;
//! * a flag encoding a **live question** became a [`Deviation`] with a `question` — this file;
//! * a flag encoding a **refuted hypothesis** was **deleted**, with the refutation written into
//!   the step it was testing. Those are `--txfix` and `--forcemac` (now in `R_MAC_INIT::why`),
//!   `--bbfix`/`--txblock`/`--ofdm`/`--clearcal` (in `R_BB_TX_DATAPATH_INIT::why`),
//!   `--replayh2c` (in `R_SEND_GENERAL_INFO::why`), and `--replayinit`/`--useinit`/`--forcebb`
//!   (in `R_PHY_INIT::why`). **Do not re-add them**: each cost a bench session and the answer is
//!   now in the driver where the next person will read it.
//!
//! Everything that read or dumped registers moved to `regs.rs`.
//!
//! ## What this does that the flags could not
//!
//! Every departure is *declared*: it lands in `report.provenance`, in `report.deviations` with its
//! own reason, and in `plan_digest`. A deviated run and a canonical run therefore have different
//! digests and can never be silently compared — which is exactly what went wrong when sixteen
//! private ladders were compared with each other for months.
#[cfg(feature = "libusb-backend")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use ndn_phy_wifi::{BringUpRequest, DeviceSelect, open_radio};
    use ndn_radio_drivers::bringup::{Deviation, Role, Stage};

    let args: Vec<String> = std::env::args().skip(1).collect();
    let val = |flag: &str| -> Option<String> {
        args.iter()
            .position(|a| a == flag)
            .and_then(|i| args.get(i + 1).cloned())
    };
    let all = |flag: &str| -> Vec<String> {
        args.iter()
            .enumerate()
            .filter(|(_, a)| a.as_str() == flag)
            .filter_map(|(i, _)| args.get(i + 1).cloned())
            .collect()
    };
    let hex = |s: &str| u32::from_str_radix(s.trim().trim_start_matches("0x"), 16);

    let pid: u16 = val("--pid")
        .and_then(|s| hex(&s).ok())
        .map(|v| v as u16)
        .unwrap_or(0xa81a);
    let chan: u8 = val("--chan").and_then(|s| s.parse().ok()).unwrap_or(6);
    let role = match val("--role").as_deref() {
        Some("rx") => Role::ReceiveOnly,
        Some("txrx") | None => Role::TransmitAndReceive,
        Some(other) => return Err(format!("--role: expected rx|txrx, got {other:?}").into()),
    };

    // `from_env` first, so the fleet's `NDN_*` still mean what they mean on a node; the flags below
    // then override. LAW 1 — this is the only environment read in the whole run.
    let mut req = BringUpRequest::from_env(chan).with_role(role);
    if let Some(idx) = val("--raw").and_then(|s| hex(&s).ok()) {
        // ⚠ Off the regulatory scale. Needs NDN_RF_UNRESTRICTED="<operator>:<reason>"; the
        // operator's own words are printed in the report for the life of the run.
        req.power = ndn_radio_drivers::PowerRequest::raw_from_env(idx as u8)?;
    }

    let skips = all("--skip");
    let stop = val("--stop-after");
    let pokes: Vec<(u32, u32)> = all("--poke")
        .iter()
        .filter_map(|kv| {
            let (a, v) = kv.split_once('=')?;
            Some((hex(a).ok()?, hex(v).ok()?))
        })
        .collect();

    if !skips.is_empty() || stop.is_some() || !pokes.is_empty() {
        let question = val("--question").unwrap_or_else(|| {
            format!(
                "bringup_probe: skip={skips:?} stop-after={stop:?} pokes={} — an ad-hoc bisect of \
                 the canonical plan",
                pokes.len()
            )
        });
        let mut d = Deviation::new(question);
        for id in &skips {
            d = d.skip(
                id.clone(),
                "bringup_probe --skip: an operator's bisect. What this costs is whatever the \
                 rung's own `why` says it establishes; read it in the plan before believing a \
                 number from this run.",
            );
        }
        if let Some(s) = &stop {
            let stage = match s.to_ascii_lowercase().as_str() {
                "attach" => Stage::Attach,
                "poweron" | "power-on" => Stage::PowerOn,
                "firmware" => Stage::Firmware,
                "macinit" | "mac-init" => Stage::MacInit,
                "phyinit" | "phy-init" | "phy" => Stage::PhyInit,
                "tune" => Stage::Tune,
                "calibrate" | "cal" => Stage::Calibrate,
                "txenable" | "tx-enable" => Stage::TxEnable,
                "rxenable" | "rx-enable" | "rx" => Stage::RxEnable,
                "power" => Stage::Power,
                "posture" => Stage::Posture,
                "verify" => Stage::Verify,
                other => return Err(format!("--stop-after: unknown stage {other:?}").into()),
            };
            d = d.stop_after(
                stage,
                "bringup_probe --stop-after: cut the canonical plan here. Naming a stage this \
                 plan does not label is an error, not a silent no-cut.",
            );
        }
        for (addr, v) in &pokes {
            // ⚠ `run_plan` RECORDS a poke and does not perform it — the HAL cannot name a register
            // bus. This file declares it so it changes the digest, and `regs.rs --poke` performs
            // it. Two halves, on purpose.
            d = d.poke(
                *addr,
                *v,
                32,
                "bringup_probe --poke: DECLARED here so the digest of a poked run differs from a \
                 canonical one. It is NOT executed by the runner; use `regs --poke` to write it.",
            );
        }
        req = req.with_deviation(d);
    }

    match open_radio(pid, &DeviceSelect::from_env(), &req) {
        Ok(radio) => {
            if val("--report").as_deref() == Some("json") {
                println!("{}", report_json(radio.report()));
            } else {
                println!("{}", radio.report().render());
            }
            Ok(())
        }
        // ★ §3: a failed bring-up says HOW FAR IT GOT — which rung, in which stage, with
        // everything established up to it. That is the whole reason `open_radio` returns
        // `BringUpFailure` and not `FaceError`.
        Err(f) => {
            if val("--report").as_deref() == Some("json") {
                println!("{}", report_json(&f.report));
            } else {
                println!("FAILED at `{}`\n{}", f.failed_at, f.report.render());
            }
            Err(f.into())
        }
    }
}

/// A compact machine-readable form of the report, hand-built because the HAL deliberately carries
/// no serde dependency. Enough for a shell loop to key an on-air number to the bring-up that
/// produced it: **record `plan_digest` beside every number.**
#[cfg(feature = "libusb-backend")]
fn report_json(r: &ndn_radio_drivers::BringUpReport) -> String {
    let esc = |s: &str| s.replace('\\', "\\\\").replace('"', "\\\"");
    let steps: Vec<String> = r
        .steps
        .iter()
        .map(|s| format!("{{\"id\":\"{}\",\"outcome\":\"{:?}\"}}", s.id, s.outcome))
        .collect();
    let asserts: Vec<String> = r
        .asserts
        .iter()
        .map(|a| format!("{{\"id\":\"{}\",\"ok\":{}}}", a.id, a.ok))
        .collect();
    let warns: Vec<String> = r
        .warnings
        .iter()
        .map(|w| {
            format!(
                "{{\"at\":\"{}\",\"degrades\":\"{}\"}}",
                w.at,
                esc(&w.degrades)
            )
        })
        .collect();
    format!(
        "{{\"part\":\"{}\",\"device\":\"{}\",\"plan\":\"{}\",\"plan_digest\":\"{:#018x}\",\
         \"provenance\":\"{:?}\",\"channel\":{},\"bw\":\"{:?}\",\"role\":\"{:?}\",\
         \"power\":\"{}\",\"tx_proof\":\"{}\",\"steps\":[{}],\"asserts\":[{}],\"warnings\":[{}]}}",
        r.part,
        r.device,
        r.plan,
        r.plan_digest,
        r.provenance,
        r.state.channel,
        r.state.bw,
        r.state.role,
        esc(&r.state.power.render()),
        esc(&r.tx.render()),
        steps.join(","),
        asserts.join(","),
        warns.join(","),
    )
}

#[cfg(not(feature = "libusb-backend"))]
fn main() {
    eprintln!("build with --features libusb-backend");
    std::process::exit(1);
}
