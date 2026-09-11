//! The named-data-radio **cognition** telemetry as a generic mgmt introspection
//! surface.
//!
//! The radio control plane *actuates* its radios itself (rate / channel / power /
//! FEC, decided every ~500 ms), so an operator UI should **observe what cognition
//! decided**, not offer manual radio knobs. This adapter exposes a live, read-only
//! snapshot of [`RadioControl::telemetry`] through the sans-io [`ControlSurface`]
//! trait — served generically by the mgmt server under `/localhost/nfd/ext/list`
//! as `key=value` text (no protobuf; trivial to consume from a WASM dashboard).
//!
//! It holds an `Arc<RadioControl>` (a separate handle from the one the cognition
//! loop runs on) and reads a fresh snapshot per `stats()` call — `telemetry()` is
//! `&self` and only briefly locks `last_plans`, so it is safe to call at any
//! cadence from the mgmt dispatch thread.

use std::sync::Arc;

use ndn_mgmt_wire::control_surface::{ControlInfo, ControlStats, ControlSurface};

use crate::control::RadioControl;

/// `ControlSurface` adapter over the radio cognition control plane.
///
/// Registered with the engine via `MgmtHandles::control_surfaces`; the mgmt server
/// renders it under the `[named-radio]` section of the `/localhost/nfd/ext/list`
/// dataset. Read-only — `set_option` stays the trait default (rejects).
pub struct RadioCognitionSurface {
    control: Arc<RadioControl>,
}

impl RadioCognitionSurface {
    /// Wrap a shared radio control handle. Cheap; clone the `Arc` you already have.
    pub fn new(control: Arc<RadioControl>) -> Self {
        Self { control }
    }
}

/// `Option<T>` → display string, `"-"` for `None` (matches the trace-site
/// `?a.channel` debug intent while staying human/parse friendly).
fn opt<T: std::fmt::Display>(v: Option<T>) -> String {
    v.map(|x| x.to_string()).unwrap_or_else(|| "-".to_string())
}

impl ControlSurface for RadioCognitionSurface {
    fn name(&self) -> &str {
        "named-radio"
    }

    fn describe(&self) -> ControlInfo {
        let t = self.control.telemetry();
        ControlInfo {
            caps: vec![
                ("subsystem".into(), "named-radio-cognition".into()),
                ("strategy".into(), t.strategy.into()),
                ("actuation".into(), "rate+channel+power+fec".into()),
                ("readonly".into(), "true".into()),
            ],
            // Read-only: cognition owns actuation; the UI observes, it does not set.
            options: Vec::new(),
        }
    }

    fn stats(&self) -> ControlStats {
        let t = self.control.telemetry();
        let mut e: Vec<(String, String)> = Vec::new();

        // --- Actual radio TX egress (distinct from the forwarder's per-face `out`, which counts
        //     only FORWARDED traffic; cognition self-reports are injected directly). Surfaced so
        //     `out=0` is never misread as a silent radio (field 2026-09-10). ---
        let tx = crate::medium::tx_egress_snapshot();
        e.push(("radio_tx_injected_ok".into(), tx.done_ok.to_string()));
        e.push(("radio_tx_injected_err".into(), tx.done_err.to_string()));
        e.push(("radio_tx_robust_bypassed".into(), tx.bypassed.to_string()));
        e.push(("radio_rx_received".into(), tx.received.to_string()));

        // --- Aggregate cognition state ---
        e.push(("strategy".into(), t.strategy.into()));
        e.push(("managed_objects".into(), t.managed_objects.to_string()));
        e.push(("suppressed".into(), t.suppressed.to_string()));
        e.push(("objective".into(), format!("{:.4}", t.objective)));
        if let Some(th) = t.learned_thresholds {
            let joined = th
                .iter()
                .map(|v| format!("{v:.1}"))
                .collect::<Vec<_>>()
                .join(",");
            e.push(("learned_thresholds".into(), joined));
        }

        // --- Per-radio DECIDED plan (what cognition actuated) ---
        // Flatten every allocation across the active plans keyed by radio id, using
        // the exact accessors the decision trace site emits (control.rs "radio:
        // decision"): channel, mcs, nss, bw, he, tx_power, link_fec + plan flags.
        for plan in &t.plans {
            for a in &plan.allocations {
                let id = a.radio.0;
                let k = |field: &str| format!("radio.{id}.{field}");
                e.push((k("channel"), opt(a.channel)));
                e.push((k("mcs"), opt(a.params.mcs())));
                e.push((k("nss"), opt(a.params.nss())));
                e.push((k("bw"), opt(a.params.bw())));
                e.push((k("he"), a.params.he().to_string()));
                e.push((k("tx_power"), opt(a.params.tx_power)));
                e.push((k("link_fec"), opt(a.params.link_fec_redundancy)));
                // ★ The two shared-medium claims, surfaced beside the decision so the ledger
                // counters below have something to be compared AGAINST. They were absent: an
                // operator could see the power back-off and the parity budget but not whether this
                // node had stopped deferring to a busy channel — the loudest thing it can do.
                e.push((k("edcca_ignore"), a.params.edcca_ignore().to_string()));
                e.push((
                    k("defer_threshold_dbm"),
                    a.params
                        .edcca_threshold_dbm
                        .map(|(l2h, h2l)| format!("{l2h}/{h2l}"))
                        .unwrap_or_else(|| "-".to_string()),
                ));
                e.push((k("suppress"), plan.suppress.to_string()));
                e.push((k("relay"), plan.relay.to_string()));
                e.push((k("objective"), format!("{:.4}", plan.objective)));
                // Occupancy is keyed by the operating channel, which the plan holds.
                if let Some(ch) = a.channel
                    && let Some(busy) = self.control.busy_pct(a.radio, ch)
                {
                    e.push((k("occupancy_pct"), busy.to_string()));
                }
            }
        }

        // --- ACTUATOR-SIDE LEDGER (what actually reached silicon) ---
        //
        // The half the decision trace cannot supply. `contention.edcca_ignored` rising while every
        // `radio.N.edcca_ignore` above reads `false` is a medium claim that did not come from this
        // node's policy; `defer_threshold_clamped` is sharper still, because a threshold outside the
        // decidable band cannot have been produced by `decide_edcca_threshold_dbm` at all. Not an
        // equation — one decision fans out per radio and knobs are re-pushed only on change — so
        // read them as "did this move at all". NOT MEASURED on air.
        let led = ndn_radio_cognition::ledger::counts();
        e.push((
            "contention.edcca_ignored".into(),
            led.edcca_ignored.to_string(),
        ));
        e.push((
            "contention.defer_threshold_clamped".into(),
            led.defer_threshold_clamped.to_string(),
        ));
        e.push((
            "contention.fec_parity_over_generation".into(),
            led.fec_parity_over_generation.to_string(),
        ));

        // --- Per-radio HARDWARE SUBSTRATE (what cognition acts on) ---
        // The device capability + weakest recently-heard RSSI, distinct from the
        // decided plan above. Keys the operator dashboard's Hardware view reads;
        // chip name / driver / USB address / link-state / frame counters are not
        // yet reachable from the control plane, so they are simply not emitted
        // (the consumer renders them as "not reported").
        for (id, cap, rssi) in self.control.radio_hardware() {
            let id = id.0;
            let k = |field: &str| format!("radio.{id}.{field}");
            // `kind` is a radio *class* (WifiMonitor/Lora/…), the best chip label available.
            e.push((k("chip"), format!("{:?}", cap.kind)));
            e.push((
                k("band"),
                cap.bands
                    .iter()
                    .map(|b| format!("{b:?}"))
                    .collect::<Vec<_>>()
                    .join(","),
            ));
            e.push((k("max_mcs"), cap.max_mcs().to_string()));
            // No spatial-stream count on the capability; max_nss is the proxy.
            e.push((k("rx_chains"), cap.max_nss().to_string()));
            e.push((k("he_cap"), cap.he_cap.to_string()));
            if let Some(dbm) = cap.tx_power_dbm {
                e.push((k("dbm_max"), dbm.max.to_string()));
            }
            e.push((k("duty_max"), format!("{:.2}", cap.duty_cycle_max)));
            e.push((k("rx_only"), cap.rx_only.to_string()));
            if let Some(r) = rssi {
                e.push((k("rssi_dbm"), r.to_string()));
            }
        }

        ControlStats { entries: e }
    }
}
