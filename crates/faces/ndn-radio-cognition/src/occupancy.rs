//! **Frame-free occupancy sensing** (#30) — the bearer-agnostic half of the SENSE plane.
//!
//! A radio that can count channel activity *without the host decoding frames* gives the
//! policy real medium load for free: two reads of a free-running counter, differenced over
//! a window, become a frames/s rate, and [`ChannelOccupancy::from_activity`] maps that to
//! channel-busy%. The 8812au backs it with `REG_RXERR_RPT` (`0x0664`, validated to track the
//! decoded-frame rate ~1:1); a LoRa node backs it with the 7E-A5 `CMD_SENSE` opcode; a radio
//! with no such counter answers `Ok(None)` and is simply never sampled.
//!
//! **Why this lives here and not in a PHY crate.** Everything below reaches the radio only
//! through [`RadioKnobs::read_channel_activity`] — the shared HAL control-plane trait — and
//! feeds only the cognition sense bus. Nothing in it is 802.11. It used to live in
//! `ndn-phy-wifi::control`, which meant a **LoRa** PHY had to depend on the **Wi-Fi** crate to
//! sense its own channel; that inverts the named-radio rule that shared MAC primitives are
//! bearer-agnostic and live beside [`ChannelOccupancy`] / [`MediumState`]. `ndn-phy-wifi`
//! re-exports both items, so every existing call site is unchanged.
//!
//! Dependency direction: `ndn-radio-cognition` already depends on `ndn-radio-hal` (for
//! `RadioCapability` / `Band` / `RadioKind`), and `ndn-radio-hal` depends only on
//! `ndn-transport` + `ndn-time` + `bytes` + `async-trait`. So reaching `RadioKnobs` from here
//! adds **no** new edge and cannot close a cycle: the layering is
//! `ndn-rs` ← `ndn-radio-drivers` (HAL) ← `ndn-radio` (cognition, PHYs) ← apps.

use crate::{ChannelOccupancy, DEFAULT_SATURATION_FPS, MediumState, MediumView, RadioId};

/// frames/s from two `REG_RXERR_RPT`-style counter samples `dt_s` apart, u16
/// wrap-aware (the counter is a 16-bit hardware accumulator that rolls over).
/// The pure core of frame-free occupancy sensing (#30).
pub fn activity_rate(prev: u16, cur: u16, dt_s: f32) -> f32 {
    if dt_s <= 0.0 {
        return 0.0;
    }
    cur.wrapping_sub(prev) as f32 / dt_s
}

/// Where a sampled activity rate lands: the SENSE-bus end of frame-free occupancy.
///
/// A seam rather than a concrete type because the two ends that exist today are different
/// shapes — the Wi-Fi face's `RadioControl` (which owns a `Mutex<MediumState>` plus a policy)
/// and a bare shared [`MediumState`] a LoRa/BLE wiring site holds directly. Both mean the
/// same thing to the sampler: *take this frames/s reading for `(radio, channel)`*.
pub trait OccupancySink: Send + Sync + 'static {
    /// Feed one frame-free occupancy sample. Implementors map it through
    /// [`ChannelOccupancy::from_activity`] with their own saturation constant.
    fn observe_activity(&self, radio: RadioId, channel: u8, frames_per_s: f32, now_ms: u64);

    /// Current sensed busy% for `(radio, channel)`, if observed — telemetry only (the
    /// sampler traces it); returning `None` is always safe.
    fn busy_pct(&self, radio: RadioId, channel: u8) -> Option<u8>;
}

/// The plain shared sense bus as a sink — what a wiring site uses when it holds a
/// [`MediumState`] directly rather than a face-specific control plane (the LoRa/BLE case).
/// Saturation is [`DEFAULT_SATURATION_FPS`]; a site with a calibrated figure should feed
/// [`MediumState::observe_occupancy`] itself.
///
/// A poisoned lock is dropped silently: an occupancy sample is a *hint*, and killing the
/// sampler (or the process) over one lost hint would be worse than missing it.
impl OccupancySink for std::sync::Mutex<MediumState> {
    fn observe_activity(&self, radio: RadioId, channel: u8, frames_per_s: f32, now_ms: u64) {
        if let Ok(mut m) = self.lock() {
            m.observe_occupancy(ChannelOccupancy::from_activity(
                radio,
                channel,
                frames_per_s,
                DEFAULT_SATURATION_FPS,
                now_ms,
            ));
        }
    }

    fn busy_pct(&self, radio: RadioId, channel: u8) -> Option<u8> {
        self.lock().ok().and_then(|m| m.busy_pct(radio, channel))
    }
}

#[cfg(feature = "occupancy-sampler")]
mod sampler {
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use ndn_radio_hal::RadioKnobs;
    use tracing::Instrument;

    use super::{OccupancySink, activity_rate};
    use crate::RadioId;

    /// Spawn a background **frame-free occupancy sampler**: every `interval`, read the
    /// radio's activity counter ([`RadioKnobs::read_channel_activity`])
    /// off the inject hot path, difference it into frames/s ([`activity_rate`]), and
    /// feed it to the sense bus ([`OccupancySink::observe_activity`]) so the policy
    /// decides on real medium load. A radio that returns `None` (no such counter) is
    /// polled once and the task exits — nothing to sample. `now_ms` supplies the
    /// sense-bus timestamp. The blocking read (a USB control transfer on Wi-Fi, a serial
    /// command round-trip on a LoRa bridge) runs on `spawn_blocking`, so the sampler never
    /// stalls the runtime.
    ///
    /// Bearer-agnostic in both directions: `knobs` is the HAL trait object every backend
    /// implements, and `sink` is any [`OccupancySink`] — the Wi-Fi `RadioControl`, or a
    /// shared `Mutex<MediumState>` on a LoRa/BLE node.
    pub fn spawn_occupancy_sampler<S>(
        sink: Arc<S>,
        radio: RadioId,
        channel: u8,
        knobs: Arc<dyn RadioKnobs>,
        interval: Duration,
        now_ms: impl Fn() -> u64 + Send + 'static,
    ) -> tokio::task::JoinHandle<()>
    where
        S: OccupancySink + ?Sized,
    {
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            let mut prev: Option<(u16, Instant)> = None;
            loop {
                ticker.tick().await;
                let k = knobs.clone();
                // Time the frame-free counter read (a device round-trip, off the hot
                // path) as its own span under the sampler.
                let read = tokio::task::spawn_blocking(move || k.read_channel_activity())
                    .instrument(
                        tracing::debug_span!(target: "named_radio", "occupancy_read", radio = radio.0),
                    )
                    .await;
                let cur = match read {
                    Ok(Ok(Some(v))) => v,
                    Ok(Ok(None)) => return, // this radio can't sense occupancy — stop
                    _ => continue,          // transient read / join error — retry next tick
                };
                let now = Instant::now();
                if let Some((p, t)) = prev {
                    let dt = now.duration_since(t).as_secs_f32();
                    let fps = activity_rate(p, cur, dt);
                    let ts = now_ms();
                    sink.observe_activity(radio, channel, fps, ts);
                    // Frame-free occupancy is a first-class sensed signal — trace it so
                    // the OTLP span pipeline (ndn-observability) can carry "what the
                    // radio saw" alongside the DECIDE that consumes it.
                    tracing::debug!(
                        target: "named_radio",
                        radio = radio.0,
                        channel,
                        frames_per_s = fps,
                        busy_pct = sink.busy_pct(radio, channel),
                        "occupancy_sample"
                    );
                }
                prev = Some((cur, now));
            }
        })
    }
}

#[cfg(feature = "occupancy-sampler")]
pub use sampler::spawn_occupancy_sampler;

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    const W: RadioId = RadioId(0);

    #[test]
    fn wrap_aware_rate() {
        // Counter 65530 → 10 over 1 s is 16 frames/s, not a negative spike.
        assert_eq!(activity_rate(65530, 10, 1.0), 16.0);
        assert_eq!(activity_rate(1000, 1000, 1.0), 0.0);
        assert_eq!(activity_rate(0, 100, 0.0), 0.0, "no divide-by-zero");
    }

    /// E1: the sense bus itself is a sink, so a bearer with no face-specific control
    /// plane (LoRa, BLE) can be sampled without a Wi-Fi type anywhere in the path.
    #[test]
    fn a_bare_medium_state_is_an_occupancy_sink() {
        let bus: Mutex<MediumState> = Mutex::new(MediumState::new());
        // 50 frames/s at the default 100-fps saturation → 50% busy, which is exactly the
        // number the policy reads for least-busy channel selection / EDCCA.
        bus.observe_activity(W, 6, activity_rate(1000, 1050, 1.0), 0);
        assert_eq!(OccupancySink::busy_pct(&bus, W, 6), Some(50));
        // A quiet channel reads 0% — the whole point of sensing without decoding.
        bus.observe_activity(W, 11, 0.0, 0);
        assert_eq!(OccupancySink::busy_pct(&bus, W, 11), Some(0));
        // Never observed ⇒ None, not a fabricated 0.
        assert_eq!(OccupancySink::busy_pct(&bus, W, 1), None);
    }
}
