//! Contextual bandit — the joint-axis tuning rung above single-axis calibration.
//!
//! Single-axis online calibration ([`crate::RateCalibrator`]) learns one cliff at a
//! time (per-MCS RSSI). But the knobs *interact*: rate ↔ power (raise power to raise
//! rate and shorten airtime, vs. lower power for spatial reuse), rate ↔ FEC
//! (robustness via a lower rate or via more parity). Hand-rules pick a fixed
//! priority order (we max rate, then trim power) — which the airtime harness showed
//! is not always optimal. A contextual bandit *learns the joint operating point per
//! situation* from the measured reward.
//!
//! Deliberately simple and embedded-friendly: a **tabular UCB1** bandit over a
//! discretized context, a handful of interpretable arms, no RNG (UCB exploration is
//! deterministic), no model. It sits **on top of** [`crate::RadioPolicy`] — the
//! policy produces the baseline plan, the bandit nudges the joint axes and learns —
//! so the architecture doesn't change; it's a drop-in beside the policy, exactly
//! like the calibrator. Reward is the optimand: **airtime per satisfied Interest**,
//! plus a small **footprint** term so spatial reuse (lower power) is valued, since
//! lowering power costs no airtime and a pure-airtime reward would ignore it.

use std::collections::HashMap;

use crate::plan::TxParams;
use crate::policy::NameContext;

/// dB per chip TXAGC index (mirrors the policy's power model).
// See the note where this constant used to live in `policy.rs`: a single global dB-per-index step
// was wrong on every radio it was applied to. The arm renders through the part's own MEASURED
// scale, and a part without one gets no power arm at all.
/// Reward penalty for a delivery miss (≫ any airtime term so misses dominate).
pub const MISS_PENALTY: f32 = 5.0;
/// Weight of the spatial-footprint (power) term in the reward — small, so it breaks
/// ties toward lower power without overriding delivery/airtime.
pub const FOOTPRINT_LAMBDA: f32 = 0.3;

/// A joint adjustment to the policy's baseline operating point.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Arm {
    pub mcs_delta: i8,
    pub power_backoff_db: i8,
    pub fec_delta: i8,
}

/// The reasoning behind one [`ContextualBandit::select_traced`] decision — the decision-observability
/// record. `scores` is the per-arm UCB value at decision time (`+∞` marks an unpulled arm forced by
/// exploration); `cold_start` is true whenever any arm was still unpulled; `pulls` is how many times
/// this context has been seen. Emit it as a span/event to watch the bandit learn.
#[derive(Clone, Copy, Debug)]
pub struct ArmChoice {
    pub arm: usize,
    pub scores: [f32; ARMS.len()],
    pub cold_start: bool,
    pub pulls: u32,
}

/// The arm set spanning the rate × power × FEC tradeoff around the baseline.
pub const ARMS: [Arm; 5] = [
    Arm {
        mcs_delta: 0,
        power_backoff_db: 0,
        fec_delta: 0,
    }, // 0: baseline (trust the policy)
    Arm {
        mcs_delta: -1,
        power_backoff_db: 0,
        fec_delta: 0,
    }, // 1: more robust rate
    Arm {
        mcs_delta: 1,
        power_backoff_db: 0,
        fec_delta: 0,
    }, // 2: more aggressive rate
    Arm {
        mcs_delta: 0,
        power_backoff_db: 6,
        fec_delta: 0,
    }, // 3: trim power (spatial reuse)
    Arm {
        mcs_delta: -1,
        power_backoff_db: 0,
        fec_delta: 1,
    }, // 4: robustness via FEC, not rate
];

/// Apply an arm to a baseline [`TxParams`], clamped to the radio's capability.
///
/// ★ `db_per_power_idx` is the radio's own MEASURED dB-per-index step
/// ([`RadioCapability::db_per_power_idx`]) and `power_floor` its monotone floor
/// ([`RadioCapability::min_tx_power`]). Both must come from the part, not from a constant: a single
/// global 0.5 dB/step was MEASURED wrong on every radio it was applied to (2x on the a81a, 4x on
/// the RTL8733BU, non-linear on the RTL8812AU). **A radio with no measured scale gets no power
/// arm** — the bandit must not be allowed to "explore" an axis whose units it does not know, since
/// it would then be rewarded for a footprint reduction of unknown, possibly zero, size.
pub fn apply_arm(
    arm: &Arm,
    p: &mut TxParams,
    max_mcs: u8,
    max_power: u8,
    db_per_power_idx: Option<f32>,
    power_floor: u8,
) {
    // The bandit's rate arm is a Wi-Fi MCS bump — only touch a Wi-Fi rate.
    if let Some(w) = p.wifi_mut()
        && let Some(m) = w.mcs
    {
        w.mcs = Some((m as i16 + arm.mcs_delta as i16).clamp(0, max_mcs as i16) as u8);
    }
    if arm.power_backoff_db != 0
        && let Some(db_per_idx) = db_per_power_idx
    {
        let cur = p.tx_power.unwrap_or(max_power) as i16;
        let d = (arm.power_backoff_db as f32 / db_per_idx).round() as i16;
        p.tx_power = Some((cur - d).clamp(power_floor as i16, max_power as i16) as u8);
    }
    if arm.fec_delta != 0 {
        let cur = p.link_fec_redundancy.unwrap_or(0) as i16;
        let r = (cur + arm.fec_delta as i16).max(0);
        p.link_fec_redundancy = if r == 0 { None } else { Some(r as u16) };
    }
}

/// Relative airtime proxy (lower = faster): `(1+parity)/rate`. Monotone, not calibrated.
fn relative_airtime(p: &TxParams) -> f32 {
    let bw = match p.bw().unwrap_or(0) {
        1 => 2.0,
        2 => 4.0,
        3 => 0.5,
        4 => 0.25,
        _ => 1.0,
    };
    let rate = (p.mcs().unwrap_or(0) as f32 + 1.0) * bw * p.nss().unwrap_or(1).max(1) as f32;
    (1.0 + p.link_fec_redundancy.unwrap_or(0) as f32) / rate.max(0.5)
}

/// Reward for one transmission outcome — the optimand, online: a delivery is
/// rewarded inversely to airtime + a small footprint (power) penalty; a miss is
/// heavily penalized (wasted airtime, nothing satisfied).
pub fn reward(delivered: bool, params: &TxParams, max_power: u8) -> f32 {
    let airtime = relative_airtime(params);
    if delivered {
        let footprint = params.tx_power.unwrap_or(max_power) as f32 / max_power.max(1) as f32;
        -(airtime + FOOTPRINT_LAMBDA * footprint)
    } else {
        -(airtime + MISS_PENALTY)
    }
}

/// A discretized situation the bandit keys its learning on.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Context {
    rssi_bin: u8,
    occ_bin: u8,
    recv_bin: u8,
    priority: u8,
}

impl Context {
    /// Bin one situation for the bandit.
    ///
    /// ★ **Takes the [`NameContext`], not a bare `u8`.** The class arrived here as
    /// `name_ctx.priority().rank()` — a private-field-protected enum flattened into an integer at
    /// the crate boundary, so an external caller could hand the bandit any priority bucket it
    /// liked. Converting it makes this consistent with `decide_adv_phy` and `PhyDial::evaluate`,
    /// which take the context for the same reason.
    ///
    /// ⚠ **Billed as a CONSISTENCY fix, not a security fix.** The selected arm does reach live
    /// `TxParams` (measured: a 2-MCS-step difference between arms), but ALL FIVE arms are reachable
    /// from every priority bucket and the arm's effect is bounded by radio capability
    /// (`apply_arm` clamps the MCS to `max_mcs` and the power to the part's own floor/ceiling), so
    /// a forged bucket unlocked nothing — it could only mis-key the learning table and make the
    /// bandit converge more slowly against itself. What the conversion buys is that the class has
    /// ONE representation on the way in, so a future arm that *is* class-sensitive cannot be
    /// reached by an unauthorised caller through a seam nobody remembered was open.
    pub fn new(rssi_dbm: i8, busy_pct: u8, receivers: usize, name_ctx: &NameContext) -> Self {
        Self {
            rssi_bin: ((rssi_dbm as i32 + 95).clamp(0, 75) / 5) as u8, // 5 dB SNR bins
            occ_bin: (busy_pct / 25).min(3),
            recv_bin: match receivers {
                0 | 1 => 0,
                2 | 3 => 1,
                _ => 2,
            },
            priority: name_ctx.priority().rank().min(2),
        }
    }
    fn key(&self) -> u32 {
        (self.rssi_bin as u32)
            | ((self.occ_bin as u32) << 4)
            | ((self.recv_bin as u32) << 6)
            | ((self.priority as u32) << 8)
    }
}

#[derive(Clone, Copy, Default)]
struct ArmStat {
    n: u32,
    mean: f32,
}

/// Tabular UCB1 contextual bandit.
pub struct ContextualBandit {
    stats: HashMap<u32, [ArmStat; ARMS.len()]>,
    explore_c: f32,
}

impl ContextualBandit {
    pub fn new(explore_c: f32) -> Self {
        Self {
            stats: HashMap::new(),
            explore_c: explore_c.max(0.0),
        }
    }

    /// Choose an arm for `ctx`: any unpulled arm first, then UCB1
    /// (`mean + c·√(ln N / n)`). Deterministic — no RNG.
    pub fn select(&self, ctx: &Context) -> usize {
        self.select_traced(ctx).arm
    }

    /// Like [`select`](Self::select) but returns the decision's *reasoning* as data — the chosen
    /// arm, the per-arm UCB scores at decision time, whether it was a cold-start (an unpulled arm,
    /// scored `+∞`), and the pull count for this context. This is the decision-observability surface
    /// (no `tracing` dependency, `no_std`-friendly): a caller emits it as a span/event/metric, and a
    /// convergence view can watch the scores separate. `select` is exactly `select_traced(ctx).arm`.
    pub fn select_traced(&self, ctx: &Context) -> ArmChoice {
        let arms = match self.stats.get(&ctx.key()) {
            Some(a) => a,
            None => {
                return ArmChoice {
                    arm: 0,
                    scores: [f32::INFINITY; ARMS.len()],
                    cold_start: true,
                    pulls: 0,
                };
            }
        };
        let total: u32 = arms.iter().map(|a| a.n).sum();
        let lnt = (total.max(1) as f32).ln();
        let mut scores = [f32::NEG_INFINITY; ARMS.len()];
        let mut cold = false;
        for (i, a) in arms.iter().enumerate() {
            scores[i] = if a.n == 0 {
                cold = true;
                f32::INFINITY // force exploration of an unpulled arm (matches `select`'s first-unpulled rule)
            } else {
                a.mean + self.explore_c * (lnt / a.n as f32).sqrt()
            };
        }
        // First-max wins (strictly-greater), so a leading `+∞` picks the first unpulled arm — identical
        // to the original `position(n==0)` then argmax path.
        let mut arm = 0;
        let mut best = f32::NEG_INFINITY;
        for (i, &s) in scores.iter().enumerate() {
            if s > best {
                best = s;
                arm = i;
            }
        }
        ArmChoice {
            arm,
            scores,
            cold_start: cold,
            pulls: total,
        }
    }

    /// Record a reward for `(ctx, arm)` (incremental mean).
    pub fn update(&mut self, ctx: &Context, arm: usize, reward: f32) {
        let arms = self
            .stats
            .entry(ctx.key())
            .or_insert_with(|| [ArmStat::default(); ARMS.len()]);
        if let Some(s) = arms.get_mut(arm) {
            s.n += 1;
            s.mean += (reward - s.mean) / s.n as f32;
        }
    }

    /// Pure-exploit best arm for `ctx` (telemetry / convergence checks).
    pub fn best(&self, ctx: &Context) -> Option<usize> {
        self.stats.get(&ctx.key()).map(|arms| {
            arms.iter()
                .enumerate()
                .max_by(|a, b| a.1.mean.total_cmp(&b.1.mean))
                .map(|(i, _)| i)
                .unwrap_or(0)
        })
    }

    /// Total pulls recorded for `ctx`.
    pub fn pulls(&self, ctx: &Context) -> u32 {
        self.stats
            .get(&ctx.key())
            .map(|a| a.iter().map(|s| s.n).sum())
            .unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plan::WifiRate;

    fn params(mcs: u8) -> TxParams {
        TxParams::wifi(WifiRate {
            mcs: Some(mcs),
            bw: Some(2),
            nss: Some(1),
            ..Default::default()
        })
    }

    /// **Surface C, and it is a CONSISTENCY fix, not a security fix.**
    ///
    /// The class used to arrive here as a bare `u8` (`name_ctx.priority().rank()` at the call site,
    /// but any integer from anywhere else), which flattened a private-field-protected enum into a
    /// forgeable integer at the crate boundary. It now arrives as the context, so the bucket is
    /// always the GRANTED ceiling — including after a `capped_by`, which lowers with no inverse.
    ///
    /// It unlocks nothing: all five arms are reachable from every bucket and `apply_arm` bounds
    /// each by radio capability. What it buys is one representation of the class on the way in.
    ///
    /// Falsified by binning anything other than `name_ctx.priority().rank()` — a constant, or a
    /// re-introduced caller-supplied integer: the capped context then stops binning with the plain
    /// one.
    #[test]
    fn the_bandit_bins_the_granted_class_not_an_asserted_one() {
        use crate::policy::{ClassAuthority, ClassCeiling, Priority};
        struct Urgent;
        impl ClassAuthority for Urgent {
            fn ceiling_for(&self, _h: u64) -> Priority {
                Priority::Urgent
            }
        }
        let h = 0xABu64;
        let urgent = NameContext::new(h).with_ceiling(ClassCeiling::authorised(&Urgent, h));
        let capped = urgent.capped_by(Priority::Normal);
        let plain = NameContext::new(h);

        let mut b = ContextualBandit::new(1.0);
        b.update(&Context::new(-60, 0, 1, &urgent), 0, 1.0);

        assert_eq!(b.pulls(&Context::new(-60, 0, 1, &urgent)), 1);
        assert_eq!(
            b.pulls(&Context::new(-60, 0, 1, &capped)),
            0,
            "a context whose ceiling was lowered must not read the class it once held"
        );
        assert_eq!(
            b.pulls(&Context::new(-60, 0, 1, &capped)),
            b.pulls(&Context::new(-60, 0, 1, &plain)),
            "the bucket follows the granted ceiling, nothing else"
        );
    }

    #[test]
    fn reward_orders_outcomes_correctly() {
        // delivered beats missed
        assert!(reward(true, &params(5), 63) > reward(false, &params(5), 63));
        // delivered fast beats delivered slow
        assert!(reward(true, &params(9), 63) > reward(true, &params(2), 63));
        // delivered at lower power beats delivered at full power (footprint)
        let mut lowp = params(5);
        lowp.tx_power = Some(20);
        let mut fullp = params(5);
        fullp.tx_power = Some(63);
        assert!(reward(true, &lowp, 63) > reward(true, &fullp, 63));
    }

    #[test]
    fn apply_arm_adjusts_and_clamps() {
        let mut p = params(7);
        apply_arm(&ARMS[2], &mut p, 9, 63, Some(0.5), 0); // +1 rate
        assert_eq!(p.mcs(), Some(8));
        let mut p = params(0);
        apply_arm(&ARMS[1], &mut p, 9, 63, Some(0.5), 0); // -1 rate clamps at 0
        assert_eq!(p.mcs(), Some(0));
        let mut p = params(5);
        apply_arm(&ARMS[3], &mut p, 9, 63, Some(0.5), 0); // power -6 dB = -12 idx
        assert_eq!(p.tx_power, Some(51));
        let mut p = params(5);
        apply_arm(&ARMS[4], &mut p, 9, 63, Some(0.5), 0); // -1 rate + fec
        assert_eq!(p.mcs(), Some(4));
        assert_eq!(p.link_fec_redundancy, Some(1));
    }

    #[test]
    fn converges_to_the_best_arm() {
        let mut b = ContextualBandit::new(0.5);
        let ctx = Context::new(-60, 10, 1, &NameContext::new(0x1));
        // arm 2 yields the best reward in this context; the rest are worse.
        for _ in 0..300 {
            let a = b.select(&ctx);
            let r = if a == 2 { -0.2 } else { -1.0 };
            b.update(&ctx, a, r);
        }
        assert_eq!(b.best(&ctx), Some(2));
        assert!(b.pulls(&ctx) >= 300);
    }

    #[test]
    fn explores_all_arms_before_exploiting() {
        let mut b = ContextualBandit::new(1.0);
        let ctx = Context::new(-70, 0, 1, &NameContext::new(0x1));
        let mut seen = [false; ARMS.len()];
        for _ in 0..ARMS.len() {
            let a = b.select(&ctx);
            seen[a] = true;
            b.update(&ctx, a, -1.0);
        }
        assert!(
            seen.iter().all(|&s| s),
            "each arm tried once before UCB kicks in"
        );
    }

    #[test]
    fn contexts_learn_independently() {
        let mut b = ContextualBandit::new(0.5);
        let weak = Context::new(-85, 0, 1, &NameContext::new(0x1));
        let strong = Context::new(-45, 0, 1, &NameContext::new(0x1));
        assert_ne!(weak, strong);
        b.update(&strong, 2, -0.1);
        assert_eq!(b.pulls(&strong), 1);
        assert_eq!(b.pulls(&weak), 0, "distinct contexts don't share learning");
    }
}
