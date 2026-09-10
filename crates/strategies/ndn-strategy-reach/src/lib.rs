//! **Soft prefix-reach** — a mobility-first named-radio forwarding family, the base candidate from
//! `ndn-ext/crates/faces/ndn-phy-wifi/docs/wireless-forwarding-under-flux.md` §5, with each of the
//! six design axes exposed as a swappable variant so the ndn-sim `ndr_mobility_sweep` harness can A/B one at a
//! time (doc §7). All variants share the invariant: the prior is the MAC's one legal soft-state memory (§7) —
//! reinforced on Data-return, decayed on read, keyed on the **name only** (no host identity) — and a cold or
//! wrong prior only ever *widens* the flood, so it can never blackhole.
//!
//! Registered strategies (env `NDR_STRATEGY`):
//! - **`soft-prefix-reach`** — *decision* = probabilistic gate (drop below `p`); moves *along* the
//!   delivery/airtime curve.
//! - **`soft-prefix-reach-defer`** — *decision* = defer + overhear-cancel (LFBL/CCLF): the prior sets the
//!   re-broadcast delay (high reach → fires first), the engine's overhear-cancel suppresses the redundant
//!   copies. *Shifts* the curve (the Pareto win).
//! - **`soft-prefix-reach-bandit`** — *decision* = defer, but the reach used for the delay is a **Thompson
//!   sample** from a Beta posterior over (success, attempt) — so an *uncertain* (cold/stale, i.e. mobile)
//!   node sometimes fires first and explores, while a *confident* node exploits. The non-stationary bandit
//!   answering "when does the prior beat flooding" (doc §3, axis H).
//! - **`soft-prefix-reach-bloom`** — *memory* = a counting/decaying **Bloom filter** over name-prefixes
//!   (BFR/BLOOGO; the doctrine's prefix-set Bloom made counting) instead of a per-prefix scalar map; same
//!   defer decision. A drop-in at small scale; its real benefit is compact, gossipable memory at many
//!   prefixes (a wire/scale property, not a single-neighbourhood delivery win).
//!
//! Tunables are env-overridable for §8 sweeps: `NDR_PFLOOR`, `NDR_REINFORCE`, `NDR_WMAX`, `NDR_TAU_MS`,
//! `NDR_DEFER_MIN_MS`, `NDR_DEFER_MAX_MS`. Only the re-broadcast on the arrival face is gated/deferred; a
//! genuine hop (a consumer's own Interest, or an Interest reaching a local producer) always forwards.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ndn_packet::{Name, NameComponent};
use ndn_strategy::{ErasedStrategy, Strategy, StrategyContext, register_strategy};
use ndn_transport::{FaceId, ForwardingAction, NackReason};
use smallvec::{SmallVec, smallvec};

register_strategy!(SOFT_PREFIX_REACH_REG, b"soft-prefix-reach", 1, || Arc::new(
    SoftPrefixReachStrategy::new(Mode::Probabilistic)
)
    as Arc<dyn ErasedStrategy>,);
register_strategy!(
    SOFT_PREFIX_REACH_DEFER_REG,
    b"soft-prefix-reach-defer",
    1,
    || Arc::new(SoftPrefixReachStrategy::new(Mode::Defer)) as Arc<dyn ErasedStrategy>,
);
register_strategy!(
    SOFT_PREFIX_REACH_BANDIT_REG,
    b"soft-prefix-reach-bandit",
    1,
    || Arc::new(SoftPrefixReachStrategy::new(Mode::Bandit)) as Arc<dyn ErasedStrategy>,
);
register_strategy!(
    SOFT_PREFIX_REACH_BLOOM_REG,
    b"soft-prefix-reach-bloom",
    1,
    || Arc::new(SoftPrefixReachStrategy::new(Mode::BloomDefer)) as Arc<dyn ErasedStrategy>,
);

/// Counting-Bloom default width (cells) and hash count. Width is env-tunable (`NDR_BLOOM_CELLS`) so a
/// multi-producer scenario can force saturation at a low prefix count and expose the graceful-degradation
/// (fail-safe false-positive) behaviour that is the whole point of a *bounded* memory.
const BLOOM_CELLS: usize = 256;
const BLOOM_K: usize = 4;

#[derive(Clone, Copy, PartialEq)]
pub enum Mode {
    Probabilistic, // v1: re-broadcast with prob p(reach); else suppress.
    Defer,         // v2: defer by delay(reach); engine overhear-cancels the redundant ones.
    Bandit, // v3: defer, reach = Thompson sample from a Beta posterior (explore under uncertainty).
    BloomDefer, // v4: defer, memory = counting/decaying Bloom over prefixes (vs the scalar map).
}

/// Env-overridable tunables (doc §8). Read once at construction.
struct Params {
    p_floor: f64,
    reinforce: f64,
    w_max: f64,
    tau_ms: f64,
    defer_min_ms: f64,
    defer_max_ms: f64,
    /// Name-component depth the reach prior keys on — 1 = the registered producer prefix's first component
    /// (single-producer default); 2 for a `/p/{k}` multi-producer scenario (distinguish producers under one
    /// routable `/p` parent + one strategy instance).
    prefix_depth: usize,
    /// Counting-Bloom width (cells). Low ⇒ forced saturation ⇒ visible false-positive behaviour.
    bloom_cells: usize,
}

impl Params {
    fn from_env() -> Self {
        let env = |k: &str, d: f64| {
            std::env::var(k)
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(d)
        };
        let envu = |k: &str, d: usize| {
            std::env::var(k)
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(d)
        };
        Self {
            p_floor: env("NDR_PFLOOR", 0.2),
            reinforce: env("NDR_REINFORCE", 1.0),
            w_max: env("NDR_WMAX", 4.0),
            tau_ms: env("NDR_TAU_MS", 4000.0),
            defer_min_ms: env("NDR_DEFER_MIN_MS", 2.0),
            // Sweep (ndr_mobility_sweep, N=12, ~3-4 hops): delivery improved monotonically as the window
            // tightened (40→15→8 ms), especially at high mobility (less per-hop latency ⇒ more Data returns
            // before the topology shifts): 8 ms was best (0.605 vs 0.568 deliv @30 m/s) but is aggressive for
            // deeper nets (tighter separation ⇒ more near-tie collisions), so 15 ms is the default with
            // headroom; override via NDR_DEFER_MAX_MS.
            defer_max_ms: env("NDR_DEFER_MAX_MS", 15.0),
            prefix_depth: envu("NDR_PREFIX_DEPTH", 1).max(1),
            bloom_cells: envu("NDR_BLOOM_CELLS", BLOOM_CELLS).max(BLOOM_K),
        }
    }
}

/// Scalar EWMA reach (Probabilistic / Defer).
struct Reach {
    weight: f64,
    last_ms: u64,
}

/// Beta posterior over (success, attempt) for the Thompson-bandit decision.
struct Beta {
    alpha: f64, // decayed successes (Data-returns)
    beta: f64,  // decayed attempts (re-broadcasts that didn't (yet) succeed)
    last_ms: u64,
}

/// A counting, geometrically-decaying Bloom filter over name-prefix hashes (the reach prior's memory).
struct CountingBloom {
    cells: Vec<f64>,
    last_ms: u64,
}

impl CountingBloom {
    fn new(cells: usize) -> Self {
        Self {
            cells: vec![0.0; cells],
            last_ms: 0,
        }
    }
    fn decay_to(&mut self, now_ms: u64, tau_ms: f64) {
        let dt = now_ms.saturating_sub(self.last_ms) as f64;
        if dt > 0.0 {
            let f = (-dt / tau_ms).exp();
            for c in &mut self.cells {
                *c *= f;
            }
            self.last_ms = now_ms;
        }
    }
    fn idxs(&self, key: u64) -> [usize; BLOOM_K] {
        let n = self.cells.len() as u64;
        let mut out = [0usize; BLOOM_K];
        let mut h = key;
        for o in &mut out {
            h ^= h >> 33;
            h = h.wrapping_mul(0xff51_afd7_ed55_8ccd);
            h ^= h >> 33;
            *o = (h % n) as usize;
        }
        out
    }
    fn insert(&mut self, key: u64, g: f64, w_max: f64) {
        for i in self.idxs(key) {
            self.cells[i] = (self.cells[i] + g).min(w_max);
        }
    }
    /// Counting-Bloom membership strength = min over the k cells.
    fn query(&self, key: u64) -> f64 {
        self.idxs(key)
            .into_iter()
            .map(|i| self.cells[i])
            .fold(f64::INFINITY, f64::min)
    }
}

/// Hands out a distinct ordinal to each `SoftPrefixReachStrategy::new`, so instances built in one
/// process (the sim, where every node lives in the same address space) get INDEPENDENT xorshift
/// streams. Construction order is deterministic, so the ordinals — and thus the runs — are reproducible.
static NEXT_INSTANCE: AtomicU32 = AtomicU32::new(0);

/// Fold an arbitrary 64-bit identity into a non-zero xorshift32 seed (splitmix64 finalizer, xored down
/// to 32 bits). Non-zero is mandatory: xorshift32 seeded 0 is a fixed point that only ever yields 0.
fn xorshift_seed(mix: u64) -> u32 {
    let mut z = mix.wrapping_add(0x9E37_79B9_7F4A_7C15);
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^= z >> 31;
    ((z as u32) ^ ((z >> 32) as u32)) | 1
}

/// The strategy: a decaying name-prefix reachability prior driving one of four axis variants.
pub struct SoftPrefixReachStrategy {
    name: Name,
    mode: Mode,
    params: Params,
    prior: Mutex<HashMap<u64, Reach>>,
    bandit: Mutex<HashMap<u64, Beta>>,
    bloom: Mutex<CountingBloom>,
    rng: Mutex<u32>, // xorshift32 — deterministic per-node stream
}

impl SoftPrefixReachStrategy {
    /// Construct with an independent RNG stream. Instances get distinct streams from a process ordinal
    /// (`NEXT_INSTANCE`) so many nodes in one process do not draw identically — the old shared constant
    /// `0x2545_F491` gave every node the same xorshift stream, so nodes that received one Interest at the
    /// same instant computed the SAME `defer_delay` and fired *simultaneously* instead of staggering,
    /// defeating the tie-break/overhear-cancel the defer variants rely on. Callers that have a real node
    /// identity should prefer [`with_seed`](Self::with_seed) so the stream is tied to the node, not to
    /// construction order.
    pub fn new(mode: Mode) -> Self {
        let ordinal = NEXT_INSTANCE.fetch_add(1, Ordering::Relaxed) as u64;
        Self::with_seed(mode, 0x2545_F491 ^ ordinal)
    }

    /// Construct with an explicit RNG seed (fold in a node/face id for a per-node-reproducible stream).
    pub fn with_seed(mode: Mode, seed: u64) -> Self {
        let leaf: &'static [u8] = match mode {
            Mode::Probabilistic => b"soft-prefix-reach",
            Mode::Defer => b"soft-prefix-reach-defer",
            Mode::Bandit => b"soft-prefix-reach-bandit",
            Mode::BloomDefer => b"soft-prefix-reach-bloom",
        };
        let params = Params::from_env();
        Self {
            name: Name::from_components([
                NameComponent::generic(bytes_static(b"localhost")),
                NameComponent::generic(bytes_static(b"nfd")),
                NameComponent::generic(bytes_static(b"strategy")),
                NameComponent::generic(bytes_static(leaf)),
            ]),
            mode,
            prior: Mutex::new(HashMap::new()),
            bandit: Mutex::new(HashMap::new()),
            bloom: Mutex::new(CountingBloom::new(params.bloom_cells)),
            rng: Mutex::new(xorshift_seed(seed)),
            params,
        }
    }

    /// FNV-1a of the name's first `prefix_depth` components — the registered-prefix granularity the reach
    /// prior keys on (see `Params::prefix_depth`). A faithful mirror of `ndn_radio::mac::prefix_hash`
    /// (same constants + separator + post-separator multiply); this crate deliberately does not depend
    /// on the radio face crate (a strategy is bearer-agnostic), so the algorithm is kept in sync here
    /// rather than shared. It keys only a process-local map, so exact cross-crate agreement is not
    /// required — but matching avoids the divergence trap of *looking* like the canonical yet differing.
    fn prefix_key(&self, ctx: &StrategyContext<'_>) -> u64 {
        let mut h = 0xcbf2_9ce4_8422_2325u64;
        for comp in ctx.name.components().iter().take(self.params.prefix_depth) {
            for b in comp.value.as_ref() {
                h ^= *b as u64;
                h = h.wrapping_mul(0x0100_0000_01b3);
            }
            h ^= 0x2f; // component separator so /p/1 and /p1 differ
            h = h.wrapping_mul(0x0100_0000_01b3);
        }
        h
    }

    fn now_ms(ctx: &StrategyContext<'_>) -> u64 {
        ctx.runtime.unix_nanos() / 1_000_000
    }

    fn draw(&self) -> f64 {
        let mut s = self.rng.lock().unwrap();
        let mut x = *s;
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        *s = x;
        (x as f64) / (u32::MAX as f64)
    }

    /// A standard-normal sample (Box–Muller on the xorshift stream) for the Thompson approximation.
    fn gauss(&self) -> f64 {
        let u1 = self.draw().max(1e-9);
        let u2 = self.draw();
        (-2.0 * u1.ln()).sqrt() * (std::f64::consts::TAU * u2).cos()
    }

    /// The reach estimate in `[0, 1]` for this prefix, per mode (with decay applied on read).
    fn reach_norm(&self, key: u64, now_ms: u64) -> f64 {
        let p = &self.params;
        match self.mode {
            Mode::Probabilistic | Mode::Defer => {
                let map = self.prior.lock().unwrap();
                let w = map.get(&key).map_or(0.0, |r| {
                    r.weight * (-(now_ms.saturating_sub(r.last_ms) as f64) / p.tau_ms).exp()
                });
                (w / p.w_max).clamp(0.0, 1.0)
            }
            Mode::BloomDefer => {
                let mut b = self.bloom.lock().unwrap();
                b.decay_to(now_ms, p.tau_ms);
                (b.query(key) / p.w_max).clamp(0.0, 1.0)
            }
            Mode::Bandit => {
                // Thompson: sample the reach from Beta(alpha+1, beta+1) via a Gaussian approximation
                // (mean + z·std). An uncertain (few observations / decayed) prefix has high variance, so a
                // mobile/cold node sometimes samples high → fires first and explores.
                let map = self.bandit.lock().unwrap();
                let (a, bta) = map.get(&key).map_or((0.0, 0.0), |b| {
                    let f = (-(now_ms.saturating_sub(b.last_ms) as f64) / p.tau_ms).exp();
                    (b.alpha * f, b.beta * f)
                });
                let (a1, b1) = (a + 1.0, bta + 1.0); // Laplace prior: cold ⇒ mean 0.5, high variance
                let n = a1 + b1;
                let mean = a1 / n;
                let var = (a1 * b1) / (n * n * (n + 1.0));
                (mean + self.gauss() * var.sqrt()).clamp(0.0, 1.0)
            }
        }
    }

    /// Defer delay: warm/high-reach → short (fires first); cold → long; a random term spreads ties so a
    /// single winner emerges per hop and the engine's overhear-cancel suppresses the rest.
    fn defer_delay(&self, reach_norm: f64) -> Duration {
        let p = &self.params;
        let frac = (0.5 * (1.0 - reach_norm) + 0.5 * self.draw()).clamp(0.0, 1.0);
        let ms = p.defer_min_ms + (p.defer_max_ms - p.defer_min_ms) * frac;
        Duration::from_micros((ms * 1000.0) as u64)
    }

    /// Count a re-broadcast attempt as a **provisional failed trial** (bandit β += 1): we forwarded but
    /// have not yet seen the Data return. If the Data does come back, [`note_success`](Self::note_success)
    /// converts this trial into a success; if it never does, the failure stands (and decays).
    fn note_attempt(&self, key: u64, now_ms: u64) {
        if self.mode == Mode::Bandit {
            let mut map = self.bandit.lock().unwrap();
            let b = map.entry(key).or_insert(Beta {
                alpha: 0.0,
                beta: 0.0,
                last_ms: now_ms,
            });
            let f = (-(now_ms.saturating_sub(b.last_ms) as f64) / self.params.tau_ms).exp();
            b.beta = b.beta * f + 1.0;
            b.alpha *= f;
            b.last_ms = now_ms;
        }
    }

    /// Data returned for `key` → convert the provisional failed trial `note_attempt` logged into a
    /// success: α gains a trial, β loses the one the matching attempt added. This keeps the posterior a
    /// genuine Beta(successes, failures). The old update only *added* to α while β kept every attempt
    /// (β = attempts, not failures), so a fully reliable path converged to α ≈ β ⇒ posterior mean → 0.5
    /// — the "confident node exploits with a high reach" half of the design was unreachable.
    fn note_success(&self, key: u64, now_ms: u64) {
        let mut map = self.bandit.lock().unwrap();
        let b = map.entry(key).or_insert(Beta {
            alpha: 0.0,
            beta: 0.0,
            last_ms: now_ms,
        });
        let f = (-(now_ms.saturating_sub(b.last_ms) as f64) / self.params.tau_ms).exp();
        b.alpha = b.alpha * f + 1.0; // one successful trial
        b.beta = (b.beta * f - 1.0).max(0.0); // remove the provisional failure this trial logged
        b.last_ms = now_ms;
    }
}

impl Strategy for SoftPrefixReachStrategy {
    fn name(&self) -> &Name {
        &self.name
    }

    fn after_receive_interest(&self, ctx: &StrategyContext<'_>) -> SmallVec<[ForwardingAction; 2]> {
        let Some(fib) = ctx.fib_entry else {
            return smallvec![ForwardingAction::Nack(NackReason::NoRoute)];
        };
        let faces: SmallVec<[FaceId; 4]> = fib.nexthops.iter().map(|n| n.face_id).collect();
        if faces.is_empty() {
            return smallvec![ForwardingAction::Nack(NackReason::NoRoute)];
        }
        // Genuine hops always forward immediately; only a pure re-broadcast on the arrival face is gated.
        let other: SmallVec<[FaceId; 4]> = faces
            .iter()
            .copied()
            .filter(|&f| f != ctx.in_face)
            .collect();
        if !other.is_empty() {
            return smallvec![ForwardingAction::Forward(other)];
        }

        let key = self.prefix_key(ctx);
        let now = Self::now_ms(ctx);
        let reach = self.reach_norm(key, now);
        match self.mode {
            Mode::Probabilistic => {
                // Cold prior (reach≈0) ⇒ p≈1 (WIDEN: forward — can't blackhole, per the module invariant);
                // warm (reach≈1) ⇒ p≈p_floor (NARROW: path is known, let overhear-cancel thin the flood).
                // Matches Defer's `(1-reach)` polarity — the old `* reach` inverted it (cold narrowed to
                // p_floor^hops, so an all-cold mobile mesh blackholed).
                let p = self.params.p_floor + (1.0 - self.params.p_floor) * (1.0 - reach);
                if self.draw() < p {
                    smallvec![ForwardingAction::Forward(faces)]
                } else {
                    smallvec![ForwardingAction::Suppress]
                }
            }
            Mode::Defer | Mode::Bandit | Mode::BloomDefer => {
                self.note_attempt(key, now);
                smallvec![ForwardingAction::ForwardAfter {
                    faces,
                    delay: self.defer_delay(reach)
                }]
            }
        }
    }

    fn after_receive_data(&self, ctx: &StrategyContext<'_>) -> SmallVec<[ForwardingAction; 2]> {
        // Data came back for this prefix through this node → reinforce the reach prior (pheromone/KITE).
        let key = self.prefix_key(ctx);
        let now = Self::now_ms(ctx);
        let p = &self.params;
        match self.mode {
            Mode::Probabilistic | Mode::Defer => {
                let mut map = self.prior.lock().unwrap();
                let r = map.entry(key).or_insert(Reach {
                    weight: 0.0,
                    last_ms: now,
                });
                r.weight = (r.weight * (-(now.saturating_sub(r.last_ms) as f64) / p.tau_ms).exp()
                    + p.reinforce)
                    .min(p.w_max);
                r.last_ms = now;
            }
            Mode::BloomDefer => {
                let mut b = self.bloom.lock().unwrap();
                b.decay_to(now, p.tau_ms);
                b.insert(key, p.reinforce, p.w_max);
            }
            Mode::Bandit => self.note_success(key, now),
        }
        SmallVec::new()
    }
}

/// `Bytes` from a static slice — small helper so the strategy name can be a const-ish literal.
fn bytes_static(b: &'static [u8]) -> bytes::Bytes {
    bytes::Bytes::from_static(b)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Two instances constructed in the same process must draw INDEPENDENT streams — the sim runs every
    /// node in one address space, and the old shared seed made them draw identically (correlated
    /// defer/tie-break → synchronized flood). `new` gives each a distinct process ordinal.
    #[test]
    fn instances_have_independent_rng_streams() {
        let a = SoftPrefixReachStrategy::new(Mode::Defer);
        let b = SoftPrefixReachStrategy::new(Mode::Defer);
        let sa: Vec<u64> = (0..8).map(|_| a.draw().to_bits()).collect();
        let sb: Vec<u64> = (0..8).map(|_| b.draw().to_bits()).collect();
        assert_ne!(
            sa, sb,
            "two instances must not share an identical draw stream"
        );
    }

    /// …but the stream stays reproducible given an explicit identity, so a scenario is repeatable.
    #[test]
    fn with_seed_is_reproducible() {
        let a = SoftPrefixReachStrategy::with_seed(Mode::Defer, 0x1234_5678);
        let b = SoftPrefixReachStrategy::with_seed(Mode::Defer, 0x1234_5678);
        let sa: Vec<u64> = (0..8).map(|_| a.draw().to_bits()).collect();
        let sb: Vec<u64> = (0..8).map(|_| b.draw().to_bits()).collect();
        assert_eq!(sa, sb, "same seed ⇒ identical stream");
    }

    /// A consistently reliable path (every forward returns Data) must earn a reach WELL above 0.5 so
    /// the confident node fires first and exploits. The old β=attempts bug pinned it at ~0.5 forever.
    #[test]
    fn reliable_path_earns_high_reach_not_stuck_at_half() {
        let s = SoftPrefixReachStrategy::with_seed(Mode::Bandit, 1);
        let key = 0xABCD;
        for _ in 0..20 {
            s.note_attempt(key, 0);
            s.note_success(key, 0);
        }
        let avg: f64 = (0..2000).map(|_| s.reach_norm(key, 0)).sum::<f64>() / 2000.0;
        assert!(
            avg > 0.7,
            "a consistently reliable path must earn reach well above 0.5, got {avg:.3}"
        );

        // Contrast: forwards that never see a Data return stay low — the posterior can distinguish them.
        let s2 = SoftPrefixReachStrategy::with_seed(Mode::Bandit, 2);
        let k2 = 0x1234;
        for _ in 0..20 {
            s2.note_attempt(k2, 0);
        }
        let avg2: f64 = (0..2000).map(|_| s2.reach_norm(k2, 0)).sum::<f64>() / 2000.0;
        assert!(
            avg2 < 0.3,
            "a path that never returns Data must stay low, got {avg2:.3}"
        );
    }
}
