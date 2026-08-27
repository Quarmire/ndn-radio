//! Design-space evaluation: split the 126-bit address budget into a `(126−w)`-bit **Blur** (prefix
//! set, for FIB/discovery) plus a `w`-bit exclusive **Fingerprint** (top bits of the full-name hash,
//! for EXACT match — PIT-exact / CS-exact).
//!
//! Two effects, measured together:
//!   1. exact-match FP drops from the Blur's ~0.4% to ≈ `1 − (1 − 2⁻ʷ)^P` (P = exact names wanted);
//!   2. those P exact names LEAVE the Blur mask set, so the Blur's `E` collapses to just the FIB
//!      prefixes — which lowers `1 − (1 − p)^E` for prefix traffic too, even though `m` shrank by `w`.
//!
//! Sweeps `w` to find the FP-minimizing split. Uses a strong mixing hash (two independent splitmix
//! streams for the Bloom double-hash, a third for the fingerprint); the statistics transfer to
//! SipHash. Run: `cargo run -p ndn-phy-wifi --example tier0_fingerprint_eval`

fn mix(mut z: u64) -> u64 {
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}
/// `cfg` is the key-configuration seed: each value is an independent hash family, so averaging over
/// cfgs kills the single-config variance that dominates a small mask set (the tier0 k-sweep lesson).
fn hash(cfg: u64, domain: u64, bytes: &[u8]) -> u64 {
    let mut h = 0xcbf2_9ce4_8422_2325u64 ^ mix(cfg.wrapping_mul(0x9E37_79B9) ^ domain);
    for &b in bytes {
        h ^= b as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    mix(h)
}

/// Component-boundary prefixes of a `/`-name, root first, capped at depth 8 (the on-wire cap).
fn for_each_prefix(name: &[u8], mut f: impl FnMut(&[u8])) {
    f(b"/");
    let mut depth = 0;
    for (i, &b) in name.iter().enumerate() {
        if i > 0 && b == b'/' {
            depth += 1;
            if depth >= 8 {
                return;
            }
            f(&name[..i]);
        }
    }
    if !name.is_empty() && depth < 8 {
        f(name);
    }
}

const K: u32 = 4;
fn positions(cfg: u64, prefix: &[u8], m: usize) -> [usize; K as usize] {
    let h1 = hash(cfg, 1, prefix);
    let h2 = hash(cfg, 2, prefix) | 1;
    let mut out = [0usize; K as usize];
    for (i, o) in out.iter_mut().enumerate() {
        *o = (h1.wrapping_add((i as u64).wrapping_mul(h2)) % m as u64) as usize;
    }
    out
}

/// A Blur of `m` bits: insert all prefixes of a name; a mask is one prefix's K bits.
struct Blur {
    bits: Vec<bool>,
    m: usize,
    cfg: u64,
}
impl Blur {
    fn of_name(cfg: u64, name: &[u8], m: usize) -> Self {
        let mut bits = vec![false; m];
        for_each_prefix(name, |p| {
            for &pos in positions(cfg, p, m).iter() {
                bits[pos] = true;
            }
        });
        Self { bits, m, cfg }
    }
    fn admits(&self, mask_prefix: &[u8]) -> bool {
        positions(self.cfg, mask_prefix, self.m)
            .iter()
            .all(|&pos| self.bits[pos])
    }
}
fn fingerprint(cfg: u64, name: &[u8], w: u32) -> u64 {
    if w == 0 {
        return 0;
    }
    hash(cfg, 3, name) >> (64 - w)
}

/// Deterministic name generator.
struct Rng(u64);
impl Rng {
    fn u(&mut self, n: u64) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        mix(self.0) % n
    }
}
fn exact_name(roots: &[&str], r: &mut Rng) -> String {
    format!(
        "{}/ep{}/v{}/seg{}",
        roots[r.u(roots.len() as u64) as usize],
        r.u(64),
        r.u(8),
        r.u(256)
    )
}

const CFGS: u64 = 64; // average over 64 independent hash families to kill single-config variance
const N: usize = 20_000;

fn main() {
    let roots = ["/ndn/edu", "/video", "/sensor/temp"];
    let fib: Vec<&[u8]> = roots.iter().map(|s| s.as_bytes()).collect();
    let mut rg = Rng(0xBEEF);
    let wanted: Vec<String> = (0..50).map(|_| exact_name(&roots, &mut rg)).collect();
    let wanted_b: Vec<&[u8]> = wanted.iter().map(|s| s.as_bytes()).collect();

    println!("── Blur / Fingerprint split — FP vs w (m = 126 − w, k=4) ─────────");
    println!("  receiver: {} FIB prefixes + {} exact wanted (PIT)", fib.len(), wanted.len());
    println!("  {N} irrelevant frames/cfg · averaged over {CFGS} hash configs · ±1σ\n");
    println!("   w   m(Blur)  Blur E   exact-FP        prefix-FP       TOTAL-FP        FN");
    println!("  ────────────────────────────────────────────────────────────────────────");

    for w in [0u32, 8, 12, 16, 20, 24, 32] {
        let m = 126 - w as usize;
        // Baseline (w=0): exact-wanted carried as Blur MASKS. Proposed (w>0): via the fingerprint,
        // and the Blur mask set collapses to the FIB prefixes only.
        let (mut te, mut tp, mut tt) = (Vec::new(), Vec::new(), Vec::new());
        let mut fn_total = 0usize;

        for cfg in 0..CFGS {
            let blur_masks: Vec<&[u8]> = if w == 0 {
                fib.iter().chain(wanted_b.iter()).copied().collect()
            } else {
                fib.clone()
            };
            let fp_set: std::collections::HashSet<u64> = if w == 0 {
                Default::default()
            } else {
                wanted_b.iter().map(|n| fingerprint(cfg, n, w)).collect()
            };
            let admit = |name: &[u8]| {
                let blur = Blur::of_name(cfg, name, m);
                blur_masks.iter().any(|mp| blur.admits(mp))
                    || (w != 0 && fp_set.contains(&fingerprint(cfg, name, w)))
            };
            fn_total += wanted_b.iter().filter(|n| !admit(n)).count();

            let mut r = Rng(0x1234u64.wrapping_add(cfg).wrapping_add(w as u64 * 7));
            let (mut fe, mut fp) = (0usize, 0usize);
            for _ in 0..N {
                // irrelevant EXACT Data — a specific name we do not want, high root diversity.
                let ex = format!("/svc{}/ep{}/v{}/seg{}", r.u(4000), r.u(64), r.u(8), r.u(256));
                if admit(ex.as_bytes()) {
                    fe += 1;
                }
                // irrelevant PREFIX/discovery frame, high diversity.
                let px = format!("/zz{}/blk{}", r.u(4000), r.u(64));
                if admit(px.as_bytes()) {
                    fp += 1;
                }
            }
            te.push(fe as f64 / N as f64 * 100.0);
            tp.push(fp as f64 / N as f64 * 100.0);
            tt.push((fe + fp) as f64 / (2 * N) as f64 * 100.0);
        }
        let stat = |v: &[f64]| {
            let mean = v.iter().sum::<f64>() / v.len() as f64;
            let var = v.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / v.len() as f64;
            (mean, var.sqrt())
        };
        let (em, es) = stat(&te);
        let (pm, ps) = stat(&tp);
        let (tm, ts) = stat(&tt);
        let e = if w == 0 { fib.len() + wanted_b.len() } else { fib.len() };
        println!(
            "  {:>2}    {:>4}    {:>4}   {:>6.3}±{:<5.3}%  {:>6.3}±{:<5.3}%  {:>6.3}±{:<5.3}%  {}",
            w, m, e, em, es, pm, ps, tm, ts, fn_total
        );
    }
    // ── WIDE profile: full 126-bit Blur (NEVER shrunk) + a SEPARATE 24-bit fingerprint (in HTC) ──
    {
        let (m, w) = (126usize, 24u32);
        let mut tt = Vec::new();
        let mut fn_total = 0usize;
        for cfg in 0..CFGS {
            let fp_set: std::collections::HashSet<u64> =
                wanted_b.iter().map(|n| fingerprint(cfg, n, w)).collect();
            let admit = |name: &[u8]| {
                let blur = Blur::of_name(cfg, name, m); // exact names are OFF the Blur; masks = FIB only
                fib.iter().any(|mp| blur.admits(mp)) || fp_set.contains(&fingerprint(cfg, name, w))
            };
            fn_total += wanted_b.iter().filter(|n| !admit(n)).count();
            let mut r = Rng(0x9999u64.wrapping_add(cfg));
            let mut fp = 0usize;
            for _ in 0..N {
                let ex = format!("/svc{}/ep{}/v{}/seg{}", r.u(4000), r.u(64), r.u(8), r.u(256));
                let px = format!("/zz{}/blk{}", r.u(4000), r.u(64));
                if admit(ex.as_bytes()) {
                    fp += 1;
                }
                if admit(px.as_bytes()) {
                    fp += 1;
                }
            }
            tt.push(fp as f64 / (2 * N) as f64 * 100.0);
        }
        let mean = tt.iter().sum::<f64>() / tt.len() as f64;
        let sd = (tt.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / tt.len() as f64).sqrt();
        println!("  ────────────────────────────────────────────────────────────────────────");
        println!(
            "  WIDE   126     3    fp separate in HTC                    {:>6.3}±{:<5.3}%  {}",
            mean, sd, fn_total
        );
    }
    println!("\n  w=0 = today's design (50 exact names carried as Blur masks, E=53).");
    println!("  compact (w>0) carves the fp from the 126 → Blur shrinks to 126−w (LoRa fallback).");
    println!("  WIDE keeps the FULL 126-bit Blur AND a separate fingerprint (802.11 pushed header):");
    println!("    full Blur precision + near-zero exact-FP + E collapses 53→3 — the best of all.");
}
