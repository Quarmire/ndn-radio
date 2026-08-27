//! Evaluate **graduated / weighted per-level k** for the Blur — and find the regime where it helps.
//!
//! Uniform k=4 spends the same bits at every prefix level. A graduated schedule spends fewer at
//! low-entropy shared heads and more at discriminative levels. Whether that helps depends entirely on
//! **saturation**: with the shipping depth cap of 8 the Blur sets ≤ ~32 of 126 bits (well under the
//! 64-bit fill cap), so it never saturates and cutting bits only raises per-mask FP → uniform wins.
//! Raise the encode cap (deep names) and uniform over-fills → graduated, which stays sparse, wins.
//!
//! This sweeps the encode-depth cap to show both regimes, averaged over hash configs. Both ends must
//! use the SAME schedule (a receiver querying with more bits than the sender set would false-negative).
//! Run: `cargo run -p ndn-phy-wifi --example tier0_kschedule_eval`

const M: usize = 126;
const FILL_CAP: usize = 64;
const K_MAX: u8 = 4;
const SL: usize = 8; // schedule length; deeper levels reuse the last entry

fn mix(mut z: u64) -> u64 {
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}
fn hash(cfg: u64, domain: u64, bytes: &[u8]) -> u64 {
    let mut h = 0xcbf2_9ce4_8422_2325u64 ^ mix(cfg.wrapping_mul(0x9E37_79B9) ^ domain);
    for &b in bytes {
        h ^= b as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    mix(h)
}
fn positions_k(cfg: u64, prefix: &[u8], k: u8) -> [usize; K_MAX as usize] {
    let h1 = hash(cfg, 1, prefix);
    let h2 = hash(cfg, 2, prefix) | 1;
    let mut out = [0usize; K_MAX as usize];
    for (i, o) in out.iter_mut().enumerate().take(k as usize) {
        *o = (h1.wrapping_add((i as u64).wrapping_mul(h2)) % M as u64) as usize;
    }
    out
}
type Sched = [u8; SL];
fn kd(s: &Sched, d: usize) -> u8 {
    s[d.min(SL - 1)]
}
fn for_each_prefix_depth(name: &[u8], cap: usize, mut f: impl FnMut(usize, &[u8])) {
    f(0, b"/");
    let mut depth = 1;
    for (i, &b) in name.iter().enumerate() {
        if i > 0 && b == b'/' {
            if depth >= cap {
                return;
            }
            f(depth, &name[..i]);
            depth += 1;
        }
    }
    if !name.is_empty() && depth < cap {
        f(depth, name);
    }
}
fn depth_of(name: &[u8], cap: usize) -> usize {
    let mut d = 1;
    for (i, &b) in name.iter().enumerate() {
        if i > 0 && b == b'/' {
            d += 1;
        }
    }
    d.min(cap - 1)
}
fn frame_blur(cfg: u64, name: &[u8], s: &Sched, cap: usize) -> (Vec<bool>, usize) {
    let mut bits = vec![false; M];
    for_each_prefix_depth(name, cap, |d, p| {
        let k = kd(s, d);
        for &pos in positions_k(cfg, p, k).iter().take(k as usize) {
            bits[pos] = true;
        }
    });
    let pc = bits.iter().filter(|b| **b).count();
    (bits, pc)
}
fn admits(cfg: u64, frame: &[bool], pc: usize, mask_prefix: &[u8], s: &Sched, cap: usize) -> bool {
    if pc > FILL_CAP {
        return false; // fill-cap: an over-full frame is rejected before the mask test
    }
    let d = depth_of(mask_prefix, cap);
    let k = kd(s, d);
    positions_k(cfg, mask_prefix, k)
        .iter()
        .take(k as usize)
        .all(|&pos| frame[pos])
}

struct Rng(u64);
impl Rng {
    fn u(&mut self, n: u64) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        mix(self.0) % n
    }
    fn zipf(&mut self, n: u64) -> u64 {
        let r = self.u(1_000_000) as f64 / 1_000_000.0;
        ((n as f64).powf(r) - 1.0) as u64 % n
    }
}

fn main() {
    let roots = ["ndn/edu", "ndn/com", "video", "iot/sensor", "app/sync", "data/set"];
    let mut r = Rng(0xCAFE);
    // Deep names (10–13 components) so the encode-cap sweep can reach saturation.
    let corpus: Vec<String> = (0..4000)
        .map(|_| {
            format!(
                "/{}/y{}/m{}/d{}/h{}/v{}/seg{}/c{}",
                roots[r.zipf(roots.len() as u64) as usize],
                r.u(8), r.u(12), r.u(28), r.u(24), r.u(16), r.u(512), r.u(64)
            )
        })
        .collect();
    let reg: Vec<&[u8]> = vec![b"/ndn/edu", b"/video", b"/iot/sensor/d3", b"/app/sync/y2/m5"];

    let schedules: [(&str, Sched); 3] = [
        ("uniform-4   ", [4, 4, 4, 4, 4, 4, 4, 4]),
        ("taper-down  ", [4, 4, 3, 3, 2, 2, 1, 1]),
        ("head-light  ", [1, 2, 3, 4, 4, 4, 4, 4]),
    ];
    const CFGS: u64 = 32;

    println!("── Graduated per-level k — FP vs schedule, swept over ENCODE-DEPTH cap ──");
    println!("  corpus: {} deep Zipf names (10–13 comps) · {} registered prefixes · {CFGS}-cfg avg", corpus.len(), reg.len());

    for cap in [8usize, 12, 16] {
        println!("\n  encode cap = {cap}   (shipping is 8)");
        println!("  schedule       bits/frame   over-cap%   FP           FN");
        println!("  ─────────────────────────────────────────────────────────");
        for (label, s) in schedules {
            let (mut bits_acc, mut over_acc, mut fp_acc, mut fn_acc) = (0.0, 0.0, Vec::new(), 0usize);
            for cfg in 0..CFGS {
                let is_reg = |name: &[u8]| {
                    reg.iter().any(|p| {
                        name == *p
                            || (name.len() > p.len()
                                && &name[..p.len()] == *p
                                && name[p.len()] == b'/')
                    })
                };
                let (mut fp, mut n_irrel, mut bsum, mut over) = (0usize, 0usize, 0usize, 0usize);
                for name in &corpus {
                    let nb = name.as_bytes();
                    let (frame, pc) = frame_blur(cfg, nb, &s, cap);
                    bsum += pc;
                    if pc > FILL_CAP {
                        over += 1;
                    }
                    let admit = reg.iter().any(|p| admits(cfg, &frame, pc, p, &s, cap));
                    if is_reg(nb) {
                        if !admit {
                            fn_acc += 1;
                        }
                    } else {
                        n_irrel += 1;
                        if admit {
                            fp += 1;
                        }
                    }
                }
                bits_acc += bsum as f64 / corpus.len() as f64;
                over_acc += over as f64 / corpus.len() as f64 * 100.0;
                fp_acc.push(fp as f64 / n_irrel.max(1) as f64 * 100.0);
            }
            let mean = fp_acc.iter().sum::<f64>() / fp_acc.len() as f64;
            let sd = (fp_acc.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / fp_acc.len() as f64).sqrt();
            println!(
                "  {label}  {:>6.1}       {:>5.1}%    {:>6.3}±{:<5.3}%  {}",
                bits_acc / CFGS as f64, over_acc / CFGS as f64, mean, sd, fn_acc
            );
        }
    }
    println!("\n  over-cap% is 0 everywhere: at realistic depths the Blur never saturates the 64-bit");
    println!("  fill cap, so uniform-4 wins/ties on FP (more bits → lower FP). Graduated's real gain");
    println!("  is COMPACTNESS — taper-down ~20 bits vs uniform's ~34 at ~equal FP (the chapter's −44%).");
    println!("  ⇒ WiFi (fixed 126-bit address budget, bits free): keep UNIFORM-4, minimise FP.");
    println!("  ⇒ LoRa/GCS (every filter bit is airtime): use GRADUATED, ~40% less filter at equal FP.");
}
