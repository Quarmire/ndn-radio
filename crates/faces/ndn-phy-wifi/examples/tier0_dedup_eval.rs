//! Evaluate **coverage-dedup** (the antichain) on the shipping Tier-0 mask set.
//!
//! The FP a receiver actually pays is `1 − (1 − p)^E` in the mask count `E`. Coverage-dedup collapses
//! every registered prefix that has a registered ancestor — most importantly the PIT churn, which is
//! Interests forwarded *because* you route a broader FIB prefix. This harness measures E, the
//! false-positive rate (irrelevant frames admitted), and the false-negative rate (relevant frames
//! dropped — MUST be 0), with and without dedup, on a realistic FIB-roots + deep-names workload.
//!
//! Run: `cargo run -p ndn-phy-wifi --example tier0_dedup_eval`

use ndn_phy_wifi::{PrefixFilter, coverage_antichain};

const KEY: [u8; 16] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
];

/// Deterministic splitmix64 so the run is reproducible without an RNG dependency.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

/// A deep versioned/segmented name under `root`, e.g. `/video/ep7/v3/seg41`.
fn deep_name(root: &str, r: &mut Rng) -> String {
    format!(
        "{root}/ep{}/v{}/seg{}",
        r.below(64),
        r.below(8),
        r.below(256)
    )
}

fn mask_set(prefixes: &[&[u8]]) -> Vec<PrefixFilter> {
    prefixes
        .iter()
        .map(|p| PrefixFilter::mask_for(&KEY, p))
        .collect()
}

fn admits(masks: &[PrefixFilter], name: &str) -> bool {
    let mut f = PrefixFilter::new();
    f.insert_name(&KEY, name.as_bytes());
    masks.iter().any(|m| f.may_match(m))
}

fn main() {
    let mut r = Rng(0xF117);

    // ---- registered set: 3 FIB roots + deep PIT-like entries under them + a few unrelated ----
    let roots = ["/ndn/edu", "/video", "/sensor/temp"];
    let unrelated = ["/misc", "/other/x/y", "/foo", "/bar/baz"];

    let mut reg: Vec<String> = Vec::new();
    for root in roots {
        reg.push(root.to_string());
    }
    // 75 outstanding-Interest-like deep names under the roots (the churn dedup should absorb).
    for _ in 0..75 {
        let root = roots[r.below(roots.len() as u64) as usize];
        reg.push(deep_name(root, &mut r));
    }
    for u in unrelated {
        reg.push(u.to_string());
    }

    let reg_refs: Vec<&[u8]> = reg.iter().map(|s| s.as_bytes()).collect();
    let deduped = coverage_antichain(&reg_refs);

    let masks_full = mask_set(&reg_refs);
    let deduped_refs: Vec<&[u8]> = deduped.clone();
    let masks_dedup = mask_set(&deduped_refs);

    // ---- workload ----
    const N: usize = 20_000;
    // relevant: names genuinely under a registered root — MUST be admitted (zero FN).
    let mut fn_full = 0usize;
    let mut fn_dedup = 0usize;
    for _ in 0..N {
        let root = roots[r.below(roots.len() as u64) as usize];
        let name = deep_name(root, &mut r);
        if !admits(&masks_full, &name) {
            fn_full += 1;
        }
        if !admits(&masks_dedup, &name) {
            fn_dedup += 1;
        }
    }
    // irrelevant: names under NO registered prefix — admissions are false positives.
    let mut fp_full = 0usize;
    let mut fp_dedup = 0usize;
    for _ in 0..N {
        let name = format!(
            "/zz{}/blk{}/v{}/seg{}",
            r.below(1000),
            r.below(64),
            r.below(8),
            r.below(256)
        );
        if admits(&masks_full, &name) {
            fp_full += 1;
        }
        if admits(&masks_dedup, &name) {
            fp_dedup += 1;
        }
    }

    let pct = |a: usize| a as f64 / N as f64 * 100.0;
    println!("── Tier-0 coverage-dedup evaluation ──────────────────────────────");
    println!("registered prefixes (E)      full = {:>4}   dedup = {:>4}   ({:.1}× fewer masks)",
        masks_full.len(), masks_dedup.len(),
        masks_full.len() as f64 / masks_dedup.len().max(1) as f64);
    println!();
    println!("false NEGATIVES (relevant dropped — must be 0)");
    println!("    full  = {}/{}   dedup = {}/{}", fn_full, N, fn_dedup, N);
    println!();
    println!("false POSITIVES (irrelevant admitted — lower is better)");
    println!("    full  = {:>5}/{}  = {:>6.2}%", fp_full, N, pct(fp_full));
    println!("    dedup = {:>5}/{}  = {:>6.2}%", fp_dedup, N, pct(fp_dedup));
    println!("    ⇒ {:.1}× lower FP, and {:.1}× less per-frame work (fewer masks tested)",
        pct(fp_full) / pct(fp_dedup).max(1e-9),
        masks_full.len() as f64 / masks_dedup.len().max(1) as f64);
    println!();
    println!("kept after dedup: {:?}",
        deduped.iter().map(|p| std::str::from_utf8(p).unwrap()).collect::<Vec<_>>());
    assert_eq!(fn_full, 0, "full set must have zero false negatives");
    assert_eq!(fn_dedup, 0, "dedup must preserve zero false negatives");
}
