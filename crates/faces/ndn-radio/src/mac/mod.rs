//! **The named-radio MAC** — the bearer-agnostic control the PHYs actuate and cognition drives.
//!
//! This is the coherent home for the MAC primitives that used to be scattered across the Wi-Fi PHY and
//! the cognition crate: ephemeral per-frame identity, the named airtime-lease scheduler's cooperation
//! model, and DoS/abuse gating. The name-derivation + prefix-set filter cluster folds in next.
pub mod coop;
pub mod dos;
pub mod ephemeral_id;
pub mod tier0;
pub mod gcs;
pub mod name;
pub mod schedule;
/// Canonical prefix-hash (FNV-1a over the name components, with a separator) — the
/// opaque key that ties demand, the sense bus, `NameContext`, and the consistency
/// digest together. The forwarder uses this to turn a `Name` prefix into the key
/// the control plane is keyed on.
pub fn prefix_hash(components: &[&[u8]]) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for c in components {
        for &b in *c {
            h ^= b as u64;
            h = h.wrapping_mul(0x100000001b3);
        }
        // component separator so ["ab","c"] ≠ ["a","bc"]
        h ^= 0x2f;
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}
