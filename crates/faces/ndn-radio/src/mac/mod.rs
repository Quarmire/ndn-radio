//! **The named-radio MAC** — the bearer-agnostic control the PHYs actuate and cognition drives.
//!
//! This is the coherent home for the MAC primitives that used to be scattered across the Wi-Fi PHY and
//! the cognition crate: ephemeral per-frame identity, the named airtime-lease scheduler's cooperation
//! model, and DoS/abuse gating. The name-derivation + prefix-set filter cluster folds in next.
pub mod coop;
pub mod dos;
pub mod ephemeral_id;
