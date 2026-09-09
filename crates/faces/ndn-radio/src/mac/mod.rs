//! **The named-radio MAC** — the bearer-agnostic control the PHYs actuate and cognition drives.
//!
//! This is the coherent home for the MAC primitives that used to be scattered across the Wi-Fi PHY and
//! the cognition crate: ephemeral per-frame identity, the named airtime-lease scheduler's cooperation
//! model, and DoS/abuse gating, plus the canonical name-derivation (parse) path.
pub(crate) mod tlv;
pub mod capability;
pub mod coop;
pub mod dos;
pub mod ephemeral_id;
pub mod name;
pub mod opacity;
pub mod rendezvous;
pub mod schedule;
/// Canonical prefix-hash (FNV-1a over the name components, with a separator) — the
/// opaque key that ties demand, the sense bus, `NameContext`, and the consistency
/// digest together. The forwarder uses this to turn a `Name` prefix into the key
/// the control plane is keyed on.
///
/// **The body moved down to `ndn-frame-io`** (`ndn_frame_io::keyspace`) and this is now a
/// re-export, so this path and every existing caller are unchanged. The move exists because the
/// bearer that has to *actuate* a name-derived slot is a driver, and the repo graph is a deliberate
/// DAG (`ndn-rs <- ndn-radio-drivers <- ndn-ext`) in which a driver cannot depend on this crate. The
/// alternative was a second copy of the hash in the driver — which would have been free to drift
/// while every test on both sides still passed, silently re-slotting the fleet. `ndn-frame-io` is
/// below both and already hosts the peer primitive (`siphash24`), and the moved function is pinned
/// there by golden vectors taken from THIS implementation by running it.
pub use ndn_frame_io::prefix_hash;
