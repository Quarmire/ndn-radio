//! **Name three-zone opacity** (NDR_MAC_SPEC §4.2) — the naming half of the NDR MAC's privacy dial.
//!
//! An NDN name is split into three zones, keyed on a per-namespace signed policy object:
//! ```text
//!   [ clear routable prefix ) [ opaque semantic middle ) [ clear structural tail )
//!     [0, B)  routing / FIB      [B, M)  NAC-tokenised      [M, N)  segment / version
//! ```
//! - **Clear prefix `[0,B)`** — routable; relays LPM on it; always exposed (the floor of the dial).
//! - **Opaque middle `[B,M)`** — each component value becomes `T_k(component)`: a **deterministic,
//!   one-way keyed hash** under the namespace **name-token key**. The wire type stays a
//!   `GenericNameComponent` (fabric-agnostic). Both endpoints compute it *forward* — a consumer knows
//!   the real name → tokenises → Interest; a producer indexes content by the same tokens → matches →
//!   serves. **Nothing recovers the name from the wire** (one-way; no recovery path). Authorised nodes
//!   (holding the key) compute identical tokens ⇒ PIT/CS exact-match works within the authorised set;
//!   an eavesdropper sees opaque bytes (meaning hidden) and can only correlate access patterns
//!   (the accepted leak). A token collision costs at most a wasted fetch, caught at the consumer's
//!   signature verify — H1 (never drop a wanted frame) is intact because relevance is still by name.
//! - **Clear tail `[M,N)`** — structural components (segment/version) the forwarder/segmenter needs.
//!
//! `T_k` is **SipHash-2-4** under the 16-byte name-token key — the same keyed PRF family as the #44
//! keyspace, so an outsider watching tokens cannot recover the key or forge/predict a private group's
//! tokens. The name-token key is distributed by the **same NAC access grant** that carries the content
//! key (spec §9): "authorised for `/ns`" = *form/read its names* (this key) AND *decrypt its content*
//! (the NAC content key, `ndn_security::confidentiality`). Granted and revoked together.
//!
//! `B, M` are **per-namespace, dynamic**, from a named signed policy object — **no boundary metadata on
//! the wire**; a node without the policy is route-only (LPM the clear prefix; cannot interpret the
//! middle). This module is the pure tokenisation; the policy fetch + key grant are L3 (NAC).

use crate::mac::tlv::{put_tlv, read_var};
use ndn_frame_io::siphash24;

/// Width of a name token (`T_k`) on the wire, bytes — a fixed-width one-way SipHash digest.
pub const TOKEN_LEN: usize = 8;

/// The per-namespace name boundaries `(B, M)` — the payload of the signed policy object endpoints hold.
/// Components `[0,B)` stay clear (routable), `[B,M)` are tokenised, `[M,N)` stay clear (structural).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NamespacePolicy {
    /// `B` — number of leading clear (routable) components.
    pub clear_prefix_len: usize,
    /// `M` — index one past the last tokenised component (opaque middle is `[B, M)`).
    pub opaque_end: usize,
}

impl NamespacePolicy {
    /// A policy tokenising `[clear_prefix_len, opaque_end)`. `opaque_end` is clamped to ≥
    /// `clear_prefix_len` (an empty middle = fully-clear name, the public baseline).
    pub fn new(clear_prefix_len: usize, opaque_end: usize) -> Self {
        Self {
            clear_prefix_len,
            opaque_end: opaque_end.max(clear_prefix_len),
        }
    }

    /// The all-clear policy (no opaque middle) — public content, no grant, no anchor needed.
    pub fn clear() -> Self {
        Self {
            clear_prefix_len: 0,
            opaque_end: 0,
        }
    }

    /// Is component index `i` (in a name of `depth` components) in the opaque middle `[B, M)`?
    fn is_opaque(&self, i: usize, depth: usize) -> bool {
        let m = self.opaque_end.min(depth);
        i >= self.clear_prefix_len && i < m
    }
}

/// `T_k(component)` — the one-way keyed token bytes for one component value.
pub fn token(key: &[u8; 16], component: &[u8]) -> [u8; TOKEN_LEN] {
    siphash24(key, component).to_be_bytes()
}

/// Tokenise a full name's component values under `policy` and the namespace name-token `key`: clear
/// components pass through verbatim; opaque-middle components become their `T_k`. The result is the
/// **wire** component values (all `GenericNameComponent`s). A consumer and a producer that hold the same
/// `(policy, key)` produce byte-identical wire names ⇒ their PIT/CS exact-match.
pub fn tokenize<C: AsRef<[u8]>>(
    policy: &NamespacePolicy,
    key: &[u8; 16],
    components: &[C],
) -> Vec<Vec<u8>> {
    let depth = components.len();
    components
        .iter()
        .enumerate()
        .map(|(i, c)| {
            if policy.is_opaque(i, depth) {
                token(key, c.as_ref()).to_vec()
            } else {
                c.as_ref().to_vec()
            }
        })
        .collect()
}

/// The clear **routable prefix** components of a wire name under `policy` — what a relay LPMs on and
/// what the rendezvous `F` keys on. (The tokenised middle and clear tail are excluded.)
pub fn clear_prefix<'a, C: AsRef<[u8]>>(policy: &NamespacePolicy, components: &'a [C]) -> &'a [C] {
    &components[..policy.clear_prefix_len.min(components.len())]
}

/// TLV types for the NAC objects that carry name opacity (§9), experimental range (peer `NdrCapability`
/// 0x0380). These are the **payloads** of L3 named signed Data; the signing, the seal-to-consumer, and
/// the anchor verification are done at L3 (`ndn_security::confidentiality` for the content key,
/// `ndn_sealed_box` to seal to a consumer's identity key). This module only defines the wire bytes.
pub const TLV_NS_POLICY: u64 = 0x0390;
pub const TLV_NS_CLEAR_PREFIX_LEN: u64 = 0x0391;
pub const TLV_NS_OPAQUE_END: u64 = 0x0392;
pub const TLV_NAC_GRANT: u64 = 0x0398;
pub const TLV_NAC_NAME_TOKEN_KEY: u64 = 0x0399;
pub const TLV_NAC_CONTENT_KEY: u64 = 0x039A;

impl NamespacePolicy {
    /// Encode the policy object's **payload** — `(B, M)`. Carried in a named signed Data
    /// (`/<ns>/NAC/policy`, verified to the anchor); a node holding it derives the zones, and a node
    /// without it is route-only (LPM the clear prefix). No boundary metadata ever rides a data frame.
    pub fn encode(&self) -> Vec<u8> {
        let mut inner = Vec::new();
        put_tlv(
            &mut inner,
            TLV_NS_CLEAR_PREFIX_LEN,
            &(self.clear_prefix_len as u32).to_be_bytes(),
        );
        put_tlv(
            &mut inner,
            TLV_NS_OPAQUE_END,
            &(self.opaque_end as u32).to_be_bytes(),
        );
        let mut out = Vec::new();
        put_tlv(&mut out, TLV_NS_POLICY, &inner);
        out
    }

    /// Decode a policy payload (as `encode` produced). `None` if not a policy TLV or malformed.
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let mut p = 0;
        if read_var(bytes, &mut p)? != TLV_NS_POLICY {
            return None;
        }
        let len = read_var(bytes, &mut p)? as usize;
        let body = bytes.get(p..p + len)?;
        let (mut b, mut m) = (0usize, 0usize);
        let mut q = 0;
        while q < body.len() {
            let t = read_var(body, &mut q)?;
            let l = read_var(body, &mut q)? as usize;
            let v = body.get(q..q + l)?;
            match t {
                TLV_NS_CLEAR_PREFIX_LEN if l >= 4 => {
                    b = u32::from_be_bytes(v[..4].try_into().ok()?) as usize
                }
                TLV_NS_OPAQUE_END if l >= 4 => {
                    m = u32::from_be_bytes(v[..4].try_into().ok()?) as usize
                }
                _ => {}
            }
            q += l;
        }
        Some(NamespacePolicy::new(b, m))
    }
}

/// **The NAC access grant** (§9) — the *one* grant that carries **both** keys an authorised node needs
/// for a namespace: the **name-token key** (form/read the opaque names, §4.2) and the **content key**
/// (decrypt the content, `ndn_security::confidentiality::ContentKey`). "Authorised for `/ns`" = both.
/// Granted and revoked together (key rotation).
///
/// This type is the grant's **plaintext payload**. At L3 it is **sealed to the authorised consumer's
/// identity key** (`ndn_sealed_box::seal`) and published as named signed Data
/// (`/<ns>/NAC/grant/ENCRYPTED-BY/<consumer>`), verified to the provisioned anchor — the NAC KDK
/// distribution path. This module never holds a private key; it only (de)serialises the payload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NacGrant {
    /// The 16-byte name-token key `k` for `T_k` (name opacity).
    pub name_token_key: [u8; 16],
    /// The raw content-key bytes (a `ContentKey`) for decrypting the namespace's content.
    pub content_key: Vec<u8>,
}

impl NacGrant {
    /// Encode the grant payload (`0x0398 { name-token-key, content-key }`) — the plaintext L3 seals.
    pub fn encode(&self) -> Vec<u8> {
        let mut inner = Vec::new();
        put_tlv(&mut inner, TLV_NAC_NAME_TOKEN_KEY, &self.name_token_key);
        put_tlv(&mut inner, TLV_NAC_CONTENT_KEY, &self.content_key);
        let mut out = Vec::new();
        put_tlv(&mut out, TLV_NAC_GRANT, &inner);
        out
    }

    /// Decode a grant payload (after L3 has opened the seal). `None` if not a grant or missing keys.
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let mut p = 0;
        if read_var(bytes, &mut p)? != TLV_NAC_GRANT {
            return None;
        }
        let len = read_var(bytes, &mut p)? as usize;
        let body = bytes.get(p..p + len)?;
        let mut ntk: Option<[u8; 16]> = None;
        let mut ck: Option<Vec<u8>> = None;
        let mut q = 0;
        while q < body.len() {
            let t = read_var(body, &mut q)?;
            let l = read_var(body, &mut q)? as usize;
            let v = body.get(q..q + l)?;
            match t {
                TLV_NAC_NAME_TOKEN_KEY if l >= 16 => ntk = Some(v[..16].try_into().ok()?),
                TLV_NAC_CONTENT_KEY => ck = Some(v.to_vec()),
                _ => {}
            }
            q += l;
        }
        Some(NacGrant {
            name_token_key: ntk?,
            content_key: ck?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn comps(parts: &[&str]) -> Vec<Vec<u8>> {
        parts.iter().map(|s| s.as_bytes().to_vec()).collect()
    }

    #[test]
    fn authorized_nodes_produce_identical_tokens() {
        // /ndn/health/<patient>/<record>/v3 : clear /ndn/health, opaque [2,4), clear tail v3.
        let key = *b"ns-name-token-k1";
        let p = NamespacePolicy::new(2, 4);
        let name = comps(&["ndn", "health", "alice", "bp", "v3"]);
        let consumer = tokenize(&p, &key, &name);
        let producer = tokenize(&p, &key, &name); // same key + policy at both ends
        assert_eq!(
            consumer, producer,
            "both endpoints tokenise forward to the same bytes"
        );
        // clear prefix + tail survive verbatim; middle is opaque + fixed-width.
        assert_eq!(&consumer[0], b"ndn");
        assert_eq!(&consumer[1], b"health");
        assert_eq!(&consumer[4], b"v3");
        assert_eq!(consumer[2].len(), TOKEN_LEN);
        assert_ne!(consumer[2].as_slice(), b"alice");
    }

    #[test]
    fn a_different_key_yields_different_tokens_opacity() {
        let p = NamespacePolicy::new(2, 4);
        let name = comps(&["ndn", "health", "alice", "bp"]);
        let a = tokenize(&p, b"ns-name-token-k1", &name);
        let b = tokenize(&p, b"OTHER-namespace!", &name);
        assert_ne!(
            a[2], b[2],
            "an eavesdropper without the key cannot reproduce the token"
        );
        assert_eq!(
            a[0], b[0],
            "the clear routable prefix is unaffected by the key"
        );
    }

    #[test]
    fn clear_policy_leaves_the_whole_name_public() {
        let p = NamespacePolicy::clear();
        let name = comps(&["ndn", "public", "doc"]);
        assert_eq!(tokenize(&p, b"anykeyanykeyany!", &name), name);
    }

    #[test]
    fn namespace_policy_payload_round_trips() {
        let p = NamespacePolicy::new(2, 5);
        assert_eq!(NamespacePolicy::decode(&p.encode()), Some(p));
        assert_eq!(NamespacePolicy::decode(&[0x07, 0x00]), None);
    }

    #[test]
    fn nac_grant_carries_both_keys_and_round_trips() {
        let g = NacGrant {
            name_token_key: *b"ns-name-token-k1",
            content_key: vec![9u8; 32],
        };
        let w = g.encode();
        let back = NacGrant::decode(&w).unwrap();
        assert_eq!(
            back.name_token_key, g.name_token_key,
            "name-token key survives"
        );
        assert_eq!(back.content_key, g.content_key, "content key survives");
        // The same grant drives the tokenizer: a node that opens it can form the opaque names.
        let p = NamespacePolicy::new(2, 4);
        let name = comps(&["ndn", "health", "alice", "bp"]);
        assert_eq!(
            tokenize(&p, &back.name_token_key, &name),
            tokenize(&p, &g.name_token_key, &name)
        );
    }

    #[test]
    fn clear_prefix_is_the_routable_zone() {
        let p = NamespacePolicy::new(2, 4);
        let name = comps(&["ndn", "health", "alice", "bp", "v3"]);
        let pre = clear_prefix(&p, &name);
        assert_eq!(pre.len(), 2);
        assert_eq!(&pre[1], b"health");
    }
}
