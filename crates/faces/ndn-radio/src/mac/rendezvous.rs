//! **Rendezvous** (NDR_MAC_SPEC §7) — the one keyless, public function `F(clear-prefix, epoch)` that
//! projects to **(channel, phase)** on the common-view clock, so a sender and every co-requester meet
//! with **no beacon and no coordinator**. It runs on the *clear* routable prefix (relays and even
//! eavesdroppers can compute it — it reveals nothing the clear prefix did not); it is coordination and
//! spectral-reuse, never privacy.
//!
//! Two projections from one function, over pinned **shared constants** (item 9) so every node computes
//! the same answer without configuration:
//! - **channel** = `channels[H(prefix ∥ epoch) mod C]` — spectral reuse / contention relief.
//! - **phase**   = `H(prefix ∥ epoch) mod slots` — the listen window a sleeper wakes for (§8).
//!
//! The constants are *defaults, then on-air calibrated* (as the lease guard was), bounded by the
//! measured µs TSF. They are `pub const` so a divergent node is a code change, never silent drift.

/// Rendezvous **epoch** (superframe) length, µs. Channel is chosen once per epoch; the epoch is also the
/// sleep duty-cycle period the phase window lives in. Default 1 s — affordable to recompute (one cheap
/// hash/prefix, cached) even on the 40 MHz AR9271; calibratable against the measured clock.
pub const RENDEZVOUS_EPOCH_US: u64 = 1_000_000;

/// Phase **slots** per epoch — the granularity of the listen window a sleeper wakes for. 16 slots of a
/// 1 s epoch ⇒ a 62.5 ms window ⇒ ~6% floor duty for a few-prefix node. Calibratable.
pub const RENDEZVOUS_SLOTS: u64 = 16;

/// Phase-window **guard**, µs — widens the listen window each side so a sender whose clock differs by up
/// to the guard still hits it. Bounded by the measured µs common-view precision (≈0.4 µs AR9271, but
/// COTS scheduled-TX jitter is larger); default 2 ms, calibratable.
pub const RENDEZVOUS_GUARD_US: u64 = 2_000;

/// The well-known **common channel** floor (§3 F1): a node with no clock / not channel-agile lives here,
/// so a `Hop`-incapable receiver is always reachable. Per-bearer; this is the 2.4 GHz default.
pub const RENDEZVOUS_COMMON_CHANNEL: u8 = 6;

/// `F(clear-prefix, epoch) → (channel, phase)` over a bearer's channel set and the pinned constants.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rendezvous {
    channels: Vec<u8>,
    epoch_us: u64,
    slots: u64,
    guard_us: u64,
}

impl Rendezvous {
    /// The **pinned-default** rendezvous over a bearer's channel set (empty ⇒ the common-channel floor).
    /// Every node that holds the name and this channel set computes identical `(channel, phase)`.
    pub fn new(channels: Vec<u8>) -> Self {
        let channels = if channels.is_empty() {
            vec![RENDEZVOUS_COMMON_CHANNEL]
        } else {
            channels
        };
        Self {
            channels,
            epoch_us: RENDEZVOUS_EPOCH_US,
            slots: RENDEZVOUS_SLOTS,
            guard_us: RENDEZVOUS_GUARD_US,
        }
    }

    /// Override the pinned constants — the on-air calibration path. `epoch_us`/`slots` clamped to ≥1.
    pub fn with_params(mut self, epoch_us: u64, slots: u64, guard_us: u64) -> Self {
        self.epoch_us = epoch_us.max(1);
        self.slots = slots.max(1);
        self.guard_us = guard_us;
        self
    }

    /// The common-view epoch at `now_us`.
    pub fn epoch(&self, now_us: u64) -> u64 {
        now_us / self.epoch_us
    }

    /// Mix the clear-prefix hash with the epoch — the one draw both projections read, so channel and
    /// phase rotate together per epoch and every node agrees. A multiply-shift avalanche of `H ⊕ epoch`.
    fn draw(&self, clear_prefix_hash: u64, now_us: u64) -> u64 {
        let mut z = clear_prefix_hash ^ self.epoch(now_us).wrapping_mul(0x9E37_79B9_7F4A_7C15);
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// **channel** — which carrier this name sits on this epoch. `channels[draw mod C]`.
    pub fn channel(&self, clear_prefix_hash: u64, now_us: u64) -> u8 {
        let i = self.draw(clear_prefix_hash, now_us) % self.channels.len() as u64;
        self.channels[i as usize]
    }

    /// **phase** — the slot index in `[0, slots)` this name's listen window falls on this epoch.
    pub fn phase_slot(&self, clear_prefix_hash: u64, now_us: u64) -> u64 {
        (self.draw(clear_prefix_hash, now_us) >> 8) % self.slots
    }

    /// The listen window (absolute µs `[start, end)`) for this name in the epoch containing `now_us`,
    /// widened by the guard each side. A sleeper wakes for this; a sender aims TX at it.
    pub fn phase_window_us(&self, clear_prefix_hash: u64, now_us: u64) -> (u64, u64) {
        let slot_us = self.epoch_us / self.slots;
        let base = self.epoch(now_us) * self.epoch_us
            + self.phase_slot(clear_prefix_hash, now_us) * slot_us;
        (
            base.saturating_sub(self.guard_us),
            base + slot_us + self.guard_us,
        )
    }

    /// Is `now_us` inside this name's (guard-widened) listen window?
    pub fn in_listen_window(&self, clear_prefix_hash: u64, now_us: u64) -> bool {
        let (a, b) = self.phase_window_us(clear_prefix_hash, now_us);
        now_us >= a && now_us < b
    }

    /// µs until the start of this name's next listen window (0 if already inside one) — for a sender to
    /// schedule TX at a sleeper's window, or a relay to hold a PIT entry until it (§8).
    pub fn next_window_us(&self, clear_prefix_hash: u64, now_us: u64) -> u64 {
        if self.in_listen_window(clear_prefix_hash, now_us) {
            return 0;
        }
        let slot_us = self.epoch_us / self.slots;
        // Search this epoch's window then the next epoch's (the slot may already be past this epoch).
        for e in [self.epoch(now_us), self.epoch(now_us) + 1] {
            let start =
                e * self.epoch_us + self.phase_slot(clear_prefix_hash, e * self.epoch_us) * slot_us;
            let win_start = start.saturating_sub(self.guard_us);
            if win_start >= now_us {
                return win_start - now_us;
            }
        }
        0
    }

    /// The channel set this rendezvous draws over.
    pub fn channels(&self) -> &[u8] {
        &self.channels
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mac::prefix_hash;

    #[test]
    fn channel_and_phase_are_pure_functions_of_name_and_clock() {
        let r = Rendezvous::new(vec![36, 40, 44, 48]);
        let a = prefix_hash(&[b"ndn", b"alarm"]);
        let now = 12_345_678u64;
        // Deterministic: same (name, clock) -> same answer at any node.
        assert_eq!(r.channel(a, now), r.channel(a, now));
        assert_eq!(r.phase_slot(a, now), r.phase_slot(a, now));
        assert!(r.channels().contains(&r.channel(a, now)));
        assert!(r.phase_slot(a, now) < RENDEZVOUS_SLOTS);
    }

    #[test]
    fn channel_rotates_per_epoch_but_holds_within_one() {
        let r = Rendezvous::new(vec![1, 6, 11]);
        let a = prefix_hash(&[b"ndn", b"bulk"]);
        let e0 = 5 * RENDEZVOUS_EPOCH_US + 100;
        let e0b = 5 * RENDEZVOUS_EPOCH_US + RENDEZVOUS_EPOCH_US - 1;
        assert_eq!(
            r.channel(a, e0),
            r.channel(a, e0b),
            "channel holds across one epoch"
        );
        // Over many epochs it visits more than one channel (spectral reuse).
        let seen: std::collections::BTreeSet<u8> = (0..300)
            .map(|e| r.channel(a, e * RENDEZVOUS_EPOCH_US))
            .collect();
        assert!(seen.len() > 1, "channel rotates across epochs");
    }

    #[test]
    fn empty_channel_set_is_the_common_channel_floor() {
        let r = Rendezvous::new(vec![]);
        assert_eq!(r.channel(0xABCD, 0), RENDEZVOUS_COMMON_CHANNEL);
    }

    #[test]
    fn listen_window_is_reachable_and_next_window_lands_in_it() {
        let r = Rendezvous::new(vec![6]);
        let a = prefix_hash(&[b"ndn", b"sleepy"]);
        let now = 7_000_003u64;
        let wait = r.next_window_us(a, now);
        assert!(
            r.in_listen_window(a, now + wait),
            "next_window_us lands inside the window"
        );
    }
}
