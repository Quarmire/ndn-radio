//! **Modulation as a decided axis** — the PHY (packet type) a radio runs, chosen the way
//! spreading factor and MCS are chosen, one level up.
//!
//! ## The design error this fixes
//!
//! An LR2021 runs FLRC because bring-up calls `SetPacketType(Flrc)` **once**. Encoding that
//! one-time call as *identity* ("this node IS an LR2021-FLRC radio, and LR2021-LoRa is a
//! different kind of node") is backwards: `SetPacketType` is a runtime command with fourteen
//! modes, and the part can be moved between them while it runs. FLRC is ~2.6 Mbit/s at short
//! reach; the same silicon in LoRa reaches vastly further at kbit/s rates. That is a
//! **reach↔rate dial**, which is exactly what cognition already decides for SF, MCS,
//! bandwidth and power — so it belongs in the plan, not in the node's name.
//!
//! It is not an LR2021 special case either: the SX1262 does LoRa + GFSK and the SX1276 does
//! LoRa + FSK + OOK. The axis is fleet-wide; only the *offered set* differs per part.
//!
//! ## What makes this axis different from SF, and what that costs
//!
//! A PHY switch is **expensive and disruptive**. It re-runs the whole bring-up chain
//! (modulation params, packet params, sync word, IRQ map), and — the part that actually
//! bites — **both ends must move or the link is simply gone**. There is no in-band
//! negotiation on a broadcast named-data bearer: nobody ACKs, nobody renegotiates, and two
//! ends in different packet types do not hear each other at all (unlike a mismatched SF,
//! which is also a total loss but at least sits on one ladder both ends dial along the same
//! measured input). So the dial here is deliberately reluctant — see [`PhyDial`] for the four
//! independent brakes and the peer-silence escape hatch.
//!
//! ## What is ranked and what is merely *named*
//!
//! The vocabulary is the HAL's: [`PhyMode`] is every `SetPacketType` value, and
//! [`PhyModeSet`] is `EVT_CAP.phy_bitmap`. Deciding on that axis needs one thing the HAL
//! rightly does not carry — a *reach/rate model* — and only the two modes this stack has one
//! for, [`PhyMode::Lora`] and [`PhyMode::Flrc`], get a [`PhyRole`] from [`phy_role`].
//! **[`PhyDial`] only ever moves between modes it can rank.** Choosing between two modes needs
//! a model of both; inventing one is how a plan starts lying. An unranked mode stays reachable
//! by an explicit caller request and is never auto-selected.
//!
//! The offer the dial reads is [`RadioCapability::phy_modes`](crate::RadioCapability) +
//! `phy_current` — the radio's own words, and the same struct that a PHY switch replaces
//! wholesale.

use crate::policy::Priority;
use crate::sense::{PhyMode, PhyModeSet};
use std::sync::Mutex;

/// What a mode is *for* on the reach↔rate axis. Assigned only where this stack has evidence;
/// see the module docs on why an unranked mode is never auto-selected.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PhyRole {
    /// Maximum link budget, minimum rate. The **rendezvous** mode: where a group meets when it
    /// knows nothing, and where a failed switch falls back to.
    Reach,
    /// Maximum rate, minimum link budget.
    Rate,
}

/// Where a modulation sits on the reach↔rate axis, or `None` when this stack has no model of
/// it. **`None` is load-bearing**: [`PhyDial`] refuses to move to or from an unranked mode.
///
/// * [`PhyMode::Lora`] → [`Reach`](PhyRole::Reach): CSS processing gain is the whole point of
///   the modulation, and its rate is not a PHY constant but the SF/BW/CR dial the rest of this
///   crate already decides ([`crate::lora_airtime_ms`]).
/// * [`PhyMode::Flrc`] → [`Rate`](PhyRole::Rate): ~2.6 Mbit/s on the LR2021 at short reach —
///   roughly three orders of magnitude above any LoRa rung, which is why the switch is worth
///   its cost at all when the margin allows it.
///
/// Everything else is `None` **on purpose**. BLE, Z-Wave, Wi-SUN and M-Bus are foreign protocol
/// stacks rather than points on this bearer's reach/rate curve; RtToF and Raw are not
/// data-carrying modes here; and no radio in this fleet has been measured in
/// FSK/OOK/BPSK/LR-FHSS, so ranking them would be invention.
pub fn phy_role(mode: PhyMode) -> Option<PhyRole> {
    match mode {
        PhyMode::Lora => Some(PhyRole::Reach),
        PhyMode::Flrc => Some(PhyRole::Rate),
        _ => None,
    }
}

/// Peak on-air bitrate (bit/s) where one is a **property of the modulation**, else `None`.
///
/// `Flrc` = 2 600 000. [`PhyMode::Lora`] is deliberately `None`: LoRa's rate is not a PHY
/// constant, it is `(SF, BW, CR)`, and every honest number for it comes from
/// [`crate::lora_airtime_ms`] with those three in hand. Returning "the LoRa bitrate" here would
/// be a figure with no operating point attached — the kind of plausible invention this crate
/// refuses.
pub fn phy_peak_bps(mode: PhyMode) -> Option<u32> {
    match mode {
        PhyMode::Flrc => Some(2_600_000),
        _ => None,
    }
}

/// The ranked modes in an offer — the only candidates [`PhyDial`] will move between.
pub fn ranked_phys(set: PhyModeSet) -> impl Iterator<Item = (PhyMode, PhyRole)> {
    set.iter().filter_map(|m| phy_role(m).map(|r| (m, r)))
}

/// The advertised [`PhyRole::Reach`] mode — the **rendezvous PHY**: where a node goes when it is
/// unsure, and the only mode it will sit in while hearing nothing.
pub fn rendezvous_phy(set: PhyModeSet) -> Option<PhyMode> {
    ranked_phys(set).find(|(_, r)| *r == PhyRole::Reach).map(|(m, _)| m)
}

/// The advertised [`PhyRole::Rate`] mode.
pub fn fastest_phy(set: PhyModeSet) -> Option<PhyMode> {
    ranked_phys(set).find(|(_, r)| *r == PhyRole::Rate).map(|(m, _)| m)
}

/// A short stable name for a mode — for a rationale/trace field and for env-var wiring.
pub fn phy_mode_name(mode: PhyMode) -> &'static str {
    match mode {
        PhyMode::Lora => "lora",
        PhyMode::FskGeneric => "fsk-generic",
        PhyMode::Fsk => "fsk",
        PhyMode::Ble => "ble",
        PhyMode::RtToF => "rttof",
        PhyMode::Flrc => "flrc",
        PhyMode::Bpsk => "bpsk",
        PhyMode::LrFhss => "lr-fhss",
        PhyMode::WMBus => "wm-bus",
        PhyMode::WiSun => "wi-sun",
        PhyMode::Ook => "ook",
        PhyMode::Raw => "raw",
        PhyMode::ZWave => "z-wave",
        PhyMode::OQpsk154 => "o-qpsk-15.4",
        PhyMode::Unknown(_) => "unknown",
    }
}

/// Parse [`phy_mode_name`] (case-insensitive), for a wiring site that takes a mode by name.
/// Unknown text is `None` — never a default mode, because defaulting a misspelled PHY would
/// silently move the radio somewhere nobody asked for.
pub fn parse_phy_mode(s: &str) -> Option<PhyMode> {
    let s = s.trim().to_ascii_lowercase();
    (0u8..32)
        .map(PhyMode::from_code)
        .filter(|m| !matches!(m, PhyMode::Unknown(_)))
        .find(|m| phy_mode_name(*m) == s)
}

/// Tunables for [`PhyDial`]. Every default is a **deadband or a delay**, not a sensitivity
/// claim: this dial deliberately holds no absolute threshold of its own (see [`PhyDial`]).
#[derive(Clone, Copy, Debug)]
pub struct PhyDialConfig {
    /// Surplus (dB) over the anchor threshold required to ENGAGE the rate PHY.
    pub up_margin_db: f32,
    /// Margin (dB) relative to the same anchor below which we RETURN to the reach PHY.
    /// Must be well below [`up_margin_db`](Self::up_margin_db) — their difference is the
    /// deadband.
    pub down_margin_db: f32,
    /// Consecutive agreeing evaluations before a switch is committed.
    pub min_confirmations: u8,
    /// Minimum time (ms) between switches — the cool-down.
    pub min_dwell_ms: u64,
    /// After moving off the rendezvous PHY, how long (ms) we tolerate hearing **nobody**
    /// before concluding the peers did not follow, and retreating.
    pub peer_silence_ms: u64,
    /// How much (dB) each failed excursion raises the engage threshold, so a group that
    /// repeatedly fails to follow makes the next attempt strictly harder.
    pub silence_penalty_db: f32,
    /// Ceiling on the accumulated penalty (dB), so the dial can still recover if the
    /// neighbourhood genuinely changes.
    pub max_penalty_db: f32,
}

impl Default for PhyDialConfig {
    fn default() -> Self {
        Self {
            // The SF dial's own hold band is ~18 dB wide at its default 4 dB margin (adjacent SF
            // thresholds are 8-10 dB apart and the margin widens the band on both sides). This
            // dial's band is 20 dB — deliberately wider than the axis one level below it, because
            // a wrong SF is one bad link and a wrong PHY is no link at all.
            up_margin_db: 12.0,
            down_margin_db: -8.0,
            min_confirmations: 5,
            min_dwell_ms: 60_000,
            peer_silence_ms: 30_000,
            silence_penalty_db: 4.0,
            max_penalty_db: 12.0,
        }
    }
}

/// Why the dial is where it is — carried on the decision rationale so a trace shows the *why*
/// of a mode as well as the mode.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PhyHold {
    /// Fewer than two rankable modes are advertised: there is nothing to choose between.
    NothingToDecide,
    /// Inside the deadband — the measured margin does not decisively favour either mode.
    Deadband,
    /// The candidate has not been confirmed enough consecutive times yet.
    Confirming,
    /// A switch happened too recently (cool-down).
    CoolDown,
    /// Reach is what this traffic wants (`Urgent`), so the rate mode is not a candidate.
    ReachPriority,
    /// No measured peer RSSI. The dial refuses to move on a proxy — see [`PhyDial::evaluate`].
    Unmeasured,
    /// The dial committed a change on this evaluation.
    Switched,
    /// The dial retreated to the rendezvous PHY because nobody was heard after an excursion.
    PeerSilence,
}

#[derive(Clone, Copy, Debug)]
struct DialState {
    current: Option<PhyMode>,
    candidate: Option<PhyMode>,
    confirmations: u8,
    last_switch_ms: u64,
    /// When we last had a fresh receiver while off the rendezvous PHY. `None` = never yet.
    last_peer_ms: Option<u64>,
    penalty_db: f32,
    /// Earliest instant at which one excursion's worth of penalty may be forgiven. Rate-limiting
    /// forgiveness is what makes the penalty mean anything: without it, a single heard frame
    /// clears the whole history of failed excursions and the dial is back where it started.
    forgive_at_ms: u64,
    last_hold: PhyHold,
}

/// **The modulation dial** — the hysteresis that makes a rare, deliberate, reversible PHY move
/// out of a per-frame decision.
///
/// ## What stops it oscillating
///
/// Four independent brakes, each of which alone would stop a different failure mode:
///
/// 1. **A 20 dB deadband, anchored on the calibrated ladder rather than an invented number.**
///    Engaging the rate PHY needs `up_margin_db` of surplus *over the reach PHY's fastest
///    rung's operating threshold*; returning needs the margin to fall to `down_margin_db`
///    against that same anchor. The anchor is a threshold this crate already measures and
///    calibrates ([`crate::SfCalibrator`]) — the dial invents no sensitivity figure for FLRC,
///    which nobody here has measured, and states the crossover purely as a *relation* to the
///    one ladder that is real.
/// 2. **Consecutive confirmations.** A single strong sample cannot move the PHY;
///    `min_confirmations` evaluations must agree in a row, and any disagreement resets the
///    count.
/// 3. **A cool-down.** No two switches within `min_dwell_ms`, whatever the evidence says.
/// 4. **A measured-only input.** The dial reads the MEASURED weakest-receiver RSSI and holds
///    ([`PhyHold::Unmeasured`]) when there is none. The synthetic/proxy RSSI reads strong at
///    low PER and would trip one end into a mode the other never entered — the same trap that
///    pinned LoRa *bandwidth* to a real measurement in [`crate::RadioPolicy`].
///
/// ## What happens to a peer that did not follow
///
/// Nothing is negotiated on air, so a switch is a bet that every peer computed the same move
/// from the same measured inputs. When the bet loses, the losing side is **deaf**, not
/// degraded — so silence is the signal, and the dial treats it as one:
///
/// * after leaving the rendezvous PHY, hearing **no fresh receiver at all** for
///   `peer_silence_ms` is taken as "the group did not follow", and the dial retreats to the
///   rendezvous PHY immediately (bypassing the confirmation counter — the cost of staying is
///   total, the cost of retreating is rate);
/// * the retreat costs a **penalty** (`silence_penalty_db`, accumulated up to
///   `max_penalty_db`) added to the engage threshold, so a group that keeps failing to follow
///   makes each further attempt strictly harder rather than looping;
/// * the retreat also starts the cool-down, so the dial cannot immediately re-engage.
///
/// The rendezvous PHY is therefore the mode with the property that matters most here: it is
/// where a node goes when it is *unsure*, and it is the only mode a node will sit in while
/// hearing nothing. Two nodes that lose each other both end up there, which is what makes the
/// link recoverable without any protocol.
pub struct PhyDial {
    cfg: PhyDialConfig,
    state: Mutex<DialState>,
}

impl PhyDial {
    /// A dial holding `current` (usually the node's advertised `phy_current`), with default
    /// tunables.
    pub fn new(current: Option<PhyMode>) -> Self {
        Self::with_config(current, PhyDialConfig::default())
    }

    pub fn with_config(current: Option<PhyMode>, cfg: PhyDialConfig) -> Self {
        Self {
            cfg,
            state: Mutex::new(DialState {
                current,
                candidate: None,
                confirmations: 0,
                last_switch_ms: 0,
                last_peer_ms: None,
                penalty_db: 0.0,
                forgive_at_ms: 0,
                last_hold: PhyHold::NothingToDecide,
            }),
        }
    }

    /// The mode the dial currently believes the radio is in.
    pub fn current(&self) -> Option<PhyMode> {
        self.state.lock().unwrap().current
    }

    /// Accumulated engage penalty (dB) from failed excursions — telemetry.
    pub fn penalty_db(&self) -> f32 {
        self.state.lock().unwrap().penalty_db
    }

    /// Why the dial is where it is, as of the last [`evaluate`](Self::evaluate) — rendered onto
    /// the decision rationale so a trace shows the *why* of a mode, not just the mode.
    pub fn last_hold(&self) -> PhyHold {
        self.state.lock().unwrap().last_hold
    }

    /// **Decide the modulation for this transmission.**
    ///
    /// Returns the mode the plan should name (`None` when nothing is advertised, or when the
    /// dial holds no belief — leave the radio where it is) together with why.
    ///
    /// * `available` — [`RadioCapability::phy_modes`](crate::RadioCapability), what the radio
    ///   advertises. A mode outside it is **never** named.
    /// * `declared` — `RadioCapability::phy_current`, the mode the radio says it is in. Used to
    ///   seed the dial's belief the first time, and to re-seat it if the radio turns out to be
    ///   somewhere else.
    /// * `rssi_dbm` — the MEASURED weakest wanted-receiver RSSI, or `None`. Never a proxy.
    /// * `anchor_dbm` — the operating threshold of the reach PHY's *fastest* rung (today
    ///   `thresholds[SF7]`), which is what "the reach mode has margin to spare" means.
    /// * `priority` — `Urgent` wants reach and never engages the rate mode; only `Bulk`
    ///   (favour throughput) asks for it, matching how this crate already gates the 250 kHz
    ///   bandwidth widening.
    /// * `have_peer` — is any fresh receiver being heard right now (`receiver_count > 0`)?
    ///   The peer-silence escape hatch reads this.
    #[allow(clippy::too_many_arguments)]
    pub fn evaluate(
        &self,
        available: PhyModeSet,
        declared: Option<PhyMode>,
        rssi_dbm: Option<i8>,
        anchor_dbm: f32,
        priority: Priority,
        have_peer: bool,
        now_ms: u64,
    ) -> (Option<PhyMode>, PhyHold) {
        let out = self.evaluate_inner(
            available, declared, rssi_dbm, anchor_dbm, priority, have_peer, now_ms,
        );
        self.state.lock().unwrap().last_hold = out.1;
        out
    }

    #[allow(clippy::too_many_arguments)]
    fn evaluate_inner(
        &self,
        available: PhyModeSet,
        declared: Option<PhyMode>,
        rssi_dbm: Option<i8>,
        anchor_dbm: f32,
        priority: Priority,
        have_peer: bool,
        now_ms: u64,
    ) -> (Option<PhyMode>, PhyHold) {
        let mut st = self.state.lock().unwrap();

        // Seed from the node's own report the first time we see one: the dial's belief about
        // where the radio IS must come from the radio, not from a default.
        if st.current.is_none() {
            st.current = declared;
        }
        // Never keep believing in a mode the node no longer offers (it re-read its capability
        // after a switch, or a different radio was plugged in).
        if let Some(c) = st.current
            && !available.is_empty()
            && !available.contains(c)
        {
            st.current = declared.filter(|m| available.contains(*m));
        }

        let (Some(rendezvous), Some(fastest)) = (rendezvous_phy(available), fastest_phy(available))
        else {
            // Fewer than two rankable modes: report whatever the node is running (so the plan
            // is still faithful) but decide nothing.
            return (st.current, PhyHold::NothingToDecide);
        };

        // --- Escape hatch: an excursion nobody followed ---
        // Off the rendezvous PHY, being heard is the only evidence the peers came along.
        if st.current == Some(fastest) {
            if have_peer {
                st.last_peer_ms = Some(now_ms);
            } else {
                let since = st.last_peer_ms.unwrap_or(st.last_switch_ms);
                if now_ms.saturating_sub(since) >= self.cfg.peer_silence_ms {
                    st.current = Some(rendezvous);
                    st.candidate = None;
                    st.confirmations = 0;
                    st.last_switch_ms = now_ms;
                    st.last_peer_ms = None;
                    st.penalty_db =
                        (st.penalty_db + self.cfg.silence_penalty_db).min(self.cfg.max_penalty_db);
                    st.forgive_at_ms = now_ms.saturating_add(self.cfg.min_dwell_ms);
                    return (Some(rendezvous), PhyHold::PeerSilence);
                }
            }
        } else if have_peer {
            // Back in touch on the rendezvous PHY. Forgive one excursion's worth of penalty — a
            // genuinely changed neighbourhood must be retriable rather than locked out by
            // history — but at most once per cool-down. Forgiving on every decision would make
            // the penalty decorative: one heard frame would erase the whole record of failed
            // excursions, and the dial would go straight back out on the same evidence that just
            // failed.
            if st.penalty_db > 0.0 && now_ms >= st.forgive_at_ms {
                st.penalty_db = (st.penalty_db - self.cfg.silence_penalty_db).max(0.0);
                st.forgive_at_ms = now_ms.saturating_add(self.cfg.min_dwell_ms);
            }
            st.last_peer_ms = Some(now_ms);
        }

        // --- The measured margin ---
        let Some(rssi) = rssi_dbm else {
            return (st.current, PhyHold::Unmeasured);
        };
        let margin = rssi as f32 - anchor_dbm;

        // Urgent favours reach; the rate mode is not a candidate for it. (Same asymmetry as
        // `radio_score`'s reach/rate weights one level up.)
        let wants_rate = matches!(priority, Priority::Bulk);
        let target = if wants_rate && margin >= self.cfg.up_margin_db + st.penalty_db {
            fastest
        } else if margin < self.cfg.down_margin_db || (!wants_rate && st.current != Some(fastest)) {
            rendezvous
        } else if !wants_rate && st.current == Some(fastest) {
            // Already fast and this object is not bulk: hold rather than thrash the PHY for one
            // urgent name. The margin rule above is what brings us home, not the priority.
            return (st.current, PhyHold::ReachPriority);
        } else {
            return (st.current, PhyHold::Deadband);
        };

        if st.current == Some(target) {
            st.candidate = None;
            st.confirmations = 0;
            return (st.current, PhyHold::Deadband);
        }

        // --- Brakes: confirmations, then cool-down ---
        if st.candidate != Some(target) {
            st.candidate = Some(target);
            st.confirmations = 1;
        } else {
            st.confirmations = st.confirmations.saturating_add(1);
        }
        if st.confirmations < self.cfg.min_confirmations {
            return (st.current, PhyHold::Confirming);
        }
        if st.last_switch_ms != 0 && now_ms.saturating_sub(st.last_switch_ms) < self.cfg.min_dwell_ms
        {
            return (st.current, PhyHold::CoolDown);
        }

        st.current = Some(target);
        st.candidate = None;
        st.confirmations = 0;
        st.last_switch_ms = now_ms;
        st.last_peer_ms = have_peer.then_some(now_ms);
        (st.current, PhyHold::Switched)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An LR2021: LoRa + FLRC, booted in LoRa.
    fn offer() -> PhyModeSet {
        PhyModeSet::single(PhyMode::Lora).with(PhyMode::Flrc)
    }
    /// `STATIC_REQ_RSSI_SF[7]` — the fastest LoRa rung's operating threshold, and the anchor the
    /// dial states its crossover against.
    const ANCHOR: f32 = -80.0;

    fn dial() -> PhyDial {
        PhyDial::new(None)
    }

    fn eval(
        d: &PhyDial,
        rssi: Option<i8>,
        prio: Priority,
        peer: bool,
        t: u64,
    ) -> (Option<PhyMode>, PhyHold) {
        d.evaluate(offer(), Some(PhyMode::Lora), rssi, ANCHOR, prio, peer, t)
    }

    /// Drive `d` onto the rate PHY with a decisive link, returning the instant the switch
    /// committed (which is what the cool-down and the silence timer are measured from — not the
    /// instant the evidence started).
    fn engage(d: &PhyDial) -> u64 {
        for i in 0..100u64 {
            let t = 1_000 + i * 10;
            if eval(d, Some(-40), Priority::Bulk, true, t).1 == PhyHold::Switched {
                return t;
            }
        }
        panic!("the dial never engaged the rate PHY on a decisive link");
    }

    /// Only the two modes with a model are ranked; the rest are unranked ON PURPOSE, so the dial
    /// can never auto-select them.
    #[test]
    fn only_modelled_modes_are_ranked() {
        assert_eq!(phy_role(PhyMode::Lora), Some(PhyRole::Reach));
        assert_eq!(phy_role(PhyMode::Flrc), Some(PhyRole::Rate));
        for m in (0u8..32).map(PhyMode::from_code) {
            if m != PhyMode::Lora && m != PhyMode::Flrc {
                assert_eq!(phy_role(m), None, "{m:?} must not be ranked without evidence");
                assert_eq!(phy_peak_bps(m), None);
            }
        }
        assert_eq!(phy_peak_bps(PhyMode::Flrc), Some(2_600_000));
        assert_eq!(
            phy_peak_bps(PhyMode::Lora),
            None,
            "LoRa's rate is the SF/BW/CR dial, not a PHY constant"
        );
        assert_eq!(rendezvous_phy(offer()), Some(PhyMode::Lora));
        assert_eq!(fastest_phy(offer()), Some(PhyMode::Flrc));
    }

    /// Every named mode round-trips its name, and a typo resolves to nothing rather than to a
    /// default that would silently re-modulate the radio.
    #[test]
    fn mode_names_round_trip_and_a_typo_is_refused() {
        for m in (0u8..14).map(PhyMode::from_code) {
            assert_eq!(parse_phy_mode(phy_mode_name(m)), Some(m));
        }
        assert_eq!(parse_phy_mode("flrcc"), None);
        assert_eq!(parse_phy_mode(""), None);
        assert_eq!(parse_phy_mode("  FLRC "), Some(PhyMode::Flrc));
    }

    /// A plan must never name a mode the radio did not advertise — including when the evidence
    /// screams for it.
    #[test]
    fn a_mode_not_advertised_is_never_named() {
        let d = dial();
        let lora_only = PhyModeSet::single(PhyMode::Lora);
        for i in 0..50 {
            let (m, why) = d.evaluate(
                lora_only,
                Some(PhyMode::Lora),
                Some(-20),
                ANCHOR,
                Priority::Bulk,
                true,
                i * 1000,
            );
            assert_eq!(m, Some(PhyMode::Lora));
            assert_eq!(why, PhyHold::NothingToDecide);
        }
        // Nothing advertised at all: name nothing, leave the radio where it booted.
        let (m, why) = dial().evaluate(
            PhyModeSet::empty(),
            None,
            Some(-20),
            ANCHOR,
            Priority::Bulk,
            true,
            1,
        );
        assert_eq!(m, None);
        assert_eq!(why, PhyHold::NothingToDecide);
    }

    /// A strong bulk link engages the rate PHY — but only after the confirmations, never on the
    /// first sample.
    #[test]
    fn a_strong_bulk_link_engages_the_rate_phy_after_confirmations() {
        let d = dial();
        let cfg = PhyDialConfig::default();
        for i in 1..cfg.min_confirmations as u64 {
            let (m, why) = eval(&d, Some(-50), Priority::Bulk, true, i * 100);
            assert_eq!(m, Some(PhyMode::Lora), "no switch before confirmation {i}");
            assert_eq!(why, PhyHold::Confirming);
        }
        let (m, why) = eval(&d, Some(-50), Priority::Bulk, true, 10_000);
        assert_eq!(m, Some(PhyMode::Flrc));
        assert_eq!(why, PhyHold::Switched);
    }

    /// The deadband: a link parked between the engage and return margins never moves, however
    /// many times it is evaluated. This is the property that keeps a converged pair converged.
    #[test]
    fn the_deadband_holds_across_a_long_wiggle() {
        let d = dial();
        // -80 .. -72 dBm sits above the return margin (-88) and below the engage one (-68).
        for (i, r) in [-80i8, -75, -72, -79, -74, -73, -78, -76]
            .into_iter()
            .cycle()
            .take(200)
            .enumerate()
        {
            let (m, why) = eval(&d, Some(r), Priority::Bulk, true, i as u64 * 500);
            assert_eq!(m, Some(PhyMode::Lora), "held in the deadband at {r} dBm");
            assert!(matches!(why, PhyHold::Deadband | PhyHold::Confirming));
        }
    }

    /// The cool-down: even decisive evidence in the other direction cannot switch twice inside
    /// `min_dwell_ms`.
    #[test]
    fn a_second_switch_waits_out_the_cool_down() {
        let d = dial();
        let cfg = PhyDialConfig::default();
        let t0 = engage(&d);
        assert_eq!(d.current(), Some(PhyMode::Flrc));
        for i in 0..40u64 {
            let (m, why) = eval(&d, Some(-100), Priority::Bulk, true, t0 + 1 + i);
            assert_eq!(m, Some(PhyMode::Flrc), "cool-down holds the switch");
            assert!(matches!(why, PhyHold::Confirming | PhyHold::CoolDown));
        }
        let (m, why) = eval(&d, Some(-100), Priority::Bulk, true, t0 + cfg.min_dwell_ms);
        assert_eq!(m, Some(PhyMode::Lora));
        assert_eq!(why, PhyHold::Switched);
    }

    /// A proxy-free rule: with no MEASURED peer RSSI the dial does not move, because the two ends
    /// would be dialing off different fictions.
    #[test]
    fn no_measured_rssi_means_no_move() {
        let d = dial();
        for i in 0..100 {
            let (m, why) = eval(&d, None, Priority::Bulk, true, i * 1000);
            assert_eq!(m, Some(PhyMode::Lora));
            assert_eq!(why, PhyHold::Unmeasured);
        }
    }

    /// Urgent wants reach: it never engages the rate PHY, however strong the link.
    #[test]
    fn urgent_never_engages_the_rate_phy() {
        let d = dial();
        for i in 0..100 {
            let (m, _) = eval(&d, Some(-30), Priority::Urgent, true, i * 1000);
            assert_eq!(m, Some(PhyMode::Lora));
        }
    }

    /// **The peer that did not follow.** After an excursion, hearing nobody for
    /// `peer_silence_ms` retreats to the rendezvous PHY — and the retreat raises the engage bar,
    /// so the same evidence does not immediately send us back out.
    #[test]
    fn silence_after_a_switch_retreats_to_the_rendezvous_phy() {
        let d = dial();
        let cfg = PhyDialConfig::default();
        let t0 = engage(&d);
        assert_eq!(d.current(), Some(PhyMode::Flrc));
        assert_eq!(d.penalty_db(), 0.0);

        // Nobody is heard any more. Just before the timeout, we are still out there.
        let (m, _) = eval(&d, Some(-40), Priority::Bulk, false, t0 + cfg.peer_silence_ms - 1);
        assert_eq!(m, Some(PhyMode::Flrc));
        // At the timeout: retreat, immediately, without waiting for confirmations.
        let (m, why) = eval(&d, Some(-40), Priority::Bulk, false, t0 + cfg.peer_silence_ms);
        assert_eq!(m, Some(PhyMode::Lora));
        assert_eq!(why, PhyHold::PeerSilence);
        assert_eq!(d.penalty_db(), cfg.silence_penalty_db, "the excursion cost");

        // And the same -40 dBm evidence cannot send us straight back out: the retreat restarted
        // the cool-down, and the penalty has raised the engage bar for every later attempt.
        for i in 0..50u64 {
            let (m, _) = eval(
                &d,
                Some(-40),
                Priority::Bulk,
                false,
                t0 + cfg.peer_silence_ms + 1 + i,
            );
            assert_eq!(m, Some(PhyMode::Lora), "no immediate re-excursion");
        }
    }

    /// The failed-excursion penalty is forgiven **at most once per cool-down**, not on every
    /// heard frame. Without the rate limit a single reception erases the whole record of failed
    /// excursions and the dial goes straight back out on the evidence that just failed — the
    /// penalty would be decorative.
    #[test]
    fn the_excursion_penalty_is_forgiven_slowly() {
        let d = dial();
        let cfg = PhyDialConfig::default();
        let t0 = engage(&d);
        // Two failed excursions: retreat, re-engage after the cool-down, retreat again.
        let t1 = t0 + cfg.peer_silence_ms;
        assert_eq!(eval(&d, Some(-40), Priority::Bulk, false, t1).1, PhyHold::PeerSilence);
        assert_eq!(d.penalty_db(), cfg.silence_penalty_db);

        // Peers come back and are heard constantly — but the penalty may only shed one
        // excursion's worth per cool-down, not per decision.
        for i in 0..200u64 {
            eval(&d, Some(-95), Priority::Bulk, true, t1 + 1 + i);
        }
        assert_eq!(
            d.penalty_db(),
            cfg.silence_penalty_db,
            "200 heard decisions inside one cool-down may not forgive anything"
        );
        // A full cool-down later, one excursion's worth is forgiven — and only one.
        for i in 0..50u64 {
            eval(&d, Some(-95), Priority::Bulk, true, t1 + cfg.min_dwell_ms + i);
        }
        assert_eq!(d.penalty_db(), 0.0);
    }

    /// Two nodes running the same dial on the same measured inputs make the same moves — the
    /// property the whole no-negotiation design rests on.
    #[test]
    fn two_dials_on_the_same_evidence_agree_at_every_step() {
        let a = dial();
        let b = dial();
        let track = [
            -95i8, -90, -85, -70, -60, -55, -50, -45, -40, -40, -45, -60, -75, -85, -95, -100,
        ];
        for (i, r) in track.into_iter().cycle().take(400).enumerate() {
            let t = i as u64 * 5_000;
            let ma = eval(&a, Some(r), Priority::Bulk, true, t);
            let mb = eval(&b, Some(r), Priority::Bulk, true, t);
            assert_eq!(ma.0, mb.0, "divergent mode at step {i} ({r} dBm)");
            assert_eq!(ma.1, mb.1, "divergent reason at step {i}");
        }
    }
}
