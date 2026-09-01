//! The parameters governance may change, and the floors it may not go under.
//!
//! # Why these are state rather than constants
//!
//! Every number here used to be a `const`, which meant changing one was a hard
//! fork: a flag day where every node in every corridor upgrades at the same
//! moment or the chain splits. That is the failure
//! [ADR-0009](../../../docs/adr/0009-developer-payment-surface.md) §2 already
//! rules out for the runtime, and it applies just as much to the numbers the
//! runtime reads.
//!
//! # Why a parameter without a floor is not a parameter
//!
//! A tunable safety margin that may be tuned to zero is a switch that turns the
//! safety property off. So [`ChainParams::validate`] refuses values that would
//! disarm something the chain depends on, and governance can move inside those
//! bounds and nowhere else. Two of the floors are load-bearing:
//!
//! * **`staking.unbonding_ms` may never fall below [`UNBONDING_MS`].** A light
//!   client derives its trusting period from that constant *at compile time*
//!   (`afrolink_light::TRUSTING_PERIOD_MS`). Shortening the chain's unbonding
//!   period below it would leave every deployed client trusting headers signed
//!   by validators whose stake is already withdrawn and unslashable — which is
//!   the long-range attack [ADR-0010](../../../docs/adr/0010-long-range-attacks.md)
//!   exists to prevent, arrived at by vote rather than by force. Lengthening is
//!   always allowed; it only makes clients more conservative than they need to
//!   be.
//! * **`rebind_delay_blocks` may never fall below [`MIN_REBIND_DELAY_BLOCKS`].**
//!   The delay *is* the SIM-swap defence. At zero, a rebind requested by a
//!   compromised attestor takes effect before the owner can look at their phone.
//!
//! The remaining floors keep the chain able to function at all: a validator set
//! that cannot tolerate a single fault, a candidate list too short to fill it, a
//! voting period shorter than the time it takes to notice a proposal.
//!
//! One rule is a ratchet rather than a floor. `max_council_country_share_bps`
//! may be tightened and never loosened, because a cap the capped party can widen
//! is not a cap — the same reasoning, and the same shape, as
//! [`Issuer::tighten_cap`](../../../crates/bank/src/issuer.rs).

use afrolink_primitives::codec::{CodecError, Decode, Encode, Reader};
use afrolink_primitives::{Amount, UNBONDING_MS};

pub use afrolink_alias::REBIND_DELAY_BLOCKS;

/// Shortest rebinding delay governance may set, in blocks.
///
/// About 24 hours at one-second blocks. The default is 72 hours; this is the
/// point past which the SIM-swap defence stops being a defence, because a victim
/// asleep, travelling or without connectivity cannot veto in time.
pub const MIN_REBIND_DELAY_BLOCKS: u64 = 86_400;

/// Shortest voting period governance may set, in blocks.
///
/// About one hour. Below that a proposal can pass before seats in other time
/// zones have seen it exists, which is a way to decide something with a quorum
/// that only looks like one.
pub const MIN_VOTING_PERIOD_BLOCKS: u64 = 3_600;

/// Shortest timelock governance may set, in blocks.
///
/// About one hour. The timelock is notice, not deliberation — see
/// [`ChainParams::timelock_blocks`].
pub const MIN_TIMELOCK_BLOCKS: u64 = 3_600;

/// The concentration cap a mainnet genesis file must be at or under.
///
/// A third, rounded down. Combined with the two-thirds threshold floor in
/// [`crate::council`], this is what makes a single jurisdiction unable either to
/// pass a proposal with one ally or to block one on its own.
///
/// Checked by `GenesisLimits` rather than by [`ChainParams::validate`], exactly
/// as the validator distribution rule is: a devnet is one operator in one
/// country and could not start otherwise. What holds on every chain regardless
/// is the ratchet — wherever a network launches its cap, it can only tighten
/// from there.
pub const MAX_COUNCIL_COUNTRY_SHARE_BPS: u32 = 3_333;

/// Smallest active validator set governance may configure.
///
/// Four is the smallest set in which Byzantine fault tolerance means anything:
/// `n >= 3f + 1` with `f = 1`. Below it the chain has a quorum but no tolerance,
/// and one faulty node halts or forks it.
pub const MIN_VALIDATORS: usize = 4;

/// Limits on staking, tunable by governance inside [`ChainParams::validate`].
///
/// Lives here rather than in `crates/staking` for the same reason
/// [`afrolink_primitives::CountryCode`] left `crates/consensus`: a number the
/// network votes on is a value shared between modules, not a private detail of
/// the one module that happens to read it. `crates/staking` re-exports it, so
/// every existing import keeps working.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StakingParams {
    /// Smallest bond that may join the active set.
    pub min_bond: Amount,
    /// Largest active set.
    pub max_validators: usize,
    /// Ceiling on one validator's share of voting power, in basis points.
    pub max_single_share_bps: u32,
    /// Largest number of operators that may hold a bond at once.
    pub max_candidates: usize,
    /// Largest number of queued unbonding entries per operator.
    pub max_unbonding_entries: usize,
    /// How long stake stays slashable after unbonding begins.
    pub unbonding_ms: u64,
}

impl Default for StakingParams {
    /// Mainnet limits, matching [ADR-0002](../../../docs/adr/0002-consensus.md)
    /// and [ADR-0007](../../../docs/adr/0007-distribution-and-sybil-resistance.md).
    fn default() -> Self {
        Self {
            min_bond: Amount::from_afri(10_000),
            max_validators: 100,
            max_single_share_bps: 1_000,
            // A cap is needed because the candidate list is a single state value
            // rather than a scan. `min_bond` is what makes filling it expensive:
            // squatting every slot costs `max_candidates * min_bond`.
            max_candidates: 1_000,
            // Bounds the work a slash has to do, and stops an operator making
            // their own queue too expensive to process.
            max_unbonding_entries: 16,
            unbonding_ms: UNBONDING_MS,
        }
    }
}

/// Why a set of parameters was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ParamError {
    /// An unbonding period shorter than the one light clients compile in.
    #[error(
        "unbonding period of {got}ms is below {UNBONDING_MS}ms, which deployed light clients \
         assume when deriving their trusting period"
    )]
    UnbondingTooShort {
        /// The proposed period.
        got: u64,
    },
    /// A rebinding delay below [`MIN_REBIND_DELAY_BLOCKS`].
    #[error("rebinding delay of {got} blocks is below the floor of {MIN_REBIND_DELAY_BLOCKS}")]
    RebindDelayTooShort {
        /// The proposed delay.
        got: u64,
    },
    /// A voting period below [`MIN_VOTING_PERIOD_BLOCKS`].
    #[error("voting period of {got} blocks is below the floor of {MIN_VOTING_PERIOD_BLOCKS}")]
    VotingPeriodTooShort {
        /// The proposed period.
        got: u64,
    },
    /// A timelock below [`MIN_TIMELOCK_BLOCKS`].
    #[error("timelock of {got} blocks is below the floor of {MIN_TIMELOCK_BLOCKS}")]
    TimelockTooShort {
        /// The proposed timelock.
        got: u64,
    },
    /// A council concentration cap outside 1..=10000 basis points.
    #[error("a council country cap must be 1..=10000 bps, got {got}")]
    CouncilCapOutOfRange {
        /// The proposed cap.
        got: u32,
    },
    /// A council concentration cap looser than the one currently in force.
    ///
    /// The ratchet. See [`ChainParams::max_council_country_share_bps`].
    #[error("the council country cap may only be tightened: {got} bps is looser than {current}")]
    CouncilCapWouldLoosen {
        /// The proposed cap.
        got: u32,
        /// The cap in force.
        current: u32,
    },
    /// A validator set too small to tolerate a fault.
    #[error("an active set of {got} cannot tolerate a fault; the floor is {MIN_VALIDATORS}")]
    ValidatorSetTooSmall {
        /// The proposed size.
        got: usize,
    },
    /// A candidate list smaller than the active set drawn from it.
    #[error("a candidate list of {candidates} cannot fill an active set of {validators}")]
    CandidatesBelowValidators {
        /// The proposed candidate cap.
        candidates: usize,
        /// The proposed active-set size.
        validators: usize,
    },
    /// A minimum bond of zero, or a limit of zero where one makes no sense.
    #[error("{0} must be greater than zero")]
    Zero(&'static str),
    /// A per-validator concentration cap outside 1..=10000 basis points.
    #[error("a validator share cap must be 1..=10000 bps, got {got}")]
    ValidatorCapOutOfRange {
        /// The proposed cap.
        got: u32,
    },
}

/// Every chain-wide number governance is permitted to change.
///
/// Written at genesis and read on the paths that use them, so a parameter that
/// is voted on is a parameter that takes effect. A value stored in state and
/// read by nothing is the same defect as code reachable from no transaction —
/// see [ADR-0021](../../../docs/adr/0021-licensing-attestors.md) — wearing a
/// different hat.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainParams {
    /// Staking and validator-set limits.
    pub staking: StakingParams,
    /// How long a contact rebinding waits before it may be applied, in blocks.
    pub rebind_delay_blocks: u64,
    /// How long a governance proposal stays open for votes, in blocks.
    pub voting_period_blocks: u64,
    /// How long a passed proposal waits before it may be executed, in blocks.
    ///
    /// **Notice, not deliberation.** By the time the timelock starts the council
    /// has already decided; the delay exists so that everyone who has to live
    /// with the decision — exchanges, wallets, an issuer, a regulator — learns
    /// about it before it binds, and can act while it is still reversible. It is
    /// the standard argument for a timelock on governance and the reason
    /// OpenZeppelin ships one: it "allows users to exit the system if they
    /// disagree with a decision before it is executed".
    pub timelock_blocks: u64,
    /// Ceiling on any one jurisdiction's share of council weight, in basis
    /// points.
    ///
    /// **A ratchet**, enforced in [`Self::validate_change_from`]: it may be
    /// tightened and never loosened. A governance body that can raise its own
    /// concentration cap does not have one — the cap is a promise to everyone
    /// who is not on the council, and a promise the promiser can revoke is not a
    /// promise. Same rule, same reasoning, as
    /// [`Issuer::tighten_cap`](../../../crates/bank/src/issuer.rs).
    pub max_council_country_share_bps: u32,
}

impl Default for ChainParams {
    /// The values that were compile-time constants before governance existed, so
    /// a chain that never votes behaves exactly as it did.
    fn default() -> Self {
        Self {
            staking: StakingParams::default(),
            rebind_delay_blocks: REBIND_DELAY_BLOCKS,
            // ~3 days and ~2 days at one-second blocks. A council spread across
            // African time zones needs days rather than hours to read, discuss
            // and sign.
            voting_period_blocks: 259_200,
            timelock_blocks: 172_800,
            max_council_country_share_bps: MAX_COUNCIL_COUNTRY_SHARE_BPS,
        }
    }
}

impl ChainParams {
    /// Check the parameters against the floors that keep the chain safe.
    ///
    /// # Errors
    /// Returns the first [`ParamError`] found.
    pub fn validate(&self) -> Result<(), ParamError> {
        if self.staking.unbonding_ms < UNBONDING_MS {
            return Err(ParamError::UnbondingTooShort {
                got: self.staking.unbonding_ms,
            });
        }
        if self.rebind_delay_blocks < MIN_REBIND_DELAY_BLOCKS {
            return Err(ParamError::RebindDelayTooShort {
                got: self.rebind_delay_blocks,
            });
        }
        if self.voting_period_blocks < MIN_VOTING_PERIOD_BLOCKS {
            return Err(ParamError::VotingPeriodTooShort {
                got: self.voting_period_blocks,
            });
        }
        if self.timelock_blocks < MIN_TIMELOCK_BLOCKS {
            return Err(ParamError::TimelockTooShort {
                got: self.timelock_blocks,
            });
        }
        if !(1..=10_000).contains(&self.max_council_country_share_bps) {
            return Err(ParamError::CouncilCapOutOfRange {
                got: self.max_council_country_share_bps,
            });
        }
        if self.staking.min_bond.is_zero() {
            return Err(ParamError::Zero("the minimum bond"));
        }
        if self.staking.max_unbonding_entries == 0 {
            return Err(ParamError::Zero("the unbonding entry limit"));
        }
        if self.staking.max_validators < MIN_VALIDATORS {
            return Err(ParamError::ValidatorSetTooSmall {
                got: self.staking.max_validators,
            });
        }
        if self.staking.max_candidates < self.staking.max_validators {
            return Err(ParamError::CandidatesBelowValidators {
                candidates: self.staking.max_candidates,
                validators: self.staking.max_validators,
            });
        }
        if !(1..=10_000).contains(&self.staking.max_single_share_bps) {
            return Err(ParamError::ValidatorCapOutOfRange {
                got: self.staking.max_single_share_bps,
            });
        }
        Ok(())
    }

    /// Check a proposed replacement against both the floors and the ratchet.
    ///
    /// # Errors
    /// Returns the first [`ParamError`] found.
    pub fn validate_change_from(&self, current: &Self) -> Result<(), ParamError> {
        self.validate()?;
        if self.max_council_country_share_bps > current.max_council_country_share_bps {
            return Err(ParamError::CouncilCapWouldLoosen {
                got: self.max_council_country_share_bps,
                current: current.max_council_country_share_bps,
            });
        }
        Ok(())
    }

    /// Parameters for a local devnet, where one operator runs everything.
    ///
    /// The concentration cap is wide open because a devnet council is one seat
    /// in one country. It is still a ratchet from here: a devnet that later
    /// tightens the cap cannot loosen it again.
    #[must_use]
    pub fn devnet() -> Self {
        Self {
            staking: StakingParams {
                min_bond: Amount::from_afri(1),
                max_validators: MIN_VALIDATORS,
                max_single_share_bps: 10_000,
                max_candidates: MIN_VALIDATORS,
                ..StakingParams::default()
            },
            max_council_country_share_bps: 10_000,
            ..Self::default()
        }
    }
}

/// Encode a `usize` bound as a `u32`.
///
/// Every one of these is a count of validators or queue entries, orders of
/// magnitude below `u32::MAX`, and the encoding must not depend on whether the
/// node is 32- or 64-bit — two widths would be two state roots.
fn encode_count(n: usize, out: &mut Vec<u8>) {
    u32::try_from(n).unwrap_or(u32::MAX).encode(out);
}

/// Decode a count written by [`encode_count`].
fn decode_count(r: &mut Reader<'_>) -> Result<usize, CodecError> {
    Ok(usize::try_from(u32::decode(r)?).unwrap_or(usize::MAX))
}

impl Encode for StakingParams {
    fn encode(&self, out: &mut Vec<u8>) {
        self.min_bond.encode(out);
        encode_count(self.max_validators, out);
        self.max_single_share_bps.encode(out);
        encode_count(self.max_candidates, out);
        encode_count(self.max_unbonding_entries, out);
        self.unbonding_ms.encode(out);
    }
}

impl Decode for StakingParams {
    fn decode(r: &mut Reader<'_>) -> Result<Self, CodecError> {
        Ok(Self {
            min_bond: Amount::decode(r)?,
            max_validators: decode_count(r)?,
            max_single_share_bps: u32::decode(r)?,
            max_candidates: decode_count(r)?,
            max_unbonding_entries: decode_count(r)?,
            unbonding_ms: u64::decode(r)?,
        })
    }
}

impl Encode for ChainParams {
    fn encode(&self, out: &mut Vec<u8>) {
        self.staking.encode(out);
        self.rebind_delay_blocks.encode(out);
        self.voting_period_blocks.encode(out);
        self.timelock_blocks.encode(out);
        self.max_council_country_share_bps.encode(out);
    }
}

impl Decode for ChainParams {
    fn decode(r: &mut Reader<'_>) -> Result<Self, CodecError> {
        Ok(Self {
            staking: StakingParams::decode(r)?,
            rebind_delay_blocks: u64::decode(r)?,
            voting_period_blocks: u64::decode(r)?,
            timelock_blocks: u64::decode(r)?,
            max_council_country_share_bps: u32::decode(r)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use afrolink_primitives::codec::decode_exact;

    fn with_council_cap(bps: u32) -> ChainParams {
        ChainParams {
            max_council_country_share_bps: bps,
            ..ChainParams::default()
        }
    }

    fn with_unbonding(ms: u64) -> ChainParams {
        with_staking(|s| s.unbonding_ms = ms)
    }

    fn with_staking(change: impl FnOnce(&mut StakingParams)) -> ChainParams {
        let mut staking = StakingParams::default();
        change(&mut staking);
        ChainParams {
            staking,
            ..ChainParams::default()
        }
    }

    #[test]
    fn the_defaults_are_the_constants_governance_replaced() {
        // A chain that never votes must behave exactly as it did before this
        // module existed, or shipping governance is itself a parameter change.
        let p = ChainParams::default();
        assert_eq!(p.validate(), Ok(()));
        assert_eq!(p.staking.unbonding_ms, UNBONDING_MS);
        assert_eq!(p.rebind_delay_blocks, REBIND_DELAY_BLOCKS);
        assert_eq!(p.staking, StakingParams::default());
    }

    #[test]
    fn governance_cannot_shorten_unbonding_below_what_light_clients_assume() {
        // The long-range attack of ADR-0010, reached by vote instead of by
        // force. A light client compiles in TRUSTING_PERIOD_MS = 2/3 of
        // UNBONDING_MS; shortening the chain's period below that leaves clients
        // trusting headers signed by stake that is already withdrawn.
        let short = with_unbonding(UNBONDING_MS - 1);
        assert!(matches!(
            short.validate(),
            Err(ParamError::UnbondingTooShort { .. })
        ));

        // Lengthening is always fine: it only makes clients more conservative
        // than they need to be.
        assert_eq!(with_unbonding(UNBONDING_MS * 2).validate(), Ok(()));
    }

    #[test]
    fn governance_cannot_disarm_the_sim_swap_defence() {
        // At a delay of zero a compromised attestor's rebind lands before the
        // owner can look at their phone. The delay *is* the defence.
        assert!(matches!(
            ChainParams {
                rebind_delay_blocks: 0,
                ..ChainParams::default()
            }
            .validate(),
            Err(ParamError::RebindDelayTooShort { got: 0 })
        ));
        assert_eq!(
            ChainParams {
                rebind_delay_blocks: MIN_REBIND_DELAY_BLOCKS,
                ..ChainParams::default()
            }
            .validate(),
            Ok(())
        );
    }

    #[test]
    fn governance_cannot_raise_its_own_concentration_cap() {
        // A cap the capped party can widen is not a cap.
        let current = ChainParams::default();
        let same = with_council_cap(MAX_COUNCIL_COUNTRY_SHARE_BPS);
        assert_eq!(same.validate_change_from(&current), Ok(()));

        let tighter = with_council_cap(2_000);
        assert_eq!(tighter.validate_change_from(&current), Ok(()));
        // And having tightened, it cannot go back.
        assert!(matches!(
            current.validate_change_from(&tighter),
            Err(ParamError::CouncilCapWouldLoosen { .. })
        ));
    }

    #[test]
    fn a_devnet_cap_is_still_a_ratchet() {
        let devnet = ChainParams::devnet();
        assert_eq!(devnet.validate(), Ok(()));
        let tightened = ChainParams {
            max_council_country_share_bps: MAX_COUNCIL_COUNTRY_SHARE_BPS,
            ..devnet.clone()
        };
        assert_eq!(tightened.validate_change_from(&devnet), Ok(()));
        assert!(matches!(
            devnet.validate_change_from(&tightened),
            Err(ParamError::CouncilCapWouldLoosen { .. })
        ));
    }

    #[test]
    fn an_active_set_that_cannot_tolerate_a_fault_is_refused() {
        // n >= 3f + 1. At three validators one faulty node halts the chain.
        assert!(matches!(
            with_staking(|s| s.max_validators = 3).validate(),
            Err(ParamError::ValidatorSetTooSmall { got: 3 })
        ));
    }

    #[test]
    fn a_candidate_list_too_small_to_fill_the_set_is_refused() {
        assert!(matches!(
            with_staking(|s| {
                s.max_candidates = 10;
                s.max_validators = 20;
            })
            .validate(),
            Err(ParamError::CandidatesBelowValidators { .. })
        ));
    }

    #[test]
    fn a_short_voting_period_or_timelock_is_refused() {
        assert!(matches!(
            ChainParams {
                voting_period_blocks: 1,
                ..ChainParams::default()
            }
            .validate(),
            Err(ParamError::VotingPeriodTooShort { got: 1 })
        ));
        assert!(matches!(
            ChainParams {
                timelock_blocks: 0,
                ..ChainParams::default()
            }
            .validate(),
            Err(ParamError::TimelockTooShort { got: 0 })
        ));
    }

    #[test]
    fn parameters_round_trip() {
        for p in [ChainParams::default(), ChainParams::devnet()] {
            assert_eq!(decode_exact::<ChainParams>(&p.to_bytes()), Ok(p));
        }
    }
}
