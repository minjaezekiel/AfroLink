//! What governance may decide, and the record of it deciding.
//!
//! # The list is the point
//!
//! [`Action`] is exhaustive. There is no `Action::Custom`, no encoded call, no
//! arbitrary message the council can wrap in a proposal and execute as itself.
//! That is a deliberate departure from how on-chain governance is usually built:
//! Polkadot governance dispatches a runtime `Call`, and Cosmos executes a
//! message the module holds authority over, which in both cases means the answer
//! to *"what can governance do?"* is *"anything the chain can do."*
//!
//! Here the answer is this enum, and it is six items long. Adding a seventh is a
//! code change that has to be argued for and reviewed, rather than a proposal
//! that has to be noticed.
//!
//! # What is not on the list, and why
//!
//! **Nothing that moves money.** No treasury spend, no minting, no balance
//! adjustment, no slash, no freeze. The council cannot transfer, cannot pay
//! itself, and cannot reach into an account.
//!
//! **Nothing that touches a currency already admitted.** Governance may admit a
//! new sovereign denomination, because a denomination nobody has registered has
//! no sovereign to ask. Once registered, its minters, its cap, its freezer, its
//! pause and its authority belong to that authority alone, and the only way the
//! authority changes is the two-step handover in `crates/bank`. This is the
//! mBridge rule — on a shared platform, *each central bank is the exclusive
//! issuer and redeemer of its own currency* — and it is the whole reason a
//! central bank would consider issuing on rails it does not own.
//!
//! So the split is: **the platform is governed collectively; the money on it is
//! not.**

use afrolink_alias::contact::Attestor;
use afrolink_crypto::Address;
use afrolink_primitives::codec::{CodecError, Decode, Encode, Reader};
use afrolink_primitives::{Denom, Height};

use crate::council::Council;
use crate::params::ChainParams;

/// Something governance can decide to do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// Replace the council: add seats, remove them, or reweight them.
    ///
    /// Absolute rather than incremental, and safely so. The argument against
    /// absolute assignment elsewhere in this codebase — that software built
    /// before a field existed silently clears it, which is why
    /// [`SetAccountFlag`](../../../crates/types/src/tx.rs) names one flag at a
    /// time — does not apply to a homogeneous list. A council is a set of seats
    /// and every voter reads the whole set they are enacting.
    SetCouncil(Council),

    /// Replace the chain-wide parameters.
    ///
    /// Also absolute, and for a reason particular to this codec: it refuses
    /// trailing bytes, so a node running an older binary cannot decode a
    /// [`ChainParams`] carrying a field it has never heard of. It fails loudly
    /// instead of silently reverting the field to a default — which is the exact
    /// failure the flags argument is about. A new parameter is a hard fork here,
    /// and it announces itself as one.
    SetParams(ChainParams),

    /// License a party to attest phone and email bindings.
    ///
    /// The message that [ADR-0021](../../../docs/adr/0021-licensing-attestors.md)
    /// named as missing. Until it existed, an attestor set was whatever a
    /// network's founders wrote into genesis, permanently.
    LicenseAttestor {
        /// The account that will sign attestations.
        address: Address,
        /// Its registry record. Must be active — see
        /// [`ProposalError::LicensedSuspended`].
        attestor: Attestor,
    },

    /// Withdraw or restore an attestor's licence.
    ///
    /// Suspension rather than deletion, so bindings an attestor already made
    /// keep a resolvable provenance after its licence lapses. This is what
    /// `Attestor::active` was written for and what, until now, nothing could
    /// set.
    SetAttestorActive {
        /// The attestor.
        address: Address,
        /// Whether it may attest from now on.
        active: bool,
    },

    /// Admit a new sovereign denomination, naming its authority.
    ///
    /// Registration only. Re-admitting a denomination that already has an issuer
    /// is refused, because that would be a path by which the council replaces a
    /// sovereign's authority without the sovereign's consent — the one thing
    /// this design promises it cannot do.
    AdmitDenom {
        /// The denomination, which must be sovereign.
        denom: Denom,
        /// The account that will govern it.
        authority: Address,
    },

    /// Withdraw a proposal that has passed but not yet executed.
    ///
    /// **Executes immediately on reaching the threshold, with no timelock.** A
    /// timelock exists to give notice before a change binds; withdrawing a
    /// change is a return to the state everyone already expects, and there is
    /// nothing to give notice of. Without this exception a cancellation would
    /// have to wait out its own timelock and would almost always arrive too
    /// late.
    ///
    /// It clears the same two-thirds bar as anything else, rather than being a
    /// guardian key. A key that can cancel any queued proposal is a key that can
    /// deny governance entirely, which is why OpenZeppelin warns against handing
    /// the canceller role to anyone besides the governor itself.
    Cancel {
        /// The proposal to withdraw.
        proposal: u64,
    },
}

/// Why a proposed action was refused before it was ever put to a vote.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ProposalError {
    /// An attestor proposed already suspended.
    #[error("an attestor must be licensed active; suspend it afterwards if that is the intent")]
    LicensedSuspended,
    /// A non-sovereign denomination proposed for admission.
    #[error("{0} is not a sovereign denomination and has no issuer to admit")]
    NotSovereign(String),
    /// A cancellation naming a proposal that is not awaiting execution.
    #[error("proposal {0} is not scheduled, so there is nothing to cancel")]
    NotCancellable(u64),
    /// A cancellation naming itself.
    #[error("a proposal cannot cancel itself")]
    SelfCancelling,
}

impl Action {
    /// Whether reaching the threshold applies this immediately.
    ///
    /// True only for [`Action::Cancel`]. See its documentation.
    #[must_use]
    pub const fn bypasses_timelock(&self) -> bool {
        matches!(self, Self::Cancel { .. })
    }

    /// Checks that can be made when the proposal is opened.
    ///
    /// Run at proposal time rather than at execution, so a malformed action is
    /// refused before the council spends a voting period on it — and so the
    /// failure names the proposer rather than whoever paid to execute.
    ///
    /// # Errors
    /// Returns the first [`ProposalError`] found.
    pub fn validate(&self) -> Result<(), ProposalError> {
        match self {
            Self::LicenseAttestor { attestor, .. } => {
                if attestor.active {
                    Ok(())
                } else {
                    Err(ProposalError::LicensedSuspended)
                }
            }
            Self::AdmitDenom { denom, .. } => {
                if denom.is_sovereign() {
                    Ok(())
                } else {
                    Err(ProposalError::NotSovereign(denom.to_string()))
                }
            }
            Self::SetCouncil(_) | Self::SetParams(_) | Self::SetAttestorActive { .. } => Ok(()),
            // Whether the target is cancellable is state, checked in
            // `Governance::propose`. Only the self-reference is visible here.
            Self::Cancel { .. } => Ok(()),
        }
    }
}

/// A question put to the council.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Proposal {
    /// Identifier, assigned in sequence.
    pub id: u64,
    /// The seat that opened it.
    pub proposer: Address,
    /// What it would do.
    pub action: Action,
    /// When it was opened.
    pub opened: Height,
    /// Last height at which a vote counts.
    pub voting_ends: Height,
    /// Seats that have voted in favour. Sorted and free of repeats.
    ///
    /// There is no "against". A seat that does not want a proposal declines to
    /// vote and it lapses — the same shape a savings group's quorum takes in
    /// `crates/types/src/group.rs`, and for the same reason: with a threshold to
    /// clear and a deadline to clear it by, silence already means no.
    pub votes: Vec<Address>,
    /// Set once the threshold is reached: the first height it may be executed.
    pub scheduled_for: Option<Height>,
}

impl Proposal {
    /// Whether `seat` has already voted.
    #[must_use]
    pub fn has_voted(&self, seat: &Address) -> bool {
        self.votes.binary_search(seat).is_ok()
    }

    /// Record a vote, keeping the list canonical.
    ///
    /// Returns whether the vote was new.
    pub fn record_vote(&mut self, seat: Address) -> bool {
        match self.votes.binary_search(&seat) {
            Ok(_) => false,
            Err(at) => {
                self.votes.insert(at, seat);
                true
            }
        }
    }
}

impl Encode for Action {
    fn encode(&self, out: &mut Vec<u8>) {
        match self {
            Self::SetCouncil(council) => {
                out.push(1);
                council.encode(out);
            }
            Self::SetParams(params) => {
                out.push(2);
                params.encode(out);
            }
            Self::LicenseAttestor { address, attestor } => {
                out.push(3);
                address.encode(out);
                attestor.encode(out);
            }
            Self::SetAttestorActive { address, active } => {
                out.push(4);
                address.encode(out);
                active.encode(out);
            }
            Self::AdmitDenom { denom, authority } => {
                out.push(5);
                denom.encode(out);
                authority.encode(out);
            }
            Self::Cancel { proposal } => {
                out.push(6);
                proposal.encode(out);
            }
        }
    }
}

impl Decode for Action {
    fn decode(r: &mut Reader<'_>) -> Result<Self, CodecError> {
        match u8::decode(r)? {
            1 => Ok(Self::SetCouncil(Council::decode(r)?)),
            2 => Ok(Self::SetParams(ChainParams::decode(r)?)),
            3 => Ok(Self::LicenseAttestor {
                address: Address::decode(r)?,
                attestor: Attestor::decode(r)?,
            }),
            4 => Ok(Self::SetAttestorActive {
                address: Address::decode(r)?,
                active: bool::decode(r)?,
            }),
            5 => Ok(Self::AdmitDenom {
                denom: Denom::decode(r)?,
                authority: Address::decode(r)?,
            }),
            6 => Ok(Self::Cancel {
                proposal: u64::decode(r)?,
            }),
            tag => Err(CodecError::UnknownDiscriminant {
                tag,
                type_name: "Action",
            }),
        }
    }
}

impl Encode for Proposal {
    fn encode(&self, out: &mut Vec<u8>) {
        self.id.encode(out);
        self.proposer.encode(out);
        self.action.encode(out);
        self.opened.encode(out);
        self.voting_ends.encode(out);
        self.votes.encode(out);
        self.scheduled_for.encode(out);
    }
}

impl Decode for Proposal {
    fn decode(r: &mut Reader<'_>) -> Result<Self, CodecError> {
        let proposal = Self {
            id: u64::decode(r)?,
            proposer: Address::decode(r)?,
            action: Action::decode(r)?,
            opened: Height::decode(r)?,
            voting_ends: Height::decode(r)?,
            votes: Vec::<Address>::decode(r)?,
            scheduled_for: Option::<Height>::decode(r)?,
        };
        // Refused, not sorted: the tally is read off this list and a repeat
        // would let one seat vote twice.
        if !proposal.votes.is_sorted_by(|a, b| a < b) {
            return Err(CodecError::Invalid(
                "proposal votes must be sorted and unique".to_owned(),
            ));
        }
        Ok(proposal)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use afrolink_crypto::SecretKey;
    use afrolink_primitives::CountryCode;
    use afrolink_primitives::codec::decode_exact;

    fn addr(seed: u8) -> Address {
        Address::from_public_key(&SecretKey::from_bytes(&[seed; 32]).public_key())
    }

    fn attestor(active: bool) -> Attestor {
        Attestor {
            country: CountryCode::new("ke").expect("valid"),
            name: "Safaricom".to_owned(),
            active,
        }
    }

    #[test]
    fn an_attestor_cannot_be_licensed_already_suspended() {
        // The same rule genesis enforces: a registry row nothing can turn on.
        assert_eq!(
            Action::LicenseAttestor {
                address: addr(1),
                attestor: attestor(false),
            }
            .validate(),
            Err(ProposalError::LicensedSuspended)
        );
        assert!(
            Action::LicenseAttestor {
                address: addr(1),
                attestor: attestor(true),
            }
            .validate()
            .is_ok()
        );
    }

    #[test]
    fn the_native_coin_cannot_be_admitted_as_a_sovereign_currency() {
        assert!(matches!(
            Action::AdmitDenom {
                denom: Denom::native(),
                authority: addr(1),
            }
            .validate(),
            Err(ProposalError::NotSovereign(_))
        ));
    }

    #[test]
    fn only_a_cancellation_skips_the_timelock() {
        assert!(Action::Cancel { proposal: 1 }.bypasses_timelock());
        assert!(!Action::SetParams(ChainParams::default()).bypasses_timelock());
    }

    #[test]
    fn one_seat_cannot_vote_twice() {
        let mut p = Proposal {
            id: 1,
            proposer: addr(1),
            action: Action::Cancel { proposal: 0 },
            opened: Height(1),
            voting_ends: Height(100),
            votes: Vec::new(),
            scheduled_for: None,
        };
        assert!(p.record_vote(addr(2)));
        assert!(!p.record_vote(addr(2)), "the second vote is not new");
        assert!(p.record_vote(addr(1)));
        assert_eq!(p.votes.len(), 2);
        assert!(p.votes.is_sorted(), "insertion keeps the list canonical");
        assert!(p.has_voted(&addr(1)) && p.has_voted(&addr(2)));
        assert!(!p.has_voted(&addr(3)));
    }

    #[test]
    fn a_proposal_with_repeated_votes_does_not_decode() {
        let mut bad = Vec::new();
        1u64.encode(&mut bad);
        addr(1).encode(&mut bad);
        Action::Cancel { proposal: 0 }.encode(&mut bad);
        Height(1).encode(&mut bad);
        Height(100).encode(&mut bad);
        2u32.encode(&mut bad);
        addr(2).encode(&mut bad);
        addr(2).encode(&mut bad);
        None::<Height>.encode(&mut bad);
        assert!(decode_exact::<Proposal>(&bad).is_err());
    }

    #[test]
    fn actions_round_trip() {
        for action in [
            Action::SetParams(ChainParams::default()),
            Action::LicenseAttestor {
                address: addr(1),
                attestor: attestor(true),
            },
            Action::SetAttestorActive {
                address: addr(2),
                active: false,
            },
            Action::AdmitDenom {
                denom: Denom::sovereign("ke", "kes").expect("valid"),
                authority: addr(3),
            },
            Action::Cancel { proposal: 7 },
        ] {
            assert_eq!(decode_exact::<Action>(&action.to_bytes()), Ok(action));
        }
    }
}
