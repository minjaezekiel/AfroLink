//! On-chain governance: who may change the network, what they may change, and
//! how long everyone else gets to see it coming.
//!
//! # The gap this closes
//!
//! Until this crate existed, **every trusted role on the chain was fixed at
//! genesis and could not be rotated, added or revoked**. An issuer authority
//! whose key was lost stayed lost. An attestor whose regulator withdrew its
//! licence stayed licensed on-chain. Every parameter was a `const`, so tuning one
//! meant a flag day that stops every mobile-money agent in a corridor at the same
//! moment. [ADR-0020](../../../docs/adr/0020-sovereign-issuance.md) and
//! [ADR-0021](../../../docs/adr/0021-licensing-attestors.md) both named it, and
//! both declined to invent an authority in passing. This is that authority, named
//! deliberately.
//!
//! # Two tracks, and the line between them
//!
//! **The network track** is here: the council, the parameters, attestor
//! licensing, and admitting a new currency. It is collective, it clears two
//! thirds, and it waits out a timelock.
//!
//! **The sovereign track is not here at all.** Once a denomination is admitted,
//! its authority governs it — minters, cap, freezer, pause — and hands that role
//! on through the two-step transfer in `crates/bank`, with no vote taken
//! anywhere. The council cannot mint, cannot freeze, cannot spend and cannot
//! replace an authority.
//!
//! The reason is not modesty about governance, it is what makes the chain usable
//! by a central bank: on BIS's mBridge, a shared platform run jointly by several
//! central banks, *each central bank is the exclusive issuer and redeemer of its
//! own CBDC*, and the platform's own rules are set by a separate steering
//! committee. Same split, same reason. A sovereign will not issue on rails where
//! a vote elsewhere can reach its money.
//!
//! # Where the pieces live
//!
//! * [`council`] — the body, its threshold, and the jurisdiction cap
//! * [`params`] — what may be tuned, and the floors that cannot be tuned away
//! * [`proposal`] — the exhaustive list of what governance may decide

#![cfg_attr(
    test,
    allow(
        clippy::arithmetic_side_effects,
        clippy::indexing_slicing,
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        reason = "tests assert on known-good fixtures; a panic there is a failed test, not a halted node"
    )
)]

pub mod council;
pub mod params;
pub mod proposal;

pub use council::{Council, CouncilError, MAX_SEATS, MIN_COUNCIL_THRESHOLD_BPS, Seat};
pub use params::{ChainParams, ParamError, StakingParams};
pub use proposal::{Action, Proposal, ProposalError};

use afrolink_crypto::Address;
use afrolink_primitives::Height;
use afrolink_primitives::codec::{Decode, Encode};
use afrolink_state::{KeyValueStore, StoreKey};
use thiserror::Error;

/// Most proposals that may be open at once.
///
/// A bound on the state a council can create. Proposals are opened by seated
/// members who pay a fee for each, so this is not a spam defence so much as a
/// guarantee that the index stays a fixed size — and a reason for lapsed
/// proposals to be swept rather than accumulate.
pub const MAX_OPEN_PROPOSALS: usize = 64;

/// Why a governance operation failed.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum GovError {
    /// The chain has no council, so nothing can be decided.
    ///
    /// Unreachable on a chain started from a validated genesis file, which
    /// refuses an empty council for exactly this reason.
    #[error("this chain has no seated council")]
    NoCouncil,
    /// The sender holds no seat.
    #[error("{0} holds no council seat")]
    NotSeated(Address),
    /// No proposal with that id.
    #[error("no proposal {0}")]
    NoSuchProposal(u64),
    /// The seat has already voted on this proposal.
    #[error("this seat has already voted on proposal {0}")]
    AlreadyVoted(u64),
    /// The voting period has closed.
    #[error("voting on proposal {id} closed at height {ended}, now {now}")]
    VotingClosed {
        /// The proposal.
        id: u64,
        /// When voting closed.
        ended: u64,
        /// Current height.
        now: u64,
    },
    /// Voting has already concluded and the proposal is awaiting execution.
    #[error("proposal {0} has passed and is awaiting execution")]
    AlreadyPassed(u64),
    /// The proposal has not reached the threshold.
    #[error("proposal {0} has not passed")]
    NotScheduled(u64),
    /// The timelock has not elapsed.
    #[error("proposal {id} is executable at height {executable_at}, now {now}")]
    Timelocked {
        /// The proposal.
        id: u64,
        /// First height it may be executed.
        executable_at: u64,
        /// Current height.
        now: u64,
    },
    /// [`MAX_OPEN_PROPOSALS`] are already open.
    #[error("at most {MAX_OPEN_PROPOSALS} proposals may be open at once")]
    TooManyProposals,
    /// The proposed action is malformed.
    #[error(transparent)]
    Proposal(#[from] ProposalError),
    /// The proposed council is not one the chain will accept.
    #[error(transparent)]
    Council(#[from] CouncilError),
    /// The proposed parameters are not ones the chain will accept.
    #[error(transparent)]
    Param(#[from] ParamError),
    /// Stored state did not decode.
    #[error("corrupt governance state: {0}")]
    Corrupt(String),
}

/// The open proposals, and the next identifier to hand out.
///
/// The counter is stored rather than derived from the largest open id, because
/// ids that restart once the queue empties are ids that get reused — and a
/// [`Action::Cancel`] or an audit log naming proposal 3 should never be
/// ambiguous about which proposal 3 it meant.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProposalQueue {
    /// The identifier the next proposal will take.
    pub next_id: u64,
    /// Ids of proposals still open or awaiting execution, in ascending order.
    pub open: Vec<u64>,
}

impl Encode for ProposalQueue {
    fn encode(&self, out: &mut Vec<u8>) {
        self.next_id.encode(out);
        self.open.encode(out);
    }
}

impl Decode for ProposalQueue {
    fn decode(
        r: &mut afrolink_primitives::codec::Reader<'_>,
    ) -> Result<Self, afrolink_primitives::codec::CodecError> {
        Ok(Self {
            next_id: u64::decode(r)?,
            open: Vec::<u64>::decode(r)?,
        })
    }
}

/// What a vote did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VoteOutcome {
    /// Counted, and the proposal is still short of the threshold.
    Recorded,
    /// The threshold was reached; the proposal may be executed from this height.
    Scheduled(Height),
    /// The threshold was reached on a withdrawal, which took effect at once.
    Withdrew(u64),
}

/// Read-only access to governance state.
///
/// Separate from [`Governance`] because the executor reads the parameters on
/// paths that hold the store immutably, and a read should not need a mutable
/// borrow to happen.
pub struct GovView<'a, S: KeyValueStore> {
    store: &'a S,
}

impl<'a, S: KeyValueStore> GovView<'a, S> {
    /// Borrow a store for reading.
    #[must_use]
    pub const fn new(store: &'a S) -> Self {
        Self { store }
    }

    /// The parameters in force.
    ///
    /// Falls back to [`ChainParams::default`] when none are stored, so the chain
    /// behaves exactly as it did before governance existed rather than halting.
    ///
    /// # Errors
    /// Returns [`GovError::Corrupt`] if stored bytes do not decode.
    pub fn params(&self) -> Result<ChainParams, GovError> {
        Ok(self
            .get::<ChainParams>(&StoreKey::params())?
            .unwrap_or_default())
    }

    /// The seated council, if there is one.
    ///
    /// # Errors
    /// Returns [`GovError::Corrupt`] if stored bytes do not decode.
    pub fn council(&self) -> Result<Option<Council>, GovError> {
        self.get::<Council>(&StoreKey::council())
    }

    /// One proposal, if it exists.
    ///
    /// # Errors
    /// Returns [`GovError::Corrupt`] if stored bytes do not decode.
    pub fn proposal(&self, id: u64) -> Result<Option<Proposal>, GovError> {
        self.get::<Proposal>(&StoreKey::proposal(id))
    }

    /// The queue of open proposals.
    ///
    /// # Errors
    /// Returns [`GovError::Corrupt`] if stored bytes do not decode.
    pub fn queue(&self) -> Result<ProposalQueue, GovError> {
        Ok(self
            .get::<ProposalQueue>(&StoreKey::proposal_index())?
            .unwrap_or_default())
    }

    /// The ids of every open proposal, in ascending order.
    ///
    /// # Errors
    /// Returns [`GovError::Corrupt`] if stored bytes do not decode.
    pub fn open_proposals(&self) -> Result<Vec<u64>, GovError> {
        Ok(self.queue()?.open)
    }

    fn get<T: Decode>(&self, key: &StoreKey) -> Result<Option<T>, GovError> {
        self.store
            .get_decoded::<T>(key)
            .map_err(|e| GovError::Corrupt(e.to_string()))
    }
}

/// Reads and writes governance state.
pub struct Governance<'a, S: KeyValueStore> {
    store: &'a mut S,
}

impl<'a, S: KeyValueStore> Governance<'a, S> {
    /// Borrow a store as a governance module.
    pub fn new(store: &'a mut S) -> Self {
        Self { store }
    }

    /// A read-only view over the same store.
    #[must_use]
    pub fn view(&self) -> GovView<'_, S> {
        GovView::new(self.store)
    }

    /// The parameters in force.
    ///
    /// # Errors
    /// Returns [`GovError::Corrupt`] if stored bytes do not decode.
    pub fn params(&self) -> Result<ChainParams, GovError> {
        self.view().params()
    }

    /// The seated council, if there is one.
    ///
    /// # Errors
    /// Returns [`GovError::Corrupt`] if stored bytes do not decode.
    pub fn council(&self) -> Result<Option<Council>, GovError> {
        self.view().council()
    }

    /// One proposal, if it exists.
    ///
    /// # Errors
    /// Returns [`GovError::Corrupt`] if stored bytes do not decode.
    pub fn proposal(&self, id: u64) -> Result<Option<Proposal>, GovError> {
        self.view().proposal(id)
    }

    /// Seat a council and write the parameters. **Genesis only.**
    ///
    /// # Errors
    /// Returns [`GovError::Param`] or [`GovError::Council`] if either is invalid
    /// under the other — the council's concentration is checked against the cap
    /// the parameters name, so a genesis file cannot seat a body its own rules
    /// would refuse.
    pub fn install(&mut self, council: &Council, params: &ChainParams) -> Result<(), GovError> {
        params.validate()?;
        council.check_concentration(params.max_council_country_share_bps)?;
        self.store.set_encoded(&StoreKey::params(), params);
        self.store.set_encoded(&StoreKey::council(), council);
        Ok(())
    }

    /// Replace the council. Reached only through an executed proposal.
    ///
    /// # Errors
    /// Returns [`GovError::Council`] if the new council breaches the
    /// concentration cap in force.
    pub fn set_council(&mut self, council: &Council) -> Result<(), GovError> {
        let params = self.params()?;
        council.check_concentration(params.max_council_country_share_bps)?;
        self.store.set_encoded(&StoreKey::council(), council);
        Ok(())
    }

    /// Replace the parameters. Reached only through an executed proposal.
    ///
    /// # Errors
    /// Returns [`GovError::Param`] if the change breaches a floor or the
    /// ratchet, or [`GovError::Council`] if the tightened cap would unseat the
    /// council that voted for it.
    pub fn set_params(&mut self, params: &ChainParams) -> Result<(), GovError> {
        let current = self.params()?;
        params.validate_change_from(&current)?;
        // A council may tighten its own concentration cap, and it may not
        // tighten it past the shape it is currently in. Otherwise the vote that
        // narrows the cap is also the vote that makes the sitting council
        // invalid, and the chain would be governed by a body its own rules
        // refuse — or by nobody.
        if let Some(council) = self.council()? {
            council.check_concentration(params.max_council_country_share_bps)?;
        }
        self.store.set_encoded(&StoreKey::params(), params);
        Ok(())
    }

    /// Open a proposal.
    ///
    /// The proposer's own vote is **not** counted automatically. Opening a
    /// question and answering it are different acts, and a tally that silently
    /// includes one seat nobody saw vote is a tally that reads wrong.
    ///
    /// # Errors
    /// Returns the first [`GovError`] encountered.
    pub fn propose(
        &mut self,
        sender: &Address,
        action: Action,
        now: Height,
    ) -> Result<u64, GovError> {
        let council = self.require_council()?;
        if !council.is_seated(sender) {
            return Err(GovError::NotSeated(*sender));
        }
        action.validate()?;

        // Anything the action can be checked for up front, is. A malformed
        // proposal should cost its proposer a fee now rather than the council a
        // voting period later.
        match &action {
            Action::SetCouncil(proposed) => {
                let cap = self.params()?.max_council_country_share_bps;
                proposed.check_concentration(cap)?;
            }
            Action::SetParams(proposed) => {
                proposed.validate_change_from(&self.params()?)?;
            }
            Action::Cancel { proposal } => {
                let target = self.require_proposal(*proposal)?;
                if target.scheduled_for.is_none() {
                    return Err(ProposalError::NotCancellable(*proposal).into());
                }
            }
            Action::LicenseAttestor { .. }
            | Action::SetAttestorActive { .. }
            | Action::AdmitDenom { .. } => {}
        }

        let mut queue = self.sweep_lapsed(now)?;
        if queue.open.len() >= MAX_OPEN_PROPOSALS {
            return Err(GovError::TooManyProposals);
        }

        let params = self.params()?;
        let id = queue.next_id;
        let proposal = Proposal {
            id,
            proposer: *sender,
            action,
            opened: now,
            voting_ends: Height(now.0.saturating_add(params.voting_period_blocks)),
            votes: Vec::new(),
            scheduled_for: None,
        };
        queue.next_id = queue.next_id.saturating_add(1);
        queue.open.push(id);
        self.store.set_encoded(&StoreKey::proposal_index(), &queue);
        self.store.set_encoded(&StoreKey::proposal(id), &proposal);
        Ok(id)
    }

    /// Cast a seat's vote in favour.
    ///
    /// # Errors
    /// Returns the first [`GovError`] encountered.
    pub fn vote(
        &mut self,
        sender: &Address,
        id: u64,
        now: Height,
    ) -> Result<VoteOutcome, GovError> {
        let council = self.require_council()?;
        if !council.is_seated(sender) {
            return Err(GovError::NotSeated(*sender));
        }
        let mut proposal = self.require_proposal(id)?;
        if proposal.scheduled_for.is_some() {
            return Err(GovError::AlreadyPassed(id));
        }
        if now > proposal.voting_ends {
            return Err(GovError::VotingClosed {
                id,
                ended: proposal.voting_ends.0,
                now: now.0,
            });
        }
        if !proposal.record_vote(*sender) {
            return Err(GovError::AlreadyVoted(id));
        }

        // Tallied against the council as it stands right now, not as it stood
        // when the proposal opened. A seat removed mid-vote stops counting, which
        // is the only reading under which removing a compromised seat is worth
        // doing.
        let tally: u64 = proposal
            .votes
            .iter()
            .map(|seat| u64::from(council.weight_of(seat)))
            .sum();

        if !council.reached(tally) {
            self.store.set_encoded(&StoreKey::proposal(id), &proposal);
            return Ok(VoteOutcome::Recorded);
        }

        if let Action::Cancel { proposal: target } = proposal.action {
            // Applied here rather than after a timelock: see `Action::Cancel`.
            self.remove(target)?;
            self.remove(id)?;
            return Ok(VoteOutcome::Withdrew(target));
        }

        let params = self.params()?;
        let at = Height(now.0.saturating_add(params.timelock_blocks));
        proposal.scheduled_for = Some(at);
        self.store.set_encoded(&StoreKey::proposal(id), &proposal);
        Ok(VoteOutcome::Scheduled(at))
    }

    /// Take a passed proposal off the queue and hand back what it decided.
    ///
    /// **Permissionless**, like `ApplyRebind` and for the same reason: the vote
    /// has been taken and the timelock has run, so the outcome is already
    /// settled and whoever pays the fee to finish the job changes nothing about
    /// it. Requiring a seat would mean a council that loses interest, or a seat
    /// that is removed between passing and execution, leaves a decided question
    /// unexecuted forever.
    ///
    /// The caller applies the returned [`Action`]. This module deliberately does
    /// not: an action can touch the attestor registry or the issuer registry,
    /// and moving those writes here would mean either a dependency cycle or a
    /// second copy of rules that live next to the state they protect.
    ///
    /// # Errors
    /// Returns the first [`GovError`] encountered.
    pub fn execute(&mut self, id: u64, now: Height) -> Result<Action, GovError> {
        let proposal = self.require_proposal(id)?;
        let Some(executable_at) = proposal.scheduled_for else {
            return Err(GovError::NotScheduled(id));
        };
        if now < executable_at {
            return Err(GovError::Timelocked {
                id,
                executable_at: executable_at.0,
                now: now.0,
            });
        }
        self.remove(id)?;
        Ok(proposal.action)
    }

    fn require_council(&self) -> Result<Council, GovError> {
        self.council()?.ok_or(GovError::NoCouncil)
    }

    fn require_proposal(&self, id: u64) -> Result<Proposal, GovError> {
        self.proposal(id)?.ok_or(GovError::NoSuchProposal(id))
    }

    /// Delete a proposal and drop it from the queue.
    fn remove(&mut self, id: u64) -> Result<(), GovError> {
        self.store.delete(&StoreKey::proposal(id));
        let mut queue = self.view().queue()?;
        queue.open.retain(|open_id| *open_id != id);
        self.store.set_encoded(&StoreKey::proposal_index(), &queue);
        Ok(())
    }

    /// Drop proposals whose voting period ended without them passing.
    ///
    /// Returns the surviving queue. Swept at proposal time rather than at the
    /// end of every block: a lapsed proposal is inert, so the only thing its
    /// lingering costs is a slot, and the only person who wants the slot is the
    /// next proposer.
    fn sweep_lapsed(&mut self, now: Height) -> Result<ProposalQueue, GovError> {
        let mut queue = self.view().queue()?;
        let mut kept = Vec::with_capacity(queue.open.len());
        for id in queue.open {
            match self.proposal(id)? {
                Some(p) if p.scheduled_for.is_some() || now <= p.voting_ends => kept.push(id),
                Some(_) => {
                    self.store.delete(&StoreKey::proposal(id));
                }
                // An id in the queue with no record behind it: drop it rather
                // than let it hold a slot forever.
                None => {}
            }
        }
        queue.open = kept;
        self.store.set_encoded(&StoreKey::proposal_index(), &queue);
        Ok(queue)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use afrolink_alias::contact::Attestor;
    use afrolink_crypto::SecretKey;
    use afrolink_primitives::{CountryCode, Denom};
    use afrolink_state::MemoryStore;

    fn addr(seed: u8) -> Address {
        Address::from_public_key(&SecretKey::from_bytes(&[seed; 32]).public_key())
    }

    fn cc(s: &str) -> CountryCode {
        CountryCode::new(s).expect("valid country")
    }

    /// Four equally weighted seats in four countries, passing at two thirds.
    ///
    /// Four rather than three because three equal countries is exactly the shape
    /// the concentration rule refuses: a third each, and a third is enough to
    /// block a two-thirds threshold. Each seat here holds 2500 bps, three of the
    /// four are needed to pass, and no jurisdiction can decide or block alone.
    fn council() -> Council {
        seats_of(&[(1, 10, "ke"), (2, 10, "ng"), (3, 10, "za"), (4, 10, "gh")])
    }

    /// Seats given as `(seed, weight, country)`, sorted into canonical order.
    fn seats_of(seats: &[(u8, u32, &str)]) -> Council {
        let mut seats: Vec<Seat> = seats
            .iter()
            .map(|(seed, weight, country)| Seat::new(addr(*seed), *weight, cc(country)))
            .collect();
        seats.sort_by_key(|seat| seat.holder);
        Council::new(seats, MIN_COUNCIL_THRESHOLD_BPS).expect("valid council")
    }

    fn seated() -> MemoryStore {
        let mut store = MemoryStore::new();
        Governance::new(&mut store)
            .install(&council(), &ChainParams::devnet())
            .expect("installs");
        store
    }

    fn attestor() -> Attestor {
        Attestor {
            country: cc("ke"),
            name: "Safaricom".to_owned(),
            active: true,
        }
    }

    fn license() -> Action {
        Action::LicenseAttestor {
            address: addr(10),
            attestor: attestor(),
        }
    }

    /// Vote a proposal through and execute it, returning the action.
    fn pass(store: &mut MemoryStore, id: u64, at: Height) -> Action {
        let mut gov = Governance::new(store);
        for seat in [addr(1), addr(2), addr(3), addr(4)] {
            match gov.vote(&seat, id, at) {
                Ok(VoteOutcome::Scheduled(when)) => {
                    return gov.execute(id, when).expect("executes at the timelock");
                }
                Ok(VoteOutcome::Recorded) => {}
                other => panic!("unexpected vote outcome: {other:?}"),
            }
        }
        panic!("proposal never reached the threshold");
    }

    #[test]
    fn a_stranger_can_neither_propose_nor_vote() {
        let mut store = seated();
        let mut gov = Governance::new(&mut store);
        assert_eq!(
            gov.propose(&addr(99), license(), Height(1)),
            Err(GovError::NotSeated(addr(99)))
        );
        let id = gov.propose(&addr(1), license(), Height(1)).expect("opens");
        assert_eq!(
            gov.vote(&addr(99), id, Height(2)),
            Err(GovError::NotSeated(addr(99)))
        );
    }

    #[test]
    fn a_proposal_cannot_be_executed_before_its_timelock() {
        // The whole value of the timelock is the window between "decided" and
        // "binding". If it can be skipped there is no window.
        let mut store = seated();
        let mut gov = Governance::new(&mut store);
        let id = gov.propose(&addr(1), license(), Height(1)).expect("opens");
        assert_eq!(gov.vote(&addr(1), id, Height(1)), Ok(VoteOutcome::Recorded));
        assert_eq!(gov.vote(&addr(2), id, Height(1)), Ok(VoteOutcome::Recorded));
        let VoteOutcome::Scheduled(at) = gov.vote(&addr(3), id, Height(1)).expect("passes") else {
            panic!("three of four seats reaches two thirds");
        };
        assert_eq!(at.0, 1 + ChainParams::devnet().timelock_blocks);

        assert!(matches!(
            gov.execute(id, Height(at.0 - 1)),
            Err(GovError::Timelocked { .. })
        ));
        assert_eq!(gov.execute(id, at), Ok(license()));
    }

    #[test]
    fn one_seat_cannot_reach_the_threshold_alone() {
        let mut store = seated();
        let mut gov = Governance::new(&mut store);
        let id = gov.propose(&addr(1), license(), Height(1)).expect("opens");
        assert_eq!(gov.vote(&addr(1), id, Height(1)), Ok(VoteOutcome::Recorded));
        assert_eq!(
            gov.vote(&addr(1), id, Height(1)),
            Err(GovError::AlreadyVoted(id))
        );
        assert!(matches!(
            gov.execute(id, Height(2)),
            Err(GovError::NotScheduled(_))
        ));
    }

    #[test]
    fn a_proposal_nobody_answers_lapses_and_frees_its_slot() {
        let mut store = seated();
        let period = ChainParams::devnet().voting_period_blocks;
        let mut gov = Governance::new(&mut store);
        let id = gov.propose(&addr(1), license(), Height(1)).expect("opens");
        assert_eq!(gov.view().open_proposals(), Ok(vec![id]));

        let later = Height(2 + period);
        assert!(matches!(
            gov.vote(&addr(1), id, later),
            Err(GovError::VotingClosed { .. })
        ));

        // The next proposal sweeps it.
        let next = gov.propose(&addr(1), license(), later).expect("opens");
        assert_eq!(gov.view().open_proposals(), Ok(vec![next]));
        assert_eq!(gov.proposal(id), Ok(None));
    }

    #[test]
    fn a_passed_proposal_can_be_withdrawn_inside_its_timelock() {
        // The reason for a cancellation path at all: a council that changes its
        // mind, or reads the reaction, while the change is still reversible.
        let mut store = seated();
        let mut gov = Governance::new(&mut store);
        let id = gov.propose(&addr(1), license(), Height(1)).expect("opens");
        gov.vote(&addr(1), id, Height(1)).expect("votes");
        gov.vote(&addr(2), id, Height(1)).expect("votes");
        let VoteOutcome::Scheduled(at) = gov.vote(&addr(3), id, Height(1)).expect("passes") else {
            panic!("expected a schedule");
        };

        let cancel = gov
            .propose(&addr(4), Action::Cancel { proposal: id }, Height(2))
            .expect("opens");
        gov.vote(&addr(1), cancel, Height(2)).expect("votes");
        gov.vote(&addr(2), cancel, Height(2)).expect("votes");
        assert_eq!(
            gov.vote(&addr(3), cancel, Height(2)),
            Ok(VoteOutcome::Withdrew(id)),
            "a withdrawal takes effect at once — there is nothing to give notice of"
        );

        assert_eq!(gov.proposal(id), Ok(None));
        assert_eq!(gov.view().open_proposals(), Ok(Vec::new()));
        assert!(matches!(
            gov.execute(id, at),
            Err(GovError::NoSuchProposal(_))
        ));
    }

    #[test]
    fn nothing_that_has_not_passed_can_be_cancelled() {
        let mut store = seated();
        let mut gov = Governance::new(&mut store);
        let id = gov.propose(&addr(1), license(), Height(1)).expect("opens");
        assert!(matches!(
            gov.propose(&addr(2), Action::Cancel { proposal: id }, Height(2)),
            Err(GovError::Proposal(ProposalError::NotCancellable(_)))
        ));
    }

    #[test]
    fn a_seat_removed_mid_vote_stops_counting() {
        // The tally reads the council as it stands, not as it stood. Any other
        // reading makes removing a compromised seat pointless: its votes would
        // keep landing on every proposal opened before it left.
        let mut store = seated();
        let narrowed = seats_of(&[(1, 10, "ke"), (2, 10, "ng"), (3, 10, "za")]);

        let mut gov = Governance::new(&mut store);
        let id = gov.propose(&addr(1), license(), Height(1)).expect("opens");
        gov.vote(&addr(4), id, Height(1))
            .expect("the fourth seat votes");
        gov.set_council(&narrowed).expect("reseats");

        // addr(4) is gone, so its vote is now worth nothing: under the old
        // council two more votes would have passed this, and under the new one
        // it takes all three remaining seats.
        assert_eq!(gov.vote(&addr(1), id, Height(2)), Ok(VoteOutcome::Recorded));
        assert_eq!(gov.vote(&addr(2), id, Height(2)), Ok(VoteOutcome::Recorded));
        assert!(matches!(
            gov.vote(&addr(3), id, Height(2)),
            Ok(VoteOutcome::Scheduled(_))
        ));
    }

    #[test]
    fn the_council_cannot_seat_a_body_the_cap_refuses() {
        let mut store = MemoryStore::new();
        let params = ChainParams {
            max_council_country_share_bps: 3_333,
            ..ChainParams::default()
        };
        let mut gov = Governance::new(&mut store);

        let one_country = seats_of(&[(1, 10, "ke"), (2, 10, "ke")]);

        assert!(matches!(
            gov.install(&one_country, &params),
            Err(GovError::Council(CouncilError::CountryConcentration { .. }))
        ));

        gov.install(&council(), &params).expect("three countries");
        assert!(matches!(
            gov.set_council(&one_country),
            Err(GovError::Council(CouncilError::CountryConcentration { .. }))
        ));
    }

    #[test]
    fn tightening_the_cap_cannot_unseat_the_council_that_voted_for_it() {
        // Otherwise the vote that narrows the cap is the vote that leaves the
        // chain governed by a body its own rules refuse.
        let mut store = seated();
        let mut gov = Governance::new(&mut store);
        let mut params = ChainParams::devnet();
        // Four equal seats in four countries sit at 2500 bps each.
        params.max_council_country_share_bps = 2_000;
        assert!(matches!(
            gov.set_params(&params),
            Err(GovError::Council(CouncilError::CountryConcentration { .. }))
        ));

        params.max_council_country_share_bps = 2_500;
        assert_eq!(gov.set_params(&params), Ok(()));
    }

    #[test]
    fn a_full_lifecycle_licenses_an_attestor() {
        let mut store = seated();
        let id = Governance::new(&mut store)
            .propose(&addr(1), license(), Height(1))
            .expect("opens");
        assert_eq!(pass(&mut store, id, Height(1)), license());
        assert_eq!(
            Governance::new(&mut store).view().open_proposals(),
            Ok(Vec::new()),
            "an executed proposal leaves the queue"
        );
    }

    #[test]
    fn an_ungoverned_chain_refuses_every_proposal() {
        let mut store = MemoryStore::new();
        let mut gov = Governance::new(&mut store);
        assert_eq!(
            gov.propose(&addr(1), license(), Height(1)),
            Err(GovError::NoCouncil)
        );
        // And its parameters read as the defaults rather than halting.
        assert_eq!(gov.params(), Ok(ChainParams::default()));
    }

    #[test]
    fn the_queue_is_bounded() {
        let mut store = seated();
        let mut gov = Governance::new(&mut store);
        for _ in 0..MAX_OPEN_PROPOSALS {
            gov.propose(&addr(1), license(), Height(1)).expect("opens");
        }
        assert_eq!(
            gov.propose(&addr(1), license(), Height(1)),
            Err(GovError::TooManyProposals)
        );
    }

    #[test]
    fn admitting_a_currency_is_the_only_thing_governance_says_about_money() {
        // The action exists; nothing in `Action` can mint, freeze, spend or
        // replace an authority. This is the exhaustive match that would stop
        // compiling if a seventh variant were added.
        let admit = Action::AdmitDenom {
            denom: Denom::sovereign("ke", "kes").expect("valid"),
            authority: addr(50),
        };
        for action in [
            Action::SetCouncil(council()),
            Action::SetParams(ChainParams::devnet()),
            license(),
            Action::SetAttestorActive {
                address: addr(10),
                active: false,
            },
            admit.clone(),
            Action::Cancel { proposal: 1 },
        ] {
            let touches_money = match action {
                Action::AdmitDenom { .. } => true,
                Action::SetCouncil(_)
                | Action::SetParams(_)
                | Action::LicenseAttestor { .. }
                | Action::SetAttestorActive { .. }
                | Action::Cancel { .. } => false,
            };
            assert_eq!(touches_money, action == admit);
        }
    }
}
