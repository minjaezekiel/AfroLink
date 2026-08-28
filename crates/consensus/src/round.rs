//! The Ubuntu-BFT round state machine.
//!
//! One height proceeds through rounds; each round has three steps:
//!
//! ```text
//!   Propose  ──▶  Prevote  ──▶  Precommit  ──▶  commit, or next round
//! ```
//!
//! # Why locking exists
//!
//! Suppose validators precommit block A in round 0 but a quorum never forms
//! because of a network partition. Some validators saw the precommits; others
//! did not. In round 1 the naive behaviour is to prevote whatever the new
//! proposer offers — say block B. If A had in fact been committed somewhere,
//! the chain has now forked.
//!
//! The **lock** prevents this: once a validator precommits a value it becomes
//! *locked* on it, and in later rounds it may only prevote that value. The lock
//! releases in exactly one circumstance — the validator sees proof (a quorum of
//! prevotes) that a **later** round already agreed on something else. That proof
//! could only exist if its own locked value was never committed.
//!
//! These rules are the safety argument of the entire protocol, so they are
//! implemented as small explicit functions and tested directly rather than being
//! buried in an event loop.

use afrolink_crypto::hash::Hash32;
use afrolink_primitives::{Height, Round};

/// Which step of a round is in progress.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Step {
    /// Waiting for, or issuing, a proposal.
    Propose,
    /// Prevoting.
    Prevote,
    /// Precommitting.
    Precommit,
}

/// What the state machine wants the node to do next.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// Broadcast a prevote for this value (`None` for nil).
    Prevote(Option<Hash32>),
    /// Broadcast a precommit for this value (`None` for nil).
    Precommit(Option<Hash32>),
    /// Commit this block. The height is decided.
    Commit(Hash32),
    /// Move to the next round; nothing was decided.
    NextRound(Round),
    /// Nothing to do yet.
    Wait,
}

/// A validator's state within one height.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoundState {
    /// Height being decided.
    pub height: Height,
    /// Current round.
    pub round: Round,
    /// Current step.
    pub step: Step,
    /// Value this validator is locked on, if any.
    pub locked_value: Option<Hash32>,
    /// Round in which the lock was taken.
    pub locked_round: Option<Round>,
    /// Most recent value seen to have a prevote quorum.
    pub valid_value: Option<Hash32>,
    /// Round in which `valid_value` was observed.
    pub valid_round: Option<Round>,
}

impl RoundState {
    /// Begin a height at round 0, unlocked.
    #[must_use]
    pub fn new(height: Height) -> Self {
        Self {
            height,
            round: Round::ZERO,
            step: Step::Propose,
            locked_value: None,
            locked_round: None,
            valid_value: None,
            valid_round: None,
        }
    }

    /// Whether this validator is locked on some value.
    #[must_use]
    pub fn is_locked(&self) -> bool {
        self.locked_value.is_some()
    }

    /// Decide what to prevote, given the round's proposal.
    ///
    /// `proposal` is the block offered by this round's proposer, and
    /// `proposal_valid_round` is the round the proposer claims already had a
    /// prevote quorum for it (its "proof of freshness", `None` if it is new).
    ///
    /// The rules, in order:
    ///
    /// 1. No proposal, or an invalid one → prevote nil.
    /// 2. Not locked → prevote the proposal.
    /// 3. Locked on this same value → prevote it.
    /// 4. Locked on something else, but the proposal carries proof of a quorum
    ///    from a round **later** than the lock → release the lock, prevote the
    ///    proposal.
    /// 5. Otherwise → prevote nil. Refusing is what preserves safety.
    #[must_use]
    pub fn decide_prevote(
        &self,
        proposal: Option<Hash32>,
        proposal_valid_round: Option<Round>,
        proposal_is_valid: bool,
    ) -> Decision {
        let Some(value) = proposal else {
            return Decision::Prevote(None);
        };
        if !proposal_is_valid {
            return Decision::Prevote(None);
        }

        match (self.locked_value, self.locked_round) {
            // Rule 2: nothing to protect.
            (None, _) => Decision::Prevote(Some(value)),

            // Rule 3: the proposal is what we are already committed to.
            (Some(locked), _) if locked == value => Decision::Prevote(Some(value)),

            // Rule 4: proof from a later round releases the lock.
            (Some(_), Some(locked_round)) => match proposal_valid_round {
                Some(pvr) if pvr > locked_round => Decision::Prevote(Some(value)),
                _ => Decision::Prevote(None),
            },

            // Locked without a recorded round should not happen; refuse safely.
            (Some(_), None) => Decision::Prevote(None),
        }
    }

    /// Decide what to precommit, given the outcome of the prevote step.
    ///
    /// `prevote_quorum` is `Some(Some(v))` when a quorum prevoted value `v`,
    /// `Some(None)` when a quorum prevoted nil, and `None` when no quorum formed.
    ///
    /// A quorum for a value locks this validator onto it. A quorum for nil
    /// *releases* any lock — a quorum agreeing on nothing is proof that no value
    /// was committed this round, so holding the lock would only stall later
    /// rounds.
    pub fn decide_precommit(&mut self, prevote_quorum: Option<Option<Hash32>>) -> Decision {
        match prevote_quorum {
            Some(Some(value)) => {
                self.locked_value = Some(value);
                self.locked_round = Some(self.round);
                self.valid_value = Some(value);
                self.valid_round = Some(self.round);
                self.step = Step::Precommit;
                Decision::Precommit(Some(value))
            }
            Some(None) => {
                // A quorum for nil: safe to unlock.
                self.locked_value = None;
                self.locked_round = None;
                self.step = Step::Precommit;
                Decision::Precommit(None)
            }
            None => {
                self.step = Step::Precommit;
                Decision::Precommit(None)
            }
        }
    }

    /// Decide the round's outcome from the precommit step.
    ///
    /// A quorum of precommits for a value commits it — this is where finality
    /// happens, in one round, with no probability attached.
    pub fn decide_commit(&mut self, precommit_quorum: Option<Option<Hash32>>) -> Decision {
        match precommit_quorum {
            Some(Some(value)) => Decision::Commit(value),
            _ => {
                let next = self.round.next();
                self.advance_to(next);
                Decision::NextRound(next)
            }
        }
    }

    /// Move to a new round, preserving locks.
    ///
    /// Locks deliberately survive round changes — that is the entire point of
    /// them. Only [`Self::decide_precommit`] with a nil quorum releases a lock.
    pub fn advance_to(&mut self, round: Round) {
        self.round = round;
        self.step = Step::Propose;
    }

    /// What this validator should propose if it is the proposer.
    ///
    /// A locked or valid value must be re-proposed rather than replaced, or the
    /// network could never converge on a value that already has support.
    #[must_use]
    pub fn value_to_propose(&self, fresh: Hash32) -> (Hash32, Option<Round>) {
        match (self.valid_value, self.valid_round) {
            (Some(v), vr) => (v, vr),
            _ => (fresh, None),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use afrolink_crypto::hash::{Domain, hash};

    fn block(tag: &str) -> Hash32 {
        hash(Domain::BlockId, tag.as_bytes())
    }

    #[test]
    fn an_unlocked_validator_prevotes_the_proposal() {
        let rs = RoundState::new(Height(1));
        let a = block("A");
        assert_eq!(
            rs.decide_prevote(Some(a), None, true),
            Decision::Prevote(Some(a))
        );
    }

    #[test]
    fn a_missing_or_invalid_proposal_gets_a_nil_prevote() {
        let rs = RoundState::new(Height(1));
        assert_eq!(rs.decide_prevote(None, None, true), Decision::Prevote(None));
        assert_eq!(
            rs.decide_prevote(Some(block("A")), None, false),
            Decision::Prevote(None)
        );
    }

    #[test]
    fn a_prevote_quorum_locks_the_validator() {
        let mut rs = RoundState::new(Height(1));
        let a = block("A");
        assert_eq!(
            rs.decide_precommit(Some(Some(a))),
            Decision::Precommit(Some(a))
        );
        assert_eq!(rs.locked_value, Some(a));
        assert_eq!(rs.locked_round, Some(Round::ZERO));
    }

    #[test]
    fn a_locked_validator_refuses_to_prevote_a_different_value() {
        // The core safety rule. Without it, a partition can fork the chain.
        let mut rs = RoundState::new(Height(1));
        let (a, b) = (block("A"), block("B"));
        rs.decide_precommit(Some(Some(a)));
        rs.advance_to(Round(1));

        assert_eq!(
            rs.decide_prevote(Some(b), None, true),
            Decision::Prevote(None),
            "a locked validator must not endorse a competing value"
        );
        assert_eq!(
            rs.decide_prevote(Some(a), None, true),
            Decision::Prevote(Some(a)),
            "but it happily re-prevotes what it is locked on"
        );
    }

    #[test]
    fn a_lock_survives_round_changes() {
        let mut rs = RoundState::new(Height(1));
        let a = block("A");
        rs.decide_precommit(Some(Some(a)));
        for r in 1..10u32 {
            rs.advance_to(Round(r));
            assert!(rs.is_locked(), "lock must persist into round {r}");
            assert_eq!(
                rs.decide_prevote(Some(block("B")), None, true),
                Decision::Prevote(None)
            );
        }
    }

    #[test]
    fn proof_from_a_later_round_releases_the_lock() {
        // The only way to change a locked validator's mind: evidence that a
        // later round already agreed on something else, which could only exist
        // if the locked value was never committed.
        let mut rs = RoundState::new(Height(1));
        let (a, b) = (block("A"), block("B"));
        rs.decide_precommit(Some(Some(a))); // locked on A in round 0
        rs.advance_to(Round(3));

        assert_eq!(
            rs.decide_prevote(Some(b), Some(Round(2)), true),
            Decision::Prevote(Some(b)),
            "a quorum from round 2 postdates the round-0 lock"
        );
    }

    #[test]
    fn proof_from_an_earlier_round_does_not_release_the_lock() {
        // Accepting stale proof would defeat the lock entirely.
        let mut rs = RoundState::new(Height(1));
        let (a, b) = (block("A"), block("B"));
        rs.advance_to(Round(5));
        rs.decide_precommit(Some(Some(a))); // locked on A in round 5
        rs.advance_to(Round(6));

        assert_eq!(
            rs.decide_prevote(Some(b), Some(Round(2)), true),
            Decision::Prevote(None),
            "round-2 proof cannot override a round-5 lock"
        );
        assert_eq!(
            rs.decide_prevote(Some(b), Some(Round(5)), true),
            Decision::Prevote(None),
            "proof from the same round is not later than the lock"
        );
    }

    #[test]
    fn a_nil_prevote_quorum_releases_the_lock() {
        // A quorum agreeing on nothing proves nothing was committed, so holding
        // the lock would only stall future rounds.
        let mut rs = RoundState::new(Height(1));
        rs.decide_precommit(Some(Some(block("A"))));
        assert!(rs.is_locked());

        rs.advance_to(Round(1));
        rs.decide_precommit(Some(None));
        assert!(!rs.is_locked(), "a nil quorum must unlock");

        let b = block("B");
        rs.advance_to(Round(2));
        assert_eq!(
            rs.decide_prevote(Some(b), None, true),
            Decision::Prevote(Some(b))
        );
    }

    #[test]
    fn a_precommit_quorum_commits_in_a_single_round() {
        // Deterministic finality: no confirmations, no reorg probability.
        let mut rs = RoundState::new(Height(1));
        let a = block("A");
        assert_eq!(rs.decide_commit(Some(Some(a))), Decision::Commit(a));
    }

    #[test]
    fn no_precommit_quorum_advances_the_round_without_deciding() {
        let mut rs = RoundState::new(Height(1));
        assert_eq!(rs.decide_commit(None), Decision::NextRound(Round(1)));
        assert_eq!(rs.round, Round(1));
        assert_eq!(rs.step, Step::Propose);

        assert_eq!(rs.decide_commit(Some(None)), Decision::NextRound(Round(2)));
    }

    #[test]
    fn a_proposer_re_proposes_a_valid_value_rather_than_a_fresh_one() {
        // Replacing a value that already has support would stop the network
        // converging.
        let mut rs = RoundState::new(Height(1));
        let (a, fresh) = (block("A"), block("FRESH"));
        rs.decide_precommit(Some(Some(a)));
        rs.advance_to(Round(1));

        assert_eq!(rs.value_to_propose(fresh), (a, Some(Round::ZERO)));

        let clean = RoundState::new(Height(2));
        assert_eq!(clean.value_to_propose(fresh), (fresh, None));
    }

    #[test]
    fn a_full_round_runs_propose_prevote_precommit_commit() {
        let mut rs = RoundState::new(Height(1));
        let a = block("A");

        assert_eq!(rs.step, Step::Propose);
        assert_eq!(
            rs.decide_prevote(Some(a), None, true),
            Decision::Prevote(Some(a))
        );
        assert_eq!(
            rs.decide_precommit(Some(Some(a))),
            Decision::Precommit(Some(a))
        );
        assert_eq!(rs.step, Step::Precommit);
        assert_eq!(rs.decide_commit(Some(Some(a))), Decision::Commit(a));
    }

    #[test]
    fn two_validators_partitioned_across_rounds_cannot_commit_different_values() {
        // End-to-end safety: one validator locks on A in round 0 and never sees
        // a quorum. In round 1 a proposer offers B with no later-round proof.
        // The locked validator must withhold its prevote, so B cannot reach a
        // quorum that includes it — which is what prevents two commits.
        let mut locked = RoundState::new(Height(1));
        let (a, b) = (block("A"), block("B"));
        locked.decide_precommit(Some(Some(a)));

        let mut fresh = RoundState::new(Height(1));
        fresh.advance_to(Round(1));
        locked.advance_to(Round(1));

        assert_eq!(
            fresh.decide_prevote(Some(b), None, true),
            Decision::Prevote(Some(b))
        );
        assert_eq!(
            locked.decide_prevote(Some(b), None, true),
            Decision::Prevote(None),
            "the locked validator's refusal is what denies B a quorum"
        );
    }
}
