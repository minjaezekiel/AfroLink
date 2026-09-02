//! The last thing this validator signed, and the refusal to sign it again.
//!
//! # Why this exists, and why it ships with evidence reporting
//!
//! A validator that signs two different values for one `(height, round)` is
//! equivocating, and this chain slashes 5% of its stake for it. Until now
//! nothing in the network could report that, so the punishment was theoretical.
//! Now it is not — and the first thing that makes real is an **honest operator's
//! mistake**, because the most likely equivocator on a young chain is not an
//! attacker.
//!
//! A node restarted from a rolled-back disk, a restored snapshot, a mis-copied
//! data directory, or the same key running in two places will replay a height it
//! has already voted at and sign a different value for it. Nobody meant anything
//! by it and the chain cannot tell the difference. So the two ship together: the
//! thing that makes equivocation cost money, and the thing that stops a careful
//! operator paying it.
//!
//! # The rule
//!
//! Tendermint's, unchanged: keep the **height, round and step** of the last
//! signature, and refuse to sign anything that is not strictly after it. `Step`
//! orders `Propose < Prevote < Precommit`, so one `(H, R, S)` triple compares
//! directly.
//!
//! Two details are load-bearing and both are places Tendermint has been bitten:
//!
//! * **Written before the signature is released.** A record written afterwards
//!   is a record that a crash in between makes a lie.
//! * **Fail closed.** If the record cannot be made durable, the node does not
//!   sign. The cost of refusing is missed blocks; the cost of signing anyway is
//!   the whole stake.
//!
//! The state also lives beside the consensus key and is created with it, because
//! Tendermint splitting `priv_validator_key.json` from `priv_validator_state.json`
//! is exactly how the two get out of sync.

use std::sync::Mutex;

use afrolink_consensus::Step;
use afrolink_primitives::{Height, Round};

/// Why a signature was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SignRefusal {
    /// This node has already signed at or beyond this point.
    #[error(
        "refusing to sign at height {height} round {round} {step:?}: \
         already signed at height {last_height} round {last_round} {last_step:?}"
    )]
    AlreadySigned {
        /// The height asked for.
        height: u64,
        /// The round asked for.
        round: u32,
        /// The step asked for.
        step: Step,
        /// The height last signed at.
        last_height: u64,
        /// The round last signed at.
        last_round: u32,
        /// The step last signed at.
        last_step: Step,
    },
    /// The record could not be made durable, so nothing may be signed.
    #[error("refusing to sign: the signing record could not be written: {0}")]
    NotDurable(String),
}

/// Remembers what this validator has signed, so it cannot sign it twice.
///
/// A trait for the same reason `BlockSource` is one: `crates/node` does not
/// learn what a file is. The daemon implements it over a file it `fsync`s; a
/// test implements it over memory, and a validator with a remote signer would
/// implement it over that signer, which is where this state belongs in the end.
pub trait SignRecord: Send + Sync {
    /// Claim `(height, round, step)` as the next thing this node will sign.
    ///
    /// Must be **durable before returning `Ok`**. The caller signs only if this
    /// returns `Ok`, so an implementation that returns early has removed the
    /// protection rather than provided it.
    ///
    /// # Errors
    /// [`SignRefusal::AlreadySigned`] if it is not strictly after the last
    /// claim, or [`SignRefusal::NotDurable`] if it could not be recorded.
    fn claim(&self, height: Height, round: Round, step: Step) -> Result<(), SignRefusal>;

    /// The last point claimed, if any. For logs and for tests.
    fn last(&self) -> Option<(Height, Round, Step)>;
}

/// The comparison every implementation must make.
///
/// Shared rather than reimplemented, because "strictly after" is the whole rule
/// and two copies of it are two chances to get it subtly different.
///
/// # Errors
/// [`SignRefusal::AlreadySigned`] if `next` is not strictly after `last`.
pub fn check_after(
    last: Option<(Height, Round, Step)>,
    next: (Height, Round, Step),
) -> Result<(), SignRefusal> {
    let Some(last) = last else {
        return Ok(());
    };
    if next > last {
        return Ok(());
    }
    Err(SignRefusal::AlreadySigned {
        height: next.0.0,
        round: next.1.0,
        step: next.2,
        last_height: last.0.0,
        last_round: last.1.0,
        last_step: last.2,
    })
}

/// A record that lives only as long as the process.
///
/// Correct while a node runs and worth nothing across a restart, which is the
/// case that matters. It is the default so that a `Node` is never *unguarded* —
/// a node with no record at all would sign anything — and the daemon replaces it
/// with one that reaches a disk.
#[derive(Debug, Default)]
pub struct MemorySignRecord(Mutex<Option<(Height, Round, Step)>>);

impl MemorySignRecord {
    /// A fresh record, having signed nothing.
    #[must_use]
    pub fn new() -> Self {
        Self(Mutex::new(None))
    }
}

impl SignRecord for MemorySignRecord {
    fn claim(&self, height: Height, round: Round, step: Step) -> Result<(), SignRefusal> {
        let mut held = self
            .0
            .lock()
            .map_err(|_| SignRefusal::NotDurable("signing record lock is poisoned".to_owned()))?;
        check_after(*held, (height, round, step))?;
        *held = Some((height, round, step));
        Ok(())
    }

    fn last(&self) -> Option<(Height, Round, Step)> {
        self.0.lock().ok().and_then(|held| *held)
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "tests assert on known-good fixtures; a panic there is a failed test, not a halted node"
)]
mod tests {
    use super::*;

    fn at(h: u64, r: u32, s: Step) -> (Height, Round, Step) {
        (Height(h), Round(r), s)
    }

    #[test]
    fn a_step_may_only_move_forwards() {
        let record = MemorySignRecord::new();
        assert!(record.claim(Height(1), Round(0), Step::Propose).is_ok());
        assert!(record.claim(Height(1), Round(0), Step::Prevote).is_ok());
        assert!(record.claim(Height(1), Round(0), Step::Precommit).is_ok());
        // The same step again is the double-sign.
        assert!(record.claim(Height(1), Round(0), Step::Precommit).is_err());
        // And so is going back a step within the round.
        assert!(record.claim(Height(1), Round(0), Step::Prevote).is_err());
    }

    #[test]
    fn a_replayed_height_is_refused() {
        // The case this exists for. A node restarted from a stale database
        // reaches a height it has already voted at, and votes differently.
        let record = MemorySignRecord::new();
        record.claim(Height(9), Round(0), Step::Precommit).unwrap();
        let refused = record
            .claim(Height(9), Round(0), Step::Prevote)
            .unwrap_err();
        assert!(
            matches!(refused, SignRefusal::AlreadySigned { .. }),
            "got {refused}"
        );
        assert!(record.claim(Height(8), Round(5), Step::Propose).is_err());
        // Forwards is still allowed, so a recovered node is not bricked.
        assert!(record.claim(Height(10), Round(0), Step::Propose).is_ok());
    }

    #[test]
    fn a_later_round_at_the_same_height_is_allowed() {
        // Rounds are how a height recovers from a proposer nobody could reach.
        // Refusing them would trade double-signing for never committing.
        let record = MemorySignRecord::new();
        record.claim(Height(4), Round(0), Step::Precommit).unwrap();
        assert!(record.claim(Height(4), Round(1), Step::Propose).is_ok());
        assert!(record.claim(Height(4), Round(1), Step::Prevote).is_ok());
    }

    #[test]
    fn the_ordering_is_height_then_round_then_step() {
        assert!(check_after(Some(at(1, 0, Step::Prevote)), at(1, 0, Step::Precommit)).is_ok());
        assert!(check_after(Some(at(1, 0, Step::Precommit)), at(1, 1, Step::Propose)).is_ok());
        assert!(check_after(Some(at(1, 9, Step::Precommit)), at(2, 0, Step::Propose)).is_ok());
        assert!(check_after(Some(at(2, 0, Step::Propose)), at(1, 9, Step::Precommit)).is_err());
        assert!(check_after(Some(at(1, 1, Step::Propose)), at(1, 0, Step::Precommit)).is_err());
    }

    #[test]
    fn a_record_that_has_seen_nothing_allows_anything() {
        let record = MemorySignRecord::new();
        assert_eq!(record.last(), None);
        assert!(record.claim(Height(5_000), Round(3), Step::Prevote).is_ok());
        assert_eq!(record.last(), Some(at(5_000, 3, Step::Prevote)));
    }
}
