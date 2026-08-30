//! Walking an account's history backwards, so that omission is detectable.
//!
//! # The problem this closes
//!
//! [ADR-0014](../../../docs/adr/0014-payment-history-and-the-mempool.md) shipped
//! a transaction index and was explicit that it is a *hint*: it is not consensus
//! state, no header commits to it, and **a node can omit an entry** — hide a
//! payment from you — with nothing in the response revealing it.
//!
//! # The mechanism
//!
//! [`Account::last_txn`] is in state, so it is proved against a header the
//! wallet verified. It names one transaction. That transaction's **receipt** is
//! proved against the header's `outcome_root`, and names the account's
//! *previous* pointer. And so on backwards.
//!
//! ```text
//!   Account (proved against app_hash)
//!        └── last_txn ─────► T₄₂  (proved against tx_root + outcome_root)
//!                             └── receipt.previous_for(me) ─► T₄₁
//!                                                              └── … ─► None
//! ```
//!
//! Every link is committed. A server can decline to answer, but it cannot
//! produce a receipt naming a different predecessor, because the receipt is
//! hashed into a header signed by two thirds of the validator set.
//!
//! So the failure mode changes shape: **a hidden payment becomes a refusal to
//! serve rather than a silent gap.** A client that reaches the end of the chain
//! knows it has everything; one that is stonewalled knows it is being
//! stonewalled. Neither is possible with an index alone.
//!
//! # What this still does not do
//!
//! It does not make a node *answer*. Withholding is always available to whoever
//! holds the data, on any protocol. What it removes is the ability to withhold
//! **invisibly**, which is the difference between a wallet that shows a user a
//! wrong balance history and one that shows them an error.
//!
//! Walking is also `O(number of your transactions)` round trips. The index
//! stays as the fast path — ask it where to look, walk the chain when the answer
//! matters. That is the same split `crates/store`'s Clio-shaped serving role
//! already takes.

use afrolink_crypto::Address;
use afrolink_executor::BlockHeader;
use afrolink_light::LightError;
use afrolink_types::{Account, Transaction, TxPointer};
use thiserror::Error;

use crate::query::ProvedTransaction;

/// Why a history walk stopped.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum HistoryError {
    /// The walk is already complete; there is nothing further back.
    #[error("the history walk is already at its end")]
    Finished,
    /// The server answered with a transaction other than the one asked for.
    ///
    /// The pointer being followed is committed, so this is not a mistake a
    /// correct server can make.
    #[error("expected transaction {expected}, server returned {got}")]
    WrongTransaction {
        /// What the committed pointer named.
        expected: String,
        /// What arrived.
        got: String,
    },
    /// The transaction was served for the wrong height.
    #[error("expected a transaction in block {expected}, got block {got}")]
    WrongHeight {
        /// Height the pointer named.
        expected: u64,
        /// Height the answer was for.
        got: u64,
    },
    /// The receipt does not mention this account.
    ///
    /// **This is the broken chain.** The account's pointer named this
    /// transaction, so the transaction's receipt must name the account —
    /// anything else means the two were not produced by the same execution.
    #[error("receipt does not name this account: the history chain is broken")]
    BrokenChain,
    /// A proof did not verify.
    #[error(transparent)]
    Verification(#[from] LightError),
}

/// A cursor walking one account's history from newest to oldest.
///
/// Nothing here fetches. The caller obtains each [`ProvedTransaction`] however
/// it likes — over HTTP, from a cache, from a stranger's phone — and hands it to
/// [`step`](Self::step) with the header it belongs to. The cursor's job is to
/// refuse anything that does not continue the committed chain.
#[derive(Debug, Clone)]
pub struct HistoryCursor {
    address: Address,
    next: Option<TxPointer>,
    seen: usize,
}

impl HistoryCursor {
    /// Start from a **proved** account record.
    ///
    /// Take the account from [`ProvedValue::verify`](crate::ProvedValue::verify)
    /// on a [`Query::Account`](crate::Query::Account) answer, never from an
    /// unverified read — the whole chain hangs off this first pointer, and an
    /// attacker who chooses it chooses the history.
    #[must_use]
    pub fn new(address: Address, account: &Account) -> Self {
        Self {
            address,
            next: account.last_txn,
            seen: 0,
        }
    }

    /// Start from an account that does not exist yet.
    ///
    /// A proved absence is a complete history of length zero, and saying so is
    /// the point: it is different from a server that declined to answer.
    #[must_use]
    pub fn empty(address: Address) -> Self {
        Self {
            address,
            next: None,
            seen: 0,
        }
    }

    /// The transaction to fetch next, or `None` when the walk is complete.
    #[must_use]
    pub fn next_pointer(&self) -> Option<TxPointer> {
        self.next
    }

    /// Whether the whole history has been walked.
    ///
    /// True only after following the chain to its end. A client that stops
    /// early because a server stopped answering must not report this.
    #[must_use]
    pub fn complete(&self) -> bool {
        self.next.is_none()
    }

    /// How many transactions have been verified so far.
    #[must_use]
    pub fn seen(&self) -> usize {
        self.seen
    }

    /// Verify the next transaction in the chain and step backwards.
    ///
    /// `header` must be one the caller has already verified, for the height the
    /// cursor is pointing at.
    ///
    /// # Errors
    /// [`HistoryError`] for a failed proof, a substituted answer, or a broken
    /// link.
    pub fn step<'a>(
        &mut self,
        proved: &'a ProvedTransaction,
        header: &BlockHeader,
    ) -> Result<&'a Transaction, HistoryError> {
        let pointer = self.next.ok_or(HistoryError::Finished)?;

        if header.height != pointer.height {
            return Err(HistoryError::WrongHeight {
                expected: pointer.height.0,
                got: header.height.0,
            });
        }

        // Proofs first. Everything below reads fields, and reading an
        // unverified field is how a chain gets walked into an attacker's
        // fiction.
        let effects = proved.verify(header)?;

        if effects.transaction.id() != pointer.tx_id {
            return Err(HistoryError::WrongTransaction {
                expected: pointer.tx_id.to_hex(),
                got: effects.transaction.id().to_hex(),
            });
        }

        // The link. `previous_for` fails when the receipt does not mention this
        // account at all — which cannot happen for a receipt that genuinely
        // moved the pointer we followed here.
        let previous = effects
            .receipt
            .previous_for(&self.address)
            .map_err(|()| HistoryError::BrokenChain)?;

        self.next = previous;
        self.seen = self.seen.saturating_add(1);
        Ok(effects.transaction)
    }
}
