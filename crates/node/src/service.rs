//! Sharing one node with a server that has many threads.
//!
//! # Why this is the only shared-mutable thing in the workspace
//!
//! [`Node`] is a synchronous state machine and deliberately owns its state. A
//! transport, though, hands each connection its own thread, so *something* has
//! to reconcile "one node" with "many callers". This is that something, and it
//! is kept to one small type so the reconciliation is in one place rather than
//! spread through the transport.
//!
//! # Why the dependency points this way
//!
//! `crates/rpc` is protocol *types* — a `Query`, a `Response`, and the two
//! traits describing what a server needs from a node. It is not a service and
//! it does not know about sockets, so a node depending on it adds no networking
//! and no runtime. The reverse direction would be worse: `crates/rpc` is tested
//! against an adversary in isolation precisely because it cannot reach a
//! consensus engine.
//!
//! # Reads do not come through here
//!
//! Only [`Submit`] is implemented. A server's *reads* come from
//! [`ServedChain`](afrolink_store::ServedChain) over the durable store, which is
//! also the real deployment shape: the node writes committed blocks to disk, and
//! the query path reads them there. Serving reads from a live node's memory
//! would put every balance lookup behind the same lock as consensus.

use std::sync::Mutex;

use afrolink_crypto::hash::Hash32;
use afrolink_rpc::{Submit, SubmitError};
use afrolink_types::Transaction;

use crate::Node;

/// A [`Node`] that several threads may submit to.
///
/// The lock is held only for the length of one mempool insertion — a signature
/// check and a few map writes — never across I/O.
pub struct SharedNode {
    inner: Mutex<Node>,
}

impl SharedNode {
    /// Wrap a node.
    #[must_use]
    pub fn new(node: Node) -> Self {
        Self {
            inner: Mutex::new(node),
        }
    }

    /// Borrow the node for consensus work.
    ///
    /// Returns `None` if a previous holder panicked while holding the lock. A
    /// node whose invariants may have been left half-updated must not keep
    /// serving, and the workspace forbids the `unwrap` that would hide it.
    pub fn lock(&self) -> Option<std::sync::MutexGuard<'_, Node>> {
        self.inner.lock().ok()
    }

    /// Take the node back.
    ///
    /// Returns `None` on a poisoned lock, for the same reason as [`Self::lock`].
    pub fn into_inner(self) -> Option<Node> {
        self.inner.into_inner().ok()
    }
}

impl Submit for SharedNode {
    fn submit(&self, transaction: Transaction) -> Result<Hash32, SubmitError> {
        let id = transaction.id();
        let mut node = self
            .inner
            .lock()
            .map_err(|_| SubmitError::Backend("node lock is poisoned".to_owned()))?;
        node.submit(transaction)
            // The reason describes the caller's own transaction — a bad
            // signature, a spent nonce, a full pool — so echoing it tells them
            // something actionable and leaks nothing about the node.
            .map_err(|reason| SubmitError::Rejected(reason.to_string()))?;
        Ok(id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use afrolink_consensus::{CountryCode, Validator, ValidatorSet};
    use afrolink_crypto::{Address, SecretKey};
    use afrolink_executor::{Allocation, Genesis, GenesisLimits};
    use afrolink_primitives::{Amount, ChainId, Denom, Height, Timestamp};
    use afrolink_state::MemoryStore;
    use afrolink_types::{Fee, Message, TxBody};

    fn key(seed: u8) -> SecretKey {
        SecretKey::from_bytes(&[seed; 32])
    }

    fn account(seed: u8) -> Address {
        Address::from_public_key(&key(seed).public_key())
    }

    fn chain() -> ChainId {
        ChainId::new("afrolink-service-test").unwrap()
    }

    fn shared() -> SharedNode {
        let validators = ValidatorSet::new(
            (1..=4u8)
                .map(|i| Validator::new(key(i).public_key(), 1, CountryCode::new("ke").unwrap()))
                .collect(),
        )
        .unwrap();
        let genesis = Genesis {
            chain_id: chain(),
            genesis_time: Timestamp::from_millis(1_700_000_000_000),
            validators: validators.clone(),
            // AFRI has no issuer by construction — it is minted at genesis and
            // never again, which is what `NativeNotIssuable` enforces.
            issuers: Vec::new(),
            attestors: Vec::new(),
            council: afrolink_executor::Council::devnet(account(50)),
            params: afrolink_executor::ChainParams::devnet(),
            allocations: vec![Allocation {
                address: account(50),
                denom: Denom::native(),
                amount: Amount::from_afri(1_000),
            }],
        };
        let mut store = MemoryStore::new();
        let block = genesis.apply(&mut store, GenesisLimits::devnet()).unwrap();
        SharedNode::new(Node::new(chain(), key(1), validators, store, &block))
    }

    fn payment(nonce: u64) -> Transaction {
        TxBody {
            chain_id: chain(),
            sender: account(50),
            nonce,
            valid_until: Height(1_000),
            fee: Fee::new(Amount::from_units(1_000), Denom::native()),
            messages: vec![Message::Transfer {
                to: account(60),
                denom: Denom::native(),
                amount: Amount::from_afri(1),
                reference: None,
            }],
            memo: String::new(),
        }
        .sign(&key(50))
    }

    #[test]
    fn a_submitted_transaction_becomes_pending() {
        let node = shared();
        let id = node.submit(payment(0)).unwrap();

        assert_eq!(id, payment(0).id());
        let guard = node.lock().unwrap();
        assert!(guard.is_pending(&id));
        assert_eq!(guard.pending(), 1);
    }

    #[test]
    fn a_rejection_reaches_the_submitter_with_a_reason() {
        // A wallet told only "no" retries forever; one told which chain it
        // signed for fixes itself. The reason describes the caller's own
        // transaction, so echoing it leaks nothing about the node.
        let node = shared();
        let wrong_chain = TxBody {
            chain_id: ChainId::new("some-other-chain").unwrap(),
            sender: account(50),
            nonce: 0,
            valid_until: Height(1_000),
            fee: Fee::new(Amount::from_units(1_000), Denom::native()),
            messages: vec![Message::WithdrawUnbonded],
            memo: String::new(),
        }
        .sign(&key(50));

        let error = node.submit(wrong_chain).unwrap_err();
        let SubmitError::Rejected(reason) = &error else {
            panic!("expected a rejection, got {error:?}");
        };
        assert!(reason.contains("chain"), "{reason}");
    }

    #[test]
    fn a_future_nonce_is_held_rather_than_refused() {
        // Deliberate: a wallet queues several payments at once, and the second
        // is valid the moment the first commits. Refusing it here would make a
        // wallet send them one round-trip at a time.
        let node = shared();
        node.submit(payment(0)).unwrap();
        node.submit(payment(1)).unwrap();
        assert_eq!(node.lock().unwrap().pending(), 2);
    }

    #[test]
    fn submitting_the_same_payment_twice_does_not_duplicate_it() {
        let node = shared();
        node.submit(payment(0)).unwrap();
        assert!(node.submit(payment(0)).is_err());
        assert_eq!(node.lock().unwrap().pending(), 1);
    }

    #[test]
    fn several_threads_may_submit_at_once() {
        // The reason this type exists: a server hands each connection a thread,
        // and all of them reach one node.
        let node = shared();
        std::thread::scope(|scope| {
            for nonce in 0..8u64 {
                let node = &node;
                scope.spawn(move || {
                    let _ = node.submit(payment(nonce));
                });
            }
        });
        assert_eq!(node.lock().unwrap().pending(), 8);
    }
}
