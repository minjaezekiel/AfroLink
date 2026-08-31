//! The queue a proposer draws from.
//!
//! # What this replaces
//!
//! Until now the node held `pub mempool: Vec<Transaction>` — an unbounded,
//! unvalidated, publicly-writable vector. That was fine while the only way to
//! reach it was a test in the same process. The moment a socket exists it is a
//! remote denial of service: anyone can fill a validator's memory with junk that
//! is never valid, and nothing charges them for it.
//!
//! So a mempool is mostly a set of refusals. Every limit here answers a specific
//! way of making a node do unpaid work.
//!
//! | Limit | The attack it answers |
//! |---|---|
//! | [`MempoolLimits::max_transactions`] | Fill memory with valid-looking transactions |
//! | [`MempoolLimits::max_bytes`] | Do the same with fewer, larger ones |
//! | [`MempoolLimits::max_per_sender`] | One account monopolising the queue, so nobody else's payment is ever proposed |
//! | Stateless verification on insert | Make a node hold, gossip and re-check transactions that could never have applied |
//! | Nonce floor | Replay something already committed |
//! | Expiry eviction | Park a transaction with a distant `valid_until` and never let it be collected |
//!
//! # Two things it deliberately does not do
//!
//! **It does not check balances.** A balance is a fact about state at a height,
//! and the height moves. A transaction that cannot pay now may be able to pay by
//! the time it is proposed, and rejecting it here would make the mempool's answer
//! depend on when you asked. Nonce and signature are stable facts about the
//! transaction itself; balance is not, and the executor charges the fee anyway.
//!
//! **It does not replace by fee.** A `(sender, nonce)` already in the pool is
//! refused rather than overwritten. Fee replacement is a policy with real teeth —
//! it needs a minimum bump, or it becomes free churn — and getting it wrong is
//! worse than not having it. A stuck transaction expires at its own
//! `valid_until`, which is the escape hatch the type already carries.
//!
//! # Selection does not drain
//!
//! [`Mempool::select`] returns transactions without removing them, and
//! [`Mempool::remove_committed`] is what forgets them. That is not a
//! micro-optimisation: a proposal that fails to reach a quorum is ordinary — a
//! partition, a timeout, a round change — and a mempool that emptied itself at
//! proposal time would silently lose every transaction in a round that did not
//! commit. The user's payment would simply never arrive, with nothing in any log
//! to say why.

use std::collections::BTreeMap;

use afrolink_crypto::Address;
use afrolink_crypto::hash::Hash32;
use afrolink_executor::{MAX_BLOCK_BYTES, MAX_BLOCK_TRANSACTIONS};
use afrolink_primitives::codec::Encode;
use afrolink_primitives::{ChainId, Height};
use afrolink_types::{Account, Transaction, TxError};
use thiserror::Error;

/// How much a node is willing to hold on someone else's behalf.
#[derive(Debug, Clone)]
pub struct MempoolLimits {
    /// Most transactions held at once.
    pub max_transactions: usize,
    /// Most bytes held at once, summed over encoded transactions.
    pub max_bytes: usize,
    /// Most transactions from any one sender.
    ///
    /// The fairness limit. Without it, one account with a fast connection can
    /// occupy the whole pool and every other user's payment waits behind it —
    /// which on this network means a market trader's transfer waiting behind a
    /// bot's.
    pub max_per_sender: usize,
}

impl Default for MempoolLimits {
    fn default() -> Self {
        Self {
            max_transactions: 20_000,
            max_bytes: 32 * 1024 * 1024,
            max_per_sender: 64,
        }
    }
}

/// Why a transaction was not accepted into the pool.
///
/// Every variant is a refusal a submitter should be told about, which is why
/// this is a rich enum rather than a boolean: a wallet that gets
/// [`Self::NonceTooLow`] should re-read the account, and one that gets
/// [`Self::Full`] should retry later. Collapsing them would make both look like
/// the same failure.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum Rejected {
    /// Already held, by id.
    #[error("already in the mempool")]
    Duplicate,
    /// Another transaction from this sender already claims that nonce.
    #[error("nonce {0} is already claimed by another transaction from this sender")]
    NonceClaimed(u64),
    /// The nonce is behind the account's current sequence.
    #[error("nonce {got} is behind the account's next nonce {expected}")]
    NonceTooLow {
        /// What the transaction carries.
        got: u64,
        /// What the account expects.
        expected: u64,
    },
    /// The pool is at its transaction or byte limit.
    #[error("mempool is full")]
    Full,
    /// This sender already holds as many slots as it may.
    #[error("this sender already has {0} transactions queued")]
    SenderFull(usize),
    /// One transaction larger than a whole block may carry.
    #[error("transaction is larger than a block")]
    TooLarge,
    /// Stateless verification failed.
    #[error(transparent)]
    Invalid(#[from] TxError),
    /// The signatures are genuine, but not from keys entitled to act for the
    /// sender.
    ///
    /// Checked **here**, not only in the executor. Since authorisation became a
    /// fact about the account record rather than about the transaction alone,
    /// stateless verification no longer ties a signature to a sender — so
    /// without this check anyone could sign a body naming any address and make
    /// a node hold it, gossip it, and re-check it forever.
    #[error("the signing keys are not authorised for this account")]
    Unauthorised,
    /// The named fee payer did not consent to covering this fee.
    #[error("the named fee payer did not authorise this transaction")]
    SponsorUnauthorised,
}

/// A bounded, validated queue of pending transactions.
#[derive(Debug)]
pub struct Mempool {
    /// Keyed by `(sender, nonce)`, which gives per-sender nonce ordering for
    /// free and makes a second transaction at one nonce impossible to insert by
    /// accident.
    by_key: BTreeMap<(Address, u64), Transaction>,
    /// Id to key, for deduplication and lookup.
    by_id: BTreeMap<Hash32, (Address, u64)>,
    /// How many each sender holds.
    per_sender: BTreeMap<Address, usize>,
    bytes: usize,
    limits: MempoolLimits,
}

impl Mempool {
    /// An empty pool.
    #[must_use]
    pub fn new(limits: MempoolLimits) -> Self {
        Self {
            by_key: BTreeMap::new(),
            by_id: BTreeMap::new(),
            per_sender: BTreeMap::new(),
            bytes: 0,
            limits,
        }
    }

    /// How many transactions are held.
    #[must_use]
    pub fn len(&self) -> usize {
        self.by_key.len()
    }

    /// Whether the pool is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_key.is_empty()
    }

    /// Encoded bytes held.
    #[must_use]
    pub fn bytes(&self) -> usize {
        self.bytes
    }

    /// Whether a transaction with this id is held.
    #[must_use]
    pub fn contains(&self, id: &Hash32) -> bool {
        self.by_id.contains_key(id)
    }

    /// Offer a transaction to the pool.
    ///
    /// `sender_account` is the sender's record in committed state. It carries
    /// both facts this needs — the next nonce, and who may sign — and passing
    /// the record rather than the nonce alone is what keeps those two answers
    /// from being read at different heights.
    ///
    /// `fee_payer_account` is the sponsor's record, when the fee names one. A
    /// sponsored fee spends a third party's balance, so a pool that skipped this
    /// would hold and gossip transactions that drain strangers.
    ///
    /// Checks run cheapest-first, so a hostile peer pays for the expensive one —
    /// signature verification — only after everything free has passed.
    ///
    /// # Errors
    /// Returns the first [`Rejected`] reason found.
    pub fn insert(
        &mut self,
        transaction: Transaction,
        chain_id: &ChainId,
        height: Height,
        sender_account: &Account,
        fee_payer_account: Option<&Account>,
    ) -> Result<Hash32, Rejected> {
        let sender = transaction.body.sender;
        let nonce = transaction.body.nonce;
        let next_nonce = sender_account.nonce;

        if nonce < next_nonce {
            return Err(Rejected::NonceTooLow {
                got: nonce,
                expected: next_nonce,
            });
        }
        if self.by_key.contains_key(&(sender, nonce)) {
            return Err(Rejected::NonceClaimed(nonce));
        }
        if self.by_key.len() >= self.limits.max_transactions {
            return Err(Rejected::Full);
        }
        let held = self.per_sender.get(&sender).copied().unwrap_or(0);
        if held >= self.limits.max_per_sender {
            return Err(Rejected::SenderFull(held));
        }

        let encoded = transaction.to_bytes();
        // A transaction no block could ever carry is not "pending", it is
        // impossible. Holding it would be paying storage for something that can
        // never be proposed.
        if encoded.len() > MAX_BLOCK_BYTES {
            return Err(Rejected::TooLarge);
        }
        let bytes = self.bytes.saturating_add(encoded.len());
        if bytes > self.limits.max_bytes {
            return Err(Rejected::Full);
        }

        // Last, because these are the only checks that cost real CPU.
        transaction.verify_stateless(chain_id, height)?;
        if !sender_account.authorises(&transaction.signing_keys()) {
            return Err(Rejected::Unauthorised);
        }
        // A sponsored fee spends someone else's balance, so the pool must not
        // hold or gossip one the sponsor never agreed to.
        if transaction.body.fee.is_sponsored()
            && !fee_payer_account.is_some_and(|payer| payer.authorises(&transaction.sponsor_keys()))
        {
            return Err(Rejected::SponsorUnauthorised);
        }

        let id = transaction.id();
        if self.by_id.contains_key(&id) {
            return Err(Rejected::Duplicate);
        }

        self.by_key.insert((sender, nonce), transaction);
        self.by_id.insert(id, (sender, nonce));
        *self.per_sender.entry(sender).or_insert(0) = held.saturating_add(1);
        self.bytes = bytes;
        Ok(id)
    }

    /// Choose transactions for a block, **without removing them**.
    ///
    /// `next_nonce` reports a sender's committed sequence number. Only a
    /// contiguous run starting there is includable: a transaction with nonce
    /// `n+2` cannot apply while `n+1` is missing, and proposing it would waste a
    /// block slot on something the executor will reject.
    ///
    /// See the module docs for why this does not drain the pool.
    pub fn select<F>(&self, next_nonce: F) -> Vec<Transaction>
    where
        F: Fn(&Address) -> u64,
    {
        let mut chosen = Vec::new();
        let mut bytes = 0usize;
        // Tracks the nonce we are waiting for from the sender currently being
        // walked. `None` means that sender hit a gap and the rest of its
        // transactions are unreachable this block.
        let mut wanted: Option<(Address, Option<u64>)> = None;

        for ((sender, nonce), transaction) in &self.by_key {
            let want = match wanted {
                Some((current, want)) if current == *sender => want,
                _ => Some(next_nonce(sender)),
            };
            let Some(want) = want else { continue };

            if *nonce != want {
                // A gap. Everything later from this sender waits for the
                // missing nonce, however long the queue behind it is.
                wanted = Some((*sender, None));
                continue;
            }

            let size = transaction.to_bytes().len();
            if chosen.len() >= MAX_BLOCK_TRANSACTIONS
                || bytes.saturating_add(size) > MAX_BLOCK_BYTES
            {
                break;
            }

            chosen.push(transaction.clone());
            bytes = bytes.saturating_add(size);
            wanted = Some((*sender, Some(want.saturating_add(1))));
        }

        chosen
    }

    /// Forget transactions that made it into a committed block.
    ///
    /// Removes by `(sender, nonce)` rather than by id, so a *different*
    /// transaction that claimed the same nonce is dropped too. It can never
    /// apply now — the nonce is spent — and leaving it would keep a slot
    /// occupied until it expired.
    pub fn remove_committed(&mut self, transactions: &[Transaction]) {
        for transaction in transactions {
            self.remove_key(transaction.body.sender, transaction.body.nonce);
        }
    }

    /// Drop transactions that can no longer be included at `height`.
    ///
    /// Without this a transaction with a distant `valid_until` occupies a slot
    /// until someone collects it, which is nobody.
    pub fn evict_expired(&mut self, height: Height) {
        let stale: Vec<(Address, u64)> = self
            .by_key
            .iter()
            .filter(|(_, transaction)| height > transaction.body.valid_until)
            .map(|((sender, nonce), _)| (*sender, *nonce))
            .collect();
        for (sender, nonce) in stale {
            self.remove_key(sender, nonce);
        }
    }

    fn remove_key(&mut self, sender: Address, nonce: u64) {
        let Some(transaction) = self.by_key.remove(&(sender, nonce)) else {
            return;
        };
        self.by_id.remove(&transaction.id());
        self.bytes = self.bytes.saturating_sub(transaction.to_bytes().len());
        if let Some(count) = self.per_sender.get_mut(&sender) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                self.per_sender.remove(&sender);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use afrolink_crypto::SecretKey;
    use afrolink_primitives::{Amount, Denom};
    use afrolink_types::{Fee, Message, TxBody};

    fn key(seed: u8) -> SecretKey {
        SecretKey::from_bytes(&[seed; 32])
    }

    fn account(seed: u8) -> Address {
        Address::from_public_key(&key(seed).public_key())
    }

    fn chain() -> ChainId {
        ChainId::new("afrolink-mempool-test").unwrap()
    }

    fn tx(sender: u8, nonce: u64, valid_until: u64) -> Transaction {
        TxBody {
            chain_id: chain(),
            sender: account(sender),
            nonce,
            valid_until: Height(valid_until),
            fee: Fee::new(Amount::from_units(1_000), Denom::native()),
            messages: vec![Message::Transfer {
                to: account(200),
                denom: Denom::native(),
                amount: Amount::from_afri(1),
                reference: None,
            }],
            memo: String::new(),
        }
        .sign(&key(sender))
    }

    fn pool() -> Mempool {
        Mempool::new(MempoolLimits::default())
    }

    /// Offer a transaction, with the sender's account at nonce `next`.
    fn insert(pool: &mut Mempool, transaction: Transaction, next: u64) -> Result<Hash32, Rejected> {
        let mut sender = Account::individual(transaction.body.sender);
        sender.nonce = next;
        pool.insert(transaction, &chain(), Height(1), &sender, None)
    }

    #[test]
    fn a_valid_transaction_is_accepted_once() {
        let mut pool = pool();
        let transaction = tx(1, 0, 100);
        let id = insert(&mut pool, transaction.clone(), 0).unwrap();

        assert_eq!(id, transaction.id());
        assert!(pool.contains(&id));
        assert_eq!(pool.len(), 1);
    }

    #[test]
    fn the_same_transaction_twice_is_refused() {
        let mut pool = pool();
        insert(&mut pool, tx(1, 0, 100), 0).unwrap();
        assert_eq!(
            insert(&mut pool, tx(1, 0, 100), 0).unwrap_err(),
            Rejected::NonceClaimed(0)
        );
        assert_eq!(pool.len(), 1);
    }

    #[test]
    fn a_replay_of_a_committed_nonce_is_refused() {
        // The account has moved on to nonce 5; a transaction carrying 3 can
        // never apply, and holding it would be storage spent on a certainty.
        let mut pool = pool();
        assert_eq!(
            insert(&mut pool, tx(1, 3, 100), 5).unwrap_err(),
            Rejected::NonceTooLow {
                got: 3,
                expected: 5
            }
        );
    }

    #[test]
    fn a_forged_signature_never_reaches_the_pool() {
        let mut pool = pool();
        let mut forged = tx(1, 0, 100);
        // Sign the same body with someone else's key. The signature is
        // perfectly valid — it just is not from a key the sender's account
        // recognises. Since authorisation became stateful, this is the check
        // that keeps a stranger from filling a validator's memory with
        // transactions naming addresses they do not hold.
        forged.signatures = forged.body.clone().sign(&key(9)).signatures;

        assert_eq!(
            insert(&mut pool, forged, 0).unwrap_err(),
            Rejected::Unauthorised
        );
        assert!(pool.is_empty());
    }

    #[test]
    fn a_rotated_key_is_accepted_where_the_master_key_would_be_too() {
        // The other half: the pool must not refuse a transaction the executor
        // would apply, or a user who rotated their key could never transact.
        let mut pool = pool();
        let mut rotated = tx(1, 0, 100);
        rotated.signatures = rotated.body.clone().sign(&key(9)).signatures;

        let mut sender = Account::individual(rotated.body.sender);
        sender.regular_key = Some(key(9).public_key());

        assert!(
            pool.insert(rotated, &chain(), Height(1), &sender, None)
                .is_ok(),
            "a regular key must be as good as the master key here"
        );
    }

    #[test]
    fn a_transaction_for_another_chain_is_refused() {
        let mut pool = pool();
        let other = TxBody {
            chain_id: ChainId::new("some-other-chain").unwrap(),
            sender: account(1),
            nonce: 0,
            valid_until: Height(100),
            fee: Fee::new(Amount::from_units(1_000), Denom::native()),
            messages: vec![Message::WithdrawUnbonded],
            memo: String::new(),
        }
        .sign(&key(1));

        assert!(matches!(
            insert(&mut pool, other, 0).unwrap_err(),
            Rejected::Invalid(_)
        ));
    }

    #[test]
    fn one_sender_cannot_monopolise_the_queue() {
        // Without this limit, everyone else's payment waits behind one account.
        let mut pool = Mempool::new(MempoolLimits {
            max_per_sender: 3,
            ..MempoolLimits::default()
        });
        for nonce in 0..3 {
            insert(&mut pool, tx(1, nonce, 100), 0).unwrap();
        }
        assert_eq!(
            insert(&mut pool, tx(1, 3, 100), 0).unwrap_err(),
            Rejected::SenderFull(3)
        );

        // And another sender is still served.
        insert(&mut pool, tx(2, 0, 100), 0).unwrap();
        assert_eq!(pool.len(), 4);
    }

    #[test]
    fn a_full_pool_refuses_rather_than_growing() {
        let mut pool = Mempool::new(MempoolLimits {
            max_transactions: 2,
            ..MempoolLimits::default()
        });
        insert(&mut pool, tx(1, 0, 100), 0).unwrap();
        insert(&mut pool, tx(2, 0, 100), 0).unwrap();
        assert_eq!(
            insert(&mut pool, tx(3, 0, 100), 0).unwrap_err(),
            Rejected::Full
        );
    }

    #[test]
    fn the_byte_limit_binds_independently_of_the_count() {
        let mut pool = Mempool::new(MempoolLimits {
            max_bytes: 1,
            ..MempoolLimits::default()
        });
        assert_eq!(
            insert(&mut pool, tx(1, 0, 100), 0).unwrap_err(),
            Rejected::Full
        );
    }

    #[test]
    fn selection_stops_at_a_nonce_gap() {
        // 0 and 1 are includable; 3 is not, because 2 is missing. Proposing 3
        // would waste a block slot on something the executor rejects.
        let mut pool = pool();
        insert(&mut pool, tx(1, 0, 100), 0).unwrap();
        insert(&mut pool, tx(1, 1, 100), 0).unwrap();
        insert(&mut pool, tx(1, 3, 100), 0).unwrap();

        let chosen = pool.select(|_| 0);
        assert_eq!(chosen.len(), 2);
        assert_eq!(chosen[0].body.nonce, 0);
        assert_eq!(chosen[1].body.nonce, 1);
    }

    #[test]
    fn a_gap_for_one_sender_does_not_block_another() {
        let mut pool = pool();
        insert(&mut pool, tx(1, 5, 100), 0).unwrap(); // gap: account is at 0
        insert(&mut pool, tx(2, 0, 100), 0).unwrap();

        let chosen = pool.select(|_| 0);
        assert_eq!(chosen.len(), 1);
        assert_eq!(chosen[0].body.sender, account(2));
    }

    #[test]
    fn selection_does_not_drain_the_pool() {
        // The bug this prevents: a round that fails to commit is ordinary, and
        // a draining select would lose every transaction in it silently.
        let mut pool = pool();
        insert(&mut pool, tx(1, 0, 100), 0).unwrap();

        let first = pool.select(|_| 0);
        assert_eq!(first.len(), 1);
        assert_eq!(pool.len(), 1, "select must not remove anything");

        let second = pool.select(|_| 0);
        assert_eq!(second, first, "a failed round must be re-proposable");
    }

    #[test]
    fn committing_a_block_forgets_its_transactions() {
        let mut pool = pool();
        insert(&mut pool, tx(1, 0, 100), 0).unwrap();
        insert(&mut pool, tx(1, 1, 100), 0).unwrap();

        let chosen = pool.select(|_| 0);
        pool.remove_committed(&chosen);

        assert!(pool.is_empty());
        assert_eq!(pool.bytes(), 0, "byte accounting must come back to zero");
    }

    #[test]
    fn committing_a_nonce_drops_a_rival_claiming_it() {
        // Two different transactions can claim one nonce if one arrived after a
        // restart. Once the nonce is spent, the loser can never apply.
        let mut pool = pool();
        insert(&mut pool, tx(1, 0, 100), 0).unwrap();

        let rival = tx(1, 0, 500);
        assert_ne!(rival.id(), tx(1, 0, 100).id());
        pool.remove_committed(&[rival]);

        assert!(pool.is_empty());
    }

    #[test]
    fn expired_transactions_are_evicted() {
        let mut pool = pool();
        insert(&mut pool, tx(1, 0, 10), 0).unwrap();
        insert(&mut pool, tx(2, 0, 1_000), 0).unwrap();

        pool.evict_expired(Height(11));

        assert_eq!(pool.len(), 1);
        assert_eq!(pool.select(|_| 0)[0].body.sender, account(2));
    }

    #[test]
    fn a_selection_never_exceeds_what_a_block_may_carry() {
        // The pool is allowed to hold more than one block's worth; a selection
        // is not allowed to propose it.
        let mut pool = pool();
        for nonce in 0..10u64 {
            insert(&mut pool, tx(1, nonce, 100), 0).unwrap();
        }
        let chosen = pool.select(|_| 0);
        assert!(chosen.len() <= MAX_BLOCK_TRANSACTIONS);
        let bytes: usize = chosen.iter().map(|t| t.to_bytes().len()).sum();
        assert!(bytes <= MAX_BLOCK_BYTES);
    }

    #[test]
    fn accounting_survives_a_full_cycle() {
        // Bytes and per-sender counts are maintained by hand on both paths, so
        // the property worth asserting is that insert and remove agree.
        let mut pool = pool();
        for sender in 1..=5u8 {
            for nonce in 0..4u64 {
                insert(&mut pool, tx(sender, nonce, 100), 0).unwrap();
            }
        }
        assert_eq!(pool.len(), 20);

        let all = pool.select(|_| 0);
        assert_eq!(all.len(), 20);
        pool.remove_committed(&all);

        assert_eq!(pool.len(), 0);
        assert_eq!(pool.bytes(), 0);
        // Room for a full sender again, which only holds if the per-sender
        // counters were decremented rather than merely the map cleared.
        for nonce in 0..4u64 {
            insert(&mut pool, tx(1, nonce, 100), 0).unwrap();
        }
    }
}
