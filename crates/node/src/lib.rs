//! The consensus driver.
//!
//! Ties [`afrolink_consensus`] to [`afrolink_executor`]: consumes proposals and
//! votes, produces the messages a node should broadcast, and commits blocks.
//!
//! # No networking, no clock
//!
//! The driver is a pure function of `(state, event) → actions`. Timeouts arrive
//! as [`Event::Timeout`] rather than being read from a clock, and outbound
//! messages are returned as [`Action`]s rather than sent. That is what lets the
//! test harness in [`sim`] run a whole validator set in one process,
//! deterministically, and reproduce Byzantine scenarios exactly.
//!
//! # Validators re-execute every proposal
//!
//! A proposal carries a block whose header claims an `app_hash`. A validator
//! never takes that claim on trust: it re-executes the transactions against a
//! copy of its own state and compares. A proposer that lies about the resulting
//! state gets nil prevotes and its block dies. This is the step that makes the
//! chain a *verification* system rather than a *replication* one.

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

pub mod mempool;
pub mod proposal;
pub mod service;
pub mod sim;

pub use mempool::{Mempool, MempoolLimits, Rejected};
pub use proposal::{Proposal, SignedProposal};
pub use service::SharedNode;

use afrolink_consensus::{
    Commit, CommitError, Decision, RoundState, SignedVote, Step, ValidatorSet, Vote, VoteSet,
    VoteType,
};
use afrolink_crypto::hash::Hash32;
use afrolink_crypto::{Address, SecretKey};
use afrolink_executor::{Block, BlockContext, Executor, TxReceipt, ValidatorSets};
use afrolink_primitives::{ChainId, Height, Round, Timestamp};
use afrolink_state::{KeyValueStore, MemoryStore, StoreKey};
use afrolink_types::{Account, Transaction};
use std::collections::BTreeMap;

/// Something that happened to the node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// A proposal arrived.
    Proposal(Box<SignedProposal>),
    /// A vote arrived.
    Vote(Box<SignedVote>),
    /// A transaction was submitted, by a client or a peer.
    ///
    /// Boxed like the others: an enum is as large as its widest variant, and
    /// this one carries a whole signed transaction.
    Transaction(Box<Transaction>),
    /// A step's timer expired.
    Timeout(Step),
}

/// Something the node wants done.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// Broadcast this proposal to peers.
    BroadcastProposal(Box<SignedProposal>),
    /// Broadcast this vote to peers.
    BroadcastVote(Box<SignedVote>),
    /// Relay this transaction to peers.
    ///
    /// Emitted only when the transaction was *newly* accepted, never when it
    /// was already held. Re-broadcasting what we already had is how a gossip
    /// network amplifies one submission into a storm.
    BroadcastTransaction(Box<Transaction>),
    /// A block was committed. The height is final.
    ///
    /// Carries the commit certificate alongside the block: those precommit
    /// signatures are what lets a light client verify this height without the
    /// chain, so they are part of the output rather than an internal detail.
    Committed(Box<Block>, Box<Commit>),
    /// Start a timer for this step.
    ScheduleTimeout(Step, Round),
}

/// Why a block offered by a peer was not applied.
///
/// Every one of these is a refusal to advance. A node that cannot verify a block
/// stays where it is: being behind is recoverable, and having applied somebody
/// else's idea of history is not.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SyncError {
    /// The block belongs to another chain.
    #[error("block is for chain {got}, this node is on {expected}")]
    WrongChain {
        /// The chain this node runs.
        expected: ChainId,
        /// The chain the block claims.
        got: ChainId,
    },
    /// Not the height this node needs next.
    #[error("block is at height {got}, this node needs {expected}")]
    WrongHeight {
        /// The height this node is ready to apply.
        expected: u64,
        /// The height the block claims.
        got: u64,
    },
    /// The block does not follow the one this node last committed.
    #[error("block's parent is not this node's tip")]
    WrongParent,
    /// The certificate finalises some other block.
    #[error("the certificate does not finalise this block")]
    CommitIsForAnotherBlock,
    /// The transactions do not match the root the header commits to.
    #[error("the transactions do not match the header's tx_root")]
    TxRootMismatch,
    /// Larger than a validator will execute.
    #[error("block exceeds the size a validator will execute")]
    Oversized,
    /// The certificate did not carry more than two thirds of voting power.
    #[error("certificate rejected: {0}")]
    BadCommit(#[from] CommitError),
    /// Re-execution produced a different state root than the header claims.
    ///
    /// The gravest of these. A certificate this node accepted says two thirds of
    /// the validator set executed these transactions and got that root, and this
    /// node got another. That is either a consensus-breaking bug in this build or
    /// a chain that has forked, and in both cases the only safe thing to do is
    /// stop rather than write a state nobody else has.
    #[error("re-execution produced a different app_hash than the header claims")]
    AppHashMismatch,
}

/// An account's next expected nonce, or zero if it has never transacted.
///
/// A free function rather than a method so a selection closure can borrow the
/// store without borrowing the whole node.
fn next_nonce(store: &MemoryStore, address: &Address) -> u64 {
    account_record(store, address).nonce
}

/// An account's committed record, or a fresh one if it has never been seen.
///
/// A fresh record authorises exactly the master key, which is what an address
/// that has never transacted should accept — so an unknown sender is treated as
/// unrotated rather than as unauthorised.
fn account_record(store: &MemoryStore, address: &Address) -> Account {
    store
        .get_decoded::<Account>(&StoreKey::account(address))
        .ok()
        .flatten()
        .unwrap_or_else(|| Account::individual(*address))
}

/// A validator node.
pub struct Node {
    chain_id: ChainId,
    key: SecretKey,
    address: Address,
    validators: ValidatorSet,
    executor: Executor,

    store: MemoryStore,
    height: Height,
    last_block_id: Hash32,
    round_state: RoundState,

    proposals: BTreeMap<Round, SignedProposal>,
    prevotes: BTreeMap<Round, VoteSet>,
    precommits: BTreeMap<Round, VoteSet>,

    /// Transactions waiting to be proposed.
    ///
    /// Private, and reachable only through [`Node::submit`], which validates.
    /// It used to be a `pub Vec` that anyone could push to — harmless while the
    /// only caller was a test in the same process, and a remote denial of
    /// service the moment a socket exists.
    mempool: Mempool,
    /// Blocks committed by this node, in order.
    pub committed: Vec<Block>,
    /// The certificate for the most recently committed block.
    pub last_commit: Option<Commit>,
    /// Receipts from the most recently committed block, in execution order.
    ///
    /// Kept because the header commits to their Merkle root: a node holding the
    /// block but not these can prove a transaction *ran* and not what it *did*.
    /// They exist for exactly as long as it takes the caller that persists the
    /// block to take them.
    last_receipts: Vec<TxReceipt>,
    /// Whether the current height has already been decided.
    decided: bool,
}

impl Node {
    /// Build a node starting just after `genesis_block` at the given state.
    #[must_use]
    pub fn new(
        chain_id: ChainId,
        key: SecretKey,
        validators: ValidatorSet,
        store: MemoryStore,
        genesis_block: &Block,
    ) -> Self {
        let address = Address::from_public_key(&key.public_key());
        let height = genesis_block.header.height.next();
        Self {
            executor: Executor::new(chain_id.clone()),
            chain_id,
            key,
            address,
            validators,
            store,
            height,
            last_block_id: genesis_block.header.id(),
            round_state: RoundState::new(height),
            proposals: BTreeMap::new(),
            prevotes: BTreeMap::new(),
            precommits: BTreeMap::new(),
            mempool: Mempool::new(MempoolLimits::default()),
            committed: Vec::new(),
            last_commit: None,
            last_receipts: Vec::new(),
            decided: false,
        }
    }

    /// This node's address.
    #[must_use]
    pub fn address(&self) -> Address {
        self.address
    }

    /// The height currently being decided.
    #[must_use]
    pub fn height(&self) -> Height {
        self.height
    }

    /// The current state root.
    #[must_use]
    pub fn app_hash(&self) -> Hash32 {
        self.store.root()
    }

    /// Offer a transaction to this node's mempool.
    ///
    /// The only way in. Validation happens here — signature, chain, expiry, and
    /// the sender's committed nonce — so nothing unvalidated is ever held, and a
    /// caller learns *why* a transaction was refused rather than only that it
    /// was.
    ///
    /// Returns the accepted transaction so a caller can relay it without having
    /// kept a copy.
    ///
    /// # Errors
    /// Returns the [`Rejected`] reason.
    pub fn submit(&mut self, transaction: Transaction) -> Result<Transaction, Rejected> {
        let sender = account_record(&self.store, &transaction.body.sender);
        let sponsor = transaction
            .body
            .fee
            .payer
            .map(|payer| account_record(&self.store, &payer));
        let echo = transaction.clone();
        self.mempool.insert(
            transaction,
            &self.chain_id,
            self.height,
            &sender,
            sponsor.as_ref(),
        )?;
        Ok(echo)
    }

    /// How many transactions are waiting.
    #[must_use]
    pub fn pending(&self) -> usize {
        self.mempool.len()
    }

    /// Whether a transaction is waiting, by id.
    ///
    /// What a wallet asks between submitting a payment and seeing it in a block.
    #[must_use]
    pub fn is_pending(&self, id: &Hash32) -> bool {
        self.mempool.contains(id)
    }

    /// Read-only access to state, for queries and proofs.
    #[must_use]
    pub fn store(&self) -> &MemoryStore {
        &self.store
    }

    /// Whether this node proposes in the given round.
    #[must_use]
    pub fn is_proposer(&self, round: Round) -> bool {
        self.validators
            .proposer(self.height, round)
            .is_some_and(|v| v.address == self.address)
    }

    /// Begin the current round, proposing if it is our turn.
    pub fn start_round(&mut self, time: Timestamp) -> Vec<Action> {
        let round = self.round_state.round;
        let mut actions = Vec::new();

        if self.is_proposer(round) {
            // Selected, not drained. A round that does not commit is ordinary,
            // and taking the transactions here would lose every one of them.
            let store = &self.store;
            let transactions = self.mempool.select(|address| next_nonce(store, address));

            // Re-propose a value that already has support rather than replacing
            // it, or the network may never converge.
            let (block, valid_round) = match self.round_state.valid_value {
                Some(_) => match self.proposals.values().next_back().cloned() {
                    Some(prev) => (prev.proposal.block, self.round_state.valid_round),
                    None => (self.build_block(time, transactions), None),
                },
                None => (self.build_block(time, transactions), None),
            };

            let signed = Proposal {
                chain_id: self.chain_id.clone(),
                height: self.height,
                round,
                block,
                valid_round,
                proposer: self.address,
            }
            .sign(&self.key);

            actions.push(Action::BroadcastProposal(Box::new(signed.clone())));
            // Feed our own proposal back through the normal path, so proposing
            // and receiving take exactly the same code path.
            actions.extend(self.on_proposal(signed));
        } else {
            actions.push(Action::ScheduleTimeout(Step::Propose, round));
        }

        actions
    }

    /// Build a block by executing `transactions` against a copy of state.
    fn build_block(&self, time: Timestamp, transactions: Vec<Transaction>) -> Block {
        let mut trial = self.store.clone();
        // Validator set changes are not implemented yet, so this block and the
        // next are signed by the same set. The header commits to both regardless,
        // which is what lets a light client skip ahead (ADR-0010).
        let (block, _) = self.executor.build_block(
            &mut trial,
            self.height,
            time,
            self.last_block_id,
            transactions,
            ValidatorSets::unchanged(&self.validators),
        );
        block
    }

    /// Handle one event.
    pub fn handle(&mut self, event: Event) -> Vec<Action> {
        match event {
            Event::Proposal(p) => self.on_proposal(*p),
            Event::Vote(v) => self.on_vote(*v),
            Event::Transaction(t) => match self.submit(*t) {
                Ok(transaction) => vec![Action::BroadcastTransaction(Box::new(transaction))],
                // A refused transaction is not an error the node acts on — the
                // submitter is told through `submit`, and a peer that sent us
                // junk gets nothing back to amplify.
                Err(_) => Vec::new(),
            },
            Event::Timeout(step) => self.on_timeout(step),
        }
    }

    fn on_proposal(&mut self, signed: SignedProposal) -> Vec<Action> {
        let p = &signed.proposal;
        if self.decided || p.height != self.height || p.round != self.round_state.round {
            return Vec::new();
        }
        // Only the round's designated proposer may propose.
        if self
            .validators
            .proposer(self.height, p.round)
            .is_none_or(|v| v.address != p.proposer)
        {
            return Vec::new();
        }
        if p.chain_id != self.chain_id {
            return Vec::new();
        }

        let block_id = p.block_id();
        let valid = self.validate_block(&signed.proposal.block);
        self.proposals.insert(p.round, signed.clone());

        let decision =
            self.round_state
                .decide_prevote(Some(block_id), signed.proposal.valid_round, valid);
        let Decision::Prevote(value) = decision else {
            return Vec::new();
        };
        self.round_state.step = Step::Prevote;
        self.emit_vote(VoteType::Prevote, value)
    }

    /// Re-execute a proposed block and check it matches its own header.
    ///
    /// This is the anti-lying check: a proposer cannot claim a state root it did
    /// not actually produce, because every validator recomputes it.
    fn validate_block(&self, block: &Block) -> bool {
        if block.header.height != self.height
            || block.header.parent != self.last_block_id
            || block.header.chain_id != self.chain_id
            || !block.tx_root_matches()
        {
            return false;
        }
        // Before executing, not after. A proposer is *entitled* to propose, so
        // no signature or stake check stops it making the whole network execute
        // an arbitrarily large block — the size limit is the only thing that
        // does, and it is worth nothing if the work happens first.
        if !block.within_size_limits() {
            return false;
        }
        let mut trial = self.store.clone();
        let outcome = self.executor.execute_block(
            &mut trial,
            BlockContext {
                height: self.height,
                time: block.header.time,
            },
            &block.transactions,
        );
        outcome.app_hash == block.header.app_hash
    }

    fn on_vote(&mut self, signed: SignedVote) -> Vec<Action> {
        if self.decided || signed.vote.height != self.height {
            return Vec::new();
        }
        let (round, vote_type) = (signed.vote.round, signed.vote.vote_type);

        let set = match vote_type {
            VoteType::Prevote => &mut self.prevotes,
            VoteType::Precommit => &mut self.precommits,
        }
        .entry(round)
        .or_insert_with(|| VoteSet::new(self.chain_id.clone(), self.height, round, vote_type));

        if set.add(&self.validators, signed).is_err() {
            return Vec::new();
        }

        // Only the current round can drive this node's own progress.
        if round != self.round_state.round {
            return Vec::new();
        }

        match vote_type {
            VoteType::Prevote => self.check_prevote_quorum(),
            VoteType::Precommit => self.check_precommit_quorum(),
        }
    }

    fn check_prevote_quorum(&mut self) -> Vec<Action> {
        if self.round_state.step == Step::Precommit {
            return Vec::new();
        }
        let round = self.round_state.round;
        let Some(quorum) = self
            .prevotes
            .get(&round)
            .and_then(|s| s.quorum_value(&self.validators))
        else {
            return Vec::new();
        };

        let Decision::Precommit(value) = self.round_state.decide_precommit(Some(quorum)) else {
            return Vec::new();
        };
        self.emit_vote(VoteType::Precommit, value)
    }

    fn check_precommit_quorum(&mut self) -> Vec<Action> {
        let round = self.round_state.round;
        let Some(quorum) = self
            .precommits
            .get(&round)
            .and_then(|s| s.quorum_value(&self.validators))
        else {
            return Vec::new();
        };

        match self.round_state.decide_commit(Some(quorum)) {
            Decision::Commit(block_id) => self.commit(block_id),
            Decision::NextRound(next) => {
                vec![Action::ScheduleTimeout(Step::Propose, next)]
            }
            _ => Vec::new(),
        }
    }

    /// Apply the committed block to real state and advance the height.
    fn commit(&mut self, block_id: Hash32) -> Vec<Action> {
        let Some(signed) = self
            .proposals
            .values()
            .find(|p| p.proposal.block_id() == block_id)
            .cloned()
        else {
            // Decided on a block we have not seen. A real node would fetch it;
            // here we simply cannot proceed, and must not fabricate state.
            return Vec::new();
        };

        let block = signed.proposal.block;

        // Assemble the certificate from the precommits that carried this block
        // over the quorum line, before the round's vote sets are cleared.
        let round = self.round_state.round;
        let signatures = self
            .precommits
            .get(&round)
            .map(|s| s.votes_for(Some(block_id)))
            .unwrap_or_default();
        let commit = Commit::new(self.height, round, block_id, signatures);

        let outcome = self.executor.execute_block(
            &mut self.store,
            BlockContext {
                height: self.height,
                time: block.header.time,
            },
            &block.transactions,
        );
        self.last_receipts = outcome.outcomes.into_iter().map(|o| o.receipt).collect();

        self.decided = true;
        self.advance_past(block, commit)
    }

    /// Receipts from the most recently committed block, in execution order.
    ///
    /// What a caller persisting the block needs and cannot recompute without
    /// re-executing: the header commits to their root, so a stored block without
    /// them can prove a transaction ran but not what it did.
    #[must_use]
    pub fn last_receipts(&self) -> &[TxReceipt] {
        &self.last_receipts
    }

    /// Take a block finalised elsewhere, verify it, and advance to it.
    ///
    /// The catch-up path: how a node that fell behind, or one that has just
    /// restarted, reaches the tip without having taken part in deciding any of it.
    ///
    /// # Nothing here is taken on trust
    ///
    /// A peer handing over a block is not an authority, and this function is
    /// written on that assumption. The certificate is checked against **this
    /// node's own validator set**, which is what makes a peer unable to invent
    /// history: forging it needs more than two thirds of the validators' signing
    /// keys, and anyone holding those does not need to lie to this node.
    ///
    /// Then the block is re-executed anyway. The certificate proves the network
    /// agreed; re-execution is how this node ends up holding the state rather
    /// than a root hash somebody sent it. If the two disagree the block is
    /// refused and **nothing is written** — the trial state is discarded rather
    /// than merged, so a node that cannot verify a height simply stays at the
    /// height before it.
    ///
    /// The checks run cheapest-first on purpose. Verifying a certificate is
    /// dozens of signature verifications and executing a block is more; a peer
    /// should not be able to buy either with a header field that costs one
    /// comparison to refuse.
    ///
    /// # Errors
    /// The first [`SyncError`] encountered. Every one of them leaves this node
    /// exactly where it was.
    pub fn apply_synced(&mut self, block: Block, commit: Commit) -> Result<Vec<Action>, SyncError> {
        if block.header.chain_id != self.chain_id {
            return Err(SyncError::WrongChain {
                expected: self.chain_id.clone(),
                got: block.header.chain_id.clone(),
            });
        }
        if block.header.height != self.height {
            return Err(SyncError::WrongHeight {
                expected: self.height.0,
                got: block.header.height.0,
            });
        }
        if block.header.parent != self.last_block_id {
            // A block at the right height that does not follow ours. Either the
            // peer is on a fork or this node is, and applying it either way is
            // how a node adopts a history it never verified the middle of.
            return Err(SyncError::WrongParent);
        }
        let block_id = block.header.id();
        if commit.block_id != block_id || commit.height != block.header.height {
            return Err(SyncError::CommitIsForAnotherBlock);
        }
        if !block.tx_root_matches() {
            return Err(SyncError::TxRootMismatch);
        }
        // Before executing, exactly as on the proposal path. A peer is no more
        // entitled to make this node execute an unbounded block than a proposer is.
        if !block.within_size_limits() {
            return Err(SyncError::Oversized);
        }

        commit.verify(&self.chain_id, &self.validators)?;

        // Into a copy, so a block that does not verify writes nothing at all.
        let mut trial = self.store.clone();
        let outcome = self.executor.execute_block(
            &mut trial,
            BlockContext {
                height: block.header.height,
                time: block.header.time,
            },
            &block.transactions,
        );
        if outcome.app_hash != block.header.app_hash {
            return Err(SyncError::AppHashMismatch);
        }

        self.store = trial;
        self.last_receipts = outcome.outcomes.into_iter().map(|o| o.receipt).collect();
        Ok(self.advance_past(block, commit))
    }

    /// Retire a finalised block and open the next height.
    ///
    /// Shared by the two ways a height becomes final — deciding it here, and
    /// learning it from a peer — because a node that reached a height by syncing
    /// must be indistinguishable afterwards from one that voted on it. Two copies
    /// of this bookkeeping would be two chances to drift apart.
    fn advance_past(&mut self, block: Block, commit: Commit) -> Vec<Action> {
        // Everything in this block is spent, and anything that can no longer be
        // included is dead weight. Both happen here, once, on the one path that
        // is reached exactly when a height is final.
        self.mempool.remove_committed(&block.transactions);
        self.mempool.evict_expired(self.height.next());

        self.committed.push(block.clone());
        self.last_block_id = block.header.id();
        self.height = self.height.next();
        self.round_state = RoundState::new(self.height);
        self.proposals.clear();
        self.prevotes.clear();
        self.precommits.clear();
        self.decided = false;
        self.last_commit = Some(commit.clone());

        vec![Action::Committed(Box::new(block), Box::new(commit))]
    }

    fn on_timeout(&mut self, step: Step) -> Vec<Action> {
        let round = self.round_state.round;
        match step {
            // No proposal arrived in time: prevote nil so the round can conclude.
            Step::Propose if self.round_state.step == Step::Propose => {
                self.round_state.step = Step::Prevote;
                self.emit_vote(VoteType::Prevote, None)
            }
            // Prevotes were inconclusive: precommit nil.
            Step::Prevote if self.round_state.step == Step::Prevote => {
                self.round_state.step = Step::Precommit;
                self.emit_vote(VoteType::Precommit, None)
            }
            // Precommits were inconclusive: move on to the next round.
            Step::Precommit if self.round_state.step == Step::Precommit => {
                let next = round.next();
                self.round_state.advance_to(next);
                vec![Action::ScheduleTimeout(Step::Propose, next)]
            }
            _ => Vec::new(),
        }
    }

    /// Sign a vote, **count it**, and ask for it to be broadcast.
    ///
    /// # A node counts its own vote, and does it here rather than on the wire
    ///
    /// This is CometBFT's `signAddVote`: the vote is signed and immediately
    /// placed on the node's own internal queue with an empty peer id, so it
    /// reaches `addVote` by exactly the path a peer's vote takes. Gossip is
    /// *downstream* of that, never the mechanism by which it happens.
    ///
    /// The direction matters. A design where the network loops a node's own vote
    /// back makes a consensus invariant depend on a transport, so every caller
    /// that drives the state machine without one silently breaks quorum — and
    /// that is precisely the defect this replaces. The version fixed on the wire
    /// worked, and left the trap set for the next caller.
    ///
    /// Returning `Vec<Action>` rather than one action is a consequence: counting
    /// our own vote can complete a quorum, which produces the next vote, which
    /// can complete the next quorum, which can commit. The recursion terminates
    /// because `VoteSet` refuses a vote it already holds and because each step
    /// moves the round forward — prevote, precommit, commit — and never back.
    fn emit_vote(&mut self, vote_type: VoteType, block_id: Option<Hash32>) -> Vec<Action> {
        let signed = Vote {
            chain_id: self.chain_id.clone(),
            height: self.height,
            round: self.round_state.round,
            vote_type,
            block_id,
            validator: self.address,
        }
        .sign(&self.key);

        let mut actions = vec![Action::BroadcastVote(Box::new(signed.clone()))];
        // Through the same door as everybody else's. A second path into the vote
        // set would be a second place for the counting rules to be wrong.
        actions.extend(self.on_vote(signed));
        actions
    }
}
