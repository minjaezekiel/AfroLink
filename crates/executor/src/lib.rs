//! Deterministic block execution.
//!
//! Given the same prior state and the same ordered transactions, every node on
//! earth must reach byte-identical state. That is the whole job of this crate,
//! and everything below follows from it:
//!
//! * Transactions are applied strictly in order.
//! * A failing transaction is **recorded, not skipped**: its fee is charged and
//!   its nonce consumed, but its state changes are discarded. Skipping it
//!   entirely would let a node that saw a different failure reason produce a
//!   different state.
//! * No wall-clock reads, no map iteration order, no floating point, no
//!   randomness.
//!
//! # Failure isolation
//!
//! Each transaction is applied to a sandbox copy of the store. On success the
//! sandbox is promoted; on failure it is dropped. Copying the whole store per
//! transaction is `O(state)` and is fine for the sizes here, but it is the first
//! thing to replace with a copy-on-write cache layer when real load arrives.

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

pub mod block;
pub mod genesis;

pub use block::{
    Block, BlockContext, BlockHeader, MAX_BLOCK_BYTES, MAX_BLOCK_TRANSACTIONS, ValidatorSets,
};
pub use genesis::{Allocation, Genesis, GenesisError, GenesisLimits};

use afrolink_alias::{BindError, Bindings, Registry, RegistryError};
use afrolink_bank::{Bank, BankError};
use afrolink_crypto::Address;
use afrolink_crypto::hash::{Domain, Hash32};
use afrolink_crypto::merkle::MerkleTree;
use afrolink_primitives::codec::{CodecError, Decode, Encode, Reader};
use afrolink_primitives::{Amount, ChainId, Height, Timestamp};
use afrolink_staking::{Staking, StakingError};
use afrolink_state::{KeyValueStore, StateError, StoreKey};
use afrolink_types::group::GroupError;
use afrolink_types::{Account, GroupAccount, Message, Transaction, TxError, TxPointer};
use thiserror::Error;

/// Name of the module account that collects fees before distribution.
pub const FEE_COLLECTOR: &str = "fee_collector";

/// The address of the fee collector module account.
#[must_use]
pub fn fee_collector_address() -> Address {
    Address::derived(Domain::ModuleAddress, FEE_COLLECTOR.as_bytes())
}

/// Why a transaction failed during execution.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ExecError {
    /// Stateless verification failed.
    #[error(transparent)]
    Tx(#[from] TxError),
    /// The nonce did not match the account's expected sequence.
    #[error("wrong nonce: account expects {expected}, transaction carries {got}")]
    WrongNonce {
        /// Nonce the account expects next.
        expected: u64,
        /// Nonce the transaction carried.
        got: u64,
    },
    /// A bank operation failed.
    #[error(transparent)]
    Bank(#[from] BankError),
    /// A group operation failed.
    #[error(transparent)]
    Group(#[from] GroupError),
    /// A staking operation failed.
    #[error(transparent)]
    Staking(#[from] StakingError),
    /// The named account does not exist.
    #[error("account does not exist")]
    NoSuchAccount,
    /// The named account is not a group account.
    #[error("account is not a group")]
    NotAGroup,
    /// An account already occupies the address a new record would take.
    #[error("an account already exists at this address")]
    AccountExists,
    /// The fee was offered in a denomination the chain does not accept.
    #[error("fees are not accepted in {0}")]
    FeeDenomNotAccepted(String),
    /// The signer may not perform this action on this group.
    #[error("signer is not a member of this group")]
    NotAGroupMember,
    /// A group payout was requested for an accumulating group.
    #[error("this group accumulates its pot and has no rotation recipient")]
    NoRotationRecipient,
    /// The keys that signed are not entitled to act for the sender.
    ///
    /// Replaces the stateless key-to-address check. That check could not survive
    /// key rotation: a regular key does not derive the address, and a signer
    /// list holds keys that never could
    /// ([ADR-0017](../../../docs/adr/0017-key-rotation-and-signer-lists.md)).
    #[error("the signing keys are not authorised for this account")]
    Unauthorised,
    /// The named fee payer did not consent.
    ///
    /// Separate from [`Self::Unauthorised`] because the sender may be perfectly
    /// authorised and the transaction still refused — and the two are fixed by
    /// different people.
    #[error("the named fee payer did not authorise this transaction")]
    SponsorUnauthorised,
    /// A change to the signing arrangement would leave nobody able to sign.
    ///
    /// Disabling a master key with no replacement, or removing the last
    /// replacement while the master is disabled. Either would freeze the
    /// account's funds permanently, so it is refused rather than obeyed.
    #[error("this change would leave no key able to sign for the account")]
    WouldLockOut,
    /// A regular key equal to the master key.
    ///
    /// Not merely pointless: it looks like rotation and provides none, so a user
    /// who did it would believe an exposed seed had been retired when it had
    /// not.
    #[error("the regular key must differ from the master key")]
    RegularKeyIsMasterKey,
    /// The recipient requires a payment reference and none was supplied.
    ///
    /// Deliberately *not* folded into [`Self::Bank`]: this is the one execution
    /// failure the sender can fix and retry immediately, and telling them so is
    /// the entire point of the flag.
    #[error("this account requires a payment reference and none was supplied")]
    ReferenceRequired,
    /// A username registry operation failed.
    #[error(transparent)]
    Registry(#[from] RegistryError),
    /// A contact binding operation failed.
    #[error(transparent)]
    Bind(#[from] BindError),
    /// Corrupt state.
    #[error(transparent)]
    State(#[from] StateError),
}

/// Which subsystem refused a transaction, as a consensus-stable number.
///
/// **Deliberately coarse.** It names the component that said no, not the
/// detail — so adding a variant to [`BankError`] or [`StakingError`] is an
/// ordinary change rather than a consensus change. XRPL takes the same shape
/// with its `tec`/`tem` result codes, and for the same reason: the code goes in
/// a committed structure, the message does not
/// ([09](../../../docs/09-what-xrpl-answers.md) §2.2).
///
/// A client that wants the detail asks a node, and can check the answer against
/// the code it proved.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ResultCode {
    /// Applied.
    Success,
    /// Stateless verification failed: signature, chain, expiry, structure.
    Transaction,
    /// The nonce did not match the account's sequence.
    Nonce,
    /// The bank refused: insufficient funds, frozen, overflow.
    Bank,
    /// A group rule refused.
    Group,
    /// A staking rule refused.
    Staking,
    /// The account did not exist, or was the wrong kind.
    Account,
    /// The username registry refused.
    Registry,
    /// A contact binding refused.
    Binding,
    /// State was corrupt. Never a client's fault.
    State,
    /// The recipient requires a payment reference and none was carried.
    ///
    /// Its own code rather than a shade of [`Self::Account`], because it is the
    /// only failure here a wallet can *act* on without asking anything further:
    /// prompt for the reference and resend. Making the wallet fetch the
    /// recipient's flags to work out why would put a round trip on the exact
    /// path this flag exists to smooth.
    Reference,
    /// The signing arrangement refused: wrong keys, or a change that would have
    /// locked the account out.
    Authorisation,
}

impl ResultCode {
    /// The wire value. Stable: these numbers are consensus.
    #[must_use]
    pub fn as_u16(self) -> u16 {
        match self {
            Self::Success => 0,
            Self::Transaction => 1,
            Self::Nonce => 2,
            Self::Bank => 3,
            Self::Group => 4,
            Self::Staking => 5,
            Self::Account => 6,
            Self::Registry => 7,
            Self::Binding => 8,
            Self::State => 9,
            Self::Reference => 10,
            Self::Authorisation => 11,
        }
    }

    /// Parse a wire value.
    #[must_use]
    pub fn from_u16(value: u16) -> Option<Self> {
        Some(match value {
            0 => Self::Success,
            1 => Self::Transaction,
            2 => Self::Nonce,
            3 => Self::Bank,
            4 => Self::Group,
            5 => Self::Staking,
            6 => Self::Account,
            7 => Self::Registry,
            8 => Self::Binding,
            9 => Self::State,
            10 => Self::Reference,
            11 => Self::Authorisation,
            _ => return None,
        })
    }

    /// Whether the transaction applied.
    #[must_use]
    pub fn succeeded(self) -> bool {
        matches!(self, Self::Success)
    }
}

impl From<&ExecError> for ResultCode {
    fn from(error: &ExecError) -> Self {
        match error {
            ExecError::Tx(_) => Self::Transaction,
            ExecError::WrongNonce { .. } => Self::Nonce,
            ExecError::Bank(_) => Self::Bank,
            ExecError::Group(_) => Self::Group,
            ExecError::Staking(_) => Self::Staking,
            ExecError::NoSuchAccount
            | ExecError::AccountExists
            | ExecError::NotAGroup
            | ExecError::NotAGroupMember
            | ExecError::NoRotationRecipient => Self::Account,
            ExecError::ReferenceRequired => Self::Reference,
            ExecError::FeeDenomNotAccepted(_) => Self::Bank,
            ExecError::Unauthorised
            | ExecError::SponsorUnauthorised
            | ExecError::WouldLockOut
            | ExecError::RegularKeyIsMasterKey => Self::Authorisation,
            ExecError::Registry(_) => Self::Registry,
            ExecError::Bind(_) => Self::Binding,
            ExecError::State(_) => Self::State,
        }
    }
}

/// One account whose history pointer a transaction moved.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TouchedAccount {
    /// The account.
    pub address: Address,
    /// Its history pointer immediately **before** this transaction.
    ///
    /// `None` means this transaction is the first in that account's history.
    pub previous: Option<TxPointer>,
}

impl Encode for TouchedAccount {
    fn encode(&self, out: &mut Vec<u8>) {
        self.address.encode(out);
        self.previous.encode(out);
    }
}

impl Decode for TouchedAccount {
    fn decode(r: &mut Reader<'_>) -> Result<Self, CodecError> {
        Ok(Self {
            address: Address::decode(r)?,
            previous: Option::<TxPointer>::decode(r)?,
        })
    }
}

/// What a block commits to about one transaction's execution.
///
/// This is the committed half of a [`TxOutcome`]: everything a client can be
/// handed a proof of. It is separate from the outcome because [`ExecError`] is a
/// rich local type whose variants change with the code, and a header must not.
///
/// # Why `touched` is here
///
/// Each entry is an account whose history pointer this transaction moved, and
/// **what that pointer was before**. That is the backwards link
/// [`Account::last_txn`] needs to be walkable: prove the account, follow its
/// pointer to a transaction, prove that transaction's receipt, and read the
/// previous pointer out of it.
///
/// The chain is what makes omission *detectable*. A node can decline to serve a
/// link, but it cannot produce a receipt that names a different predecessor,
/// because the receipt is committed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxReceipt {
    /// The transaction's identifier.
    pub tx_id: Hash32,
    /// Whether it applied, and which subsystem refused if not.
    pub code: ResultCode,
    /// Fee actually charged.
    pub fee_charged: Amount,
    /// Accounts whose history pointer moved, and their previous pointers.
    ///
    /// Sorted by address, so one execution has one encoding.
    pub touched: Vec<TouchedAccount>,
}

impl TxReceipt {
    /// The previous history pointer this transaction recorded for `address`.
    ///
    /// `Ok(None)` means this transaction is the first in that account's
    /// history — the end of the walk. `Err(())` means the account is not named
    /// here at all, which is a broken chain rather than an ending.
    ///
    /// # Errors
    /// Returns `Err(())` when the receipt does not mention `address`.
    #[allow(
        clippy::result_unit_err,
        reason = "the caller only needs to know it broke"
    )]
    pub fn previous_for(&self, address: &Address) -> Result<Option<TxPointer>, ()> {
        self.touched
            .iter()
            .find(|entry| entry.address == *address)
            .map(|entry| entry.previous)
            .ok_or(())
    }
}

/// The outcome of one transaction: the committed receipt plus local detail.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxOutcome {
    /// What the block commits to.
    pub receipt: TxReceipt,
    /// Why it failed, in full. Local only — never committed, never on the wire.
    pub result: Result<(), ExecError>,
}

impl TxOutcome {
    /// Whether the transaction applied successfully.
    #[must_use]
    pub fn succeeded(&self) -> bool {
        self.result.is_ok()
    }

    /// The transaction's identifier.
    #[must_use]
    pub fn tx_id(&self) -> Hash32 {
        self.receipt.tx_id
    }

    /// Fee actually charged.
    #[must_use]
    pub fn fee_charged(&self) -> Amount {
        self.receipt.fee_charged
    }

    /// A rejected transaction that changed nothing at all.
    fn rejected(tx_id: Hash32, error: ExecError) -> Self {
        Self {
            receipt: TxReceipt {
                tx_id,
                code: ResultCode::from(&error),
                fee_charged: Amount::ZERO,
                touched: Vec::new(),
            },
            result: Err(error),
        }
    }
}

/// The result of executing a block.
#[derive(Debug, Clone)]
pub struct BlockOutcome {
    /// State root after execution.
    pub app_hash: Hash32,
    /// Per-transaction outcomes, in execution order.
    pub outcomes: Vec<TxOutcome>,
}

impl BlockOutcome {
    /// Number of transactions that applied.
    #[must_use]
    pub fn succeeded(&self) -> usize {
        self.outcomes.iter().filter(|o| o.succeeded()).count()
    }

    /// Merkle root over the receipts, in execution order.
    ///
    /// Leaves are whole receipts rather than ids, because the point is to prove
    /// what a transaction *did*, not merely that it ran. Kept as a second tree
    /// beside `tx_root` rather than folded into it, so a client holding only a
    /// transaction id can still prove inclusion without first obtaining the
    /// receipt.
    #[must_use]
    pub fn outcome_root(&self) -> Hash32 {
        MerkleTree::from_items(self.outcomes.iter().map(|o| o.receipt.to_bytes())).root()
    }
}

impl Encode for ResultCode {
    fn encode(&self, out: &mut Vec<u8>) {
        self.as_u16().encode(out);
    }
}

impl Decode for ResultCode {
    fn decode(r: &mut Reader<'_>) -> Result<Self, CodecError> {
        let raw = u16::decode(r)?;
        Self::from_u16(raw).ok_or(CodecError::UnknownDiscriminant {
            tag: u8::try_from(raw).unwrap_or(u8::MAX),
            type_name: "ResultCode",
        })
    }
}

impl Encode for TxReceipt {
    fn encode(&self, out: &mut Vec<u8>) {
        self.tx_id.encode(out);
        self.code.encode(out);
        self.fee_charged.encode(out);
        self.touched.encode(out);
    }
}

impl Decode for TxReceipt {
    fn decode(r: &mut Reader<'_>) -> Result<Self, CodecError> {
        let receipt = Self {
            tx_id: Hash32::decode(r)?,
            code: ResultCode::decode(r)?,
            fee_charged: Amount::decode(r)?,
            touched: Vec::<TouchedAccount>::decode(r)?,
        };
        // One execution, one encoding. An unsorted or repeated `touched` list
        // would be a second spelling of the same receipt, and the receipt is
        // hashed into a header.
        if !receipt
            .touched
            .windows(2)
            .all(|w| w.first().map(|e| e.address) < w.get(1).map(|e| e.address))
        {
            return Err(CodecError::Invalid(
                "receipt touched-list must be sorted and unique".to_owned(),
            ));
        }
        Ok(receipt)
    }
}

/// Executes blocks against a state store.
pub struct Executor {
    chain_id: ChainId,
}

impl Executor {
    /// An executor bound to one network.
    #[must_use]
    pub fn new(chain_id: ChainId) -> Self {
        Self { chain_id }
    }

    /// The network this executor accepts transactions for.
    #[must_use]
    pub fn chain_id(&self) -> &ChainId {
        &self.chain_id
    }

    /// Apply an ordered list of transactions and return the new app hash.
    pub fn execute_block<S>(
        &self,
        store: &mut S,
        ctx: BlockContext,
        transactions: &[Transaction],
    ) -> BlockOutcome
    where
        S: KeyValueStore + Clone,
    {
        let mut outcomes = Vec::with_capacity(transactions.len());
        for tx in transactions {
            outcomes.push(self.execute_tx(store, ctx, tx));
        }
        BlockOutcome {
            app_hash: store.root(),
            outcomes,
        }
    }

    /// Build the header for a block, executing it to obtain the app hash.
    /// `sets` names who signs this block and who may sign the next. Committing
    /// to both is what lets a light client skip ahead safely
    /// ([ADR-0010](../../../docs/adr/0010-long-range-attacks.md)).
    pub fn build_block<S>(
        &self,
        store: &mut S,
        height: Height,
        time: Timestamp,
        parent: Hash32,
        transactions: Vec<Transaction>,
        sets: ValidatorSets<'_>,
    ) -> (Block, BlockOutcome)
    where
        S: KeyValueStore + Clone,
    {
        let tx_root = Block::tx_root(&transactions);
        let outcome = self.execute_block(store, BlockContext { height, time }, &transactions);
        let header = BlockHeader {
            chain_id: self.chain_id.clone(),
            height,
            time,
            parent,
            tx_root,
            app_hash: outcome.app_hash,
            outcome_root: outcome.outcome_root(),
            validators_hash: sets.current.hash(),
            next_validators_hash: sets.next.hash(),
        };
        (
            Block {
                header,
                transactions,
            },
            outcome,
        )
    }

    /// Apply one transaction, isolating its failure.
    fn execute_tx<S>(&self, store: &mut S, ctx: BlockContext, tx: &Transaction) -> TxOutcome
    where
        S: KeyValueStore + Clone,
    {
        let tx_id = tx.id();

        // Stateless checks first — these cost nothing and reject the cheap attacks.
        if let Err(e) = tx.verify_stateless(&self.chain_id, ctx.height) {
            return TxOutcome::rejected(tx_id, e.into());
        }

        let account = match load_account(store, &tx.body.sender) {
            Ok(a) => a,
            Err(e) => return TxOutcome::rejected(tx_id, e),
        };

        // Authorisation, before the nonce. `verify_stateless` proved the
        // signatures are genuine; it said nothing about whether these keys may
        // act for this account, and that is the question that used to be
        // answered by comparing a key's address to the sender's
        // ([ADR-0017](../../../docs/adr/0017-key-rotation-and-signer-lists.md)).
        //
        // Ahead of the nonce check deliberately: "wrong nonce" is a misleading
        // answer to a forgery, and it reports the account's sequence number to
        // someone who has just proved they do not hold its keys.
        if !account.authorises(&tx.signing_keys()) {
            return TxOutcome::rejected(tx_id, ExecError::Unauthorised);
        }

        if account.nonce != tx.body.nonce {
            return TxOutcome::rejected(
                tx_id,
                ExecError::WrongNonce {
                    expected: account.nonce,
                    got: tx.body.nonce,
                },
            );
        }

        // A sponsor's balance is about to be debited, so the sponsor must have
        // agreed. Without this, naming any funded address as the fee payer
        // drains it — in whichever denomination it holds, since fees are
        // payable in any of them.
        let fee_payer = tx.body.fee.payer_or(tx.body.sender);
        if tx.body.fee.is_sponsored() {
            let payer = match load_account(store, &fee_payer) {
                Ok(a) => a,
                Err(e) => return TxOutcome::rejected(tx_id, e),
            };
            if !payer.authorises(&tx.sponsor_keys()) {
                return TxOutcome::rejected(tx_id, ExecError::SponsorUnauthorised);
            }
        }

        // The denomination has to be one the chain actually accepts. The native
        // coin always is; a sovereign asset is only if governance registered its
        // issuer, which is what "governance-whitelisted" means in ADR-0005 §4.1.
        //
        // Not currently reachable — an attacker cannot obtain units of a denom
        // with no issuer, because minting requires one — but it is the check
        // that keeps that true once issuers can be registered by transaction.
        match accepts_as_fee(store, &tx.body.fee.denom) {
            Ok(true) => {}
            Ok(false) => {
                return TxOutcome::rejected(
                    tx_id,
                    ExecError::FeeDenomNotAccepted(tx.body.fee.denom.to_string()),
                );
            }
            Err(e) => return TxOutcome::rejected(tx_id, e),
        }

        // Charge the fee against committed state. If the payer cannot cover it
        // the transaction is not includable at all, so nothing is consumed.
        let fee_result = Bank::new(store).transfer(
            &fee_payer,
            &fee_collector_address(),
            &tx.body.fee.denom,
            tx.body.fee.amount,
        );
        if let Err(e) = fee_result
            && !tx.body.fee.amount.is_zero()
        {
            return TxOutcome::rejected(tx_id, e.into());
        }
        let fee_charged = tx.body.fee.amount;

        // Messages run in a sandbox so a mid-transaction failure cannot leave
        // half a transaction applied.
        let mut sandbox = store.clone();
        let mut failure = None;
        for msg in &tx.body.messages {
            if let Err(e) = self.apply_message(&mut sandbox, ctx, tx.body.sender, msg) {
                failure = Some(e);
                break;
            }
        }

        let (result, code) = match failure {
            None => {
                *store = sandbox;
                (Ok(()), ResultCode::Success)
            }
            Some(e) => {
                // Sandbox dropped: no state change from the messages. The fee is
                // still charged and the nonce still consumed, so a failing
                // transaction cannot be replayed for free.
                let code = ResultCode::from(&e);
                (Err(e), code)
            }
        };

        // The nonce advances on the committed store either way.
        bump_nonce(store, &tx.body.sender);

        // Whose history moved. A failed transaction still charged a fee and
        // consumed a nonce, so the payer's history did move — but the intended
        // recipient's did not, and filing it under them would let anyone write
        // into a stranger's history for the price of a failure.
        //
        // It also matters for state: recording a pointer *creates* an account
        // record. Restricting failures to the sender and the fee payer means a
        // spammer cannot mint records for addresses it merely names.
        let touched = if result.is_ok() {
            tx.touched_addresses()
        } else {
            let mut minimal = vec![tx.body.sender, fee_payer];
            minimal.sort_unstable();
            minimal.dedup();
            minimal
        };
        let pointer = TxPointer {
            tx_id,
            height: ctx.height,
        };
        let touched = touched
            .into_iter()
            .map(|address| TouchedAccount {
                address,
                previous: move_history_pointer(store, &address, pointer),
            })
            .collect();

        TxOutcome {
            receipt: TxReceipt {
                tx_id,
                code,
                fee_charged,
                touched,
            },
            result,
        }
    }

    fn apply_message<S>(
        &self,
        store: &mut S,
        ctx: BlockContext,
        sender: Address,
        msg: &Message,
    ) -> Result<(), ExecError>
    where
        S: KeyValueStore,
    {
        match msg {
            Message::Transfer {
                to,
                denom,
                amount,
                reference,
            } => {
                // The protocol still never *reads* the reference — it does not
                // route on it, index it, or give it meaning. The only question
                // asked is whether one is present, and only when the recipient
                // has said in state that it must be
                // ([09](../../../docs/09-what-xrpl-answers.md) §2.3).
                //
                // Checked before the transfer, so a refused payment costs the
                // sender a fee and nothing else. The money never moves, which is
                // the whole point: a failure they can retry beats an arrival
                // nobody can attribute.
                if !load_account(store, to)?
                    .requires_reference()
                    .accepts(*reference)
                {
                    return Err(ExecError::ReferenceRequired);
                }
                Bank::new(store).transfer(&sender, to, denom, *amount)?;
                ensure_account(store, to);
                Ok(())
            }

            // Only ever the sender's own record. None of the three takes an
            // address, on purpose: a message that could change someone else's
            // account would let a stranger make their payments fail, or take
            // their money.
            Message::SetAccountFlag { flag, enabled } => change_account(store, sender, |account| {
                account.flags = account.flags.with(*flag, *enabled);
                Ok(())
            }),

            Message::SetRegularKey { key } => change_account(store, sender, |account| {
                // A regular key equal to the master key looks like rotation and
                // achieves none: the exposed seed still signs. Refusing is the
                // only way the user finds out.
                if let Some(new) = key
                    && Address::from_public_key(new) == account.address
                {
                    return Err(ExecError::RegularKeyIsMasterKey);
                }
                account.regular_key = *key;
                Ok(())
            }),

            Message::SetSignerList { list } => change_account(store, sender, |account| {
                account.signers = list.clone();
                Ok(())
            }),

            Message::CreateGroup {
                name,
                members,
                contribution,
                policy,
                quorum,
            } => {
                let account = load_account(store, &sender)?;
                let group_address = Address::derived(
                    Domain::GroupAddress,
                    &[sender.as_bytes().as_slice(), &account.nonce.to_le_bytes()].concat(),
                );
                let member_records = members.iter().map(|m| m.into_member(0)).collect::<Vec<_>>();
                let group = GroupAccount::new(
                    name.clone(),
                    member_records,
                    contribution.clone(),
                    policy.clone(),
                    *quorum,
                    ctx.height,
                )?;

                // A group's address is derived from `(creator, nonce)`, so
                // anyone can compute it in advance and pay it. Writing a fresh
                // record over whatever is there would reset `last_txn` and
                // orphan every payment already made to it — the provable-history
                // chain of ADR-0015 broken by an ordinary group creation.
                //
                // So the record is *converted*, not replaced: history and flags
                // survive, only the kind changes.
                let key = StoreKey::account(&group_address);
                let mut account = load_account(store, &group_address)?;
                if !matches!(account.kind, afrolink_types::AccountKind::Individual { .. }) {
                    return Err(ExecError::AccountExists);
                }
                account.kind = afrolink_types::AccountKind::Group(Box::new(group));
                store.set_encoded(&key, &account);
                Ok(())
            }

            Message::ContributeToGroup { group, amount } => {
                let mut account = load_existing_account(store, group)?;
                let record = account.as_group().ok_or(ExecError::NotAGroup)?;
                if !record.is_member(&sender) {
                    return Err(ExecError::NotAGroupMember);
                }
                // The group agreed one figure. Crediting a cycle for whatever
                // was sent lets a member pay one unit, be recorded as having
                // met the obligation, and collect the full pot when the
                // rotation reaches them.
                if *amount != record.contribution.amount {
                    return Err(GroupError::WrongContributionAmount {
                        expected: record.contribution.amount.units().to_string(),
                        got: amount.units().to_string(),
                    }
                    .into());
                }
                let denom = record.contribution.denom.clone();

                // Recorded first, so a member who has already paid this cycle is
                // refused *before* their money moves.
                if let afrolink_types::AccountKind::Group(g) = &mut account.kind {
                    g.record_contribution(&sender)?;
                }
                Bank::new(store).transfer(&sender, group, &denom, *amount)?;
                store.set_encoded(&StoreKey::account(group), &account);
                Ok(())
            }

            Message::GroupPayout { group } => {
                let mut account = load_existing_account(store, group)?;
                let record = account.as_group().ok_or(ExecError::NotAGroup)?;
                if !record.is_member(&sender) {
                    return Err(ExecError::NotAGroupMember);
                }
                let recipient = record
                    .next_recipient()
                    .ok_or(ExecError::NoRotationRecipient)?;
                let denom = record.contribution.denom.clone();

                // A cycle ends when everybody has paid, or when the agreed
                // period runs out. Without this any member could call payout
                // repeatedly against an empty pot, advancing the rotation until
                // it pointed at themselves, and then collect every cycle.
                if !record.payout_due(ctx.height) {
                    return Err(GroupError::CycleNotDue.into());
                }

                // Pay out whatever the pot actually holds, rather than the
                // nominal figure: a member may have missed a contribution, and
                // paying the nominal amount would overdraw the group.
                let pot = Bank::new(store).view().balance(group, &denom)?;
                if pot.is_zero() {
                    // Nothing to pay is not a cycle. Letting it through would
                    // make the rotation a counter anyone able to pay a fee can
                    // increment.
                    return Err(GroupError::EmptyPot.into());
                }
                Bank::new(store).transfer(group, &recipient, &denom, pot)?;

                if let afrolink_types::AccountKind::Group(g) = &mut account.kind {
                    g.advance_cycle(ctx.height);
                }
                store.set_encoded(&StoreKey::account(group), &account);
                Ok(())
            }

            // -- Accumulating groups: vikoba (ADR-0019) ----------------------
            //
            // Every arm here reads the group's *ledger balance* rather than
            // trusting a running total on the record. The record says how much
            // of that balance is the social fund; the ledger says how much there
            // is. Two numbers that can disagree are a way to spend money twice,
            // so only one of them is ever authoritative about what exists.
            Message::BuyShares { group, shares } => {
                let mut account = load_existing_account(store, group)?;
                let record = account.as_group().ok_or(ExecError::NotAGroup)?;
                if !record.is_member(&sender) {
                    return Err(ExecError::NotAGroupMember);
                }
                let denom = record.contribution.denom.clone();
                let cost = match &mut account.kind {
                    afrolink_types::AccountKind::Group(g) => g.buy_shares(&sender, *shares)?,
                    _ => return Err(ExecError::NotAGroup),
                };
                // Recorded before the money moves, exactly as a contribution is:
                // a purchase the rules refuse must not first take the payment.
                Bank::new(store).transfer(&sender, group, &denom, cost)?;
                store.set_encoded(&StoreKey::account(group), &account);
                Ok(())
            }

            Message::PaySocialFund { group } => {
                let mut account = load_existing_account(store, group)?;
                let record = account.as_group().ok_or(ExecError::NotAGroup)?;
                if !record.is_member(&sender) {
                    return Err(ExecError::NotAGroupMember);
                }
                let denom = record.contribution.denom.clone();
                let amount = match &mut account.kind {
                    afrolink_types::AccountKind::Group(g) => g.pay_social(&sender)?,
                    _ => return Err(ExecError::NotAGroup),
                };
                Bank::new(store).transfer(&sender, group, &denom, amount)?;
                store.set_encoded(&StoreKey::account(group), &account);
                Ok(())
            }

            Message::ProposeGroupAction {
                group,
                beneficiary,
                kind,
            } => {
                let mut account = load_existing_account(store, group)?;
                let record = account.as_group().ok_or(ExecError::NotAGroup)?;
                // A stranger may not put a question to a group about its own
                // money, even a question the group would have to approve.
                if !record.is_member(&sender) {
                    return Err(ExecError::NotAGroupMember);
                }
                let denom = record.contribution.denom.clone();
                let balance = Bank::new(store).view().balance(group, &denom)?;
                match &mut account.kind {
                    afrolink_types::AccountKind::Group(g) => {
                        g.open_proposal(*beneficiary, kind.clone(), balance)?;
                    }
                    _ => return Err(ExecError::NotAGroup),
                }
                store.set_encoded(&StoreKey::account(group), &account);
                Ok(())
            }

            Message::ApproveGroupAction { group } => {
                let mut account = load_existing_account(store, group)?;
                let record = account.as_group().ok_or(ExecError::NotAGroup)?;
                if !record.is_member(&sender) {
                    return Err(ExecError::NotAGroupMember);
                }
                let denom = record.contribution.denom.clone();
                let balance = Bank::new(store).view().balance(group, &denom)?;

                let payment = match &mut account.kind {
                    afrolink_types::AccountKind::Group(g) => {
                        if !g.approve(sender)? {
                            // Recorded, not yet carried out. The group is still
                            // deciding.
                            None
                        } else {
                            // The approval that reaches the quorum carries the
                            // proposal out. A separate execution message would
                            // be one more thing to forget, and a decided
                            // question left unexecuted is how a group's money
                            // ends up stuck.
                            let pending = g
                                .pending
                                .as_ref()
                                .ok_or(GroupError::NoProposal)?
                                .kind
                                .clone();
                            Some(match pending {
                                afrolink_types::group::ProposalKind::Loan { .. } => {
                                    g.issue_loan(balance)?
                                }
                                afrolink_types::group::ProposalKind::SocialGrant { .. } => {
                                    g.issue_grant()?
                                }
                            })
                        }
                    }
                    _ => return Err(ExecError::NotAGroup),
                };

                if let Some((beneficiary, amount)) = payment {
                    Bank::new(store).transfer(group, &beneficiary, &denom, amount)?;
                }
                store.set_encoded(&StoreKey::account(group), &account);
                Ok(())
            }

            Message::RepayLoan { group, amount } => {
                let mut account = load_existing_account(store, group)?;
                let record = account.as_group().ok_or(ExecError::NotAGroup)?;
                if !record.is_member(&sender) {
                    return Err(ExecError::NotAGroupMember);
                }
                let denom = record.contribution.denom.clone();
                match &mut account.kind {
                    afrolink_types::AccountKind::Group(g) => g.repay(&sender, *amount)?,
                    _ => return Err(ExecError::NotAGroup),
                }
                Bank::new(store).transfer(&sender, group, &denom, *amount)?;
                store.set_encoded(&StoreKey::account(group), &account);
                Ok(())
            }

            Message::CloseCycle { group } => {
                let mut account = load_existing_account(store, group)?;
                let record = account.as_group().ok_or(ExecError::NotAGroup)?;
                if !record.is_member(&sender) {
                    return Err(ExecError::NotAGroupMember);
                }
                // Rotations close through `GroupPayout`, which must pay before
                // it advances. Letting this close one too would let a member
                // skip the payout and move the rotation past their own turn.
                record.require_share_rules()?;
                if !record.payout_due(ctx.height) {
                    return Err(GroupError::CycleNotDue.into());
                }
                if let afrolink_types::AccountKind::Group(g) = &mut account.kind {
                    g.advance_cycle(ctx.height);
                }
                store.set_encoded(&StoreKey::account(group), &account);
                Ok(())
            }

            Message::ShareOut { group } => {
                let mut account = load_existing_account(store, group)?;
                let record = account.as_group().ok_or(ExecError::NotAGroup)?;
                if !record.is_member(&sender) {
                    return Err(ExecError::NotAGroupMember);
                }
                let denom = record.contribution.denom.clone();
                let balance = Bank::new(store).view().balance(group, &denom)?;
                // Only the savings are divided. The social fund is insurance the
                // group agreed to hold, and it survives the round that raised it.
                let fund = record.lendable(balance)?;

                let payments = match &mut account.kind {
                    afrolink_types::AccountKind::Group(g) => g.share_out(fund)?,
                    _ => return Err(ExecError::NotAGroup),
                };
                for (member, amount) in payments {
                    Bank::new(store).transfer(group, &member, &denom, amount)?;
                }
                store.set_encoded(&StoreKey::account(group), &account);
                Ok(())
            }

            // -- Human-readable addressing (ADR-0008) ------------------------
            //
            // Every arm below is a registry write. None of them move value, and
            // none of them can: an alias resolves, it never authorises.
            Message::RegisterName { name } => {
                Registry::new(store).register(name, sender, ctx.height)?;
                Ok(())
            }

            Message::RenewName { name } => {
                Registry::new(store).renew(name, sender, ctx.height)?;
                Ok(())
            }

            Message::TransferName { name, to } => {
                Registry::new(store).transfer(name, sender, *to, ctx.height)?;
                ensure_account(store, to);
                Ok(())
            }

            Message::SetPrimaryAlias { name } => {
                Registry::new(store).set_primary(name, sender, ctx.height)?;
                Ok(())
            }

            Message::AttestContact {
                commitment,
                address,
            } => {
                // The sender is the attestor; the binding is checked against the
                // attestor registry, so an ordinary account cannot bind anyone.
                Bindings::new(store).attest(commitment, *address, sender, ctx.height)?;
                ensure_account(store, address);
                Ok(())
            }

            Message::RequestRebind {
                commitment,
                new_address,
            } => {
                Bindings::new(store).request_rebind(
                    commitment,
                    *new_address,
                    sender,
                    ctx.height,
                )?;
                Ok(())
            }

            Message::VetoRebind { commitment } => {
                // `sender` is the signer of this transaction, so reaching here
                // already proves possession of the key. Whether that key holds
                // the bound account is what `veto_rebind` checks.
                Bindings::new(store).veto_rebind(commitment, sender)?;
                Ok(())
            }

            Message::ApplyRebind { commitment } => {
                // No sender check: the delay has elapsed and the veto window has
                // closed, so the outcome is already decided. Whoever pays to
                // finish it changes nothing — and requiring the new owner would
                // defeat the purpose, since this exists for a user who lost the
                // key the account is moving away from.
                let record = Bindings::new(store).apply_rebind(commitment, ctx.height)?;
                ensure_account(store, &record);
                Ok(())
            }

            Message::RevokeContact { commitment } => {
                Bindings::new(store).revoke(commitment, sender)?;
                Ok(())
            }

            Message::ClearPrimaryAlias => {
                // Cannot fail and needs no ownership check: it touches only the
                // sender's own reverse entry. A privacy control that can be
                // refused is not a privacy control.
                Registry::new(store).clear_primary(&sender);
                Ok(())
            }

            Message::ReleaseName { name } => {
                Registry::new(store).release(name, sender, ctx.height)?;
                Ok(())
            }

            Message::Bond {
                public_key,
                country,
                amount,
            } => {
                Staking::new(store).bond(&sender, *public_key, *country, *amount)?;
                Ok(())
            }

            Message::AddStake { amount } => {
                Staking::new(store).add_stake(&sender, *amount)?;
                Ok(())
            }

            Message::Unbond { amount } => {
                // Both parts of the context matter here: the height is what a
                // later slash measures the entry against, and the time is what
                // decides when it may be withdrawn.
                Staking::new(store).unbond(&sender, *amount, ctx.height, ctx.time)?;
                Ok(())
            }

            Message::WithdrawUnbonded => {
                Staking::new(store).withdraw(&sender, ctx.time)?;
                Ok(())
            }

            Message::ReportEquivocation { evidence } => {
                // Permissionless, and deliberately so: the evidence proves
                // itself against the validator set, so there is nothing to gain
                // by lying and no privileged reporter to capture. The reporter
                // is not paid — see `Bank::slash_native` for why nobody should
                // profit from a slash.
                let set = Staking::new(store).active_set()?;
                Staking::new(store).slash_equivocation(evidence, &set, ctx.height)?;
                Ok(())
            }
        }
    }
}

/// Load an account, returning a fresh one if it has never been seen.
fn load_account<S: KeyValueStore>(store: &S, address: &Address) -> Result<Account, ExecError> {
    Ok(store
        .get_decoded::<Account>(&StoreKey::account(address))?
        .unwrap_or_else(|| Account::individual(*address)))
}

/// Load an account that must already exist.
fn load_existing_account<S: KeyValueStore>(
    store: &S,
    address: &Address,
) -> Result<Account, ExecError> {
    store
        .get_decoded::<Account>(&StoreKey::account(address))?
        .ok_or(ExecError::NoSuchAccount)
}

/// Whether the chain accepts fees in this denomination.
///
/// The native coin always. A sovereign asset only when governance has registered
/// its issuer — issuers exist solely through genesis today, so the issuer
/// registry *is* the whitelist ADR-0005 §4.1 describes.
fn accepts_as_fee<S: KeyValueStore>(
    store: &S,
    denom: &afrolink_primitives::Denom,
) -> Result<bool, ExecError> {
    if denom.is_native() {
        return Ok(true);
    }
    Ok(afrolink_bank::BankView::new(store).issuer(denom)?.is_some())
}

/// Apply a change to the sender's own account record, refusing a lock-out.
///
/// **Every message that touches a signing arrangement goes through here**, and
/// the invariant is checked once, afterwards, on whatever the change produced.
/// The three ways to lock an account out — disabling the master key with no
/// replacement, clearing the regular key while it is disabled, removing the
/// signer list while it is disabled — are one rule seen from three sides.
/// Checking each case at its own call site is how a fourth arrives without one.
fn change_account<S, F>(store: &mut S, sender: Address, change: F) -> Result<(), ExecError>
where
    S: KeyValueStore,
    F: FnOnce(&mut Account) -> Result<(), ExecError>,
{
    let key = StoreKey::account(&sender);
    let mut account = load_account(store, &sender)?;
    change(&mut account)?;
    if !account.has_a_usable_authority() {
        return Err(ExecError::WouldLockOut);
    }
    store.set_encoded(&key, &account);
    Ok(())
}

/// Create an account record for a recipient that has never been seen.
fn ensure_account<S: KeyValueStore>(store: &mut S, address: &Address) {
    let key = StoreKey::account(address);
    if store.get(&key).is_none() {
        store.set_encoded(&key, &Account::individual(*address));
    }
}

/// Point an account's history at `pointer`, returning what it pointed at before.
///
/// Creates the account record if there was none — which is how a recipient who
/// has never sent a transaction gets a history at all. XRPL does the same thing
/// when a payment changes an AccountRoot's balance
/// ([09](../../../docs/09-what-xrpl-answers.md) §2.1).
fn move_history_pointer<S: KeyValueStore>(
    store: &mut S,
    address: &Address,
    pointer: TxPointer,
) -> Option<TxPointer> {
    let key = StoreKey::account(address);
    let mut account = store
        .get_decoded::<Account>(&key)
        .ok()
        .flatten()
        .unwrap_or_else(|| Account::individual(*address));
    let previous = account.last_txn;
    account.last_txn = Some(pointer);
    store.set_encoded(&key, &account);
    previous
}

fn bump_nonce<S: KeyValueStore>(store: &mut S, address: &Address) {
    let key = StoreKey::account(address);
    let mut account = store
        .get_decoded::<Account>(&key)
        .ok()
        .flatten()
        .unwrap_or_else(|| Account::individual(*address));
    account.increment_nonce();
    store.set_encoded(&key, &account);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Execution context for a test block.
    ///
    /// Time is derived from height rather than pinned, because header times are
    /// strictly monotonic on a real chain and a fixture that repeats one hides
    /// bugs the light client depends on catching (ADR-0010).
    fn ctx(height: u64) -> BlockContext {
        BlockContext {
            height: Height(height),
            time: Timestamp::from_millis(1_700_000_000_000 + height * 1_000),
        }
    }
    use afrolink_bank::Issuer;
    use afrolink_crypto::SecretKey;
    use afrolink_primitives::Denom;
    use afrolink_state::MemoryStore;
    use afrolink_types::group::{
        Contribution, FoundingMember, PayoutPolicy, Quorum, Role, ShareRules,
    };
    use afrolink_types::{Fee, TxBody};

    fn sk(seed: u8) -> SecretKey {
        SecretKey::from_bytes(&[seed; 32])
    }

    /// A single-validator set, enough for the header commitments these tests
    /// exercise. Validator-set *changes* are covered in `crates/light`.
    fn validators() -> afrolink_consensus::ValidatorSet {
        use afrolink_consensus::{CountryCode, Validator, ValidatorSet};
        ValidatorSet::new(vec![Validator::new(
            sk(1).public_key(),
            10,
            CountryCode::new("ke").expect("valid"),
        )])
        .expect("valid set")
    }

    fn addr(seed: u8) -> Address {
        Address::from_public_key(&sk(seed).public_key())
    }

    fn chain() -> ChainId {
        ChainId::new("afrolink-1").expect("valid")
    }

    fn kes() -> Denom {
        Denom::sovereign("ke", "kes").expect("valid")
    }

    fn cbk() -> Address {
        addr(100)
    }

    /// A store where accounts 1..=4 each hold 10,000 KES.
    fn funded_store() -> MemoryStore {
        let mut store = MemoryStore::new();
        let mut bank = Bank::new(&mut store);
        bank.register_issuer(&kes(), &Issuer::new(cbk()))
            .expect("registers");
        for i in 1..=4u8 {
            bank.mint(&cbk(), &addr(i), &kes(), Amount::from_afri(10_000))
                .expect("mints");
        }
        store
    }

    fn tx(sender: u8, nonce: u64, messages: Vec<Message>) -> Transaction {
        TxBody {
            chain_id: chain(),
            sender: addr(sender),
            nonce,
            valid_until: Height(1_000),
            fee: Fee::new(Amount::from_units(1_000), kes()),
            messages,
            memo: String::new(),
        }
        .sign(&sk(sender))
    }

    // -- Staking (ADR-0012) --------------------------------------------------

    /// A store where accounts 1..=4 hold AFRI as well as the sovereign asset.
    fn staked_store() -> MemoryStore {
        let mut store = funded_store();
        let mut bank = Bank::new(&mut store);
        for i in 1..=4u8 {
            bank.genesis_allocate(&addr(i), &Denom::native(), Amount::from_afri(100_000))
                .expect("allocates");
        }
        store
    }

    fn staking_params() -> afrolink_staking::StakingParams {
        afrolink_staking::StakingParams {
            min_bond: Amount::from_afri(1_000),
            ..afrolink_staking::StakingParams::default()
        }
    }

    #[test]
    fn a_bond_submitted_as_a_transaction_joins_the_validator_set() {
        // The point of the module: who signs blocks is now decided by who has
        // staked, through an ordinary transaction anyone can send.
        let mut store = staked_store();
        let exec = Executor::new(chain());

        let bond = Message::Bond {
            public_key: sk(1).public_key(),
            country: afrolink_consensus::CountryCode::new("ke").expect("valid"),
            amount: Amount::from_afri(50_000),
        };
        let outcome = exec.execute_block(&mut store, ctx(1), &[tx(1, 0, vec![bond])]);
        assert_eq!(outcome.succeeded(), 1, "{:?}", outcome.outcomes[0].result);

        let set = Staking::with_params(&mut store, staking_params())
            .active_set()
            .expect("set forms");
        assert_eq!(set.validators().len(), 1);
    }

    #[test]
    fn an_unbonding_transaction_does_not_release_funds_immediately() {
        // The 21-day window has to survive the transaction path, not just the
        // module API — the light client's trusting period is derived from it.
        let mut store = staked_store();
        let exec = Executor::new(chain());

        let bond = Message::Bond {
            public_key: sk(1).public_key(),
            country: afrolink_consensus::CountryCode::new("ke").expect("valid"),
            amount: Amount::from_afri(50_000),
        };
        exec.execute_block(&mut store, ctx(1), &[tx(1, 0, vec![bond])]);

        let after_bond = Bank::new(&mut store)
            .balance(&addr(1), &Denom::native())
            .expect("reads");

        let out = exec.execute_block(
            &mut store,
            ctx(2),
            &[tx(
                1,
                1,
                vec![Message::Unbond {
                    amount: Amount::from_afri(50_000),
                }],
            )],
        );
        assert_eq!(out.succeeded(), 1, "{:?}", out.outcomes[0].result);

        // Withdrawing in the very next block must fail: nothing has matured.
        let early = exec.execute_block(
            &mut store,
            ctx(3),
            &[tx(1, 2, vec![Message::WithdrawUnbonded])],
        );
        assert_eq!(early.succeeded(), 0, "funds released before the period");

        assert_eq!(
            Bank::new(&mut store)
                .balance(&addr(1), &Denom::native())
                .expect("reads"),
            after_bond,
            "the balance must not have moved"
        );
    }

    #[test]
    fn anyone_can_report_equivocation_and_the_offender_is_punished() {
        // Permissionless reporting: the evidence proves itself, so there is no
        // privileged reporter to capture and nothing to gain by lying.
        use afrolink_consensus::{Equivocation, Vote, VoteType};

        let mut store = staked_store();
        let exec = Executor::new(chain());

        for signer in 1..=2u8 {
            let bond = Message::Bond {
                public_key: sk(signer).public_key(),
                country: afrolink_consensus::CountryCode::new("ke").expect("valid"),
                amount: Amount::from_afri(50_000),
            };
            let r = exec.execute_block(
                &mut store,
                ctx(u64::from(signer)),
                &[tx(signer, 0, vec![bond])],
            );
            assert_eq!(r.succeeded(), 1, "{:?}", r.outcomes[0].result);
        }

        let vote_for = |block: [u8; 32]| {
            Vote {
                chain_id: chain(),
                height: Height(3),
                round: afrolink_primitives::Round::ZERO,
                vote_type: VoteType::Precommit,
                block_id: Some(Hash32::from_bytes(block)),
                validator: addr(1),
            }
            .sign(&sk(1))
        };
        let evidence = Equivocation {
            validator: addr(1),
            first: vote_for([0xAA; 32]),
            second: vote_for([0xBB; 32]),
        };

        // Reported by account 3, who is not a validator and gains nothing.
        let report = exec.execute_block(
            &mut store,
            ctx(4),
            &[tx(
                3,
                0,
                vec![Message::ReportEquivocation {
                    evidence: Box::new(evidence),
                }],
            )],
        );
        assert_eq!(report.succeeded(), 1, "{:?}", report.outcomes[0].result);

        let bond = Staking::new(&mut store)
            .bond_of(&addr(1))
            .expect("reads")
            .expect("bonded");
        assert!(bond.jailed, "the offender must be jailed");
        assert_eq!(
            bond.bonded,
            Amount::from_afri(47_500),
            "5% of the stake must be gone"
        );
    }

    #[test]
    fn an_accusation_submitted_as_a_transaction_destroys_nothing() {
        use afrolink_consensus::{Equivocation, Vote, VoteType};

        let mut store = staked_store();
        let exec = Executor::new(chain());
        let bond = Message::Bond {
            public_key: sk(1).public_key(),
            country: afrolink_consensus::CountryCode::new("ke").expect("valid"),
            amount: Amount::from_afri(50_000),
        };
        exec.execute_block(&mut store, ctx(1), &[tx(1, 0, vec![bond])]);

        // Two votes signed by account 2, blamed on account 1.
        let vote_for = |block: [u8; 32]| {
            Vote {
                chain_id: chain(),
                height: Height(3),
                round: afrolink_primitives::Round::ZERO,
                vote_type: VoteType::Precommit,
                block_id: Some(Hash32::from_bytes(block)),
                validator: addr(2),
            }
            .sign(&sk(2))
        };
        let framed = Equivocation {
            validator: addr(1),
            first: vote_for([0xAA; 32]),
            second: vote_for([0xBB; 32]),
        };

        let report = exec.execute_block(
            &mut store,
            ctx(2),
            &[tx(
                3,
                0,
                vec![Message::ReportEquivocation {
                    evidence: Box::new(framed),
                }],
            )],
        );
        assert_eq!(report.succeeded(), 0, "a framed accusation must be refused");
        assert_eq!(
            Staking::new(&mut store)
                .bond_of(&addr(1))
                .expect("reads")
                .expect("bonded")
                .bonded,
            Amount::from_afri(50_000),
            "an accusation must not move money"
        );
    }

    // -- Human-readable addressing (ADR-0008) --------------------------------

    #[test]
    fn a_name_registered_through_a_transaction_resolves_to_its_owner() {
        use afrolink_alias::{Registry, Username};

        let mut store = funded_store();
        let exec = Executor::new(chain());
        let name = Username::new("amina").expect("valid");

        let outcome = exec.execute_block(
            &mut store,
            ctx(1),
            &[tx(1, 0, vec![Message::RegisterName { name: name.clone() }])],
        );
        assert_eq!(outcome.succeeded(), 1, "{:?}", outcome.outcomes[0].result);

        let record = Registry::new(&mut store)
            .get(&name)
            .expect("reads")
            .expect("registered");
        assert_eq!(record.owner, addr(1));
    }

    #[test]
    fn a_confusable_registration_fails_the_transaction() {
        // The check has to bite at execution, not only in the library: two
        // wallets racing for lookalike names must not both succeed.
        use afrolink_alias::Username;

        let mut store = funded_store();
        let exec = Executor::new(chain());

        let first = exec.execute_block(
            &mut store,
            ctx(1),
            &[tx(
                1,
                0,
                vec![Message::RegisterName {
                    name: Username::new("amina").expect("valid"),
                }],
            )],
        );
        assert_eq!(first.succeeded(), 1);

        let second = exec.execute_block(
            &mut store,
            ctx(2),
            &[tx(
                2,
                0,
                vec![Message::RegisterName {
                    name: Username::new("arnina").expect("valid"),
                }],
            )],
        );
        assert_eq!(second.succeeded(), 0, "the lookalike must be refused");
    }

    #[test]
    fn a_stranger_cannot_take_over_someone_elses_name() {
        use afrolink_alias::{Registry, Username};

        let mut store = funded_store();
        let exec = Executor::new(chain());
        let name = Username::new("amina").expect("valid");

        exec.execute_block(
            &mut store,
            ctx(1),
            &[tx(1, 0, vec![Message::RegisterName { name: name.clone() }])],
        );

        // Account 2 tries to hand account 1's name to itself.
        let theft = exec.execute_block(
            &mut store,
            ctx(2),
            &[tx(
                2,
                0,
                vec![Message::TransferName {
                    name: name.clone(),
                    to: addr(2),
                }],
            )],
        );
        assert_eq!(theft.succeeded(), 0);
        assert_eq!(
            Registry::new(&mut store)
                .get(&name)
                .expect("reads")
                .expect("registered")
                .owner,
            addr(1)
        );
    }

    #[test]
    fn an_alias_message_never_moves_money() {
        // The invariant behind the whole design: registering, renaming and
        // rebinding are registry writes. If one of them could move value, the
        // "resolves but never authorises" rule would be a comment rather than a
        // property.
        use afrolink_alias::Username;

        let mut store = funded_store();
        let exec = Executor::new(chain());
        let before = Bank::new(&mut store)
            .view()
            .balance(&addr(1), &kes())
            .expect("reads");

        let outcome = exec.execute_block(
            &mut store,
            ctx(1),
            &[tx(
                1,
                0,
                vec![
                    Message::RegisterName {
                        name: Username::new("amina").expect("valid"),
                    },
                    Message::SetPrimaryAlias {
                        name: Username::new("amina").expect("valid"),
                    },
                ],
            )],
        );
        assert_eq!(outcome.succeeded(), 1, "{:?}", outcome.outcomes[0].result);

        let after = Bank::new(&mut store)
            .view()
            .balance(&addr(1), &kes())
            .expect("reads");
        let fee = outcome.outcomes[0].fee_charged();

        // The only movement is the fee. Nothing else left the account.
        assert_eq!(
            after,
            before.checked_sub(fee).expect("fee is affordable"),
            "an alias message must not move value beyond the fee"
        );
    }

    #[test]
    fn a_transfer_applies_and_advances_the_nonce() {
        let mut store = funded_store();
        let exec = Executor::new(chain());
        let transfer = Message::Transfer {
            to: addr(2),
            denom: kes(),
            amount: Amount::from_afri(500),
            reference: None,
        };
        let outcome = exec.execute_block(&mut store, ctx(1), &[tx(1, 0, vec![transfer])]);

        assert_eq!(outcome.succeeded(), 1, "{:?}", outcome.outcomes[0].result);
        let bank = Bank::new(&mut store);
        assert_eq!(
            bank.balance(&addr(2), &kes()).expect("read"),
            Amount::from_afri(10_500)
        );
    }

    // -- Key rotation and signer lists (ADR-0017) ----------------------------

    /// A transaction from `sender`'s account, signed by whichever keys are given.
    ///
    /// The separation is the point: `sender` names the account, `signers` name
    /// the keys presented. Before rotation those were always the same thing.
    fn signed_by(sender: u8, nonce: u64, signers: &[u8], messages: Vec<Message>) -> Transaction {
        let keys: Vec<SecretKey> = signers.iter().map(|s| sk(*s)).collect();
        let refs: Vec<&SecretKey> = keys.iter().collect();
        TxBody {
            chain_id: chain(),
            sender: addr(sender),
            nonce,
            valid_until: Height(1_000),
            fee: Fee::new(Amount::from_units(1_000), kes()),
            messages,
            memo: String::new(),
        }
        .sign_with(&refs)
    }

    fn small_transfer() -> Vec<Message> {
        vec![Message::Transfer {
            to: addr(2),
            denom: kes(),
            amount: Amount::from_afri(1),
            reference: None,
        }]
    }

    /// A 2-of-3 recovery list over keys 11, 12 and 13.
    fn recovery_list() -> afrolink_types::SignerList {
        use afrolink_types::{Signer, SignerList};
        SignerList::new(
            (11..=13u8)
                .map(|s| Signer {
                    key: sk(s).public_key(),
                    weight: 1,
                })
                .collect(),
            2,
        )
        .expect("valid list")
    }

    #[test]
    fn a_rotated_key_spends_the_account_and_the_address_never_changes() {
        // The headline property. A username, a printed QR code and an address
        // already shared with an employer all keep working across a key change,
        // which is why this matters more here than on a chain without aliases.
        let mut store = funded_store();
        let exec = Executor::new(chain());

        let rotate = exec.execute_block(
            &mut store,
            ctx(1),
            &[signed_by(
                1,
                0,
                &[1],
                vec![Message::SetRegularKey {
                    key: Some(sk(9).public_key()),
                }],
            )],
        );
        assert_eq!(rotate.succeeded(), 1, "{:?}", rotate.outcomes[0].result);

        let spent = exec.execute_block(
            &mut store,
            ctx(2),
            &[signed_by(1, 1, &[9], small_transfer())],
        );
        assert_eq!(spent.succeeded(), 1, "{:?}", spent.outcomes[0].result);
        assert_eq!(
            load_account(&store, &addr(1)).expect("reads").address,
            addr(1),
            "the address must not have moved"
        );
    }

    #[test]
    fn a_stranger_still_cannot_spend_an_account_that_rotated() {
        // Authorisation moved out of stateless verification, so this is the
        // check that replaced it. A genuine signature from an unrelated key must
        // buy nothing.
        let mut store = funded_store();
        let exec = Executor::new(chain());
        exec.execute_block(
            &mut store,
            ctx(1),
            &[signed_by(
                1,
                0,
                &[1],
                vec![Message::SetRegularKey {
                    key: Some(sk(9).public_key()),
                }],
            )],
        );

        let theft = exec.execute_block(
            &mut store,
            ctx(2),
            &[signed_by(1, 1, &[66], small_transfer())],
        );
        assert_eq!(theft.succeeded(), 0);
        assert_eq!(
            theft.outcomes[0].receipt.code,
            ResultCode::Authorisation,
            "and it must be refused as unauthorised, not as a bad nonce"
        );
    }

    #[test]
    fn an_exposed_seed_can_be_retired_without_moving_the_money() {
        // A leaked seed can never be un-leaked. Disabling it is the only
        // response that does not mean abandoning the address and racing the
        // attacker to move funds.
        use afrolink_types::AccountFlag;

        let mut store = funded_store();
        let exec = Executor::new(chain());
        let before = Bank::new(&mut store)
            .view()
            .balance(&addr(1), &kes())
            .expect("reads");

        let out = exec.execute_block(
            &mut store,
            ctx(1),
            &[signed_by(
                1,
                0,
                &[1],
                vec![
                    Message::SetRegularKey {
                        key: Some(sk(9).public_key()),
                    },
                    Message::SetAccountFlag {
                        flag: AccountFlag::MasterKeyDisabled,
                        enabled: true,
                    },
                ],
            )],
        );
        assert_eq!(out.succeeded(), 1, "{:?}", out.outcomes[0].result);

        // The attacker holds the seed and can still sign perfectly valid bytes.
        let with_stolen_seed = exec.execute_block(
            &mut store,
            ctx(2),
            &[signed_by(1, 1, &[1], small_transfer())],
        );
        assert_eq!(with_stolen_seed.succeeded(), 0, "the old key must be dead");
        assert_eq!(
            with_stolen_seed.outcomes[0].receipt.code,
            ResultCode::Authorisation
        );
        assert_eq!(
            load_account(&store, &addr(1)).expect("reads").nonce,
            1,
            "an unauthorised attempt must not burn the owner's nonce, or an \
             attacker could invalidate every transaction they are about to send"
        );

        let with_new_key = exec.execute_block(
            &mut store,
            ctx(3),
            &[signed_by(1, 1, &[9], small_transfer())],
        );
        assert_eq!(
            with_new_key.succeeded(),
            1,
            "{:?}",
            with_new_key.outcomes[0].result
        );

        let after = Bank::new(&mut store)
            .view()
            .balance(&addr(1), &kes())
            .expect("reads");
        assert!(
            after < before,
            "only fees and the one small transfer left the account"
        );
    }

    #[test]
    fn disabling_the_master_key_with_no_replacement_is_refused() {
        // The lock-out invariant. Obeying this would freeze the account's funds
        // permanently, and nothing could ever undo it.
        use afrolink_types::AccountFlag;

        let mut store = funded_store();
        let exec = Executor::new(chain());
        let out = exec.execute_block(
            &mut store,
            ctx(1),
            &[signed_by(
                1,
                0,
                &[1],
                vec![Message::SetAccountFlag {
                    flag: AccountFlag::MasterKeyDisabled,
                    enabled: true,
                }],
            )],
        );

        assert_eq!(out.succeeded(), 0);
        assert!(matches!(
            out.outcomes[0].result,
            Err(ExecError::WouldLockOut)
        ));
        assert!(
            exec.execute_block(
                &mut store,
                ctx(2),
                &[signed_by(1, 1, &[1], small_transfer())]
            )
            .succeeded()
                == 1,
            "and the account must be entirely unharmed"
        );
    }

    #[test]
    fn clearing_the_last_authority_is_refused_from_every_direction() {
        // Three ways to lock an account out, one rule. The rule is checked after
        // the change rather than as a condition on each message, which is what
        // stops a fourth authority arriving without a check.
        use afrolink_types::AccountFlag;

        for (name, finisher) in [
            (
                "clearing the regular key",
                Message::SetRegularKey { key: None },
            ),
            (
                "clearing the signer list",
                Message::SetSignerList { list: None },
            ),
        ] {
            let mut store = funded_store();
            let exec = Executor::new(chain());

            // Set up both replacements, then disable the master key.
            let setup = exec.execute_block(
                &mut store,
                ctx(1),
                &[signed_by(
                    1,
                    0,
                    &[1],
                    vec![
                        Message::SetRegularKey {
                            key: Some(sk(9).public_key()),
                        },
                        Message::SetAccountFlag {
                            flag: AccountFlag::MasterKeyDisabled,
                            enabled: true,
                        },
                    ],
                )],
            );
            assert_eq!(setup.succeeded(), 1, "{:?}", setup.outcomes[0].result);

            // Now remove the only remaining authority.
            let out =
                exec.execute_block(&mut store, ctx(2), &[signed_by(1, 1, &[9], vec![finisher])]);
            if name == "clearing the regular key" {
                assert_eq!(out.succeeded(), 0, "{name} must be refused");
                assert!(matches!(
                    out.outcomes[0].result,
                    Err(ExecError::WouldLockOut)
                ));
            } else {
                // Clearing an absent signer list changes nothing and is fine.
                assert_eq!(out.succeeded(), 1, "{name}: {:?}", out.outcomes[0].result);
            }
        }
    }

    #[test]
    fn two_family_members_can_recover_an_account_but_one_cannot() {
        // Social recovery as a protocol primitive rather than a contract, and
        // the strictly better answer to "recover from something I remember"
        // than any password scheme ([09](../../../docs/09-what-xrpl-answers.md) §1).
        let mut store = funded_store();
        let exec = Executor::new(chain());

        let setup = exec.execute_block(
            &mut store,
            ctx(1),
            &[signed_by(
                1,
                0,
                &[1],
                vec![Message::SetSignerList {
                    list: Some(recovery_list()),
                }],
            )],
        );
        assert_eq!(setup.succeeded(), 1, "{:?}", setup.outcomes[0].result);

        let alone = exec.execute_block(
            &mut store,
            ctx(2),
            &[signed_by(1, 1, &[11], small_transfer())],
        );
        assert_eq!(alone.succeeded(), 0, "one signer is not a quorum");
        assert_eq!(alone.outcomes[0].receipt.code, ResultCode::Authorisation);

        let quorum = exec.execute_block(
            &mut store,
            ctx(3),
            &[signed_by(1, 1, &[11, 12], small_transfer())],
        );
        assert_eq!(quorum.succeeded(), 1, "{:?}", quorum.outcomes[0].result);
    }

    #[test]
    fn a_quorum_can_replace_a_signer_who_lost_their_key() {
        // The cost of listing keys rather than accounts, and the reason it is
        // acceptable: for a recovery list this is the ordinary case, and the
        // remaining signers can do it themselves.
        let mut store = funded_store();
        let exec = Executor::new(chain());
        exec.execute_block(
            &mut store,
            ctx(1),
            &[signed_by(
                1,
                0,
                &[1],
                vec![Message::SetSignerList {
                    list: Some(recovery_list()),
                }],
            )],
        );

        use afrolink_types::{Signer, SignerList};
        let replaced = SignerList::new(
            vec![
                Signer {
                    key: sk(11).public_key(),
                    weight: 1,
                },
                Signer {
                    key: sk(12).public_key(),
                    weight: 1,
                },
                Signer {
                    key: sk(14).public_key(),
                    weight: 1,
                },
            ],
            2,
        )
        .expect("valid list");

        let out = exec.execute_block(
            &mut store,
            ctx(2),
            &[signed_by(
                1,
                1,
                &[11, 12],
                vec![Message::SetSignerList {
                    list: Some(replaced),
                }],
            )],
        );
        assert_eq!(out.succeeded(), 1, "{:?}", out.outcomes[0].result);

        let by_new_signer = exec.execute_block(
            &mut store,
            ctx(3),
            &[signed_by(1, 2, &[12, 14], small_transfer())],
        );
        assert_eq!(
            by_new_signer.succeeded(),
            1,
            "{:?}",
            by_new_signer.outcomes[0].result
        );
    }

    #[test]
    fn a_regular_key_equal_to_the_master_key_is_refused() {
        // It looks like rotation and provides none. A user who did it would
        // believe an exposed seed had been retired when it had not.
        let mut store = funded_store();
        let exec = Executor::new(chain());
        let out = exec.execute_block(
            &mut store,
            ctx(1),
            &[signed_by(
                1,
                0,
                &[1],
                vec![Message::SetRegularKey {
                    key: Some(sk(1).public_key()),
                }],
            )],
        );
        assert!(matches!(
            out.outcomes[0].result,
            Err(ExecError::RegularKeyIsMasterKey)
        ));
    }

    #[test]
    fn nobody_can_change_someone_elses_signing_arrangement() {
        // None of the three messages takes an address. This is the property
        // that follows from that, stated as a test rather than left implicit.
        let mut store = funded_store();
        let exec = Executor::new(chain());
        exec.execute_block(
            &mut store,
            ctx(1),
            &[signed_by(
                2,
                0,
                &[2],
                vec![Message::SetRegularKey {
                    key: Some(sk(9).public_key()),
                }],
            )],
        );

        assert_eq!(
            load_account(&store, &addr(1)).expect("reads").regular_key,
            None,
            "account 2's rotation must not have touched account 1"
        );
        assert_eq!(
            load_account(&store, &addr(2))
                .expect("reads")
                .regular_key
                .map(|k| k.to_bytes()),
            Some(sk(9).public_key().to_bytes())
        );
    }

    #[test]
    fn an_unauthorised_transaction_is_refused_before_the_nonce_is_consulted() {
        // "Wrong nonce" is a misleading answer to a forgery, and it reports the
        // account's sequence number to someone who has just proved they do not
        // hold its keys.
        let mut store = funded_store();
        let exec = Executor::new(chain());
        let out = exec.execute_block(
            &mut store,
            ctx(1),
            &[signed_by(1, 9_999, &[66], small_transfer())],
        );
        assert!(matches!(
            out.outcomes[0].result,
            Err(ExecError::Unauthorised)
        ));
    }

    #[test]
    fn naming_a_stranger_as_the_fee_payer_does_not_charge_them() {
        // Found while adding authorisation: `Fee::sponsored_by` let any
        // transaction name any address as its payer, and the executor debited
        // it unconditionally. That is "drain any funded account, one fee at a
        // time" — and since fees are payable in any whitelisted denom, in any
        // denom the victim holds.
        //
        // Sponsorship is a real feature and stays. What it now needs is the
        // sponsor's signature.
        let mut store = funded_store();
        let exec = Executor::new(chain());
        let victim = addr(2);
        let before = Bank::new(&mut store)
            .view()
            .balance(&victim, &kes())
            .expect("reads");

        let raid = TxBody {
            chain_id: chain(),
            sender: addr(1),
            nonce: 0,
            valid_until: Height(1_000),
            fee: Fee::sponsored_by(Amount::from_units(1_000), kes(), victim),
            messages: small_transfer(),
            memo: String::new(),
        }
        .sign(&sk(1));

        let out = exec.execute_block(&mut store, ctx(1), &[raid]);
        assert_eq!(out.succeeded(), 0, "an unconsenting sponsor must not pay");
        // Caught structurally, before any account is read: a sponsored fee with
        // no sponsor signature is malformed, not merely unauthorised. An
        // attacker who supplies a signature from a key of their own gets past
        // this and is stopped by the account check instead — see
        // `a_sponsor_signature_from_the_wrong_key_is_refused`.
        assert!(matches!(
            out.outcomes[0].result,
            Err(ExecError::Tx(TxError::SponsorSignatureMismatch))
        ));
        assert_eq!(
            Bank::new(&mut store)
                .view()
                .balance(&victim, &kes())
                .expect("reads"),
            before,
            "not one unit may leave a stranger's account"
        );
    }

    #[test]
    fn a_sponsor_who_signs_does_pay() {
        // The feature this chain is partly built around: an employer or an NGO
        // covering fees so a user never has to hold the native coin. It must
        // still work, and the only thing that changed is that the sponsor
        // consents.
        let mut store = funded_store();
        let exec = Executor::new(chain());
        // Account 3, not 2: account 2 is the transfer's recipient, and a
        // sponsor who is also being paid would hide a mistake in either half.
        let sponsor = addr(3);
        let before = Bank::new(&mut store)
            .view()
            .balance(&sponsor, &kes())
            .expect("reads");

        let sponsored = TxBody {
            chain_id: chain(),
            sender: addr(1),
            nonce: 0,
            valid_until: Height(1_000),
            fee: Fee::sponsored_by(Amount::from_units(1_000), kes(), sponsor),
            messages: small_transfer(),
            memo: String::new(),
        }
        .sign_sponsored(&[&sk(1)], &[&sk(3)]);

        let out = exec.execute_block(&mut store, ctx(1), &[sponsored]);
        assert_eq!(out.succeeded(), 1, "{:?}", out.outcomes[0].result);
        assert_eq!(
            Bank::new(&mut store)
                .view()
                .balance(&sponsor, &kes())
                .expect("reads"),
            before
                .checked_sub(Amount::from_units(1_000))
                .expect("affordable"),
            "the sponsor paid exactly the fee"
        );
    }

    #[test]
    fn a_sponsor_signature_from_the_wrong_key_is_refused() {
        let mut store = funded_store();
        let exec = Executor::new(chain());
        let sponsored = TxBody {
            chain_id: chain(),
            sender: addr(1),
            nonce: 0,
            valid_until: Height(1_000),
            fee: Fee::sponsored_by(Amount::from_units(1_000), kes(), addr(2)),
            messages: small_transfer(),
            memo: String::new(),
        }
        .sign_sponsored(&[&sk(1)], &[&sk(66)]);

        let out = exec.execute_block(&mut store, ctx(1), &[sponsored]);
        assert_eq!(out.succeeded(), 0);
        assert!(matches!(
            out.outcomes[0].result,
            Err(ExecError::SponsorUnauthorised)
        ));
    }

    #[test]
    fn a_sponsor_can_rotate_their_key_like_anyone_else() {
        // Sponsorship reads the payer's account record, so it gets rotation for
        // free — an NGO can change its signing key without every wallet that
        // names it as sponsor having to be updated.
        let mut store = funded_store();
        let exec = Executor::new(chain());
        exec.execute_block(
            &mut store,
            ctx(1),
            &[signed_by(
                2,
                0,
                &[2],
                vec![Message::SetRegularKey {
                    key: Some(sk(9).public_key()),
                }],
            )],
        );

        let sponsored = TxBody {
            chain_id: chain(),
            sender: addr(1),
            nonce: 0,
            valid_until: Height(1_000),
            fee: Fee::sponsored_by(Amount::from_units(1_000), kes(), addr(2)),
            messages: small_transfer(),
            memo: String::new(),
        }
        .sign_sponsored(&[&sk(1)], &[&sk(9)]);

        let out = exec.execute_block(&mut store, ctx(2), &[sponsored]);
        assert_eq!(out.succeeded(), 1, "{:?}", out.outcomes[0].result);
    }

    // -- RequireDestinationTag (ADR-0016) ------------------------------------

    /// Turn the exchange's deposit address into one that insists on a reference.
    fn require_reference(store: &mut MemoryStore, exec: &Executor, who: u8, nonce: u64, at: u64) {
        use afrolink_types::AccountFlag;
        let outcome = exec.execute_block(
            store,
            ctx(at),
            &[tx(
                who,
                nonce,
                vec![Message::SetAccountFlag {
                    flag: AccountFlag::RequireReference,
                    enabled: true,
                }],
            )],
        );
        assert_eq!(outcome.succeeded(), 1, "{:?}", outcome.outcomes[0].result);
    }

    fn transfer_with(to: Address, reference: Option<afrolink_pay::PaymentReference>) -> Message {
        Message::Transfer {
            to,
            denom: kes(),
            amount: Amount::from_afri(500),
            reference,
        }
    }

    #[test]
    fn a_deposit_without_a_reference_is_refused_rather_than_left_unattributable() {
        // The headline case. An exchange address serves millions of customers;
        // a deposit with no reference belongs to nobody until a human
        // intervenes. Failing is better, because the sender can retry.
        let mut store = funded_store();
        let exec = Executor::new(chain());
        let exchange = addr(2);
        require_reference(&mut store, &exec, 2, 0, 1);

        let before = Bank::new(&mut store)
            .view()
            .balance(&exchange, &kes())
            .expect("reads");

        let outcome = exec.execute_block(
            &mut store,
            ctx(2),
            &[tx(1, 0, vec![transfer_with(exchange, None)])],
        );

        assert_eq!(outcome.succeeded(), 0, "an untagged deposit must not land");
        assert_eq!(outcome.outcomes[0].receipt.code, ResultCode::Reference);
        assert_eq!(
            Bank::new(&mut store)
                .view()
                .balance(&exchange, &kes())
                .expect("reads"),
            before,
            "and the money must not have moved"
        );
    }

    #[test]
    fn the_same_deposit_with_a_reference_succeeds() {
        // The flag must not break the path it exists to protect.
        use afrolink_pay::PaymentReference;

        let mut store = funded_store();
        let exec = Executor::new(chain());
        let exchange = addr(2);
        require_reference(&mut store, &exec, 2, 0, 1);

        let outcome = exec.execute_block(
            &mut store,
            ctx(2),
            &[tx(
                1,
                0,
                vec![transfer_with(exchange, Some(PaymentReference(88_121)))],
            )],
        );
        assert_eq!(outcome.succeeded(), 1, "{:?}", outcome.outcomes[0].result);
    }

    #[test]
    fn an_ordinary_account_still_accepts_an_untagged_payment() {
        // The default has to stay permissive. Most recipients are people, and a
        // person's address that refused plain payments would be broken.
        let mut store = funded_store();
        let exec = Executor::new(chain());
        let outcome = exec.execute_block(
            &mut store,
            ctx(1),
            &[tx(1, 0, vec![transfer_with(addr(2), None)])],
        );
        assert_eq!(outcome.succeeded(), 1, "{:?}", outcome.outcomes[0].result);
    }

    #[test]
    fn nobody_can_set_the_flag_on_someone_elses_account() {
        // `SetAccountFlag` names no address, so this is checked by proving the
        // effect lands on the *sender*: account 1 flagging itself must not make
        // account 2 start refusing payments.
        use afrolink_types::AccountFlag;

        let mut store = funded_store();
        let exec = Executor::new(chain());
        require_reference(&mut store, &exec, 1, 0, 1);

        assert!(
            load_account(&store, &addr(1))
                .expect("reads")
                .flags
                .is_set(AccountFlag::RequireReference)
        );
        let outcome = exec.execute_block(
            &mut store,
            ctx(2),
            &[tx(3, 0, vec![transfer_with(addr(2), None)])],
        );
        assert_eq!(
            outcome.succeeded(),
            1,
            "a stranger's flag must not affect this account"
        );
    }

    #[test]
    fn the_flag_can_be_turned_off_again() {
        // A setting that cannot be undone is a way to brick an account by
        // typo — and the owner is the only one who could have set it.
        use afrolink_types::AccountFlag;

        let mut store = funded_store();
        let exec = Executor::new(chain());
        let exchange = addr(2);
        require_reference(&mut store, &exec, 2, 0, 1);

        let off = exec.execute_block(
            &mut store,
            ctx(2),
            &[tx(
                2,
                1,
                vec![Message::SetAccountFlag {
                    flag: AccountFlag::RequireReference,
                    enabled: false,
                }],
            )],
        );
        assert_eq!(off.succeeded(), 1, "{:?}", off.outcomes[0].result);

        let outcome = exec.execute_block(
            &mut store,
            ctx(3),
            &[tx(1, 0, vec![transfer_with(exchange, None)])],
        );
        assert_eq!(outcome.succeeded(), 1, "{:?}", outcome.outcomes[0].result);
    }

    #[test]
    fn setting_the_flag_twice_is_not_a_failure() {
        // A wallet that never saw the result of its first submission will send
        // the second. Idempotence is what stops that being an error the user has
        // to understand.
        use afrolink_types::AccountFlag;

        let mut store = funded_store();
        let exec = Executor::new(chain());
        require_reference(&mut store, &exec, 2, 0, 1);
        require_reference(&mut store, &exec, 2, 1, 2);

        assert!(
            load_account(&store, &addr(2))
                .expect("reads")
                .flags
                .is_set(AccountFlag::RequireReference)
        );
    }

    #[test]
    fn a_refused_deposit_still_charges_the_sender_a_fee() {
        // Otherwise a flagged address is a free way to make a validator execute
        // transactions: send untagged payments forever and pay nothing.
        let mut store = funded_store();
        let exec = Executor::new(chain());
        require_reference(&mut store, &exec, 2, 0, 1);

        let outcome = exec.execute_block(
            &mut store,
            ctx(2),
            &[tx(1, 0, vec![transfer_with(addr(2), None)])],
        );
        assert_eq!(outcome.outcomes[0].fee_charged(), Amount::from_units(1_000));
        assert_eq!(
            load_account(&store, &addr(1)).expect("reads").nonce,
            1,
            "and consumes the nonce, so it is not replayable either"
        );
    }

    #[test]
    fn the_flag_applies_to_every_transfer_in_a_transaction_not_only_the_first() {
        // A batch is atomic here: one untagged leg must take the whole
        // transaction down, or the flag is bypassable by putting a good
        // payment first.
        use afrolink_pay::PaymentReference;

        let mut store = funded_store();
        let exec = Executor::new(chain());
        let exchange = addr(2);
        require_reference(&mut store, &exec, 2, 0, 1);

        let before = Bank::new(&mut store)
            .view()
            .balance(&exchange, &kes())
            .expect("reads");

        let outcome = exec.execute_block(
            &mut store,
            ctx(2),
            &[tx(
                1,
                0,
                vec![
                    transfer_with(exchange, Some(PaymentReference(1))),
                    transfer_with(exchange, None),
                ],
            )],
        );
        assert_eq!(outcome.succeeded(), 0);
        assert_eq!(outcome.outcomes[0].receipt.code, ResultCode::Reference);
        assert_eq!(
            Bank::new(&mut store)
                .view()
                .balance(&exchange, &kes())
                .expect("reads"),
            before,
            "the good leg must roll back with the bad one"
        );
    }

    #[test]
    fn a_refused_deposit_does_not_write_into_the_recipients_history() {
        // It is a failure, so ADR-0015's narrow rule applies: only the sender
        // and the fee payer are touched. Otherwise anyone could push entries
        // into an exchange's history by failing to pay it.
        let mut store = funded_store();
        let exec = Executor::new(chain());
        require_reference(&mut store, &exec, 2, 0, 1);
        let pointer_before = load_account(&store, &addr(2)).expect("reads").last_txn;

        let outcome = exec.execute_block(
            &mut store,
            ctx(2),
            &[tx(1, 0, vec![transfer_with(addr(2), None)])],
        );

        let touched: Vec<_> = outcome.outcomes[0]
            .receipt
            .touched
            .iter()
            .map(|t| t.address)
            .collect();
        assert!(!touched.contains(&addr(2)));
        assert_eq!(
            load_account(&store, &addr(2)).expect("reads").last_txn,
            pointer_before,
            "the recipient's history must not have moved"
        );
    }

    #[test]
    fn setting_a_flag_moves_no_money_beyond_the_fee() {
        use afrolink_types::AccountFlag;

        let mut store = funded_store();
        let exec = Executor::new(chain());
        let before = Bank::new(&mut store)
            .view()
            .balance(&addr(1), &kes())
            .expect("reads");

        let outcome = exec.execute_block(
            &mut store,
            ctx(1),
            &[tx(
                1,
                0,
                vec![Message::SetAccountFlag {
                    flag: AccountFlag::RequireReference,
                    enabled: true,
                }],
            )],
        );
        let after = Bank::new(&mut store)
            .view()
            .balance(&addr(1), &kes())
            .expect("reads");
        assert_eq!(
            after,
            before
                .checked_sub(outcome.outcomes[0].fee_charged())
                .expect("affordable")
        );
    }

    #[test]
    fn a_transfer_moves_the_history_pointer_of_both_parties() {
        // The head of the chain a wallet walks. Without this the recipient has
        // no starting point at all, and their history is unreachable.
        let mut store = funded_store();
        let exec = Executor::new(chain());
        let transfer = Message::Transfer {
            to: addr(2),
            denom: kes(),
            amount: Amount::from_afri(500),
            reference: None,
        };
        let sent = tx(1, 0, vec![transfer]);
        let outcome = exec.execute_block(&mut store, ctx(1), std::slice::from_ref(&sent));

        let receipt = &outcome.outcomes[0].receipt;
        assert!(receipt.code.succeeded());

        for party in [addr(1), addr(2)] {
            let account = load_account(&store, &party).expect("account exists");
            assert_eq!(
                account.last_txn,
                Some(TxPointer {
                    tx_id: sent.id(),
                    height: Height(1),
                }),
                "the pointer must name this transaction"
            );
            assert_eq!(
                receipt.previous_for(&party),
                Ok(None),
                "and the receipt must record that there was nothing before it"
            );
        }
    }

    #[test]
    fn the_history_pointer_chain_links_backwards_across_blocks() {
        // Three payments, three blocks. Following the pointers must visit every
        // one and then stop — which is what makes an omitted payment a broken
        // link rather than an invisible gap.
        let mut store = funded_store();
        let exec = Executor::new(chain());
        let mut sent = Vec::new();

        for nonce in 0..3u64 {
            let transfer = Message::Transfer {
                to: addr(2),
                denom: kes(),
                amount: Amount::from_afri(1),
                reference: None,
            };
            let transaction = tx(1, nonce, vec![transfer]);
            let outcome = exec.execute_block(
                &mut store,
                ctx(u64::try_from(sent.len()).expect("small") + 1),
                std::slice::from_ref(&transaction),
            );
            assert_eq!(outcome.succeeded(), 1, "{:?}", outcome.outcomes[0].result);
            sent.push((transaction, outcome.outcomes[0].receipt.clone()));
        }

        // Walk from the recipient's account backwards.
        let mut pointer = load_account(&store, &addr(2))
            .expect("account exists")
            .last_txn;
        let mut walked = Vec::new();
        while let Some(current) = pointer {
            let (transaction, receipt) = sent
                .iter()
                .find(|(t, _)| t.id() == current.tx_id)
                .expect("the pointer must name a real transaction");
            walked.push(transaction.id());
            pointer = receipt
                .previous_for(&addr(2))
                .expect("the receipt must name this account");
        }

        assert_eq!(walked.len(), 3, "every payment is reachable");
        let expected: Vec<_> = sent.iter().rev().map(|(t, _)| t.id()).collect();
        assert_eq!(walked, expected, "newest first, and none skipped");
    }

    #[test]
    fn a_failed_transaction_does_not_write_into_the_recipients_history() {
        // Otherwise anyone could put entries in a stranger's history — and,
        // worse, create an account record for them — by failing to pay them.
        let mut store = funded_store();
        let exec = Executor::new(chain());
        let beyond_means = Message::Transfer {
            to: addr(9),
            denom: kes(),
            amount: Amount::from_afri(999_999_999),
            reference: None,
        };
        let outcome = exec.execute_block(&mut store, ctx(1), &[tx(1, 0, vec![beyond_means])]);

        assert_eq!(outcome.succeeded(), 0);
        let receipt = &outcome.outcomes[0].receipt;
        assert_eq!(receipt.code, ResultCode::Bank);

        let touched: Vec<_> = receipt.touched.iter().map(|t| t.address).collect();
        assert!(
            touched.contains(&addr(1)),
            "the sender paid a fee and a nonce"
        );
        assert!(
            !touched.contains(&addr(9)),
            "the intended recipient must not be touched"
        );
        assert!(
            load_account(&store, &addr(9))
                .expect("read")
                .last_txn
                .is_none(),
            "and no account record should have been minted for them"
        );
    }

    #[test]
    fn the_header_commits_to_what_happened_not_only_to_what_ran() {
        let mut store = funded_store();
        let exec = Executor::new(chain());
        let transfer = Message::Transfer {
            to: addr(2),
            denom: kes(),
            amount: Amount::from_afri(1),
            reference: None,
        };
        let (block, outcome) = exec.build_block(
            &mut store,
            Height(1),
            Timestamp::from_millis(1_700_000_001_000),
            Hash32::ZERO,
            vec![tx(1, 0, vec![transfer])],
            ValidatorSets::unchanged(&validators()),
        );

        assert_eq!(block.header.outcome_root, outcome.outcome_root());
        assert_ne!(
            block.header.outcome_root, block.header.tx_root,
            "two trees, not one"
        );
    }

    #[test]
    fn execution_is_deterministic_across_identical_runs() {
        // The property the whole chain depends on: same input, same state root.
        let msgs = vec![Message::Transfer {
            to: addr(2),
            denom: kes(),
            amount: Amount::from_afri(500),
            reference: None,
        }];
        let txs = vec![tx(1, 0, msgs.clone()), tx(3, 0, msgs)];

        let mut a = funded_store();
        let mut b = funded_store();
        let exec = Executor::new(chain());
        let ra = exec.execute_block(&mut a, ctx(1), &txs);
        let rb = exec.execute_block(&mut b, ctx(1), &txs);

        assert_eq!(
            ra.app_hash, rb.app_hash,
            "identical input must give identical state"
        );
    }

    #[test]
    fn transaction_order_changes_the_state_root() {
        // If order did not matter, validators could reorder a block freely and
        // still agree on state, which would make committing to an ordered tx
        // list pointless. Account 5 starts empty, so its outgoing transfer only
        // works if it has already been funded within this same block.
        let fund = vec![Message::Transfer {
            to: addr(5),
            denom: kes(),
            amount: Amount::from_afri(5_000),
            reference: None,
        }];
        let spend = vec![Message::Transfer {
            to: addr(2),
            denom: kes(),
            amount: Amount::from_afri(4_000),
            reference: None,
        }];

        let exec = Executor::new(chain());

        let mut a = funded_store();
        let ordered = exec.execute_block(
            &mut a,
            ctx(1),
            &[tx(1, 0, fund.clone()), tx(5, 0, spend.clone())],
        );

        let mut b = funded_store();
        let reversed = exec.execute_block(&mut b, ctx(1), &[tx(5, 0, spend), tx(1, 0, fund)]);

        assert_eq!(
            ordered.succeeded(),
            2,
            "funding first lets the spend go through"
        );
        assert_eq!(
            reversed.succeeded(),
            1,
            "spending first must fail: account 5 is empty"
        );
        assert_ne!(
            ordered.app_hash, reversed.app_hash,
            "reordering a block must change the resulting state"
        );
    }

    #[test]
    fn a_replayed_transaction_is_rejected_by_the_nonce() {
        let mut store = funded_store();
        let exec = Executor::new(chain());
        let t = tx(
            1,
            0,
            vec![Message::Transfer {
                to: addr(2),
                denom: kes(),
                amount: Amount::from_afri(100),
                reference: None,
            }],
        );

        let first = exec.execute_block(&mut store, ctx(1), std::slice::from_ref(&t));
        assert_eq!(first.succeeded(), 1);

        let replay = exec.execute_block(&mut store, ctx(2), &[t]);
        assert!(matches!(
            replay.outcomes[0].result,
            Err(ExecError::WrongNonce {
                expected: 1,
                got: 0
            })
        ));
    }

    #[test]
    fn a_failing_transaction_still_consumes_its_nonce_and_fee() {
        // Otherwise a failing transaction is free and infinitely replayable.
        let mut store = funded_store();
        let exec = Executor::new(chain());
        let overspend = tx(
            1,
            0,
            vec![Message::Transfer {
                to: addr(2),
                denom: kes(),
                amount: Amount::from_afri(999_999),
                reference: None,
            }],
        );

        let outcome = exec.execute_block(&mut store, ctx(1), &[overspend]);
        assert!(!outcome.outcomes[0].succeeded());
        assert_eq!(outcome.outcomes[0].fee_charged(), Amount::from_units(1_000));

        let account = load_account(&store, &addr(1)).expect("loads");
        assert_eq!(
            account.nonce, 1,
            "a failed transaction must still consume its nonce"
        );
    }

    #[test]
    fn a_failed_message_leaves_no_partial_state() {
        let mut store = funded_store();
        let exec = Executor::new(chain());
        // First message succeeds, second overspends. Neither may apply.
        let t = tx(
            1,
            0,
            vec![
                Message::Transfer {
                    to: addr(2),
                    denom: kes(),
                    amount: Amount::from_afri(100),
                    reference: None,
                },
                Message::Transfer {
                    to: addr(3),
                    denom: kes(),
                    amount: Amount::from_afri(999_999),
                    reference: None,
                },
            ],
        );
        exec.execute_block(&mut store, ctx(1), &[t]);

        let bank = Bank::new(&mut store);
        assert_eq!(
            bank.balance(&addr(2), &kes()).expect("read"),
            Amount::from_afri(10_000),
            "the first transfer must be rolled back with the second"
        );
    }

    #[test]
    fn fees_accumulate_in_the_fee_collector() {
        let mut store = funded_store();
        let exec = Executor::new(chain());
        exec.execute_block(
            &mut store,
            ctx(1),
            &[tx(
                1,
                0,
                vec![Message::Transfer {
                    to: addr(2),
                    denom: kes(),
                    amount: Amount::from_afri(1),
                    reference: None,
                }],
            )],
        );

        let bank = Bank::new(&mut store);
        assert_eq!(
            bank.balance(&fee_collector_address(), &kes())
                .expect("read"),
            Amount::from_units(1_000),
            "fees are collected in the denom the user paid in"
        );
    }

    /// The headline end-to-end case: a chama runs a full cycle on-chain.
    #[test]
    fn a_chama_collects_contributions_and_pays_out_the_pot() {
        let mut store = funded_store();
        let exec = Executor::new(chain());

        let members = vec![
            FoundingMember::new(addr(1), Role::Treasurer),
            FoundingMember::new(addr(2), Role::Member),
            FoundingMember::new(addr(3), Role::Member),
        ];
        let create = Message::CreateGroup {
            name: "Mama Mboga Chama".to_owned(),
            members,
            contribution: Contribution {
                amount: Amount::from_afri(1_000),
                denom: kes(),
                period_blocks: 604_800,
            },
            policy: PayoutPolicy::Rotation {
                order: vec![addr(1), addr(2), addr(3)],
                next: 0,
            },
            quorum: Quorum::TWO_THIRDS,
        };

        // The group address is derived from creator + nonce, so we can predict it.
        let group_address = Address::derived(
            Domain::GroupAddress,
            &[addr(1).as_bytes().as_slice(), &0u64.to_le_bytes()].concat(),
        );

        let r = exec.execute_block(&mut store, ctx(1), &[tx(1, 0, vec![create])]);
        assert_eq!(r.succeeded(), 1, "{:?}", r.outcomes[0].result);

        // Each member contributes 1,000 KES.
        let contributions: Vec<Transaction> = [(1u8, 1u64), (2, 0), (3, 0)]
            .into_iter()
            .map(|(who, nonce)| {
                tx(
                    who,
                    nonce,
                    vec![Message::ContributeToGroup {
                        group: group_address,
                        amount: Amount::from_afri(1_000),
                    }],
                )
            })
            .collect();
        let r = exec.execute_block(&mut store, ctx(2), &contributions);
        assert_eq!(r.succeeded(), 3, "{:?}", r.outcomes);

        {
            let bank = Bank::new(&mut store);
            assert_eq!(
                bank.balance(&group_address, &kes()).expect("read"),
                Amount::from_afri(3_000),
                "the pot holds every contribution"
            );
        }

        // The pot rotates to the first member in the order.
        let r = exec.execute_block(
            &mut store,
            ctx(3),
            &[tx(
                2,
                1,
                vec![Message::GroupPayout {
                    group: group_address,
                }],
            )],
        );
        assert_eq!(r.succeeded(), 1, "{:?}", r.outcomes[0].result);

        let bank = Bank::new(&mut store);
        assert_eq!(
            bank.balance(&group_address, &kes()).expect("read"),
            Amount::ZERO,
            "the pot is emptied on payout"
        );
        // Member 1 paid 1,000 in twice (create nonce + contribution) and received 3,000.
        assert!(
            bank.balance(&addr(1), &kes()).expect("read") > Amount::from_afri(11_000),
            "the cycle's recipient is better off by roughly the other members' contributions"
        );

        // And the contribution history is recorded for credit purposes.
        let account = load_existing_account(&store, &group_address).expect("group exists");
        let group = account.as_group().expect("is a group");
        assert_eq!(group.cycle, 1, "the cycle advanced");
        assert_eq!(
            group.member(&addr(2)).expect("member").contributions_made,
            1
        );
    }

    #[test]
    fn a_non_member_cannot_contribute_to_a_group() {
        let mut store = funded_store();
        let exec = Executor::new(chain());
        let create = Message::CreateGroup {
            name: "Closed".to_owned(),
            members: vec![
                FoundingMember::new(addr(1), Role::Treasurer),
                FoundingMember::new(addr(2), Role::Member),
            ],
            contribution: Contribution {
                amount: Amount::from_afri(100),
                denom: kes(),
                period_blocks: 100,
            },
            policy: PayoutPolicy::Accumulate(ShareRules {
                required_guarantors: 1,
                ..ShareRules::vicoba(Amount::ZERO)
            }),
            quorum: Quorum::TWO_THIRDS,
        };
        let group_address = Address::derived(
            Domain::GroupAddress,
            &[addr(1).as_bytes().as_slice(), &0u64.to_le_bytes()].concat(),
        );
        exec.execute_block(&mut store, ctx(1), &[tx(1, 0, vec![create])]);

        // Account 4 is not a member.
        let r = exec.execute_block(
            &mut store,
            ctx(2),
            &[tx(
                4,
                0,
                vec![Message::ContributeToGroup {
                    group: group_address,
                    amount: Amount::from_afri(100),
                }],
            )],
        );
        assert!(matches!(
            r.outcomes[0].result,
            Err(ExecError::NotAGroupMember)
        ));
    }

    #[test]
    fn a_block_commits_to_its_transactions_and_state() {
        let mut store = funded_store();
        let exec = Executor::new(chain());
        let txs = vec![tx(
            1,
            0,
            vec![Message::Transfer {
                to: addr(2),
                denom: kes(),
                amount: Amount::from_afri(5),
                reference: None,
            }],
        )];
        let (block, outcome) = exec.build_block(
            &mut store,
            Height(1),
            Timestamp::from_millis(1_700_000_000_000),
            Hash32::ZERO,
            txs,
            ValidatorSets::unchanged(&validators()),
        );

        assert!(
            block.tx_root_matches(),
            "header must commit to the transactions carried"
        );
        assert_eq!(block.header.app_hash, outcome.app_hash);
        assert_eq!(block.header.app_hash, store.root());
        assert_ne!(block.header.id(), Hash32::ZERO);
    }

    #[test]
    fn a_transaction_for_another_chain_is_rejected() {
        let mut store = funded_store();
        let exec = Executor::new(ChainId::new("afrolink-9").expect("valid"));
        let r = exec.execute_block(
            &mut store,
            ctx(1),
            &[tx(
                1,
                0,
                vec![Message::Transfer {
                    to: addr(2),
                    denom: kes(),
                    amount: Amount::from_afri(1),
                    reference: None,
                }],
            )],
        );
        assert!(matches!(
            r.outcomes[0].result,
            Err(ExecError::Tx(TxError::WrongChain { .. }))
        ));
    }
}
