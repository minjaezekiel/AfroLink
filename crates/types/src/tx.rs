//! Transactions, messages and signing.
//!
//! # Replay protection
//!
//! The signed bytes commit to `(chain_id, nonce, valid_until, fee, messages,
//! memo)`. Each element closes a specific attack:
//!
//! * **`chain_id`** — a transaction signed on testnet cannot be replayed on
//!   mainnet, and vice versa.
//! * **`nonce`** — the same transfer cannot be submitted twice.
//! * **`valid_until`** — a transaction that never gets included expires instead
//!   of sitting in a mempool indefinitely, waiting for a moment when it is
//!   suddenly harmful.
//!
//! The whole document is hashed under [`Domain::TxSignDoc`], so a transaction
//! signature can never be presented as a consensus vote.
//!
//! # Authentication is not authorisation
//!
//! [`Transaction::verify_stateless`] establishes that every signature is
//! genuine. It does **not** establish that the signers may act for the sender —
//! that question is [`Account::authorises`](crate::Account::authorises), and it
//! is answered against the account record because it is exactly what key
//! rotation changes
//! ([ADR-0017](../../../docs/adr/0017-key-rotation-and-signer-lists.md)).
//!
//! Anything that accepts a transaction must ask both. There are two such places:
//! the executor, where it decides correctness, and the mempool, where it decides
//! whether a node will hold and gossip something on a stranger's behalf.

use afrolink_alias::{ContactCommitment, Username};
use afrolink_consensus::{CountryCode, Equivocation};
use afrolink_crypto::hash::{Domain, Hash32, hash};
use afrolink_crypto::{Address, CryptoError, PublicKey, SecretKey, Signature};
use afrolink_pay::PaymentReference;
use afrolink_primitives::codec::{CodecError, Decode, Encode, Reader, decode_exact};
use afrolink_primitives::{Amount, ChainId, Denom, Height};
use thiserror::Error;

use crate::account::{AccountFlag, MAX_SIGNERS, SignerList};
use crate::group::{Contribution, FoundingMember, PayoutPolicy, Quorum};

/// Maximum bytes in a transaction memo.
pub const MAX_MEMO_LEN: usize = 256;
/// Maximum messages in one transaction.
pub const MAX_MESSAGES: usize = 64;
/// Maximum signatures on one transaction.
///
/// Matches [`MAX_SIGNERS`], which is the most a signer list can require. Every
/// signature is verified before anything else happens, so this is a bound on the
/// elliptic-curve work one message can buy from a validator.
pub const MAX_SIGNATURES: usize = MAX_SIGNERS;

/// Why a transaction was rejected.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum TxError {
    /// A signature did not verify against the key that presented it.
    #[error("invalid signature")]
    InvalidSignature,
    /// No signatures at all, or more than [`MAX_SIGNATURES`].
    #[error("a transaction must carry 1..={MAX_SIGNATURES} signatures, got {0}")]
    SignatureCount(usize),
    /// Signatures out of order, or one key signing twice.
    ///
    /// Refused rather than sorted: the transaction's id is a hash of its
    /// encoding, so a second ordering would be a second id for one signed
    /// transaction — and deduplication by id is what stops a replay.
    #[error("signatures must be sorted by public key and unique")]
    UnsortedSignatures,
    /// Sponsor signatures present without a sponsor, or missing with one.
    #[error("sponsor signatures must be present exactly when a fee payer is named")]
    SponsorSignatureMismatch,
    /// A fee payer that is the sender.
    ///
    /// A redundant spelling of an ordinary fee. Two spellings of one meaning is
    /// the thing the codec refuses everywhere else, and here it would also
    /// demand a pointless second signature from the sender.
    #[error("the fee payer must not be the sender; leave it unset instead")]
    SelfSponsored,
    /// The transaction was signed for a different network.
    #[error("wrong chain id: signed for {signed}, this chain is {expected}")]
    WrongChain {
        /// Chain the transaction was signed for.
        signed: String,
        /// Chain evaluating it.
        expected: String,
    },
    /// The transaction expired before inclusion.
    #[error("transaction expired at height {valid_until}, current height is {current}")]
    Expired {
        /// Last height at which it was valid.
        valid_until: u64,
        /// Current chain height.
        current: u64,
    },
    /// The transaction carried no messages, or too many.
    #[error("transaction must carry 1..={MAX_MESSAGES} messages, got {0}")]
    MessageCount(usize),
    /// The memo exceeded [`MAX_MEMO_LEN`].
    #[error("memo exceeds {MAX_MEMO_LEN} bytes")]
    MemoTooLong,
    /// A transfer of zero.
    #[error("transfer amount must be greater than zero")]
    ZeroAmount,
    /// A transaction offering no fee at all.
    ///
    /// The fee is the only cost of making every validator on the network
    /// execute a transaction, and the only punishment a *failed* one carries.
    /// At zero, failure is free and one account can make the whole network
    /// re-execute for as long as it likes.
    #[error("a transaction must offer a fee greater than zero")]
    ZeroFee,
    /// Underlying crypto failure.
    #[error(transparent)]
    Crypto(#[from] CryptoError),
}

/// How the fee is paid.
///
/// **This is the fee-abstraction primitive** (see architecture §4.1). Two
/// properties make it different from a conventional chain's fee field:
///
/// * `denom` need not be AFRI. Any governance-whitelisted stablecoin works, so a
///   user sending money home never has to acquire the network's token first.
/// * `payer` may be someone other than the sender — a merchant, an employer or
///   an NGO sponsoring its users' fees.
///
/// Together they mean a person can hold nothing but their local currency, and
/// still transact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fee {
    /// Amount offered.
    pub amount: Amount,
    /// Denomination offered — need not be the native coin.
    pub denom: Denom,
    /// Who pays. `None` means the transaction's sender.
    pub payer: Option<Address>,
}

impl Fee {
    /// A fee paid by the sender in the given denomination.
    #[must_use]
    pub fn new(amount: Amount, denom: Denom) -> Self {
        Self {
            amount,
            denom,
            payer: None,
        }
    }

    /// A fee sponsored by a third party.
    #[must_use]
    pub fn sponsored_by(amount: Amount, denom: Denom, payer: Address) -> Self {
        Self {
            amount,
            denom,
            payer: Some(payer),
        }
    }

    /// The account actually charged, given the transaction's sender.
    #[must_use]
    pub fn payer_or(&self, sender: Address) -> Address {
        self.payer.unwrap_or(sender)
    }

    /// Whether a third party is covering this fee.
    #[must_use]
    pub fn is_sponsored(&self) -> bool {
        self.payer.is_some()
    }
}

/// An instruction within a transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Message {
    /// Move tokens between accounts.
    Transfer {
        /// Recipient.
        to: Address,
        /// Asset moved.
        denom: Denom,
        /// Quantity moved.
        amount: Amount,
        /// The recipient's own reconciliation reference, if they asked for one.
        ///
        /// XRPL's destination tag, and it earns its place as a field rather
        /// than a convention inside `memo`: one exchange address serves
        /// millions of customers, and a deposit with no machine-readable tag
        /// belongs to nobody until a human intervenes. Free text gets
        /// truncated, auto-corrected and pasted with a trailing space; a `u64`
        /// does not.
        ///
        /// The protocol never reads its **value** — it does not route on it,
        /// index it, or give it meaning. It is data for the recipient's systems.
        /// The one question consensus asks is whether a reference is *present*,
        /// and only when the recipient has set
        /// [`AccountFlag::RequireReference`] on their own record
        /// ([ADR-0016](../../../docs/adr/0016-required-payment-references.md)).
        reference: Option<PaymentReference>,
    },
    /// Form a savings group (chama, susu, stokvel, tontine, equb, VSLA).
    CreateGroup {
        /// The group's name.
        name: String,
        /// Founding members and their roles.
        members: Vec<FoundingMember>,
        /// Recurring obligation.
        contribution: Contribution,
        /// Rotation or accumulation.
        policy: PayoutPolicy,
        /// Approval share for extraordinary withdrawals.
        quorum: Quorum,
    },
    /// Pay this cycle's contribution into a group.
    ContributeToGroup {
        /// The group account.
        group: Address,
        /// Amount paid in.
        amount: Amount,
    },
    /// Release the pot to the cycle's recipient and advance the rotation.
    GroupPayout {
        /// The group account.
        group: Address,
    },

    // -- Human-readable addressing (ADR-0008) --------------------------------
    //
    // Note what is *not* here: no message accepts an alias as a payment
    // destination. `Transfer` takes an `Address` and always will. A wallet
    // resolves a name to an address, shows the user who they are about to pay,
    // and signs the address — so a rebinding that lands between signing and
    // inclusion cannot redirect the money.
    /// Claim an unregistered username.
    RegisterName {
        /// The name to claim.
        name: Username,
    },
    /// Extend a registration the sender owns.
    RenewName {
        /// The name to renew.
        name: Username,
    },
    /// Hand a username to another account.
    TransferName {
        /// The name to hand over.
        name: Username,
        /// The new owner.
        to: Address,
    },
    /// Choose which owned name wallets display for the sender's address.
    ///
    /// Opt-in disclosure: it lets anyone seeing the address discover the handle,
    /// and so link that address's whole history to one name. A merchant wants
    /// that; a person often does not.
    SetPrimaryAlias {
        /// The name to display.
        name: Username,
    },
    /// Stop publishing a display name for the sender's address.
    ///
    /// The counterpart to [`Self::SetPrimaryAlias`]. A disclosure that cannot be
    /// withdrawn is not a choice, so this takes no arguments and cannot fail.
    ClearPrimaryAlias,
    /// Give up a name entirely, freeing it and its skeleton.
    ReleaseName {
        /// The name to release.
        name: Username,
    },
    /// Bind a phone number or email to an account. Sender must be a licensed
    /// attestor.
    AttestContact {
        /// Commitment to the identifier — never the identifier itself.
        commitment: ContactCommitment,
        /// The account it resolves to.
        address: Address,
    },
    /// Ask to point a contact at a different account, subject to the delay.
    RequestRebind {
        /// The contact to move.
        commitment: ContactCommitment,
        /// Where it should point once the delay elapses.
        new_address: Address,
    },
    /// Cancel a pending rebinding. **Only the currently bound account may.**
    ///
    /// This is the SIM-swap defence expressed as a message: possession of the
    /// number is not possession of the account.
    VetoRebind {
        /// The contact whose rebinding should be cancelled.
        commitment: ContactCommitment,
    },
    /// Push a rebinding whose delay has elapsed into effect.
    ///
    /// **Permissionless on purpose.** The protection is the delay and the
    /// veto, both of which have already run their course by the time this can
    /// succeed; whoever pays the fee to finish the job changes nothing about
    /// the outcome. Requiring the *new* owner to send it would defeat the point,
    /// since the case this exists for is a user who has lost the key that
    /// account is being moved away from.
    ///
    /// Without it a matured rebinding sits pending forever and genuine recovery
    /// never completes.
    ApplyRebind {
        /// The contact whose pending rebinding should take effect.
        commitment: ContactCommitment,
    },
    /// Remove a contact binding, by the account it points at.
    RevokeContact {
        /// The contact to unbind.
        commitment: ContactCommitment,
    },

    // -- Account settings ----------------------------------------------------
    /// Turn one flag on the sender's own account record on or off.
    ///
    /// **One flag per message, named explicitly**, rather than assigning a whole
    /// flags word. XRPL takes the same shape (`SetFlag`/`ClearFlag`) and the
    /// reason is upgrades: a wallet built before a flag existed, submitting an
    /// absolute assignment, would silently clear the flag it has never heard of.
    /// Naming one flag means a message can only ever change what it names.
    SetAccountFlag {
        /// Which switch.
        flag: AccountFlag,
        /// On or off. Idempotent: setting a flag that is already set succeeds
        /// and changes nothing, so a wallet may safely retry a submission whose
        /// result it never saw.
        enabled: bool,
    },

    /// Replace, or clear, the sender's rotatable signing key.
    ///
    /// `None` clears it. Clearing is refused if it would leave nobody able to
    /// sign — the lock-out invariant is checked once, after the change, rather
    /// than as a special case here.
    SetRegularKey {
        /// The new day-to-day key, or `None` to go back to the master key
        /// alone.
        key: Option<PublicKey>,
    },
    /// Replace, or clear, the sender's signer list.
    ///
    /// The social-recovery primitive: an M-of-N arrangement of family, an agent
    /// and an attestor, expressed in the protocol rather than in a contract.
    SetSignerList {
        /// The new arrangement, or `None` to remove it.
        list: Option<SignerList>,
    },

    /// Lock AFRI and register as a validator candidate.
    Bond {
        /// The consensus key this operator will sign blocks with.
        ///
        /// Deliberately not the sender's key: the consensus key lives on a
        /// machine that is online continuously, and the account holding the
        /// money should not have to be.
        public_key: PublicKey,
        /// Where the operator is, for the concentration limits in ADR-0007.
        country: CountryCode,
        /// How much to lock.
        amount: Amount,
    },
    /// Add to an existing bond.
    AddStake {
        /// How much more to lock.
        amount: Amount,
    },
    /// Begin withdrawing stake.
    ///
    /// The stake leaves the active set at once and stays slashable for the
    /// unbonding period — see `crates/staking`.
    Unbond {
        /// How much to queue for withdrawal.
        amount: Amount,
    },
    /// Collect every unbonding entry whose period has elapsed.
    WithdrawUnbonded,
    /// Submit proof that a validator signed two conflicting votes.
    ///
    /// Permissionless on purpose: anyone who observes the two signatures can
    /// report them. The evidence proves itself, so there is nothing to gain by
    /// lying and no privileged reporter to capture.
    ///
    /// Boxed because two signed votes are far larger than any other message,
    /// and an enum is as big as its largest variant.
    ReportEquivocation {
        /// The two conflicting votes.
        evidence: Box<Equivocation>,
    },
}

/// The signed portion of a transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxBody {
    /// Network this transaction is valid on.
    pub chain_id: ChainId,
    /// Account submitting it.
    pub sender: Address,
    /// Sender's next sequence number.
    pub nonce: u64,
    /// Last block height at which this may be included.
    pub valid_until: Height,
    /// Offered fee.
    pub fee: Fee,
    /// Instructions to execute, in order.
    pub messages: Vec<Message>,
    /// Free-form note.
    pub memo: String,
}

impl TxBody {
    /// The bytes a signature commits to.
    #[must_use]
    pub fn sign_doc(&self) -> Vec<u8> {
        self.to_bytes()
    }

    /// Sign this body with one key — the ordinary case.
    #[must_use]
    pub fn sign(self, key: &SecretKey) -> Transaction {
        self.sign_with(std::slice::from_ref(&key))
    }

    /// Sign this body as sender, with a sponsor co-signing for the fee.
    ///
    /// Both authorities are needed because the fee comes out of the sponsor's
    /// balance. Without the sponsor's signature, naming someone as fee payer
    /// would be a way to spend their money.
    #[must_use]
    pub fn sign_sponsored(self, sender: &[&SecretKey], sponsor: &[&SecretKey]) -> Transaction {
        let doc = self.sign_doc();
        let sponsor_signatures = canonical_signatures(&doc, sponsor);
        let mut transaction = self.sign_with(sender);
        transaction.sponsor_signatures = sponsor_signatures;
        transaction
    }

    /// Sign this body with several keys, for an account with a signer list.
    ///
    /// The result is sorted and de-duplicated, so the same set of signers always
    /// produces the same transaction id however the caller ordered them.
    ///
    /// # Panics
    /// Never for a non-empty `keys`; an empty slice produces a transaction that
    /// [`Transaction::verify_stateless`] will refuse.
    #[must_use]
    pub fn sign_with(self, keys: &[&SecretKey]) -> Transaction {
        let signatures = canonical_signatures(&self.sign_doc(), keys);
        Transaction {
            body: self,
            signatures,
            sponsor_signatures: Vec::new(),
        }
    }

    /// Structural checks that need no chain state.
    ///
    /// # Errors
    /// Returns the first [`TxError`] encountered.
    pub fn validate_basic(&self) -> Result<(), TxError> {
        if self.messages.is_empty() || self.messages.len() > MAX_MESSAGES {
            return Err(TxError::MessageCount(self.messages.len()));
        }
        if self.memo.len() > MAX_MEMO_LEN {
            return Err(TxError::MemoTooLong);
        }
        if self.fee.payer == Some(self.sender) {
            return Err(TxError::SelfSponsored);
        }
        if self.fee.amount.is_zero() {
            return Err(TxError::ZeroFee);
        }
        for msg in &self.messages {
            match msg {
                Message::Transfer { amount, .. }
                | Message::ContributeToGroup { amount, .. }
                | Message::Bond { amount, .. }
                | Message::AddStake { amount }
                | Message::Unbond { amount } => {
                    if amount.is_zero() {
                        return Err(TxError::ZeroAmount);
                    }
                }
                // These move no value, or carry evidence that proves itself,
                // so there is nothing here to check beyond what their own types
                // already enforce on decode.
                Message::WithdrawUnbonded
                | Message::ReportEquivocation { .. }
                | Message::CreateGroup { .. }
                | Message::GroupPayout { .. }
                | Message::RegisterName { .. }
                | Message::RenewName { .. }
                | Message::TransferName { .. }
                | Message::SetPrimaryAlias { .. }
                | Message::AttestContact { .. }
                | Message::RequestRebind { .. }
                | Message::VetoRebind { .. }
                | Message::RevokeContact { .. }
                | Message::ClearPrimaryAlias
                | Message::SetAccountFlag { .. }
                | Message::SetRegularKey { .. }
                | Message::SetSignerList { .. }
                | Message::ApplyRebind { .. }
                | Message::ReleaseName { .. } => {}
            }
        }
        Ok(())
    }
}

/// One key's signature over a transaction body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxSignature {
    /// The key that signed.
    pub public_key: PublicKey,
    /// Signature over [`TxBody::sign_doc`] in [`Domain::TxSignDoc`].
    pub signature: Signature,
}

/// Sign `doc` with every key, in the one order the wire format accepts.
///
/// Sorted and de-duplicated here so a caller cannot produce a non-canonical
/// transaction by accident, and so one signer cannot reach a quorum by
/// repeating itself.
fn canonical_signatures(doc: &[u8], keys: &[&SecretKey]) -> Vec<TxSignature> {
    let mut signatures: Vec<TxSignature> = keys
        .iter()
        .map(|key| TxSignature {
            public_key: key.public_key(),
            signature: key.sign(Domain::TxSignDoc, doc),
        })
        .collect();
    signatures.sort_by_key(|s| s.public_key.to_bytes());
    signatures.dedup_by(|a, b| a.public_key == b.public_key);
    signatures
}

/// A signed transaction.
///
/// # Why a list
///
/// One key was enough while an account had exactly one. It no longer does: an
/// account may carry a signer list, and an M-of-N arrangement needs M
/// signatures ([ADR-0017](../../../docs/adr/0017-key-rotation-and-signer-lists.md)).
/// The ordinary single-signature case is simply a list of one, so nothing about
/// a plain payment changes except where the signature is read from.
///
/// # Canonical form
///
/// Non-empty, sorted by public key, and free of repeats. All three are checked
/// on decode and none is repaired, because the transaction's *id* is a hash of
/// this encoding: a second spelling of one signed transaction would be a second
/// id for it, and deduplication by id is what stops a replay.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transaction {
    /// The signed body.
    pub body: TxBody,
    /// The **sender's** authority. Sorted by public key, unique, at least one.
    pub signatures: Vec<TxSignature>,
    /// The **fee payer's** authority, when a third party is sponsoring.
    ///
    /// Empty exactly when [`Fee::payer`] is `None`. A separate list rather than
    /// more entries in `signatures`, because they answer different questions:
    /// one set must satisfy the sender's account, the other the sponsor's. A
    /// single list would force the verifier to search for a partition, and would
    /// let a key recognised by one account be counted toward the other.
    pub sponsor_signatures: Vec<TxSignature>,
}

impl Transaction {
    /// The transaction's identifier: a hash of its complete encoding.
    #[must_use]
    pub fn id(&self) -> Hash32 {
        hash(Domain::TxId, &self.to_bytes())
    }

    /// Every address a node should file this transaction under.
    ///
    /// This is the input to a node's history index — the thing that turns
    /// *"prove my balance"* into *"show me my payments"*. It is deliberately
    /// **not** consensus state: an index is a node's private convenience, and
    /// nothing in the protocol depends on two nodes agreeing about it.
    ///
    /// # Why the match is exhaustive
    ///
    /// A new [`Message`] variant that moves value must not silently become
    /// invisible to the recipient's wallet. Writing this as an exhaustive match
    /// rather than a set of `if let`s means adding a variant fails to compile
    /// until someone decides who should see it.
    ///
    /// The sender is always included: they need their own history whether or not
    /// a message names anyone else.
    ///
    /// Duplicates are removed, and the order is deterministic, so two nodes
    /// building the same index write the same keys.
    #[must_use]
    pub fn touched_addresses(&self) -> Vec<Address> {
        let mut out = vec![self.body.sender];

        for message in &self.body.messages {
            match message {
                // Value moving to someone else — the case this index exists for.
                Message::Transfer { to, .. } => out.push(*to),
                Message::ContributeToGroup { group, .. } | Message::GroupPayout { group } => {
                    out.push(*group);
                }
                // A member should see the group they were enrolled in, even
                // though they did not send the transaction that did it.
                Message::CreateGroup { members, .. } => {
                    out.extend(members.iter().map(|m| m.address));
                }
                Message::TransferName { to, .. } => out.push(*to),
                Message::AttestContact { address, .. } => out.push(*address),
                Message::RequestRebind { new_address, .. } => out.push(*new_address),
                // The account gaining the binding should see the transaction
                // that gave it to them, even though a stranger may have sent it.
                Message::ApplyRebind { .. } => {}
                // The offender belongs in the index: a slashing is the single
                // most important thing that can happen to a validator's account,
                // and they did not send the report.
                Message::ReportEquivocation { evidence } => out.push(evidence.validator),

                // Sender-only. Named individually rather than caught by a
                // wildcard, so a future variant does not join them by accident.
                Message::RegisterName { .. }
                | Message::RenewName { .. }
                | Message::SetPrimaryAlias { .. }
                | Message::ClearPrimaryAlias
                | Message::ReleaseName { .. }
                | Message::VetoRebind { .. }
                | Message::RevokeContact { .. }
                | Message::SetAccountFlag { .. }
                | Message::SetRegularKey { .. }
                | Message::SetSignerList { .. }
                | Message::Bond { .. }
                | Message::AddStake { .. }
                | Message::Unbond { .. }
                | Message::WithdrawUnbonded => {}
            }
        }

        out.sort_unstable();
        out.dedup();
        out
    }

    /// The keys that produced valid signatures over this body.
    ///
    /// Only meaningful after [`Self::verify_stateless`] has succeeded; before
    /// that, a signature may not check out. Feed the result to
    /// [`Account::authorises`](crate::Account::authorises), which decides
    /// whether those keys are entitled to act for the sender.
    #[must_use]
    pub fn signing_keys(&self) -> Vec<PublicKey> {
        self.signatures.iter().map(|s| s.public_key).collect()
    }

    /// The keys the **fee payer** presented, when a third party is sponsoring.
    ///
    /// Empty for an ordinary transaction. Check these against the payer's
    /// account, never against the sender's: the fee comes out of the payer's
    /// balance, so naming someone as payer without their consent would be a way
    /// to spend their money.
    #[must_use]
    pub fn sponsor_keys(&self) -> Vec<PublicKey> {
        self.sponsor_signatures
            .iter()
            .map(|s| s.public_key)
            .collect()
    }

    /// Everything that can be checked without reading chain state.
    ///
    /// Structure, chain binding, expiry, signature canonicality, and that
    /// **every** signature verifies against the body.
    ///
    /// # What this deliberately no longer checks
    ///
    /// It used to also require that the signing key derive the sender's address.
    /// That check has moved to [`Account::authorises`](crate::Account::authorises)
    /// and become stateful, because it is exactly what key rotation changes: a
    /// regular key does not derive the address, and a signer list holds keys
    /// that never could.
    ///
    /// **A caller that stops here has authenticated a signature and authorised
    /// nothing.** The method is named for that, and it returns no evidence a
    /// caller could mistake for permission — the keys come from
    /// [`Self::signing_keys`], which says what it is.
    ///
    /// # Errors
    /// Returns the first [`TxError`] encountered.
    pub fn verify_stateless(
        &self,
        chain_id: &ChainId,
        current_height: Height,
    ) -> Result<(), TxError> {
        self.body.validate_basic()?;

        if &self.body.chain_id != chain_id {
            return Err(TxError::WrongChain {
                signed: self.body.chain_id.to_string(),
                expected: chain_id.to_string(),
            });
        }

        if current_height > self.body.valid_until {
            return Err(TxError::Expired {
                valid_until: self.body.valid_until.0,
                current: current_height.0,
            });
        }

        self.check_signatures()
    }

    /// Signature count, ordering and validity, for both authorities.
    fn check_signatures(&self) -> Result<(), TxError> {
        if self.signatures.is_empty() || self.signatures.len() > MAX_SIGNATURES {
            return Err(TxError::SignatureCount(self.signatures.len()));
        }
        if self.sponsor_signatures.len() > MAX_SIGNATURES {
            return Err(TxError::SignatureCount(self.sponsor_signatures.len()));
        }
        // Empty exactly when there is no sponsor. Both halves matter: a
        // sponsored fee with no sponsor signature would spend a stranger's
        // money, and sponsor signatures on an unsponsored fee are bytes that
        // change the transaction's id while authorising nothing.
        if self.body.fee.is_sponsored() == self.sponsor_signatures.is_empty() {
            return Err(TxError::SponsorSignatureMismatch);
        }

        let doc = self.body.sign_doc();
        for list in [&self.signatures, &self.sponsor_signatures] {
            if !list.windows(2).all(|w| {
                w.first().map(|s| s.public_key.to_bytes())
                    < w.get(1).map(|s| s.public_key.to_bytes())
            }) {
                return Err(TxError::UnsortedSignatures);
            }
            for entry in list {
                entry
                    .public_key
                    .verify(Domain::TxSignDoc, &doc, &entry.signature)
                    .map_err(|_| TxError::InvalidSignature)?;
            }
        }
        Ok(())
    }

    /// Decode a transaction from untrusted bytes.
    ///
    /// # Errors
    /// Returns a [`CodecError`] if the bytes are malformed or carry trailing data.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CodecError> {
        decode_exact::<Self>(bytes)
    }
}

// ---------------------------------------------------------------------------
// Canonical encoding
// ---------------------------------------------------------------------------

impl Encode for Fee {
    fn encode(&self, out: &mut Vec<u8>) {
        self.amount.encode(out);
        self.denom.encode(out);
        self.payer.encode(out);
    }
}

impl Decode for Fee {
    fn decode(r: &mut Reader<'_>) -> Result<Self, CodecError> {
        Ok(Self {
            amount: Amount::decode(r)?,
            denom: Denom::decode(r)?,
            payer: Option::<Address>::decode(r)?,
        })
    }
}

impl Encode for Message {
    fn encode(&self, out: &mut Vec<u8>) {
        match self {
            Self::Transfer {
                to,
                denom,
                amount,
                reference,
            } => {
                out.push(0);
                to.encode(out);
                denom.encode(out);
                amount.encode(out);
                reference.encode(out);
            }
            Self::CreateGroup {
                name,
                members,
                contribution,
                policy,
                quorum,
            } => {
                out.push(1);
                name.encode(out);
                members.encode(out);
                contribution.encode(out);
                policy.encode(out);
                quorum.encode(out);
            }
            Self::ContributeToGroup { group, amount } => {
                out.push(2);
                group.encode(out);
                amount.encode(out);
            }
            Self::GroupPayout { group } => {
                out.push(3);
                group.encode(out);
            }
            Self::RegisterName { name } => {
                out.push(4);
                name.encode(out);
            }
            Self::RenewName { name } => {
                out.push(5);
                name.encode(out);
            }
            Self::TransferName { name, to } => {
                out.push(6);
                name.encode(out);
                to.encode(out);
            }
            Self::SetPrimaryAlias { name } => {
                out.push(7);
                name.encode(out);
            }
            Self::AttestContact {
                commitment,
                address,
            } => {
                out.push(8);
                commitment.encode(out);
                address.encode(out);
            }
            Self::RequestRebind {
                commitment,
                new_address,
            } => {
                out.push(9);
                commitment.encode(out);
                new_address.encode(out);
            }
            Self::VetoRebind { commitment } => {
                out.push(10);
                commitment.encode(out);
            }
            Self::RevokeContact { commitment } => {
                out.push(11);
                commitment.encode(out);
            }
            Self::ClearPrimaryAlias => out.push(12),
            Self::ReleaseName { name } => {
                out.push(13);
                name.encode(out);
            }
            Self::Bond {
                public_key,
                country,
                amount,
            } => {
                out.push(14);
                public_key.encode(out);
                country.encode(out);
                amount.encode(out);
            }
            Self::AddStake { amount } => {
                out.push(15);
                amount.encode(out);
            }
            Self::Unbond { amount } => {
                out.push(16);
                amount.encode(out);
            }
            Self::WithdrawUnbonded => out.push(17),
            Self::ReportEquivocation { evidence } => {
                out.push(18);
                evidence.encode(out);
            }
            Self::SetAccountFlag { flag, enabled } => {
                out.push(19);
                flag.encode(out);
                enabled.encode(out);
            }
            Self::SetRegularKey { key } => {
                out.push(20);
                key.encode(out);
            }
            Self::SetSignerList { list } => {
                out.push(21);
                list.encode(out);
            }
            Self::ApplyRebind { commitment } => {
                out.push(22);
                commitment.encode(out);
            }
        }
    }
}

impl Decode for Message {
    fn decode(r: &mut Reader<'_>) -> Result<Self, CodecError> {
        match u8::decode(r)? {
            0 => Ok(Self::Transfer {
                to: Address::decode(r)?,
                denom: Denom::decode(r)?,
                amount: Amount::decode(r)?,
                reference: Option::<PaymentReference>::decode(r)?,
            }),
            1 => Ok(Self::CreateGroup {
                name: String::decode(r)?,
                members: Vec::<FoundingMember>::decode(r)?,
                contribution: Contribution::decode(r)?,
                policy: PayoutPolicy::decode(r)?,
                quorum: Quorum::decode(r)?,
            }),
            2 => Ok(Self::ContributeToGroup {
                group: Address::decode(r)?,
                amount: Amount::decode(r)?,
            }),
            3 => Ok(Self::GroupPayout {
                group: Address::decode(r)?,
            }),
            4 => Ok(Self::RegisterName {
                name: Username::decode(r)?,
            }),
            5 => Ok(Self::RenewName {
                name: Username::decode(r)?,
            }),
            6 => Ok(Self::TransferName {
                name: Username::decode(r)?,
                to: Address::decode(r)?,
            }),
            7 => Ok(Self::SetPrimaryAlias {
                name: Username::decode(r)?,
            }),
            8 => Ok(Self::AttestContact {
                commitment: ContactCommitment::decode(r)?,
                address: Address::decode(r)?,
            }),
            9 => Ok(Self::RequestRebind {
                commitment: ContactCommitment::decode(r)?,
                new_address: Address::decode(r)?,
            }),
            10 => Ok(Self::VetoRebind {
                commitment: ContactCommitment::decode(r)?,
            }),
            11 => Ok(Self::RevokeContact {
                commitment: ContactCommitment::decode(r)?,
            }),
            12 => Ok(Self::ClearPrimaryAlias),
            13 => Ok(Self::ReleaseName {
                name: Username::decode(r)?,
            }),
            14 => Ok(Self::Bond {
                public_key: PublicKey::decode(r)?,
                country: CountryCode::decode(r)?,
                amount: Amount::decode(r)?,
            }),
            15 => Ok(Self::AddStake {
                amount: Amount::decode(r)?,
            }),
            16 => Ok(Self::Unbond {
                amount: Amount::decode(r)?,
            }),
            17 => Ok(Self::WithdrawUnbonded),
            18 => Ok(Self::ReportEquivocation {
                evidence: Box::new(Equivocation::decode(r)?),
            }),
            19 => Ok(Self::SetAccountFlag {
                flag: AccountFlag::decode(r)?,
                enabled: bool::decode(r)?,
            }),
            20 => Ok(Self::SetRegularKey {
                key: Option::<PublicKey>::decode(r)?,
            }),
            21 => Ok(Self::SetSignerList {
                list: Option::<SignerList>::decode(r)?,
            }),
            22 => Ok(Self::ApplyRebind {
                commitment: ContactCommitment::decode(r)?,
            }),
            tag => Err(CodecError::UnknownDiscriminant {
                tag,
                type_name: "Message",
            }),
        }
    }
}

impl Encode for TxBody {
    fn encode(&self, out: &mut Vec<u8>) {
        self.chain_id.encode(out);
        self.sender.encode(out);
        self.nonce.encode(out);
        self.valid_until.encode(out);
        self.fee.encode(out);
        self.messages.encode(out);
        self.memo.encode(out);
    }
}

impl Decode for TxBody {
    fn decode(r: &mut Reader<'_>) -> Result<Self, CodecError> {
        Ok(Self {
            chain_id: ChainId::decode(r)?,
            sender: Address::decode(r)?,
            nonce: u64::decode(r)?,
            valid_until: Height::decode(r)?,
            fee: Fee::decode(r)?,
            messages: Vec::<Message>::decode(r)?,
            memo: String::decode(r)?,
        })
    }
}

impl Encode for TxSignature {
    fn encode(&self, out: &mut Vec<u8>) {
        self.public_key.encode(out);
        self.signature.encode(out);
    }
}

impl Decode for TxSignature {
    fn decode(r: &mut Reader<'_>) -> Result<Self, CodecError> {
        Ok(Self {
            public_key: PublicKey::decode(r)?,
            signature: Signature::decode(r)?,
        })
    }
}

impl Encode for Transaction {
    fn encode(&self, out: &mut Vec<u8>) {
        self.body.encode(out);
        self.signatures.encode(out);
        self.sponsor_signatures.encode(out);
    }
}

impl Decode for Transaction {
    fn decode(r: &mut Reader<'_>) -> Result<Self, CodecError> {
        let transaction = Self {
            body: TxBody::decode(r)?,
            signatures: Vec::<TxSignature>::decode(r)?,
            sponsor_signatures: Vec::<TxSignature>::decode(r)?,
        };
        // Canonical form is enforced at the decode boundary, not left to the
        // verifier, because the id is a hash of these bytes. An unsorted or
        // repeated signature list is a second spelling of one transaction, and
        // two spellings mean two ids for one payment.
        if transaction.signatures.is_empty() || transaction.signatures.len() > MAX_SIGNATURES {
            return Err(CodecError::Invalid(format!(
                "a transaction must carry 1..={MAX_SIGNATURES} signatures, got {}",
                transaction.signatures.len()
            )));
        }
        if transaction.sponsor_signatures.len() > MAX_SIGNATURES {
            return Err(CodecError::Invalid(format!(
                "a transaction may carry at most {MAX_SIGNATURES} sponsor signatures, got {}",
                transaction.sponsor_signatures.len()
            )));
        }
        for list in [&transaction.signatures, &transaction.sponsor_signatures] {
            if !list.windows(2).all(|w| {
                w.first().map(|s| s.public_key.to_bytes())
                    < w.get(1).map(|s| s.public_key.to_bytes())
            }) {
                return Err(CodecError::Invalid(
                    "transaction signatures must be sorted by public key and unique".to_owned(),
                ));
            }
        }
        Ok(transaction)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(seed: u8) -> SecretKey {
        SecretKey::from_bytes(&[seed; 32])
    }

    fn chain() -> ChainId {
        ChainId::new("afrolink-1").expect("valid chain id")
    }

    fn kes() -> Denom {
        Denom::sovereign("ke", "kes").expect("valid denom")
    }

    /// Amina sends 500 KES to Kwame, paying the fee in KES — never touching AFRI.
    fn payment(sender: &SecretKey) -> TxBody {
        TxBody {
            chain_id: chain(),
            sender: Address::from_public_key(&sender.public_key()),
            nonce: 0,
            valid_until: Height(1_000),
            fee: Fee::new(Amount::from_units(1_000), kes()),
            messages: vec![Message::Transfer {
                to: Address::from_public_key(&key(2).public_key()),
                denom: kes(),
                amount: Amount::from_afri(500),
                reference: None,
            }],
            memo: "school fees".to_owned(),
        }
    }

    #[test]
    fn a_valid_payment_verifies() {
        let sk = key(1);
        let tx = payment(&sk).sign(&sk);
        assert!(tx.verify_stateless(&chain(), Height(10)).is_ok());
    }

    #[test]
    fn a_user_can_pay_fees_without_holding_afri() {
        // The adoption-critical property: the fee denom is a local stablecoin.
        let sk = key(1);
        let tx = payment(&sk).sign(&sk);
        assert!(!tx.body.fee.denom.is_native());
        assert!(tx.body.fee.denom.is_sovereign());
        assert!(tx.verify_stateless(&chain(), Height(10)).is_ok());
    }

    #[test]
    fn a_sponsor_can_cover_someone_elses_fee() {
        let sk = key(1);
        let sponsor = Address::from_public_key(&key(9).public_key());
        let mut body = payment(&sk);
        body.fee = Fee::sponsored_by(Amount::from_units(1_000), kes(), sponsor);
        // The sponsor co-signs. Their balance is what pays, so their consent is
        // what makes this sponsorship rather than theft.
        let tx = body.sign_sponsored(&[&sk], &[&key(9)]);

        assert!(tx.body.fee.is_sponsored());
        assert_eq!(tx.body.fee.payer_or(tx.body.sender), sponsor);
        assert!(tx.verify_stateless(&chain(), Height(10)).is_ok());
    }

    #[test]
    fn an_unsponsored_fee_is_charged_to_the_sender() {
        let sk = key(1);
        let tx = payment(&sk).sign(&sk);
        assert_eq!(tx.body.fee.payer_or(tx.body.sender), tx.body.sender);
    }

    #[test]
    fn a_transaction_signed_for_another_chain_is_rejected() {
        // Cross-chain replay: a testnet signature must not spend mainnet funds.
        let sk = key(1);
        let mut body = payment(&sk);
        body.chain_id = ChainId::new("afrolink-testnet-3").expect("valid");
        let tx = body.sign(&sk);
        assert!(matches!(
            tx.verify_stateless(&chain(), Height(10)),
            Err(TxError::WrongChain { .. })
        ));
    }

    #[test]
    fn an_expired_transaction_is_rejected() {
        let sk = key(1);
        let tx = payment(&sk).sign(&sk);
        assert!(matches!(
            tx.verify_stateless(&chain(), Height(1_001)),
            Err(TxError::Expired { .. })
        ));
        assert!(
            tx.verify_stateless(&chain(), Height(1_000)).is_ok(),
            "valid_until is inclusive"
        );
    }

    #[test]
    fn tampering_with_the_amount_invalidates_the_signature() {
        let sk = key(1);
        let mut tx = payment(&sk).sign(&sk);
        tx.body.messages = vec![Message::Transfer {
            to: Address::from_public_key(&key(2).public_key()),
            denom: kes(),
            amount: Amount::from_afri(500_000),
            reference: None,
        }];
        assert_eq!(
            tx.verify_stateless(&chain(), Height(10)),
            Err(TxError::InvalidSignature)
        );
    }

    #[test]
    fn tampering_with_the_recipient_invalidates_the_signature() {
        let sk = key(1);
        let mut tx = payment(&sk).sign(&sk);
        tx.body.messages = vec![Message::Transfer {
            to: Address::from_public_key(&key(77).public_key()),
            denom: kes(),
            amount: Amount::from_afri(500),
            reference: None,
        }];
        assert_eq!(
            tx.verify_stateless(&chain(), Height(10)),
            Err(TxError::InvalidSignature)
        );
    }

    #[test]
    fn a_valid_signature_from_the_wrong_key_cannot_spend_an_account() {
        // Attacker signs a body naming someone else as sender. The signature is
        // genuine, so stateless verification passes — and must, because that is
        // all it claims to check. The account record is what refuses.
        use crate::Account;

        let victim = Address::from_public_key(&key(1).public_key());
        let attacker = key(66);
        let mut body = payment(&key(1));
        body.sender = victim;
        let tx = body.sign(&attacker);

        assert!(
            tx.verify_stateless(&chain(), Height(10)).is_ok(),
            "the signature is genuine; authentication is not authorisation"
        );
        assert!(
            !Account::individual(victim).authorises(&tx.signing_keys()),
            "but the victim's account must not recognise the attacker's key"
        );
    }

    #[test]
    fn signatures_must_arrive_sorted_and_unique() {
        // The id is a hash of the encoding, so a second ordering would be a
        // second id for one signed transaction — and dedup by id is what stops
        // a replay.
        let sk = key(1);
        let mut tx = payment(&sk).sign_with(&[&key(1), &key(2)]);
        assert!(tx.verify_stateless(&chain(), Height(10)).is_ok());

        tx.signatures.reverse();
        assert_eq!(
            tx.verify_stateless(&chain(), Height(10)),
            Err(TxError::UnsortedSignatures)
        );
        assert!(
            Transaction::from_bytes(&tx.to_bytes()).is_err(),
            "and the decoder must refuse it too, not sort it"
        );
    }

    #[test]
    fn a_sponsored_fee_without_a_sponsor_signature_is_malformed() {
        // The structural half of the sponsorship fix. A transaction naming a
        // fee payer who did not sign is not merely unauthorised — it is a
        // shape this chain does not accept, so it is refused before any account
        // is read.
        let sk = key(1);
        let mut body = payment(&sk);
        body.fee = Fee::sponsored_by(Amount::from_units(1_000), kes(), addr(7));
        let tx = body.sign(&sk);
        assert_eq!(
            tx.verify_stateless(&chain(), Height(10)),
            Err(TxError::SponsorSignatureMismatch)
        );
    }

    #[test]
    fn sponsor_signatures_on_an_unsponsored_fee_are_refused() {
        // They authorise nothing and change the transaction's id, which is a
        // way to make a wallet's status check miss its own payment.
        let sk = key(1);
        let mut tx = payment(&sk).sign(&sk);
        tx.sponsor_signatures = payment(&sk).sign(&key(7)).signatures;
        assert_eq!(
            tx.verify_stateless(&chain(), Height(10)),
            Err(TxError::SponsorSignatureMismatch)
        );
    }

    #[test]
    fn a_sponsored_transaction_round_trips_with_both_authorities() {
        let sk = key(1);
        let mut body = payment(&sk);
        body.fee = Fee::sponsored_by(Amount::from_units(1_000), kes(), addr(7));
        let tx = body.sign_sponsored(&[&key(1)], &[&key(7)]);

        assert!(tx.verify_stateless(&chain(), Height(10)).is_ok());
        assert_eq!(tx.signing_keys(), vec![key(1).public_key()]);
        assert_eq!(tx.sponsor_keys(), vec![key(7).public_key()]);
        assert_eq!(Transaction::from_bytes(&tx.to_bytes()), Ok(tx));
    }

    #[test]
    fn naming_yourself_as_your_own_sponsor_is_refused() {
        // A redundant spelling of an ordinary fee, and two spellings of one
        // meaning is what the codec refuses everywhere else.
        let sk = key(1);
        let mut body = payment(&sk);
        body.fee = Fee::sponsored_by(Amount::from_units(1_000), kes(), body.sender);
        assert_eq!(body.validate_basic(), Err(TxError::SelfSponsored));
    }

    #[test]
    fn a_transaction_with_no_signatures_is_refused() {
        let sk = key(1);
        let mut tx = payment(&sk).sign(&sk);
        tx.signatures.clear();
        assert_eq!(
            tx.verify_stateless(&chain(), Height(10)),
            Err(TxError::SignatureCount(0))
        );
        assert!(Transaction::from_bytes(&tx.to_bytes()).is_err());
    }

    #[test]
    fn signing_twice_with_one_key_produces_one_signature() {
        // Otherwise a signer could reach a quorum alone by repeating itself.
        let sk = key(1);
        let tx = payment(&sk).sign_with(&[&key(1), &key(1), &key(2)]);
        assert_eq!(tx.signatures.len(), 2);
        assert!(tx.verify_stateless(&chain(), Height(10)).is_ok());
    }

    #[test]
    fn empty_and_oversized_transactions_are_rejected() {
        let sk = key(1);
        let mut body = payment(&sk);
        body.messages.clear();
        assert_eq!(body.validate_basic(), Err(TxError::MessageCount(0)));

        let mut body = payment(&sk);
        body.memo = "x".repeat(MAX_MEMO_LEN + 1);
        assert_eq!(body.validate_basic(), Err(TxError::MemoTooLong));
    }

    #[test]
    fn zero_value_transfers_are_rejected() {
        let sk = key(1);
        let mut body = payment(&sk);
        body.messages = vec![Message::Transfer {
            to: Address::from_public_key(&key(2).public_key()),
            denom: kes(),
            amount: Amount::ZERO,
            reference: None,
        }];
        assert_eq!(body.validate_basic(), Err(TxError::ZeroAmount));
    }

    #[test]
    fn a_transfer_is_filed_under_both_parties() {
        // The recipient did not send the transaction and cannot know its id, so
        // an index that filed it under the sender alone would make every
        // incoming payment invisible to the person receiving it.
        let sent = payment(&key(1)).sign(&key(1));

        let touched = sent.touched_addresses();
        assert!(touched.contains(&addr(1)), "sender missing");
        assert!(touched.contains(&addr(2)), "recipient missing");
        assert_eq!(touched.len(), 2);
    }

    #[test]
    fn a_sender_only_message_files_under_the_sender_alone() {
        let renewed = with_messages(
            1,
            vec![Message::RenewName {
                name: Username::new("amina").expect("valid"),
            }],
        );
        assert_eq!(renewed.touched_addresses(), vec![addr(1)]);
    }

    #[test]
    fn one_address_is_filed_once_however_many_times_it_appears() {
        // Two payments to the same person in one transaction is one history
        // entry for them, not two rows pointing at the same place.
        let sent = with_messages(1, vec![transfer_to(addr(2), 1), transfer_to(addr(2), 2)]);
        assert_eq!(sent.touched_addresses().len(), 2);
    }

    #[test]
    fn paying_yourself_is_filed_once() {
        let sent = with_messages(1, vec![transfer_to(addr(1), 1)]);
        assert_eq!(sent.touched_addresses(), vec![addr(1)]);
    }

    #[test]
    fn a_slashing_report_files_under_the_offender_too() {
        // Being slashed is the most consequential thing that can happen to a
        // validator's account, and someone else sent the transaction that did it.
        let reported = with_messages(
            1,
            vec![Message::ReportEquivocation {
                evidence: Box::new(equivocation(3)),
            }],
        );
        assert!(
            reported.touched_addresses().contains(&addr(3)),
            "the reported validator must appear in its own history"
        );
    }

    fn addr(seed: u8) -> Address {
        Address::from_public_key(&key(seed).public_key())
    }

    fn transfer_to(to: Address, afri: u64) -> Message {
        Message::Transfer {
            to,
            denom: kes(),
            amount: Amount::from_afri(afri),
            reference: None,
        }
    }

    fn with_messages(sender: u8, messages: Vec<Message>) -> Transaction {
        TxBody {
            chain_id: chain(),
            sender: addr(sender),
            nonce: 0,
            valid_until: Height(1_000),
            fee: Fee::new(Amount::from_units(1_000), kes()),
            messages,
            memo: String::new(),
        }
        .sign(&key(sender))
    }

    /// Two conflicting precommits from one validator, at one height and round.
    fn equivocation(seed: u8) -> Equivocation {
        use afrolink_consensus::{Vote, VoteType};
        use afrolink_primitives::Round;

        let vote = |block: u8| {
            Vote {
                chain_id: chain(),
                height: Height(7),
                round: Round::ZERO,
                vote_type: VoteType::Precommit,
                block_id: Some(Hash32::from_bytes([block; 32])),
                validator: addr(seed),
            }
            .sign(&key(seed))
        };

        Equivocation {
            validator: addr(seed),
            first: vote(1),
            second: vote(2),
        }
    }

    #[test]
    fn a_payment_reference_survives_signing_and_the_wire() {
        // An exchange credits a customer from this field. If it were lost or
        // altered between the wallet and the ledger, the deposit would arrive
        // belonging to nobody.
        use afrolink_pay::PaymentReference;

        let sk = key(1);
        let mut body = payment(&sk);
        body.messages = vec![Message::Transfer {
            to: Address::from_public_key(&key(2).public_key()),
            denom: kes(),
            amount: Amount::from_afri(500),
            reference: Some(PaymentReference(88_121)),
        }];
        let tx = body.sign(&sk);

        let decoded = Transaction::from_bytes(&tx.to_bytes()).expect("decodes");
        assert!(decoded.verify_stateless(&chain(), Height(10)).is_ok());
        assert_eq!(
            decoded.body.messages.first(),
            Some(&Message::Transfer {
                to: Address::from_public_key(&key(2).public_key()),
                denom: kes(),
                amount: Amount::from_afri(500),
                reference: Some(PaymentReference(88_121)),
            })
        );
    }

    #[test]
    fn tampering_with_a_payment_reference_invalidates_the_signature() {
        // The reference is inside the signed document, so a relay cannot
        // redirect a deposit to a different customer account on its way past.
        use afrolink_pay::PaymentReference;

        let sk = key(1);
        let mut body = payment(&sk);
        body.messages = vec![Message::Transfer {
            to: Address::from_public_key(&key(2).public_key()),
            denom: kes(),
            amount: Amount::from_afri(500),
            reference: Some(PaymentReference(88_121)),
        }];
        let mut tx = body.sign(&sk);

        tx.body.messages = vec![Message::Transfer {
            to: Address::from_public_key(&key(2).public_key()),
            denom: kes(),
            amount: Amount::from_afri(500),
            reference: Some(PaymentReference(99_999)),
        }];

        assert_eq!(
            tx.verify_stateless(&chain(), Height(10)),
            Err(TxError::InvalidSignature)
        );
    }

    #[test]
    fn transactions_round_trip_through_the_wire_format() {
        let sk = key(1);
        let tx = payment(&sk).sign(&sk);
        let decoded = Transaction::from_bytes(&tx.to_bytes()).expect("decodes");
        assert_eq!(decoded, tx);
        assert!(decoded.verify_stateless(&chain(), Height(10)).is_ok());
    }

    #[test]
    fn trailing_bytes_on_the_wire_are_rejected() {
        // Otherwise one transaction has many encodings, breaking dedup by id.
        let sk = key(1);
        let mut bytes = payment(&sk).sign(&sk).to_bytes();
        bytes.push(0);
        assert!(Transaction::from_bytes(&bytes).is_err());
    }

    #[test]
    fn distinct_transactions_have_distinct_ids() {
        let sk = key(1);
        let a = payment(&sk).sign(&sk);
        let mut body = payment(&sk);
        body.nonce = 1;
        let b = body.sign(&sk);
        assert_ne!(a.id(), b.id(), "the nonce must change the transaction id");
    }
}
