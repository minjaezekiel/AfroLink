//! Account records.
//!
//! An account is one of three kinds. Making the group case a *variant* rather
//! than a contract deployed at an address is the point of
//! [ADR-0005](../../../docs/adr/0005-african-first-design.md) §C: the protocol
//! itself understands what a savings group is, so wallets, indexers and credit
//! providers can read a contribution history without decoding somebody's bespoke
//! contract storage.

use afrolink_crypto::hash::Hash32;
use afrolink_crypto::{Address, PublicKey};
use afrolink_pay::RequiresReference;
use afrolink_primitives::Height;
use afrolink_primitives::codec::{CodecError, Decode, Encode, Reader};

use thiserror::Error;

use crate::group::GroupAccount;

/// One switch an account owner may set on their own record.
///
/// Flags are **consensus**: the executor reads them while applying a block, so
/// every node must agree on what each bit means. That is why the set is closed
/// and why an unknown bit is refused on decode rather than ignored — see
/// [`AccountFlags::from_bits`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum AccountFlag {
    /// Incoming transfers must carry a [`PaymentReference`].
    ///
    /// XRPL's `asfRequireDest`. An exchange deposit address serves millions of
    /// customers from one address, and a deposit with no reference belongs to
    /// nobody until a human intervenes. With this set, such a payment **fails**
    /// instead — and a failed payment the sender can retry is enormously better
    /// than a successful one nobody can attribute
    /// ([09](../../../docs/09-what-xrpl-answers.md) §2.3).
    ///
    /// [`PaymentReference`]: afrolink_pay::PaymentReference
    RequireReference,
    /// The master key may no longer sign for this account.
    ///
    /// XRPL's `asfDisableMaster`. The address is derived from the master public
    /// key, so a seed that may have been exposed can never be un-exposed —
    /// setting this neutralises it **without moving the money, changing the
    /// address, or invalidating a printed QR code**
    /// ([09](../../../docs/09-what-xrpl-answers.md) §2.4).
    ///
    /// It cannot be set unless some other authority already exists, or the
    /// account would be locked out permanently. See
    /// [`Account::has_a_usable_authority`].
    MasterKeyDisabled,
}

impl AccountFlag {
    /// Every flag, in bit order. Exhaustive by construction.
    pub const ALL: &'static [Self] = &[Self::RequireReference, Self::MasterKeyDisabled];

    /// This flag's bit in an [`AccountFlags`] word.
    ///
    /// **Never renumber one.** The bit is in the state tree, so changing it
    /// changes every state root and silently reinterprets existing accounts.
    #[must_use]
    pub const fn bit(self) -> u32 {
        match self {
            Self::RequireReference => 1 << 0,
            Self::MasterKeyDisabled => 1 << 1,
        }
    }

    /// The flag a single bit names, if any.
    #[must_use]
    pub fn from_bit(bit: u32) -> Option<Self> {
        Self::ALL.iter().copied().find(|flag| flag.bit() == bit)
    }
}

/// The switches set on one account.
///
/// A bitfield rather than a struct of booleans because it is encoded into state:
/// a word has one spelling, where a growing list of `bool`s would need a length
/// and an ordering to stay canonical.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct AccountFlags(u32);

impl AccountFlags {
    /// Every bit this version understands.
    const KNOWN: u32 = AccountFlag::RequireReference.bit() | AccountFlag::MasterKeyDisabled.bit();

    /// No flags set — what every account starts with.
    pub const NONE: Self = Self(0);

    /// Whether `flag` is set.
    #[must_use]
    pub fn is_set(self, flag: AccountFlag) -> bool {
        self.0 & flag.bit() != 0
    }

    /// A copy with `flag` set or cleared.
    ///
    /// Returns a new value rather than mutating, so a caller cannot half-apply a
    /// change and leave the record in a state nobody asked for.
    #[must_use]
    pub fn with(self, flag: AccountFlag, enabled: bool) -> Self {
        if enabled {
            Self(self.0 | flag.bit())
        } else {
            Self(self.0 & !flag.bit())
        }
    }

    /// The raw word.
    #[must_use]
    pub fn bits(self) -> u32 {
        self.0
    }

    /// Parse a raw word, refusing any bit this version does not understand.
    ///
    /// **Refusing rather than masking is the consensus-critical half.** A node
    /// that masked an unknown bit away would compute a different state root than
    /// one that kept it, and the two would fork on a record neither of them can
    /// see anything wrong with. Refusing means the disagreement is a decode
    /// error at the boundary, where it is visible.
    #[must_use]
    pub fn from_bits(bits: u32) -> Option<Self> {
        (bits & !Self::KNOWN == 0).then_some(Self(bits))
    }

    /// Whether transfers into this account must carry a payment reference.
    ///
    /// The bridge between the advisory type in `crates/pay` — what a wallet
    /// reads to warn *before* sending — and the enforced flag the executor
    /// obeys. One concept, so a wallet's warning and the ledger's refusal can
    /// never disagree.
    #[must_use]
    pub fn requires_reference(self) -> RequiresReference {
        if self.is_set(AccountFlag::RequireReference) {
            RequiresReference::Yes
        } else {
            RequiresReference::No
        }
    }
}

/// Most keys one signer list may hold. XRPL's cap, and for the same reason: a
/// transaction's signatures are all verified before anything else happens, so
/// the list is a bound on work an attacker can make a validator do.
pub const MAX_SIGNERS: usize = 32;

/// Why a signing arrangement was refused.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum AuthorityError {
    /// A signer list with no signers.
    #[error("a signer list must name at least one signer")]
    NoSigners,
    /// More than [`MAX_SIGNERS`].
    #[error("a signer list may name at most {MAX_SIGNERS} signers, got {0}")]
    TooManySigners(usize),
    /// A signer appears twice, or the list is not in canonical order.
    #[error("signers must be sorted by public key and unique")]
    UnsortedOrRepeatedSigners,
    /// A signer that can never contribute.
    #[error("a signer's weight must be greater than zero")]
    ZeroWeight,
    /// A quorum of zero would let anyone sign.
    #[error("a quorum must be greater than zero")]
    ZeroQuorum,
    /// A quorum no combination of signers can reach.
    #[error("quorum {quorum} exceeds the total signer weight {total}")]
    UnreachableQuorum {
        /// The threshold asked for.
        quorum: u64,
        /// The most the list can ever produce.
        total: u64,
    },
}

/// One key on a signer list, and how much it counts for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Signer {
    /// The key entitled to contribute.
    pub key: PublicKey,
    /// How much this signature counts toward the quorum.
    pub weight: u32,
}

/// An M-of-N signing arrangement for one account.
///
/// **Weighted rather than a plain count**, because the arrangements people
/// actually want are not symmetric: a person recovering an account may want
/// *their agent plus one family member*, or *two family members*, and equal
/// votes cannot express that.
///
/// # Why signers are keys, not accounts
///
/// XRPL lists accounts, which lets a signer rotate their own key without the
/// list changing. That costs a state read per signer on the hot path, and opens
/// the question of whether a signer's own signer list may authorise — a
/// recursion XRPL has to cap explicitly.
///
/// Listing keys keeps authorisation a pure function of one account record. The
/// cost is real and worth naming: **a signer who loses their key must be
/// replaced**, by a [`Self::quorum`] of the remaining signers. For a recovery
/// list of family and an agent, that is the ordinary case rather than the
/// exceptional one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignerList {
    signers: Vec<Signer>,
    quorum: u32,
}

impl SignerList {
    /// Build and validate a list.
    ///
    /// # Errors
    /// [`AuthorityError`] if the list is malformed or could never be satisfied.
    pub fn new(mut signers: Vec<Signer>, quorum: u32) -> Result<Self, AuthorityError> {
        signers.sort_by_key(|s| s.key.to_bytes());
        Self::from_sorted(signers, quorum)
    }

    /// Validate an already-ordered list, refusing rather than reordering.
    ///
    /// This is what decoding uses. A decoder that sorted would give one list two
    /// encodings, and the list is inside an account record that is hashed into
    /// `app_hash` — so two honest nodes would compute two state roots.
    fn from_sorted(signers: Vec<Signer>, quorum: u32) -> Result<Self, AuthorityError> {
        if signers.is_empty() {
            return Err(AuthorityError::NoSigners);
        }
        if signers.len() > MAX_SIGNERS {
            return Err(AuthorityError::TooManySigners(signers.len()));
        }
        if !signers
            .windows(2)
            .all(|w| w.first().map(|s| s.key.to_bytes()) < w.get(1).map(|s| s.key.to_bytes()))
        {
            return Err(AuthorityError::UnsortedOrRepeatedSigners);
        }
        if signers.iter().any(|s| s.weight == 0) {
            return Err(AuthorityError::ZeroWeight);
        }
        if quorum == 0 {
            return Err(AuthorityError::ZeroQuorum);
        }
        // A quorum above the total weight is a locked account that looks
        // perfectly well-formed. Refusing it here is the only place it is cheap.
        let total: u64 = signers.iter().map(|s| u64::from(s.weight)).sum();
        if u64::from(quorum) > total {
            return Err(AuthorityError::UnreachableQuorum {
                quorum: u64::from(quorum),
                total,
            });
        }
        Ok(Self { signers, quorum })
    }

    /// The signers, sorted by public key.
    #[must_use]
    pub fn signers(&self) -> &[Signer] {
        &self.signers
    }

    /// The weight a transaction must gather.
    #[must_use]
    pub fn quorum(&self) -> u32 {
        self.quorum
    }

    /// The weight `key` carries, or `None` if it is not on the list.
    #[must_use]
    pub fn weight_of(&self, key: &PublicKey) -> Option<u32> {
        self.signers
            .iter()
            .find(|s| s.key == *key)
            .map(|s| s.weight)
    }

    /// Whether these keys together reach the quorum.
    ///
    /// A key that is not on the list contributes nothing **and disqualifies the
    /// whole attempt**: an unrecognised signature changes a transaction's id
    /// without changing what it authorises, which is malleability. Refusing is
    /// cheaper than reasoning about it.
    #[must_use]
    pub fn satisfied_by(&self, keys: &[PublicKey]) -> bool {
        let mut gathered = 0u64;
        for key in keys {
            match self.weight_of(key) {
                Some(weight) => gathered = gathered.saturating_add(u64::from(weight)),
                None => return false,
            }
        }
        gathered >= u64::from(self.quorum)
    }
}

/// What kind of thing owns an address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccountKind {
    /// A person or organisation holding a single key.
    ///
    /// The public key is `None` until the account first sends a transaction.
    /// Until then only the address is known — which is why funds can be sent to
    /// an address that has never been used.
    Individual {
        /// Revealed on first outbound transaction.
        public_key: Option<PublicKey>,
    },
    /// A savings group: chama, susu, stokvel, tontine, equb, VSLA.
    Group(Box<GroupAccount>),
    /// A protocol-owned account (fee pool, staking pool). Has no key and can
    /// never sign; only module logic may move its balance.
    Module {
        /// Which module owns it.
        name: String,
    },
}

/// Where a transaction sits: its id, and the block that carried it.
///
/// The two travel together because either alone is useless — an id with no
/// height means searching the chain, and a height with no id means trusting
/// whoever answers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TxPointer {
    /// The transaction's id.
    pub tx_id: Hash32,
    /// The block it was included in.
    pub height: Height,
}

/// An account record as stored in state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Account {
    /// The account's address.
    pub address: Address,
    /// Next expected transaction sequence number.
    pub nonce: u64,
    /// What kind of account this is.
    pub kind: AccountKind,
    /// The last transaction to move this account's history pointer.
    ///
    /// **The head of a provable history chain.** This field is in state, so it
    /// is committed to by `app_hash` and a client can prove it against a header
    /// it trusts. That transaction's receipt names the account's *previous*
    /// pointer, and so on backwards — an unbroken chain a server cannot open a
    /// gap in, because a gap is a link that fails to verify.
    ///
    /// It is what turns the history index of
    /// [ADR-0014](../../../docs/adr/0014-payment-history-and-the-mempool.md)
    /// from a hint into something checkable. XRPL calls it `PreviousTxnID`
    /// ([09](../../../docs/09-what-xrpl-answers.md) §2.1).
    ///
    /// `None` on an account that has never been party to a transaction.
    pub last_txn: Option<TxPointer>,
    /// Switches the owner has set on their own record.
    ///
    /// Consensus-visible: the executor reads these while applying a block, which
    /// is what makes [`AccountFlag::RequireReference`] an enforcement rather
    /// than a request.
    pub flags: AccountFlags,
    /// A day-to-day signing key, rotatable without changing the address.
    ///
    /// XRPL's regular key. The address is a hash of the *master* key and can
    /// never change; this is the key that actually signs, and replacing it is an
    /// ordinary transaction. On a chain whose addressing layer is built around
    /// usernames and printed QR codes that people have already shared, rotation
    /// without migration matters more than usual
    /// ([09](../../../docs/09-what-xrpl-answers.md) §2.4).
    pub regular_key: Option<PublicKey>,
    /// An M-of-N arrangement that may sign for this account.
    ///
    /// Social recovery as a protocol primitive rather than a contract: family,
    /// an agent, an attestor. [ADR-0005](../../../docs/adr/0005-african-first-design.md)
    /// is written for users who will lose devices, and this is the mechanism
    /// that answer rests on.
    pub signers: Option<SignerList>,
}

impl Account {
    /// A fresh individual account with no key revealed yet.
    #[must_use]
    pub fn individual(address: Address) -> Self {
        Self {
            address,
            nonce: 0,
            kind: AccountKind::Individual { public_key: None },
            last_txn: None,
            flags: AccountFlags::NONE,
            regular_key: None,
            signers: None,
        }
    }

    /// An individual account with a known key.
    #[must_use]
    pub fn with_key(public_key: PublicKey) -> Self {
        Self {
            address: Address::from_public_key(&public_key),
            nonce: 0,
            kind: AccountKind::Individual {
                public_key: Some(public_key),
            },
            last_txn: None,
            flags: AccountFlags::NONE,
            regular_key: None,
            signers: None,
        }
    }

    /// A group account at `address`.
    #[must_use]
    pub fn group(address: Address, group: GroupAccount) -> Self {
        Self {
            address,
            nonce: 0,
            kind: AccountKind::Group(Box::new(group)),
            last_txn: None,
            flags: AccountFlags::NONE,
            regular_key: None,
            signers: None,
        }
    }

    /// A protocol-owned account.
    #[must_use]
    pub fn module(address: Address, name: impl Into<String>) -> Self {
        Self {
            address,
            nonce: 0,
            kind: AccountKind::Module { name: name.into() },
            last_txn: None,
            flags: AccountFlags::NONE,
            regular_key: None,
            signers: None,
        }
    }

    /// The group record, if this is a group account.
    #[must_use]
    pub fn as_group(&self) -> Option<&GroupAccount> {
        match &self.kind {
            AccountKind::Group(g) => Some(g),
            _ => None,
        }
    }

    /// Whether this account is able to sign transactions at all.
    ///
    /// Module accounts never can — their balances move only through module
    /// logic, so a leaked key cannot drain the fee pool because there is no key.
    #[must_use]
    pub fn can_sign(&self) -> bool {
        !matches!(self.kind, AccountKind::Module { .. })
    }

    /// Advance the nonce after a successful transaction.
    pub fn increment_nonce(&mut self) {
        self.nonce = self.nonce.saturating_add(1);
    }

    /// Whether transfers into this account must carry a payment reference.
    ///
    /// The question the executor asks of the **recipient** on every transfer.
    #[must_use]
    pub fn requires_reference(&self) -> RequiresReference {
        self.flags.requires_reference()
    }

    /// Whether `key` is this account's master key and that key may still sign.
    ///
    /// The address *is* the commitment to the master key — it is a hash of it —
    /// so no stored copy is consulted and none can go stale.
    #[must_use]
    pub fn master_key_may_sign(&self, key: &PublicKey) -> bool {
        !self.flags.is_set(AccountFlag::MasterKeyDisabled)
            && Address::from_public_key(key) == self.address
    }

    /// Whether this set of signing keys is entitled to act for the account.
    ///
    /// **This replaces the key-to-address check that used to be part of
    /// stateless verification.** Authorisation is now a fact about the account
    /// record, not about the transaction alone, which is precisely what makes
    /// key rotation possible: the address never changes, the authority does.
    ///
    /// Three authorities, and a transaction must satisfy exactly one:
    ///
    /// | | |
    /// |---|---|
    /// | **Master key** | The key the address was derived from, unless [`AccountFlag::MasterKeyDisabled`] |
    /// | **Regular key** | The rotatable day-to-day key, if one is set |
    /// | **Signer list** | Weighted keys reaching a quorum |
    ///
    /// # Why the authorities do not mix
    ///
    /// A set combining a master key with signer-list keys satisfies nothing.
    /// Allowing a mixture would mean one body has many authorising sets, each a
    /// differently-numbered transaction — and an extra signature that changes an
    /// id without changing what it authorises is malleability. The signer list
    /// refuses an unrecognised key for the same reason.
    ///
    /// # What can never sign
    ///
    /// Module accounts. Their addresses are derived from a domain-separated hash
    /// of a name, so no key produces them and the check below is already
    /// unsatisfiable — but a leaked key must not be able to drain the fee pool
    /// on the strength of a future refactor, so it is stated rather than
    /// inferred.
    #[must_use]
    pub fn authorises(&self, keys: &[PublicKey]) -> bool {
        if !self.can_sign() {
            return false;
        }
        if let [only] = keys
            && (self.master_key_may_sign(only) || self.regular_key.as_ref() == Some(only))
        {
            return true;
        }
        self.signers
            .as_ref()
            .is_some_and(|list| !keys.is_empty() && list.satisfied_by(keys))
    }

    /// Whether some key can still sign for this account.
    ///
    /// **The lock-out invariant.** Every message that changes an authority is
    /// applied and then checked against this; if the result would leave nobody
    /// able to sign, the whole transaction is refused.
    ///
    /// One rule checked in one place, rather than a condition on each of
    /// disabling the master key, clearing the regular key and clearing the
    /// signer list. Those three are the same rule seen from three sides, and
    /// writing it three times is how a fourth authority arrives without one.
    #[must_use]
    pub fn has_a_usable_authority(&self) -> bool {
        !self.flags.is_set(AccountFlag::MasterKeyDisabled)
            || self.regular_key.is_some()
            || self.signers.is_some()
    }
}

impl Encode for AccountKind {
    fn encode(&self, out: &mut Vec<u8>) {
        match self {
            Self::Individual { public_key } => {
                out.push(0);
                public_key.encode(out);
            }
            Self::Group(g) => {
                out.push(1);
                g.encode(out);
            }
            Self::Module { name } => {
                out.push(2);
                name.encode(out);
            }
        }
    }
}

impl Decode for AccountKind {
    fn decode(r: &mut Reader<'_>) -> Result<Self, CodecError> {
        match u8::decode(r)? {
            0 => Ok(Self::Individual {
                public_key: Option::<PublicKey>::decode(r)?,
            }),
            1 => Ok(Self::Group(Box::new(GroupAccount::decode(r)?))),
            2 => Ok(Self::Module {
                name: String::decode(r)?,
            }),
            tag => Err(CodecError::UnknownDiscriminant {
                tag,
                type_name: "AccountKind",
            }),
        }
    }
}

impl Encode for TxPointer {
    fn encode(&self, out: &mut Vec<u8>) {
        self.tx_id.encode(out);
        self.height.encode(out);
    }
}

impl Decode for TxPointer {
    fn decode(r: &mut Reader<'_>) -> Result<Self, CodecError> {
        Ok(Self {
            tx_id: Hash32::decode(r)?,
            height: Height::decode(r)?,
        })
    }
}

impl Encode for AccountFlag {
    fn encode(&self, out: &mut Vec<u8>) {
        self.bit().encode(out);
    }
}

impl Decode for AccountFlag {
    fn decode(r: &mut Reader<'_>) -> Result<Self, CodecError> {
        // A flag travels as its bit, not as a separate discriminant, so a
        // message naming a flag and the state word holding it use one number.
        // Two numberings for one concept is how they drift apart.
        let bit = u32::decode(r)?;
        Self::from_bit(bit).ok_or_else(|| {
            CodecError::Invalid(format!("no account flag is defined for bit {bit:#x}"))
        })
    }
}

impl Encode for AccountFlags {
    fn encode(&self, out: &mut Vec<u8>) {
        self.0.encode(out);
    }
}

impl Decode for AccountFlags {
    fn decode(r: &mut Reader<'_>) -> Result<Self, CodecError> {
        let bits = u32::decode(r)?;
        Self::from_bits(bits).ok_or_else(|| {
            CodecError::Invalid(format!("account flags carry unknown bits: {bits:#x}"))
        })
    }
}

impl Encode for Signer {
    fn encode(&self, out: &mut Vec<u8>) {
        self.key.encode(out);
        self.weight.encode(out);
    }
}

impl Decode for Signer {
    fn decode(r: &mut Reader<'_>) -> Result<Self, CodecError> {
        Ok(Self {
            key: PublicKey::decode(r)?,
            weight: u32::decode(r)?,
        })
    }
}

impl Encode for SignerList {
    fn encode(&self, out: &mut Vec<u8>) {
        self.signers.encode(out);
        self.quorum.encode(out);
    }
}

impl Decode for SignerList {
    fn decode(r: &mut Reader<'_>) -> Result<Self, CodecError> {
        let signers = Vec::<Signer>::decode(r)?;
        let quorum = u32::decode(r)?;
        // Refuse rather than repair. Sorting here would give one list two
        // encodings, and this list sits inside an account record hashed into
        // `app_hash` — so two honest nodes would compute two state roots for one
        // arrangement. An unreachable quorum is refused for a different reason:
        // it is a permanently locked account that looks perfectly well-formed.
        Self::from_sorted(signers, quorum).map_err(|e| CodecError::Invalid(e.to_string()))
    }
}

impl Encode for Account {
    fn encode(&self, out: &mut Vec<u8>) {
        self.address.encode(out);
        self.nonce.encode(out);
        self.kind.encode(out);
        self.last_txn.encode(out);
        self.flags.encode(out);
        self.regular_key.encode(out);
        self.signers.encode(out);
    }
}

impl Decode for Account {
    fn decode(r: &mut Reader<'_>) -> Result<Self, CodecError> {
        let account = Self {
            address: Address::decode(r)?,
            nonce: u64::decode(r)?,
            kind: AccountKind::decode(r)?,
            last_txn: Option::<TxPointer>::decode(r)?,
            flags: AccountFlags::decode(r)?,
            regular_key: Option::<PublicKey>::decode(r)?,
            signers: Option::<SignerList>::decode(r)?,
        };
        // A record nobody can sign for is not a state this chain can produce, so
        // it can only have arrived from a corrupt database or a hostile peer.
        // Accepting it would mean serving a wallet a proof that its account is
        // permanently frozen.
        if !account.has_a_usable_authority() {
            return Err(CodecError::Invalid(
                "account record has no key that could sign for it".to_owned(),
            ));
        }
        Ok(account)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::group::{Contribution, Member, PayoutPolicy, Quorum, Role};
    use afrolink_crypto::SecretKey;
    use afrolink_primitives::codec::decode_exact;
    use afrolink_primitives::{Amount, Denom};

    fn addr(seed: u8) -> Address {
        Address::from_public_key(&SecretKey::from_bytes(&[seed; 32]).public_key())
    }

    fn sample_group() -> GroupAccount {
        let members = vec![
            Member::new(addr(1), Role::Treasurer, 0),
            Member::new(addr(2), Role::Member, 0),
            Member::new(addr(3), Role::Member, 0),
        ];
        let order = members.iter().map(|m| m.address).collect();
        GroupAccount::new(
            "Stokvel ya Soweto",
            members,
            Contribution {
                amount: Amount::from_afri(100),
                denom: Denom::sovereign("za", "zar").expect("valid denom"),
                period_blocks: 604_800,
            },
            PayoutPolicy::Rotation { order, next: 0 },
            Quorum::TWO_THIRDS,
        )
        .expect("valid group")
    }

    #[test]
    fn a_new_account_has_no_key_until_it_transacts() {
        let account = Account::individual(addr(1));
        assert_eq!(account.kind, AccountKind::Individual { public_key: None });
        assert_eq!(account.nonce, 0);
    }

    #[test]
    fn module_accounts_cannot_sign() {
        // There is no key to leak, so the fee pool cannot be drained by theft.
        let pool = Account::module(addr(200), "fee_pool");
        assert!(!pool.can_sign());
        assert!(Account::individual(addr(1)).can_sign());
    }

    #[test]
    fn a_group_account_exposes_its_group_record() {
        let account = Account::group(addr(50), sample_group());
        let group = account.as_group().expect("is a group");
        assert_eq!(group.members.len(), 3);
        assert_eq!(group.treasurer(), Some(addr(1)));
        assert!(Account::individual(addr(1)).as_group().is_none());
    }

    #[test]
    fn nonces_advance_and_saturate() {
        let mut account = Account::individual(addr(1));
        account.increment_nonce();
        assert_eq!(account.nonce, 1);
        account.nonce = u64::MAX;
        account.increment_nonce();
        assert_eq!(account.nonce, u64::MAX, "must saturate, not wrap");
    }

    #[test]
    fn a_new_account_requires_nothing_of_its_senders() {
        // The default has to be permissive: an ordinary person's address must
        // accept an ordinary payment. The flag is for the address that serves
        // millions of customers, not for everyone.
        let account = Account::individual(addr(1));
        assert_eq!(account.flags, AccountFlags::NONE);
        assert_eq!(account.requires_reference(), RequiresReference::No);
    }

    #[test]
    fn setting_a_flag_leaves_the_others_alone() {
        let flags = AccountFlags::NONE.with(AccountFlag::RequireReference, true);
        assert!(flags.is_set(AccountFlag::RequireReference));
        assert_eq!(flags.requires_reference(), RequiresReference::Yes);

        let cleared = flags.with(AccountFlag::RequireReference, false);
        assert_eq!(cleared, AccountFlags::NONE);
    }

    #[test]
    fn setting_a_flag_twice_is_the_same_as_setting_it_once() {
        // Idempotence matters because a wallet may retry a submission it never
        // saw the result of. Two arrivals must not toggle it back off.
        let once = AccountFlags::NONE.with(AccountFlag::RequireReference, true);
        assert_eq!(once.with(AccountFlag::RequireReference, true), once);
    }

    #[test]
    fn an_unknown_flag_bit_is_refused_rather_than_masked_away() {
        // Consensus-critical. A node that masked the bit away would store a
        // different account record — and so compute a different state root —
        // than one that kept it, and the fork would be invisible to both.
        assert_eq!(AccountFlags::from_bits(1 << 31), None);
        // One unknown bit alongside every known one is still a refusal: the
        // check is on the unknown bits, not on whether anything looks familiar.
        let every_known: u32 = AccountFlag::ALL.iter().map(|f| f.bit()).sum();
        assert!(AccountFlags::from_bits(every_known).is_some());
        assert_eq!(AccountFlags::from_bits(every_known | 1 << 20), None);

        let forged = 1u32 << 31;
        assert!(
            decode_exact::<AccountFlags>(&forged.to_bytes()).is_err(),
            "an unknown bit must not decode"
        );
    }

    #[test]
    fn a_flag_and_the_state_word_agree_on_its_number() {
        // One numbering, so a message naming a flag and the record holding it
        // can never drift apart.
        for flag in AccountFlag::ALL {
            assert_eq!(AccountFlag::from_bit(flag.bit()), Some(*flag));
            assert_eq!(decode_exact::<AccountFlag>(&flag.to_bytes()), Ok(*flag));
            assert!(AccountFlags::NONE.with(*flag, true).bits() == flag.bit());
        }
    }

    #[test]
    fn a_flag_naming_no_bit_at_all_is_refused() {
        // `0` is not "no flag", it is a message that names nothing. Accepting it
        // would make `SetAccountFlag` a no-op that looks like a success.
        assert_eq!(AccountFlag::from_bit(0), None);
        assert!(decode_exact::<AccountFlag>(&0u32.to_bytes()).is_err());
        assert!(decode_exact::<AccountFlag>(&0b11u32.to_bytes()).is_err());
    }

    // -- Key rotation and signer lists (ADR-0017) ----------------------------

    fn pk(seed: u8) -> PublicKey {
        SecretKey::from_bytes(&[seed; 32]).public_key()
    }

    /// A 2-of-3 recovery list: two family members and an agent, any two of them.
    fn recovery_list() -> SignerList {
        SignerList::new(
            vec![
                Signer {
                    key: pk(11),
                    weight: 1,
                },
                Signer {
                    key: pk(12),
                    weight: 1,
                },
                Signer {
                    key: pk(13),
                    weight: 1,
                },
            ],
            2,
        )
        .expect("valid list")
    }

    #[test]
    fn an_untouched_account_is_signed_for_by_its_master_key_alone() {
        // The default must be exactly what it was before rotation existed, or
        // every account in the chain changes meaning at once.
        let account = Account::individual(addr(1));
        assert!(account.authorises(&[pk(1)]));
        assert!(!account.authorises(&[pk(2)]));
        assert!(!account.authorises(&[]));
    }

    #[test]
    fn a_rotated_key_signs_without_the_address_changing() {
        // The property the whole feature exists for. A username, a QR code and
        // a shared address all keep working across a key change.
        let mut account = Account::individual(addr(1));
        let before = account.address;
        account.regular_key = Some(pk(9));

        assert!(account.authorises(&[pk(9)]), "the new key must work");
        assert!(
            account.authorises(&[pk(1)]),
            "and the master key still does until it is disabled"
        );
        assert_eq!(account.address, before, "the address must not move");
    }

    #[test]
    fn disabling_the_master_key_retires_an_exposed_seed() {
        // A seed that may have leaked can never be un-leaked. This is the only
        // response that does not require moving the money and abandoning the
        // address.
        let mut account = Account::individual(addr(1));
        account.regular_key = Some(pk(9));
        account.flags = account.flags.with(AccountFlag::MasterKeyDisabled, true);

        assert!(
            !account.authorises(&[pk(1)]),
            "the exposed key must no longer sign"
        );
        assert!(account.authorises(&[pk(9)]));
        assert!(account.has_a_usable_authority());
    }

    #[test]
    fn an_account_with_no_way_to_sign_is_not_a_state_this_chain_allows() {
        let mut account = Account::individual(addr(1));
        account.flags = account.flags.with(AccountFlag::MasterKeyDisabled, true);
        assert!(
            !account.has_a_usable_authority(),
            "disabling the master with no replacement locks the funds forever"
        );
        assert!(
            decode_exact::<Account>(&account.to_bytes()).is_err(),
            "and such a record must not even decode: it can only be corruption \
             or a hostile peer, and serving it tells a wallet it is frozen"
        );
    }

    #[test]
    fn a_quorum_of_family_can_act_but_one_member_alone_cannot() {
        // Social recovery as a protocol primitive: the point is that no single
        // signer — including a compromised agent — is sufficient.
        let mut account = Account::individual(addr(1));
        account.signers = Some(recovery_list());

        assert!(account.authorises(&[pk(11), pk(12)]));
        assert!(account.authorises(&[pk(12), pk(13)]));
        assert!(!account.authorises(&[pk(11)]), "one signer is not a quorum");
    }

    #[test]
    fn a_stranger_alongside_a_quorum_invalidates_the_whole_attempt() {
        // An unrecognised signature would otherwise change a transaction's id
        // without changing what it authorises, which is malleability.
        let mut account = Account::individual(addr(1));
        account.signers = Some(recovery_list());
        assert!(!account.authorises(&[pk(11), pk(12), pk(99)]));
    }

    #[test]
    fn authorities_do_not_combine() {
        // One authority per transaction. Mixing would give one body many
        // authorising sets, and so many ids.
        let mut account = Account::individual(addr(1));
        account.signers = Some(recovery_list());
        account.regular_key = Some(pk(9));

        assert!(
            !account.authorises(&[pk(1), pk(11)]),
            "master plus a signer"
        );
        assert!(
            !account.authorises(&[pk(9), pk(11)]),
            "regular key plus a signer"
        );
        assert!(account.authorises(&[pk(9)]));
        assert!(account.authorises(&[pk(11), pk(12)]));
    }

    #[test]
    fn weights_let_an_agent_count_for_more_than_a_neighbour() {
        // Equal votes cannot express "my agent, or any two family members",
        // which is the arrangement people actually ask for.
        let list = SignerList::new(
            vec![
                Signer {
                    key: pk(11),
                    weight: 2,
                },
                Signer {
                    key: pk(12),
                    weight: 1,
                },
                Signer {
                    key: pk(13),
                    weight: 1,
                },
            ],
            2,
        )
        .expect("valid list");

        assert!(list.satisfied_by(&[pk(11)]), "the agent alone");
        assert!(list.satisfied_by(&[pk(12), pk(13)]), "or two neighbours");
        assert!(!list.satisfied_by(&[pk(12)]), "but not one neighbour");
    }

    #[test]
    fn a_signer_list_nobody_can_satisfy_is_refused() {
        // A quorum above the total weight is a permanently locked account that
        // looks perfectly well-formed. Refusing at construction is the only
        // place it is cheap to notice.
        let signers = vec![
            Signer {
                key: pk(11),
                weight: 1,
            },
            Signer {
                key: pk(12),
                weight: 1,
            },
        ];
        assert_eq!(
            SignerList::new(signers.clone(), 3),
            Err(AuthorityError::UnreachableQuorum {
                quorum: 3,
                total: 2
            })
        );
        assert_eq!(
            SignerList::new(signers, 0),
            Err(AuthorityError::ZeroQuorum),
            "a quorum of zero would let anyone sign"
        );
    }

    #[test]
    fn a_signer_with_no_weight_is_refused() {
        // Otherwise a list can name someone who can never contribute, which
        // reads to a user as protection they do not have.
        assert_eq!(
            SignerList::new(
                vec![Signer {
                    key: pk(11),
                    weight: 0
                }],
                1
            ),
            Err(AuthorityError::ZeroWeight)
        );
        assert_eq!(
            SignerList::new(Vec::new(), 1),
            Err(AuthorityError::NoSigners)
        );
    }

    #[test]
    fn a_signer_list_arrives_sorted_or_not_at_all() {
        // It lives inside a record hashed into `app_hash`. A decoder that
        // sorted would give one arrangement two encodings, and two honest nodes
        // two state roots.
        let list = recovery_list();
        assert_eq!(
            decode_exact::<SignerList>(&list.to_bytes()),
            Ok(list.clone())
        );

        let mut out = Vec::new();
        let mut reversed: Vec<Signer> = list.signers().to_vec();
        reversed.reverse();
        reversed.encode(&mut out);
        list.quorum().encode(&mut out);
        assert!(
            decode_exact::<SignerList>(&out).is_err(),
            "an unsorted list must be refused, not reordered"
        );
    }

    #[test]
    fn a_repeated_signer_cannot_reach_a_quorum_alone() {
        let mut out = Vec::new();
        vec![
            Signer {
                key: pk(11),
                weight: 1,
            },
            Signer {
                key: pk(11),
                weight: 1,
            },
        ]
        .encode(&mut out);
        2u32.encode(&mut out);
        assert!(decode_exact::<SignerList>(&out).is_err());
    }

    #[test]
    fn a_module_account_can_never_be_signed_for() {
        // There is no key to leak, and the fee pool must stay that way whatever
        // is written into its record.
        let mut pool = Account::module(addr(200), "fee_pool");
        pool.regular_key = Some(pk(9));
        pool.signers = Some(recovery_list());
        assert!(!pool.authorises(&[pk(9)]));
        assert!(!pool.authorises(&[pk(11), pk(12)]));
    }

    #[test]
    fn a_rotated_account_round_trips() {
        let mut account = Account::individual(addr(1));
        account.regular_key = Some(pk(9));
        account.signers = Some(recovery_list());
        account.flags = account.flags.with(AccountFlag::MasterKeyDisabled, true);
        assert_eq!(decode_exact::<Account>(&account.to_bytes()), Ok(account));
    }

    #[test]
    fn flags_survive_the_account_record() {
        let mut account = Account::individual(addr(1));
        account.flags = account.flags.with(AccountFlag::RequireReference, true);
        let decoded = decode_exact::<Account>(&account.to_bytes()).expect("round trips");
        assert_eq!(decoded.requires_reference(), RequiresReference::Yes);
    }

    #[test]
    fn every_account_kind_round_trips() {
        for account in [
            Account::individual(addr(1)),
            Account::with_key(SecretKey::from_bytes(&[7; 32]).public_key()),
            Account::group(addr(50), sample_group()),
            Account::module(addr(200), "fee_pool"),
        ] {
            assert_eq!(decode_exact::<Account>(&account.to_bytes()), Ok(account));
        }
    }
}
