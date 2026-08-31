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
}

impl AccountFlag {
    /// Every flag, in bit order. Exhaustive by construction.
    pub const ALL: &'static [Self] = &[Self::RequireReference];

    /// This flag's bit in an [`AccountFlags`] word.
    ///
    /// **Never renumber one.** The bit is in the state tree, so changing it
    /// changes every state root and silently reinterprets existing accounts.
    #[must_use]
    pub const fn bit(self) -> u32 {
        match self {
            Self::RequireReference => 1 << 0,
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
    const KNOWN: u32 = AccountFlag::RequireReference.bit();

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

impl Encode for Account {
    fn encode(&self, out: &mut Vec<u8>) {
        self.address.encode(out);
        self.nonce.encode(out);
        self.kind.encode(out);
        self.last_txn.encode(out);
        self.flags.encode(out);
    }
}

impl Decode for Account {
    fn decode(r: &mut Reader<'_>) -> Result<Self, CodecError> {
        Ok(Self {
            address: Address::decode(r)?,
            nonce: u64::decode(r)?,
            kind: AccountKind::decode(r)?,
            last_txn: Option::<TxPointer>::decode(r)?,
            flags: AccountFlags::decode(r)?,
        })
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
        assert_eq!(AccountFlags::from_bits(0b11), None);

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
