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
use afrolink_primitives::Height;
use afrolink_primitives::codec::{CodecError, Decode, Encode, Reader};

use crate::group::GroupAccount;

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

impl Encode for Account {
    fn encode(&self, out: &mut Vec<u8>) {
        self.address.encode(out);
        self.nonce.encode(out);
        self.kind.encode(out);
        self.last_txn.encode(out);
    }
}

impl Decode for Account {
    fn decode(r: &mut Reader<'_>) -> Result<Self, CodecError> {
        Ok(Self {
            address: Address::decode(r)?,
            nonce: u64::decode(r)?,
            kind: AccountKind::decode(r)?,
            last_txn: Option::<TxPointer>::decode(r)?,
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
