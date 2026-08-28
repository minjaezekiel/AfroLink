//! Genesis: the agreed starting state of the chain.
//!
//! Every node applies the same genesis file independently and must arrive at
//! byte-identical state. If two nodes disagree about the genesis app hash they
//! are, from block 1 onward, on different chains — so this is validated
//! strictly and its output is a single 32-byte commitment that operators can
//! compare out of band before launch.

use afrolink_bank::{Bank, BankError, Issuer};
use afrolink_consensus::ValidatorSet;
use afrolink_crypto::Address;
use afrolink_crypto::hash::Hash32;
use afrolink_primitives::codec::{CodecError, Decode, Encode, Reader};
use afrolink_primitives::{Amount, ChainId, Denom, Height, Timestamp};
use afrolink_state::{KeyValueStore, StoreKey};
use afrolink_types::Account;
use thiserror::Error;

use crate::block::{Block, BlockHeader};

/// Why a genesis file was rejected.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum GenesisError {
    /// No allocations at all, so nobody could ever transact.
    #[error("genesis must allocate to at least one account")]
    NoAllocations,
    /// The same account was allocated the same denomination twice.
    #[error("duplicate allocation for one account and denomination")]
    DuplicateAllocation,
    /// A sovereign denomination was allocated with no issuer registered.
    #[error("allocation of {0} has no registered issuer")]
    UnregisteredDenom(String),
    /// The validator set does not span enough countries.
    #[error("validator set spans {found} countries, {required} required")]
    InsufficientDistribution {
        /// Countries actually represented.
        found: usize,
        /// Countries required.
        required: usize,
    },
    /// One validator holds too large a share of voting power.
    #[error("a validator holds {found} bps of voting power, cap is {cap}")]
    ExcessiveConcentration {
        /// Largest single share, in basis points.
        found: u32,
        /// Permitted cap, in basis points.
        cap: u32,
    },
    /// A bank operation failed while applying allocations.
    #[error(transparent)]
    Bank(#[from] BankError),
}

/// One account's opening balance in one denomination.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Allocation {
    /// Who receives it.
    pub address: Address,
    /// What they receive.
    pub denom: Denom,
    /// How much.
    pub amount: Amount,
}

/// The agreed starting state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Genesis {
    /// Network identifier. Mixed into every signature on this chain.
    pub chain_id: ChainId,
    /// Consensus time of block 0.
    pub genesis_time: Timestamp,
    /// The founding validator set.
    pub validators: ValidatorSet,
    /// Sovereign denominations and their authorised issuers.
    pub issuers: Vec<(Denom, Issuer)>,
    /// Opening balances.
    pub allocations: Vec<Allocation>,
}

/// Governance limits checked at genesis.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GenesisLimits {
    /// Minimum distinct countries the validator set must span.
    pub min_countries: usize,
    /// Maximum share of voting power one validator may hold, in basis points.
    pub max_single_share_bps: u32,
}

impl Default for GenesisLimits {
    /// The mainnet rule from [ADR-0002](../../../docs/adr/0002-consensus.md):
    /// at least 15 countries, no validator above 10% of voting power.
    fn default() -> Self {
        Self {
            min_countries: 15,
            max_single_share_bps: 1_000,
        }
    }
}

impl GenesisLimits {
    /// Limits suitable for a local devnet, where one operator runs everything.
    #[must_use]
    pub const fn devnet() -> Self {
        Self {
            min_countries: 1,
            max_single_share_bps: 10_000,
        }
    }
}

impl Genesis {
    /// Validate the file without touching state.
    ///
    /// # Errors
    /// Returns the first [`GenesisError`] found.
    pub fn validate(&self, limits: GenesisLimits) -> Result<(), GenesisError> {
        if self.allocations.is_empty() {
            return Err(GenesisError::NoAllocations);
        }

        let mut seen: Vec<(&Address, &str)> = self
            .allocations
            .iter()
            .map(|a| (&a.address, a.denom.as_str()))
            .collect();
        seen.sort_unstable();
        let before = seen.len();
        seen.dedup();
        if seen.len() != before {
            return Err(GenesisError::DuplicateAllocation);
        }

        // Every sovereign denomination must name its issuer up front, so no
        // stablecoin can exist on the chain with nobody accountable for it.
        for alloc in &self.allocations {
            if alloc.denom.is_sovereign() && !self.issuers.iter().any(|(d, _)| d == &alloc.denom) {
                return Err(GenesisError::UnregisteredDenom(alloc.denom.to_string()));
            }
        }

        let countries = self.validators.countries_represented();
        if countries < limits.min_countries {
            return Err(GenesisError::InsufficientDistribution {
                found: countries,
                required: limits.min_countries,
            });
        }

        let share = self.validators.max_single_share_bps();
        if share > limits.max_single_share_bps {
            return Err(GenesisError::ExcessiveConcentration {
                found: share,
                cap: limits.max_single_share_bps,
            });
        }

        Ok(())
    }

    /// Apply genesis to an empty store, returning the genesis block.
    ///
    /// # Errors
    /// Returns a [`GenesisError`] if validation or any allocation fails.
    pub fn apply<S: KeyValueStore>(
        &self,
        store: &mut S,
        limits: GenesisLimits,
    ) -> Result<Block, GenesisError> {
        self.validate(limits)?;

        {
            let mut bank = Bank::new(store);
            for (denom, issuer) in &self.issuers {
                bank.register_issuer(denom, issuer)?;
            }
            for alloc in &self.allocations {
                bank.genesis_allocate(&alloc.address, &alloc.denom, alloc.amount)?;
            }
        }

        // Materialise an account record for every allocated address, so a
        // recipient's nonce exists from the first block.
        let mut addresses: Vec<Address> = self.allocations.iter().map(|a| a.address).collect();
        addresses.sort_unstable();
        addresses.dedup();
        for address in addresses {
            store.set_encoded(&StoreKey::account(&address), &Account::individual(address));
        }

        let header = BlockHeader {
            chain_id: self.chain_id.clone(),
            height: Height::GENESIS,
            time: self.genesis_time,
            parent: Hash32::ZERO,
            tx_root: Block::tx_root(&[]),
            app_hash: store.root(),
        };
        Ok(Block {
            header,
            transactions: Vec::new(),
        })
    }

    /// Total allocated for one denomination.
    ///
    /// # Errors
    /// Returns [`GenesisError::Bank`] if the total overflows.
    pub fn total_allocated(&self, denom: &Denom) -> Result<Amount, GenesisError> {
        self.allocations
            .iter()
            .filter(|a| &a.denom == denom)
            .try_fold(Amount::ZERO, |acc, a| {
                acc.checked_add(a.amount)
                    .map_err(|_| BankError::Overflow("genesis/total").into())
            })
    }
}

impl Encode for Allocation {
    fn encode(&self, out: &mut Vec<u8>) {
        self.address.encode(out);
        self.denom.encode(out);
        self.amount.encode(out);
    }
}

impl Decode for Allocation {
    fn decode(r: &mut Reader<'_>) -> Result<Self, CodecError> {
        Ok(Self {
            address: Address::decode(r)?,
            denom: Denom::decode(r)?,
            amount: Amount::decode(r)?,
        })
    }
}

impl Encode for Genesis {
    fn encode(&self, out: &mut Vec<u8>) {
        self.chain_id.encode(out);
        self.genesis_time.encode(out);
        self.validators.encode(out);
        // Pairs are encoded field by field; there is no tuple impl by design.
        #[expect(clippy::cast_possible_truncation, reason = "issuer lists are small")]
        let len = self.issuers.len() as u32;
        len.encode(out);
        for (denom, issuer) in &self.issuers {
            denom.encode(out);
            issuer.encode(out);
        }
        self.allocations.encode(out);
    }
}

impl Decode for Genesis {
    fn decode(r: &mut Reader<'_>) -> Result<Self, CodecError> {
        let chain_id = ChainId::decode(r)?;
        let genesis_time = Timestamp::decode(r)?;
        let validators = ValidatorSet::decode(r)?;
        let count = r.take_len()?;
        let mut issuers = Vec::new();
        for _ in 0..count {
            issuers.push((Denom::decode(r)?, Issuer::decode(r)?));
        }
        Ok(Self {
            chain_id,
            genesis_time,
            validators,
            issuers,
            allocations: Vec::<Allocation>::decode(r)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use afrolink_consensus::{CountryCode, Validator};
    use afrolink_crypto::SecretKey;
    use afrolink_state::MemoryStore;

    fn addr(seed: u8) -> Address {
        Address::from_public_key(&SecretKey::from_bytes(&[seed; 32]).public_key())
    }

    fn kes() -> Denom {
        Denom::sovereign("ke", "kes").expect("valid")
    }

    fn validators(countries: &[&str]) -> ValidatorSet {
        ValidatorSet::new(
            countries
                .iter()
                .enumerate()
                .map(|(i, c)| {
                    #[expect(clippy::cast_possible_truncation, reason = "test fixtures are small")]
                    let seed = (i + 1) as u8;
                    Validator::new(
                        SecretKey::from_bytes(&[seed; 32]).public_key(),
                        100,
                        CountryCode::new(c).expect("valid country"),
                    )
                })
                .collect(),
        )
        .expect("valid set")
    }

    fn genesis() -> Genesis {
        Genesis {
            chain_id: ChainId::new("afrolink-1").expect("valid"),
            genesis_time: Timestamp::from_millis(1_700_000_000_000),
            validators: validators(&["ke", "ng", "za"]),
            issuers: vec![(kes(), Issuer::new(addr(100)))],
            allocations: vec![
                Allocation {
                    address: addr(1),
                    denom: Denom::native(),
                    amount: Amount::from_afri(1_000),
                },
                Allocation {
                    address: addr(2),
                    denom: Denom::native(),
                    amount: Amount::from_afri(500),
                },
                Allocation {
                    address: addr(1),
                    denom: kes(),
                    amount: Amount::from_afri(250),
                },
            ],
        }
    }

    #[test]
    fn the_genesis_app_hash_is_reproducible_on_any_machine() {
        // If two operators compute different app hashes they are on different
        // chains from block 1. This is the check they compare before launch.
        let g = genesis();
        let mut a = MemoryStore::new();
        let mut b = MemoryStore::new();
        let block_a = g.apply(&mut a, GenesisLimits::devnet()).expect("applies");
        let block_b = g.apply(&mut b, GenesisLimits::devnet()).expect("applies");

        assert_eq!(block_a.header.app_hash, block_b.header.app_hash);
        assert_eq!(block_a.header.id(), block_b.header.id());
        assert_eq!(block_a.header.height, Height::GENESIS);
        assert_eq!(block_a.header.parent, Hash32::ZERO);
    }

    #[test]
    fn allocation_order_does_not_change_the_app_hash() {
        let mut g = genesis();
        let mut a = MemoryStore::new();
        let first = g.apply(&mut a, GenesisLimits::devnet()).expect("applies");

        g.allocations.reverse();
        let mut b = MemoryStore::new();
        let second = g.apply(&mut b, GenesisLimits::devnet()).expect("applies");

        assert_eq!(first.header.app_hash, second.header.app_hash);
    }

    #[test]
    fn balances_and_supply_match_the_allocations() {
        let g = genesis();
        let mut store = MemoryStore::new();
        g.apply(&mut store, GenesisLimits::devnet())
            .expect("applies");

        let bank = Bank::new(&mut store);
        assert_eq!(
            bank.balance(&addr(1), &Denom::native()).expect("read"),
            Amount::from_afri(1_000)
        );
        assert_eq!(
            bank.balance(&addr(1), &kes()).expect("read"),
            Amount::from_afri(250)
        );
        assert_eq!(
            bank.total_supply(&Denom::native()).expect("read"),
            Amount::from_afri(1_500),
            "supply must equal the sum of native allocations"
        );
        assert_eq!(
            g.total_allocated(&Denom::native()).expect("sums"),
            Amount::from_afri(1_500)
        );
    }

    #[test]
    fn issuers_are_registered_and_can_mint_after_genesis() {
        let g = genesis();
        let mut store = MemoryStore::new();
        g.apply(&mut store, GenesisLimits::devnet())
            .expect("applies");

        let mut bank = Bank::new(&mut store);
        assert!(bank.issuer(&kes()).expect("read").is_some());
        bank.mint(&addr(100), &addr(3), &kes(), Amount::from_afri(10))
            .expect("issuer can mint");
    }

    #[test]
    fn a_sovereign_denom_with_no_issuer_is_refused() {
        // Otherwise a stablecoin could exist with nobody accountable for it.
        let mut g = genesis();
        g.issuers.clear();
        assert!(matches!(
            g.validate(GenesisLimits::devnet()),
            Err(GenesisError::UnregisteredDenom(_))
        ));
    }

    #[test]
    fn duplicate_allocations_are_refused() {
        let mut g = genesis();
        g.allocations.push(Allocation {
            address: addr(1),
            denom: Denom::native(),
            amount: Amount::from_afri(1),
        });
        assert_eq!(
            g.validate(GenesisLimits::devnet()),
            Err(GenesisError::DuplicateAllocation)
        );
    }

    #[test]
    fn an_empty_genesis_is_refused() {
        let mut g = genesis();
        g.allocations.clear();
        assert_eq!(
            g.validate(GenesisLimits::devnet()),
            Err(GenesisError::NoAllocations)
        );
    }

    #[test]
    fn mainnet_limits_reject_a_geographically_narrow_validator_set() {
        // The ADR-0002 rule, enforced rather than hoped for.
        let g = genesis();
        assert!(matches!(
            g.validate(GenesisLimits::default()),
            Err(GenesisError::InsufficientDistribution {
                found: 3,
                required: 15
            })
        ));
    }

    #[test]
    fn mainnet_limits_reject_a_concentrated_validator_set() {
        // Geographic spread alone is not enough: a set can span 16 countries and
        // still be controlled by one operator holding most of the stake.
        let countries = [
            "ke", "ng", "za", "gh", "tz", "ug", "rw", "et", "sn", "ci", "cm", "zm", "bw", "na",
            "mz", "ml",
        ];
        let members: Vec<Validator> = countries
            .iter()
            .enumerate()
            .map(|(i, c)| {
                #[expect(clippy::cast_possible_truncation, reason = "test fixtures are small")]
                let seed = (i + 1) as u8;
                // The first validator holds half the total power.
                let power = if i == 0 { 1_500 } else { 100 };
                Validator::new(
                    SecretKey::from_bytes(&[seed; 32]).public_key(),
                    power,
                    CountryCode::new(c).expect("valid country"),
                )
            })
            .collect();

        let mut g = genesis();
        g.validators = ValidatorSet::new(members).expect("valid set");
        assert_eq!(
            g.validators.countries_represented(),
            16,
            "distribution rule is satisfied"
        );
        assert!(
            g.validators.max_single_share_bps() > 1_000,
            "but one validator is over the 10% cap"
        );
        assert!(matches!(
            g.validate(GenesisLimits::default()),
            Err(GenesisError::ExcessiveConcentration { .. })
        ));
    }

    #[test]
    fn a_well_formed_mainnet_genesis_passes() {
        let mut g = genesis();
        let countries = [
            "ke", "ng", "za", "gh", "tz", "ug", "rw", "et", "sn", "ci", "cm", "zm", "bw", "na",
            "mz", "ml", "bf", "ne", "td", "so",
        ];
        g.validators = validators(&countries);
        assert_eq!(g.validators.countries_represented(), 20);
        assert_eq!(
            g.validators.max_single_share_bps(),
            500,
            "20 equal validators = 5% each"
        );
        assert_eq!(g.validate(GenesisLimits::default()), Ok(()));
    }

    #[test]
    fn genesis_files_round_trip() {
        let g = genesis();
        assert_eq!(
            afrolink_primitives::codec::decode_exact::<Genesis>(&g.to_bytes()),
            Ok(g)
        );
    }
}
