//! Phone and email bindings, from a genesis file a real network could ship.
//!
//! `crates/alias` had two halves. Usernames worked: `RegisterName` is a message
//! and anyone can send it. The contact half — phone numbers, email addresses,
//! the whole ADR-0008 privacy and SIM-swap design — was **inert**, and had been
//! since it was written. `AttestContact` requires the sender to be a registered
//! attestor; `Bindings::register_attestor` was called from tests and from
//! nothing else. No genesis field, no message. So no attestor could exist on a
//! real chain, so no contact could ever be bound, so the 72-hour veto window
//! and the recovery path protected a feature nobody could switch on.
//!
//! Genesis now licenses attestors the way it licenses issuers — a licensed
//! institution named by the people starting the network. These tests drive the
//! whole lifecycle from that file through ordinary signed transactions.
//!
//! See [ADR-0008](../../../docs/adr/0008-human-readable-addressing.md) for the
//! design and [ADR-0021](../../../docs/adr/0021-licensing-attestors.md) for why
//! it sat unreachable.

#![allow(
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "tests assert on known-good fixtures; a panic there is a failed test, not a halted node"
)]

use afrolink_alias::rebind::REBIND_DELAY_BLOCKS;
use afrolink_alias::{Attestor, Bindings, ContactCommitment, ContactKind};
use afrolink_bank::Issuer;
use afrolink_consensus::{Validator, ValidatorSet};
use afrolink_crypto::{Address, SecretKey};
use afrolink_executor::{Allocation, BlockContext, Executor, Genesis, GenesisError, GenesisLimits};
use afrolink_primitives::{Amount, ChainId, CountryCode, Denom, Height, Timestamp};
use afrolink_state::MemoryStore;
use afrolink_types::{Fee, Message, Transaction, TxBody};

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

/// The mobile network operator, licensed at genesis to attest bindings.
const MNO: u8 = 90;
/// The person whose number it is.
const OWNER: u8 = 1;
/// The account a SIM-swap attacker controls.
const ATTACKER: u8 = 66;
/// Where a genuine recovery moves the number to.
const NEW_PHONE: u8 = 2;

/// The pepper an attestor holds off-chain. It never reaches the ledger.
const PEPPER: &[u8] = b"a-sixteen-byte-pepper-or-longer";
const NUMBER: &str = "+254712345678";

fn sk(seed: u8) -> SecretKey {
    SecretKey::from_bytes(&[seed; 32])
}

fn addr(seed: u8) -> Address {
    Address::from_public_key(&sk(seed).public_key())
}

fn chain() -> ChainId {
    ChainId::new("afrolink-1").unwrap()
}

fn kes() -> Denom {
    Denom::sovereign("ke", "kes").unwrap()
}

fn ctx(height: u64) -> BlockContext {
    BlockContext {
        height: Height(height),
        time: Timestamp::from_millis(1_700_000_000_000 + height * 1_000),
    }
}

fn safaricom() -> Attestor {
    Attestor {
        country: CountryCode::new("ke").expect("valid country"),
        name: "Safaricom".to_owned(),
        active: true,
    }
}

fn validators() -> ValidatorSet {
    ValidatorSet::new(vec![Validator::new(
        sk(200).public_key(),
        100,
        CountryCode::new("ke").unwrap(),
    )])
    .unwrap()
}

/// A genesis file that licenses `attestors` and funds everyone for fees.
fn genesis_with(attestors: Vec<(Address, Attestor)>) -> Genesis {
    Genesis {
        chain_id: chain(),
        genesis_time: Timestamp::from_millis(1_700_000_000_000),
        validators: validators(),
        issuers: vec![(kes(), Issuer::new(addr(100)))],
        attestors,
        council: afrolink_executor::Council::devnet(addr(1)),
        params: afrolink_executor::ChainParams::devnet(),
        allocations: [MNO, OWNER, ATTACKER, NEW_PHONE, 3]
            .iter()
            .map(|w| Allocation {
                address: addr(*w),
                denom: kes(),
                amount: Amount::from_afri(100),
            })
            .collect(),
    }
}

/// Apply a genesis licensing Safaricom, and return the running state.
fn chain_with_an_attestor() -> MemoryStore {
    let mut store = MemoryStore::new();
    genesis_with(vec![(addr(MNO), safaricom())])
        .apply(&mut store, GenesisLimits::devnet())
        .expect("genesis applies");
    store
}

fn phone() -> ContactCommitment {
    ContactCommitment::new(ContactKind::Phone, NUMBER, PEPPER).unwrap()
}

fn tx(sender: u8, nonce: u64, messages: Vec<Message>) -> Transaction {
    TxBody {
        chain_id: chain(),
        sender: addr(sender),
        nonce,
        valid_until: Height(u64::MAX),
        fee: Fee::new(Amount::from_units(1_000), kes()),
        messages,
        memo: String::new(),
    }
    .sign(&sk(sender))
}

fn resolved(store: &mut MemoryStore) -> Option<Address> {
    Bindings::new(store)
        .resolve(&phone())
        .unwrap()
        .map(|r| r.address)
}

// ---------------------------------------------------------------------------
// Licensing
// ---------------------------------------------------------------------------

#[test]
fn a_genesis_licensed_attestor_can_bind_a_number_and_nobody_else_can() {
    let mut store = chain_with_an_attestor();
    let exec = Executor::new(chain());

    // Anyone may *try*. The registry is what decides, and it is the only thing
    // standing between "an operator vouches for this number" and "whoever pays
    // a fee vouches for this number".
    let out = exec.execute_block(
        &mut store,
        ctx(1),
        &[tx(
            ATTACKER,
            0,
            vec![Message::AttestContact {
                commitment: phone(),
                address: addr(ATTACKER),
            }],
        )],
    );
    assert_eq!(
        out.succeeded(),
        0,
        "an unlicensed account is not an attestor"
    );
    assert_eq!(resolved(&mut store), None);

    let out = exec.execute_block(
        &mut store,
        ctx(2),
        &[tx(
            MNO,
            0,
            vec![Message::AttestContact {
                commitment: phone(),
                address: addr(OWNER),
            }],
        )],
    );
    assert_eq!(out.succeeded(), 1, "{:?}", out.outcomes[0].result);
    assert_eq!(resolved(&mut store), Some(addr(OWNER)));
}

#[test]
fn a_chain_that_licenses_nobody_can_bind_nothing() {
    // The state this was in until now, kept as a test so the difference is
    // visible: every message in the contact half fails closed, and the failure
    // is a refusal rather than a silent success.
    let mut store = MemoryStore::new();
    genesis_with(Vec::new())
        .apply(&mut store, GenesisLimits::devnet())
        .expect("a chain may licence nobody");
    let exec = Executor::new(chain());

    let out = exec.execute_block(
        &mut store,
        ctx(1),
        &[tx(
            MNO,
            0,
            vec![Message::AttestContact {
                commitment: phone(),
                address: addr(OWNER),
            }],
        )],
    );
    assert_eq!(out.succeeded(), 0);
    assert_eq!(resolved(&mut store), None);
}

#[test]
fn a_genesis_naming_one_attestor_twice_is_refused() {
    // Two records for one address is two answers to "is this account licensed",
    // and the one that wins would depend on iteration order.
    let genesis = genesis_with(vec![
        (addr(MNO), safaricom()),
        (
            addr(MNO),
            Attestor {
                name: "Airtel".to_owned(),
                ..safaricom()
            },
        ),
    ]);
    assert!(matches!(
        genesis.validate(GenesisLimits::devnet()),
        Err(GenesisError::DuplicateAttestor(_))
    ));
}

#[test]
fn a_genesis_licensing_an_already_suspended_attestor_is_refused() {
    // It would be an entry nothing could ever activate: suspension is
    // governance's job, and governance does not exist. Better to refuse the
    // file than to ship a network with a dead registry row in it.
    let genesis = genesis_with(vec![(
        addr(MNO),
        Attestor {
            active: false,
            ..safaricom()
        },
    )]);
    assert!(matches!(
        genesis.validate(GenesisLimits::devnet()),
        Err(GenesisError::SuspendedAttestor(_))
    ));
}

// ---------------------------------------------------------------------------
// Privacy — the chain must never learn the number
// ---------------------------------------------------------------------------

#[test]
fn the_ledger_never_holds_the_phone_number_it_resolves() {
    // A national number space is about 10^9, so a bare hash is a rainbow table
    // with extra steps. The chain stores a commitment under a pepper only the
    // attestor holds; resolution runs off-chain against a rate-limited service.
    // Safaricom began masking numbers in M-Pesa in 2026 with the CBK's
    // approval, and publishing them on a public ledger would be moving in the
    // opposite direction to the incumbent regulator.
    let mut store = chain_with_an_attestor();
    let exec = Executor::new(chain());
    exec.execute_block(
        &mut store,
        ctx(1),
        &[tx(
            MNO,
            0,
            vec![Message::AttestContact {
                commitment: phone(),
                address: addr(OWNER),
            }],
        )],
    );

    let bytes = afrolink_state::KeyValueStore::get(
        &store,
        &afrolink_state::StoreKey::contact(phone().as_hash()),
    )
    .expect("the binding is stored");
    for fragment in [
        NUMBER.as_bytes(),
        b"712345678",
        b"254712345678",
        &PEPPER[..8],
    ] {
        assert!(
            !bytes.windows(fragment.len()).any(|w| w == fragment),
            "the stored record must not contain {:?}",
            String::from_utf8_lossy(fragment)
        );
    }

    // And a commitment cannot be recomputed without the pepper, so scraping the
    // chain yields nothing to guess against.
    let guessed =
        ContactCommitment::new(ContactKind::Phone, NUMBER, b"a-different-pepper-entirely").unwrap();
    assert_ne!(guessed, phone());
}

// ---------------------------------------------------------------------------
// The SIM-swap defence, now reachable
// ---------------------------------------------------------------------------

/// Bind the number to its owner and return the running chain.
fn bound() -> (MemoryStore, Executor) {
    let mut store = chain_with_an_attestor();
    let exec = Executor::new(chain());
    let out = exec.execute_block(
        &mut store,
        ctx(1),
        &[tx(
            MNO,
            0,
            vec![Message::AttestContact {
                commitment: phone(),
                address: addr(OWNER),
            }],
        )],
    );
    assert_eq!(out.succeeded(), 1);
    (store, exec)
}

#[test]
fn a_swapped_sim_gets_a_request_the_real_owner_can_refuse() {
    // The claim ADR-0008 makes, now exercised end to end from a genesis file:
    // possession of the number is not possession of the account. SIM-swap fraud
    // rose 327% in Kenya in 2025 and is up to 43% of mobile-money fraud in
    // African markets — binding spending power to a number would import the
    // single largest fraud vector in African mobile money straight into the
    // chain.
    let (mut store, exec) = bound();

    // The attacker holds the SIM and persuades the operator to move it.
    let out = exec.execute_block(
        &mut store,
        ctx(2),
        &[tx(
            MNO,
            1,
            vec![Message::RequestRebind {
                commitment: phone(),
                new_address: addr(ATTACKER),
            }],
        )],
    );
    assert_eq!(out.succeeded(), 1, "the request is allowed to be made");
    assert_eq!(
        resolved(&mut store),
        Some(addr(OWNER)),
        "but it changes nothing yet — a payment today goes where the number \
         points today"
    );

    // The owner still holds the key, sees the request, and refuses it.
    let out = exec.execute_block(
        &mut store,
        ctx(3),
        &[tx(
            OWNER,
            0,
            vec![Message::VetoRebind {
                commitment: phone(),
            }],
        )],
    );
    assert_eq!(out.succeeded(), 1);

    // Even long after the delay would have run, nothing moves.
    let out = exec.execute_block(
        &mut store,
        ctx(4 + REBIND_DELAY_BLOCKS),
        &[tx(
            ATTACKER,
            0,
            vec![Message::ApplyRebind {
                commitment: phone(),
            }],
        )],
    );
    assert_eq!(out.succeeded(), 0, "there is nothing pending to apply");
    assert_eq!(resolved(&mut store), Some(addr(OWNER)));
}

#[test]
fn only_the_currently_bound_account_may_veto() {
    // Otherwise the attacker vetoes the owner's own recovery, and the defence
    // works in exactly the wrong direction.
    let (mut store, exec) = bound();
    exec.execute_block(
        &mut store,
        ctx(2),
        &[tx(
            MNO,
            1,
            vec![Message::RequestRebind {
                commitment: phone(),
                new_address: addr(ATTACKER),
            }],
        )],
    );
    let out = exec.execute_block(
        &mut store,
        ctx(3),
        &[tx(
            ATTACKER,
            0,
            vec![Message::VetoRebind {
                commitment: phone(),
            }],
        )],
    );
    assert_eq!(out.succeeded(), 0);
}

#[test]
fn a_genuine_recovery_completes_because_the_owner_cannot_veto() {
    // The other half, and the reason the delay is a delay rather than a
    // requirement to consent: the case this exists for is a user who has lost
    // the key the number is moving away from. If a rebind needed the old
    // account's approval, real recovery would be impossible.
    let (mut store, exec) = bound();

    exec.execute_block(
        &mut store,
        ctx(2),
        &[tx(
            MNO,
            1,
            vec![Message::RequestRebind {
                commitment: phone(),
                new_address: addr(NEW_PHONE),
            }],
        )],
    );

    // Too early: the veto window is still open.
    let out = exec.execute_block(
        &mut store,
        ctx(3),
        &[tx(
            NEW_PHONE,
            0,
            vec![Message::ApplyRebind {
                commitment: phone(),
            }],
        )],
    );
    assert_eq!(out.succeeded(), 0);
    assert_eq!(resolved(&mut store), Some(addr(OWNER)));

    // The window closes with no veto, because nobody holds the old key.
    let out = exec.execute_block(
        &mut store,
        ctx(3 + REBIND_DELAY_BLOCKS),
        &[tx(
            3,
            0,
            vec![Message::ApplyRebind {
                commitment: phone(),
            }],
        )],
    );
    assert_eq!(out.succeeded(), 1, "{:?}", out.outcomes[0].result);
    assert_eq!(
        resolved(&mut store),
        Some(addr(NEW_PHONE)),
        "the number reaches the account its owner can actually sign for"
    );
}

#[test]
fn an_alias_resolves_and_never_authorises() {
    // The line ADR-0005 §D.1 draws, stated as a test. Holding the number that
    // resolves to an account confers nothing over that account: no spend, no
    // key change, no recovery. The binding is a signpost, not a credential.
    let (mut store, exec) = bound();

    let out = exec.execute_block(
        &mut store,
        ctx(2),
        &[
            // The attestor that vouched for the binding cannot spend from it.
            tx(
                MNO,
                1,
                vec![Message::Transfer {
                    to: addr(ATTACKER),
                    denom: kes(),
                    amount: Amount::from_afri(1),
                    reference: None,
                }],
            ),
        ],
    );
    // That transfer moves the *attestor's own* money, which is fine — the point
    // is that no message exists that lets it move the owner's.
    assert_eq!(out.succeeded(), 1);
    let owner_balance = afrolink_bank::BankView::new(&store)
        .balance(&addr(OWNER), &kes())
        .unwrap();
    assert_eq!(
        owner_balance,
        Amount::from_afri(100),
        "the bound account is untouched by anything the attestor can do"
    );

    // And revoking a binding is the bound account's call, not the attestor's.
    let out = exec.execute_block(
        &mut store,
        ctx(3),
        &[tx(
            MNO,
            2,
            vec![Message::RevokeContact {
                commitment: phone(),
            }],
        )],
    );
    assert_eq!(out.succeeded(), 0, "the attestor cannot unbind at will");

    let out = exec.execute_block(
        &mut store,
        ctx(4),
        &[tx(
            OWNER,
            0,
            vec![Message::RevokeContact {
                commitment: phone(),
            }],
        )],
    );
    assert_eq!(out.succeeded(), 1, "the holder can walk away from it");
    assert_eq!(resolved(&mut store), None);
}
