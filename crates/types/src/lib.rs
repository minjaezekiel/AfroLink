//! Accounts, transactions and messages.
//!
//! Two things here are deliberate departures from the account model a chain
//! designed for Western markets would ship, both recorded in
//! [ADR-0005](../../../docs/adr/0005-african-first-design.md):
//!
//! * [`group`] — savings groups (chama, susu, stokvel, tontine, equb, VSLA) are
//!   a **native account type**, not a smart contract, because that is how a very
//!   large share of the continent actually saves.
//! * [`tx::Fee`] — fees are payable in any whitelisted denomination and may be
//!   sponsored by a third party, so nobody has to acquire the native coin before
//!   they can send money.
//!
//! # Who may spend an account
//!
//! [`Account::authorises`] is the answer, and it is a fact about the **account
//! record** rather than about the transaction. That is what lets a key be
//! rotated while the address, the username and every printed QR code stay valid
//! ([ADR-0017](../../../docs/adr/0017-key-rotation-and-signer-lists.md)).
//!
//! [`Transaction::verify_stateless`] proves signatures are genuine and claims
//! nothing beyond it. Both questions have to be asked; neither substitutes for
//! the other.

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

pub mod account;
pub mod group;
pub mod tx;

pub use account::{
    Account, AccountFlag, AccountFlags, AccountKind, AuthorityError, MAX_SIGNERS, Signer,
    SignerList, TxPointer,
};
pub use group::{
    Contribution, FoundingMember, GroupAccount, GroupError, Member, PayoutPolicy, Quorum, Role,
};
pub use tx::{Fee, MAX_SIGNATURES, Message, Transaction, TxBody, TxError, TxSignature};
