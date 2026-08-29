//! Human-readable addressing — send to `@amina`, a phone number, or an email.
//!
//! `afri1qzp8h4cthjxue7g0kk4dmz9nvvqhs6xk3nlq2m` is not an interface. Nobody can
//! read it aloud, retype it, or notice that four characters in the middle
//! changed — and in a market where adult literacy runs around two-thirds, a
//! large minority of users cannot read it at all. So aliases are the primary way
//! to name a recipient here, and raw addresses are the fallback rather than the
//! default.
//!
//! Full reasoning:
//! [ADR-0008](../../../docs/adr/0008-human-readable-addressing.md).
//!
//! # The one rule everything else follows from
//!
//! **An alias resolves. It never authorises.**
//!
//! Keys sign; names point. There is no path in this crate from a username or a
//! phone number to a signature, and there is no operation that spends. Losing
//! your SIM cannot lose your money, and stealing one cannot gain it — which
//! matters because SIM-swap fraud is up to 43% of mobile-money fraud in African
//! markets, and rose 327% in Kenya in 2025 alone.
//!
//! # The second rule, which lives outside this crate
//!
//! **A transaction commits to the resolved [`Address`](afrolink_crypto::Address),
//! never to the alias.** A wallet resolves the name, shows the user who they are
//! about to pay, and signs a transfer naming the address. `Message::Transfer` is
//! deliberately unchanged and takes no alias.
//!
//! Anything else would be a live redirect: a rebind landing between signing and
//! inclusion would silently send the money elsewhere. Keeping resolution on the
//! client side also means the alias system touches no consensus-critical
//! structure at all — it is a registry and a lookup, nothing more.
//!
//! # Two kinds of alias, two different problems
//!
//! | | [`name`] — usernames | [`contact`] — phone and email |
//! |---|---|---|
//! | Public? | yes, chosen | no, private identifier |
//! | The attack | visual spoofing | enumeration of the population |
//! | The defence | ASCII-only plus a confusable skeleton | commitments, never the identifier |
//! | Who vouches | first come, first served | a licensed attestor |
//!
//! Conflating them is the mistake. A username is a handle whose whole purpose is
//! to be public; a phone number is an identifier whose exposure is itself the
//! harm. They need opposite treatments, and they get them.

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

pub mod contact;
pub mod name;
pub mod rebind;
pub mod registry;

pub use contact::{
    Attestor, ContactCommitment, ContactError, ContactKind, ContactRecord, PendingRebind,
};
pub use name::{NameError, Skeleton, Username};
pub use rebind::{BindError, Bindings, REBIND_DELAY_BLOCKS};
pub use registry::{NameRecord, Registry, RegistryError};
