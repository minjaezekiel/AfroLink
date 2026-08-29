//! The developer-facing payment surface.
//!
//! Everything below `crates/pay` is protocol. This crate is the part a developer
//! integrating "accept AFRI" actually touches, and it exists because adoption is
//! decided by how much work the *second* hour of integration is.
//!
//! Two primitives, both small on purpose:
//!
//! * [`request`] — [`PaymentRequest`] and the `afri:` URI scheme. One string a
//!   merchant emits into a link, a QR code or an HTTP `402` challenge, that any
//!   wallet understands. Modelled on BIP-21 and ERC-681, which are the reason
//!   "scan to pay" works at all.
//! * [`reference`] — [`PaymentReference`], the machine-readable tag an exchange
//!   or merchant reconciles against. XRPL's destination tag, which is the
//!   feature that lets one address serve millions of customers.
//!
//! # There is no SDK here, and that is the point
//!
//! A payment request is a string. Parsing one needs no network, no key, no
//! account with us, and no dependency beyond this crate. A merchant who can
//! print a QR code can accept payment; a developer who can read a URI can
//! integrate. The moment integration requires an API key, we have built the
//! thing we set out to replace.
//!
//! # What a URI is not
//!
//! A payment request is **untrusted input** — from a poster, an email, a
//! compromised page. It is a request, never an instruction. A wallet resolves
//! the payee, shows the user who they are about to pay
//! ([ADR-0008](../../../docs/adr/0008-human-readable-addressing.md)), and only
//! then signs a transaction naming a resolved [`Address`](afrolink_crypto::Address).
//!
//! Nothing in this crate can move money, and nothing in it is consensus-critical.

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

pub mod reference;
pub mod request;

pub use reference::{PaymentReference, RequiresReference};
pub use request::{MAX_TEXT_LEN, Payee, PaymentRequest, RequestError, SCHEME};
