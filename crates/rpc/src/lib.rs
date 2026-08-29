//! The query protocol — how an untrusted server answers a wallet.
//!
//! `crates/light` can verify a proof-carrying answer. This crate is the other
//! half: the request and response types that carry one, and the logic that
//! produces them from a node's state.
//!
//! # The rule this crate exists to enforce
//!
//! Requirement **R3** says every state read must be provable to a phone. That is
//! easy to state and easy to erode — one convenience endpoint that returns a
//! balance without a proof, added under deadline, and every wallet author will
//! use it because it is smaller and faster.
//!
//! So the guarantee is structural rather than a matter of discipline:
//! [`ProvedValue`] is the only way a state value crosses this boundary, it can
//! only be constructed by a server that produced a proof alongside it, and the
//! value cannot be read out except through [`ProvedValue::verify`], which takes
//! a [`LightClient`](afrolink_light::LightClient) and checks the proof against a
//! header the client trusts. There is one escape hatch,
//! [`ProvedValue::value_unverified`], named so that its use is obvious in review.
//!
//! # There is no networking here
//!
//! Like `crates/consensus`, this crate is a pure function over messages:
//! [`answer`] maps a [`Query`] and a [`ChainView`] to a [`Response`]. A
//! transport — HTTP, gRPC, or a socket — is a shell around it, and keeping it
//! out means the protocol is testable against an adversary without one.
//!
//! Both types have a canonical encoding rather than JSON on the wire. Research
//! §5: data is the one resource that is genuinely affordable in this market, and
//! it is still metered. A JSON view for developers belongs in the transport,
//! where its cost is opt-in.
//!
//! # What a client must not take from a server
//!
//! A response deliberately does **not** tell a client which key it answered.
//! The client already knows — it built the query — so it reconstructs the
//! [`StoreKey`](afrolink_state::StoreKey) locally and verifies against that. A
//! server that echoed the key back could otherwise answer a question the client
//! did not ask and have the proof check out.

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

pub mod query;
pub mod server;

pub use query::{ProvedValue, Query, QueryError, Response, SignedHeader, Status};
pub use server::{ChainView, answer};
