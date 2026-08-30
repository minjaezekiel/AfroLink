//! HTTP/1.1 transport for the query protocol.
//!
//! [`crates/rpc`](afrolink_rpc) is a pure function from a [`Query`] to a
//! [`Response`], and says so in its own documentation: *"a transport — HTTP,
//! gRPC, or a socket — is a shell around it"*. This crate is that shell.
//!
//! # What it is allowed to do
//!
//! Move bytes, and refuse. Nothing here can answer a state query, because
//! [`ProvedValue`](afrolink_rpc::ProvedValue) can only be built inside
//! `crates/rpc` by a server that produced a proof from the same tree it read
//! the value from. A hostile or buggy transport can drop an answer, truncate
//! it, or return the wrong status code; it cannot manufacture a balance.
//!
//! That is the whole reason this layer is allowed to be plain HTTP with no
//! transport security of its own. **Integrity does not live here.** It lives in
//! the proof, which is checked against a header the wallet verified from commit
//! signatures. A hostile proxy in the middle is in the same position as a
//! hostile node, and the light client already assumes that.
//!
//! What plain HTTP *does* cost is **privacy**: an eavesdropper learns which
//! addresses a wallet asks about. That is real and it is not solved here — the
//! deployment answer is a TLS-terminating reverse proxy, as it is for CometBFT
//! RPC. Recorded in [ADR-0013](../../../docs/adr/0013-http-transport.md)
//! rather than left implicit.
//!
//! # Why no async runtime
//!
//! The workspace contains no `async` anywhere, and that is load-bearing: the
//! node is a synchronous `Event -> Vec<Action>` state machine, which is exactly
//! why the deterministic simulator in `crates/node/src/sim.rs` can replay a
//! Byzantine schedule from a seed. Pulling an async runtime in for a read-only
//! query endpoint would put that at risk to serve a workload that is a few
//! hundred requests a second of mostly-cached reads.
//!
//! So this is blocking I/O with a bounded thread per connection, `std::net`
//! only, and no new dependency in the tree. `serde` was rejected for the codec
//! for the same reason `tokio` is rejected here.
//!
//! # Why the HTTP parser is hand-written and strict
//!
//! Request smuggling is a parser-disagreement bug: two implementations read one
//! byte stream as different requests. The defence is not cleverness, it is
//! refusing every construction where the reading is not unique — the same rule
//! the canonical codec follows.
//!
//! [`wire`] therefore rejects, rather than interprets: bare `LF` line endings,
//! obsolete header folding, whitespace before a header colon, any
//! `Transfer-Encoding` at all, a repeated or non-numeric `Content-Length`, and
//! a request line with a stray space. None of it is needed to serve a query,
//! and each one is a documented smuggling vector.
//!
//! # Layout
//!
//! | Module | Responsibility |
//! |---|---|
//! | [`wire`] | Parse a request, write a response. Knows nothing about the chain |
//! | [`route`] | Map a path and its parameters to a [`Query`]. Pure |
//! | [`json`] | The developer-facing view, opt-in and proof-carrying |
//! | [`server`] | Sockets, threads, timeouts, limits |
//!
//! [`respond`] is the seam: a pure function from a parsed [`Request`] to an
//! [`HttpResponse`], with no socket in sight. Every routing and status-code
//! test goes through it, so the parts that decide *what* to answer are tested
//! without binding a port.
//!
//! [`Query`]: afrolink_rpc::Query
//! [`Response`]: afrolink_rpc::Response

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

pub mod json;
pub mod route;
pub mod server;
pub mod wire;

use std::time::Duration;

pub use route::{Format, Route};
pub use server::{Handle, Server, respond};
pub use wire::{HttpResponse, Method, Request, Status, WireError};

/// Limits and timeouts for one server.
///
/// Every field is a refusal threshold. There is no "unlimited" setting, on
/// purpose: a public read endpoint on a validator is the cheapest thing on the
/// network to point a botnet at, and the defence available without a network
/// layer is to make each connection cost a known, bounded amount.
#[derive(Debug, Clone)]
pub struct Config {
    /// Connections served at once. Beyond this, new ones are refused with 503
    /// rather than queued, because a queue that grows is the same failure with
    /// a longer fuse.
    pub max_connections: usize,
    /// How long a connection may go without sending bytes.
    ///
    /// This is the slowloris bound: a client that opens a socket and dribbles
    /// one byte a minute holds a thread until this expires.
    pub read_timeout: Duration,
    /// How long a write may block before the peer is abandoned.
    pub write_timeout: Duration,
    /// Largest request line, in bytes.
    pub max_request_line: usize,
    /// Largest single header line, in bytes.
    pub max_header_line: usize,
    /// Largest total header block, in bytes.
    pub max_header_bytes: usize,
    /// Most headers accepted on one request.
    pub max_headers: usize,
    /// Largest request body, in bytes. Only `POST /v1/query` has one.
    pub max_body_bytes: usize,
    /// Requests served on one keep-alive connection before it is closed.
    ///
    /// Keep-alive matters here more than it does on a datacentre network: on a
    /// mobile radio, a fresh connection means waking the radio and paying a
    /// round trip, which is latency and battery. Capping it bounds how long one
    /// client can hold a thread.
    pub max_requests_per_connection: u32,
    /// Value for `Access-Control-Allow-Origin`, or `None` to send no CORS
    /// headers at all.
    ///
    /// Defaults to `*`, which is safe *here specifically*: everything served is
    /// public chain data, there are no cookies, no credentials and no ambient
    /// authority, so a browser being allowed to read it grants nothing it could
    /// not get with `curl`. It is what makes a web explorer possible without a
    /// proxy in front.
    pub allow_origin: Option<String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            max_connections: 256,
            read_timeout: Duration::from_secs(15),
            write_timeout: Duration::from_secs(15),
            max_request_line: 8 * 1024,
            max_header_line: 8 * 1024,
            max_header_bytes: 32 * 1024,
            max_headers: 64,
            // A `Query` is at most a few hundred bytes. The margin is for
            // nothing in particular, which is the point.
            max_body_bytes: 64 * 1024,
            max_requests_per_connection: 512,
            allow_origin: Some("*".to_owned()),
        }
    }
}
