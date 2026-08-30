# ADR-0013 — The HTTP transport: giving the query protocol a socket

- **Status:** accepted
- **Date:** 2026-08-30
- **Relates to:** [ADR-0009](0009-developer-payment-surface.md) (developer
  payment surface), [ADR-0011](0011-objective-anchors.md) (what a wallet checks
  against), requirement **R3**, `crates/http`, `crates/rpc`

## Context

`crates/rpc` has been finished and adversarially tested for some time, and its
own documentation names what it is missing:

> Like `crates/consensus`, this crate is a pure function over messages:
> `answer` maps a `Query` and a `ChainView` to a `Response`. A transport —
> HTTP, gRPC, or a socket — is a shell around it.

There was no shell. Every proof this project can produce was reachable only
from a Rust test. Nothing could be checked by a wallet, an explorer, a faucet,
or an x402 facilitator, because there was no way for any of them to ask.

### Why this before validator-to-validator networking

Two things were unbuilt: the client-facing transport and the peer-to-peer layer.
Peer-to-peer is the harder problem and the one that produces a decentralised
network, so it looks like the obvious next step. It was not chosen, and the
reason is worth recording because it is not a technical one.

**The unvalidated risk in this project is not networking.** Gossip is
well-understood engineering: difficult, but nobody is uncertain whether it can
be done. What is genuinely unvalidated is the thesis in
[ADR-0005](0005-african-first-design.md) and
[ADR-0008](0008-human-readable-addressing.md) — that aliases resolve safely for
non-reading users, that a confirmation screen prevents misdirection, that a
32-byte checkpoint works for someone with intermittent connectivity. None of it
has been in front of a person.

A single node with a wallet attached teaches more about whether AfroLink works
than four nodes gossiping with no wallet. And if the alias UX is wrong, that is
better learned before a peer-to-peer layer is hardened around it.

The honest cost: **a chain served by one node is not decentralised**, and this
ADR does not pretend otherwise. It is sequencing, not architecture.

### The shape most BFT chains converge on

CometBFT runs two networks: a peer-to-peer layer among validators, and a
separate HTTP RPC for clients. They have different threat models — a known,
bounded, stake-weighted set on one side; anonymous strangers on the other — and
different traffic. That is the shape this project is heading for too, so
building the client side first is not a detour from the peer-to-peer work; it is
the half of it that was always going to be separate.

## Decision

A new crate, `crates/http`: **blocking, hand-written, strict, and dependency-free
beyond `std`.**

### 1. No async runtime

The workspace contains no `async` anywhere, and that is load-bearing rather than
incidental. `crates/node` is a synchronous `Event -> Vec<Action>` state machine
with no I/O, which is precisely why the simulator in `crates/node/src/sim.rs`
can replay a Byzantine schedule from a `u64` seed and get the same answer on
every machine, forever ([08](../08-adversarial-testing.md)).

Adopting `tokio` to serve a read endpoint would put that at risk in exchange for
a concurrency model this workload does not need. The work here is hashing a
Merkle path — CPU, not waiting — for a few hundred concurrent requests.
Thread-per-connection is the wrong model for a hundred thousand idle websockets
and a perfectly ordinary one for this.

The dependency argument runs the same way. The workspace has **six** direct
external dependencies and 38 external crates in the lockfile — a number this
crate did not change, because it needs nothing outside `std`. It hand-rolls its codec,
bech32, Merkle trees and PRNG specifically to keep the audit surface something a
person can read. Pulling in an async HTTP stack to serve `GET /v1/status` would
undo that for one endpoint.

**Cost, stated plainly:** thread-per-connection has a ceiling, and this one is
[`Config::max_connections`](../../crates/http/src/lib.rs). A node expecting tens
of thousands of concurrent clients needs a different model, and the
`respond`-is-a-pure-function structure is what would make that a replaceable
layer rather than a rewrite.

### 2. Integrity does not live in the transport

This is why plain HTTP is acceptable, and it is the whole architectural payoff
of requirement **R3** — *every state read must be provable to a phone*
([00-research](../00-research.md)).

Nothing in `crates/http` can answer a state query. `ProvedValue` is constructible
only inside `crates/rpc`, by a server that produced a proof from the same tree it
read the value from. A hostile proxy can drop an answer, truncate it, or return
nonsense; it cannot manufacture a balance, because the wallet checks the proof
against a header it verified from commit signatures. **A man in the middle is in
exactly the position of a hostile node, and the light client already assumes
hostile nodes.**

What plain HTTP does cost is **privacy**: an eavesdropper learns which addresses
a wallet asks about. That is real, and it is not solved here. The deployment
answer is a TLS-terminating reverse proxy, as it is for CometBFT RPC. Terminating
TLS in-process would mean a TLS stack, which means `rustls` or `openssl` and
their trees — the one place where the dependency argument above loses, and where
the right answer is to let an audited proxy do it.

### 3. The parser refuses rather than interprets

Request smuggling is not a cryptographic failure. It is two parsers reading one
byte stream as different requests, and every published technique starts from a
construction that some parser tolerates. **A server that tolerates nothing
ambiguous cannot be the disagreeing half.**

So [`wire`](../../crates/http/src/wire.rs) applies the codec's own rule — one
reading per byte string — to a much older and much messier format:

| Refused | Why |
|---|---|
| Bare `LF` line endings | The classic desync |
| Obsolete header folding | A value continues into what another parser calls a header |
| Space before a header colon | `Content-Length : 5` is a header to some parsers and not others |
| **Any** `Transfer-Encoding` | The largest smuggling class, and nothing here needs chunked bodies |
| Repeated or comma-bearing `Content-Length` | Two readings of the body boundary |
| Non-digits in `Content-Length` | `+5` and `0x5` must not be five |
| A stray space in the request line | The target becomes whatever the parser decides |
| Absolute-form targets | Proxy syntax; this is an origin server |
| Repeated headers, repeated query parameters | First-wins and last-wins are two readings |
| Control bytes or invalid UTF-8 after percent-decoding | A newline in a path is never a legitimate query |

Percent-decoding happens **after** the path is split on `/`, so `%2F` cannot
introduce a path separator. Decoding first is how directory traversal gets past a
route table.

The parser is in the fuzz suite ([`crates/fuzz/tests/http.rs`](../../crates/fuzz/tests/http.rs)),
because it is now the first thing an anonymous peer reaches and it runs before
any signature, proof or quorum check. Three properties, ~110 000 inputs:

- **Totality** — arbitrary bytes produce a request or an error, never a panic. A
  panic here is a remote denial of service on a validator, reachable without a
  key.
- **Unique reading** — a parsed request, rendered canonically and re-parsed,
  means the same thing.
- **The boundary ignores what follows** — if bytes parse and leave `rest`
  unread, the same bytes with anything appended parse to the same request and
  leave `rest` plus the appendage. *This* is the property smuggling violates,
  and it is asserted separately because a canonicalising renderer can hide a
  first-wins mistake from a round trip and cannot hide a moved boundary.

### 4. There is no proof-free convenience endpoint, in any format

`crates/rpc` exists to prevent one specific failure:

> One convenience endpoint that returns a balance without a proof, added under
> deadline, and every wallet author will use it because it is smaller and faster.

A JSON renderer is exactly how that failure arrives. So the JSON view carries the
proof, carries the full canonical response bytes, and names the decoded field
**`value_unverified`** — the same deliberately-verbose name the Rust API uses for
its escape hatch, so misuse is as obvious in a wallet's source as it is in
review. There is no shape that emits `{"balance": 2500}` and nothing else, and
[`the_json_view_carries_the_proof_and_names_the_unverified_field`](../../crates/http/tests/serving.rs)
is the test that keeps it that way.

Canonical bytes are the default; JSON is opt-in via `?format=json` or `Accept`.
Metered data is the constraint (`crates/rpc`, research §5), so a client that
forgets to ask does not pay for hex.

### 5. Route shape follows Cosmos, because familiarity is the argument

`/v1/accounts/{address}/balance?denom=` rather than an invented scheme. The
subject goes in the path; everything else goes in the query string — not only
for looks, but because a sovereign denomination is spelled `sov/ke/kes`, and a
slash in a path segment means a percent-encoded `%2F` that intermediaries are
famous for mangling.

Permissive CORS is on by default. It is safe *here specifically*: everything
served is public, proof-carrying chain data with no cookies, no credentials and
no ambient authority, so a browser being allowed to read it grants nothing
`curl` did not already have — and it is what makes an explorer possible without
a proxy in front.

### 6. Limits are refusals, not settings

There is no "unlimited" option anywhere in [`Config`](../../crates/http/src/lib.rs).
A public read endpoint on a validator is the cheapest thing on this network to
point a botnet at, and without a peer layer the only available defence is to make
each connection cost a bounded, known amount: connection count, read and write
timeouts (the slowloris bound), request-line, header and body sizes, and requests
per connection.

Beyond `max_connections` the server refuses with 503 rather than queueing. A
backlog that grows is the same failure with a longer fuse.

## Consequences

**Good.** The proofs are reachable. A wallet, an explorer, a faucet and an x402
facilitator now have something to talk to, and the load-bearing UX thesis can
finally be tested against people rather than asserted. Consensus was not touched,
so the deterministic simulator is intact. The dependency count did not move.

**Bad.** A one-node chain is centralised, and this changes nothing about that.
Privacy depends on a reverse proxy that is not in this repository. And
thread-per-connection has a ceiling that a large deployment will eventually hit.

**Deliberately not done.** **There is no way to submit a transaction.** A wallet
can check its money and cannot yet move it, because submission needs a mempool
and an `Event::Transaction` the node does not have — that is node work, not
transport work, and it is the immediate next item rather than an omission.
No TLS (see §2). No rate limiting per peer, which needs identity the transport
does not have. No witness-log endpoints yet, though `crates/witness` is
transport-free for exactly this reason and they ride on this layer when they
come.

## Revisit if

- Measured load approaches `max_connections` on a real deployment, which is the
  trigger for a different concurrency model — and `respond` being a pure
  function is what would make that a swap rather than a rewrite
- A validator needs to serve clients directly rather than behind a proxy, which
  is when in-process TLS stops being avoidable
- The peer-to-peer layer lands and something in it wants to share this parser.
  It should not: a validator's peers are a known set with keys, and that layer
  gets an authenticated handshake rather than HTTP

## Sources

- [RFC 9110: HTTP semantics](https://datatracker.ietf.org/doc/html/rfc9110)
- [RFC 9112: HTTP/1.1 message syntax and parsing](https://datatracker.ietf.org/doc/html/rfc9112)
- [RFC 7230 §3.3.3: message body length, and the ambiguities that cause desync](https://datatracker.ietf.org/doc/html/rfc7230#section-3.3.3)
- [PortSwigger: HTTP request smuggling](https://portswigger.net/web-security/request-smuggling)
- [James Kettle: HTTP desync attacks (2019)](https://portswigger.net/research/http-desync-attacks-request-smuggling-reborn)
- [CometBFT RPC](https://docs.cometbft.com/main/rpc/)
- [Cosmos SDK gRPC-gateway REST endpoints](https://docs.cosmos.network/main/learn/advanced/grpc_rest)
- [RFC 3986 §2.3: unreserved characters](https://datatracker.ietf.org/doc/html/rfc3986#section-2.3)
