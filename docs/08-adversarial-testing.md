# 08 — Adversarial testing: what it is, and the defects it found

## What this is not

It is not a load test. There are sockets now
([ADR-0013](adr/0013-http-transport.md)), so hammering one is finally possible —
and a throughput number from one process on one laptop would still be marketing.

It also would not be a *security* test. Throughput tells you nothing about
whether a node can be **lied to**, and every security claim this project makes
is about exactly that.

## What it is

Three suites, all ordinary `cargo test`, all deterministic.

**Determinism is the design constraint.** Every case is a pure function of a
`u64` seed, so a failing assertion names the seed that produced it and re-running
that seed reproduces it on any machine, forever. No corpus directory to lose, no
"retry until it passes". That is also why the harness is hand-rolled rather than
a `proptest` or `cargo-fuzz` dependency — the same reason the codec is not serde.

### 1. `crates/fuzz/tests/codec.rs` — bytes from a hostile peer

~210 000 inputs across 53 decoder fixtures, plus ~45 000 forged proofs. Three
properties:

| Property | What it prevents |
|---|---|
| **Canonicality** — if bytes decode, re-encoding reproduces *those exact bytes* | Two encodings of one value: two honest nodes hash the same object differently, and the chain splits |
| **Truncation is rejected** — every prefix of a valid encoding fails | A decoder reading past the end, or substituting a default for a field nobody sent |
| **Trailing bytes are rejected** | A payload one implementation ignores and another reads |

Plus soundness of every verifier a client relies on: state proofs, inclusion
proofs, consistency proofs, commits, signed tree heads, signatures. Soundness is
a *negative* property — no forged proof verifies — which hand-picked fixtures are
poorly suited to.

Panics need no assertion. A panic in a decoder *is* the failure, which is why the
workspace denies `unwrap`/`expect`/`panic` outside tests.

### 2. `crates/fuzz/tests/http.rs` — malformed requests

Added with [ADR-0013](adr/0013-http-transport.md), because the HTTP parser is now
the **first thing an anonymous peer reaches** — it runs before any signature,
proof or quorum check, and a panic in it is a remote denial of service on a
validator, reachable without a key.

~110 000 inputs: mutated real requests, spliced pairs, and uniform noise. Three
properties, the first two carried over from the codec suite:

| Property | What it prevents |
|---|---|
| **Totality** — arbitrary bytes produce a request or an error | A crash reachable by anyone who can open a socket |
| **Unique reading** — a parsed request, re-rendered and re-parsed, means the same thing | Two components disagreeing about what a request said |
| **The boundary ignores what follows** — appending bytes changes neither the request nor where it ended | **Request smuggling.** This is the one that matters, and it is asserted separately because a canonicalising renderer can hide a first-wins mistake from a round trip and cannot hide a moved boundary |

The parser is written to refuse rather than interpret — bare `LF`, folded
headers, any `Transfer-Encoding`, repeated `Content-Length`, absolute-form
targets. That is the codec's rule, *one reading per byte string*, applied to a
much older and much messier format. `crates/http/tests/serving.rs` then checks
the refusals survive contact with a real socket, a thread pool and a keep-alive
connection, which is where a parser's guarantees usually leak.

The `Query` and `Response` types joined the codec suite at the same time as
[ADR-0014](adr/0014-payment-history-and-the-mempool.md). They are the only
encodings on this chain that cross a socket in **both** directions, and they had
been outside it.

### 3. `crates/node/tests/adversarial.rs` — a hostile scheduler

The scheduler is the adversary: it decides who hears what, and in what order.
[`sim.rs`](../crates/node/src/sim.rs) gained partitions, packet loss, reordering
and message injection.

Injection is how a Byzantine validator is expressed. Rather than modelling a
dishonest node, a test signs conflicting votes with a **real validator key** and
hands one to each half of the network. That is strictly stronger than a
misbehaving `Node`, because it is not limited to what the honest state machine
can emit.

Every scenario attacks **one** invariant:

> **Agreement — no two nodes commit different blocks at the same height.**

Liveness is *expected* to break under most of them. A partitioned network should
stall. Confusing the two is how a consensus test ends up asserting the wrong
thing, so progress is only required where it is genuinely guaranteed.

```bash
cargo test                                    # ~56s, default depth
AFROLINK_CAMPAIGN=25 cargo test --release     # ~1 300 schedules, ~9s
```

## The defects

Four the fuzzer found on its first run; two more turned up elsewhere and are
recorded alongside them because **all six share one root cause**: a value that
is not uniquely determined, made safe by a convention enforced somewhere else.

That is the finding worth carrying forward — not any individual bug, but that
the same shape keeps reappearing wherever untrusted input becomes a value.

### 1 & 2. Decoders that normalised instead of rejecting

`Username::decode` lowercased; `ValidatorSet::decode` sorted. Both route through
a constructor that is *right* for a caller assembling a value and *wrong* at the
decode boundary:

- `aMina` and `amina` were two encodings of one username.
- Every permutation of a membership was a valid encoding of one validator set.

The codec's own rule, stated at [codec.rs:82](../crates/primitives/src/codec.rs),
is that there is exactly one encoding of any value. The fuzzer found two places
it did not hold.

**Live impact: none.** Every call site re-encodes before hashing rather than
hashing received bytes, so `Transaction::id()` and `sign_doc()` are computed over
the canonical form. But that is a safety property held together by discipline at
every call site, and one future site that hashes what it received reintroduces
transaction malleability.

Where it mattered most was **genesis**: operators publish the genesis file's hash
before launch, and with `n!` encodings of the validator set that hash identified
no unique file.

**Fixed:** both decoders now refuse anything they would have to change.

### 3 & 4. Proofs that did not bind their own size

`MerkleProof::verify(root, leaf)` accepted `(index 17, total 64)` and
`(index 17, total 33)` identically — the sibling list does not determine the
tree's size, so both replay the same left/right walk. `ConsistencyProof` had the
same shape: `9 → 40` and `9 → 39` verify against each other's proofs.

This is not a forgery. The leaf really is committed either way. But it means a
proof's own `index`, `total`, `old_size` and `new_size` are **prover-chosen**, so
a caller reading them off the proof learns nothing.

RFC 6962 avoids this by treating the leaf index and tree size as things the
*verifier already knows* — from a signed tree head, or from having asked for that
index. Carrying them inside the proof is what created the ambiguity.

**Live impact: none.** Both primitives had exactly one production caller
([`audit.rs`](../crates/witness/src/audit.rs)), and it happened to check both
fields against the signed head. But the next caller is the one that serves "your
payment is in block N" to wallets, and that is precisely the caller likely to
trust the proof's own fields.

**Fixed:** both `verify` methods now take the expected position and sizes as
parameters, so no caller has to remember.

**The caller that was anticipated here has since arrived**, and the note held
up. [`ProvedTransaction`](../crates/rpc/src/query.rs) serves exactly *"your
payment is in block N"*. Inclusion is proved — the leaf is the transaction's own
id, so a substitution fails — but the verifier knows only the root and the id,
never the position, so `index` and `total` are still prover-chosen. That is
stated in the type's own documentation rather than left for a caller to
discover, and a client that needs the position verified fetches the block and
recomputes the root itself.

### 5. The same defect again, at a new boundary

Not a sixth defect so much as the first one turning up somewhere else, which is
the more useful observation.

`Username::new` lower-cases, which is right for a caller assembling a value and
wrong at a decode boundary — exactly the finding above. When
[ADR-0013](adr/0013-http-transport.md) added URLs, `/v1/names/AMINA` and
`/v1/names/amina` became two spellings of one lookup: two cache entries, two log
lines, and a wallet that could display `@AMINA` for a record reading `amina` — on
the screen whose entire job is letting a user recognise who they are paying.

**Fixed** the same way, in
[`route.rs`](../crates/http/src/route.rs): the edge refuses any spelling the
constructor would have to change.

The lesson is that "normalise for constructors, refuse at boundaries" is not a
property of the decoder. It is a property of *every* place untrusted input
becomes a value, and each new boundary has to be checked against it.

### 6. Header time was bounded in one direction only

Found earlier, during [ADR-0011](adr/0011-objective-anchors.md), and recorded
here because it is the same class. Monotonicity stopped an attacker *rewinding*
the trusting-period clock; nothing stopped a header dated next year parking the
deadline in the future and keeping a client trusting a chain that stopped months
ago.

**Fixed:** `MAX_CLOCK_DRIFT_MS`, with `a_header_dated_in_the_future_is_refused`.

## What this does not prove

Nothing here proves the chain is secure. It falsifies specific claims, and
failed to falsify others; that is all a test can do.

Named gaps, so they are not mistaken for coverage:

- ~~No network~~ — **partly closed.** The client transport exists and is
  fuzzed; its limits (connection cap, slowloris timeout, body and header
  bounds) are asserted over real sockets. What remains untestable is the
  **peer** layer: eclipse attacks, peer scoring and gossip amplification need
  validators that can talk to each other, which they still cannot.
- **No load test, and still no throughput number.** The transport can now be
  hammered, which makes it tempting. A number from one process on one machine
  would measure this laptop.
- ~~No staking or slashing~~ — **closed** by
  [ADR-0012](adr/0012-staking-and-slashing.md). Unbonding now locks real money,
  equivocation is slashed, and the staking types are in the fuzz suite. What is
  still untested is the *economics*: whether 5% and 21 days are the right
  numbers is a question about operator behaviour, not about code.
- **The scheduler explores randomly, not exhaustively.** It is not a model
  checker, and a rare interleaving may sit outside any seed tried. TLA+ or Stateright
  over the round state machine would be the honest next step.
- **No timing or side-channel analysis.**
- **The executor is not fuzzed against semantic invariants** — supply
  conservation under arbitrary transaction sequences is the obvious next
  property, and it is not written yet.
- **History cannot be verified at all**, by anyone. A node that omits an entry
  is not caught by any test here, because there is nothing to catch it *with*:
  the index is not consensus state and no header commits to it
  ([ADR-0014](adr/0014-payment-history-and-the-mempool.md)). What is tested is
  the weaker property that every entry is *checkable* — the id turns into an
  inclusion proof, and a substituted transaction fails it.
- **The mempool is not fuzzed.** Its limits are unit-tested and its insert path
  runs full stateless verification, but nobody has thrown a hostile sequence of
  submissions at it under the scheduler.

## Where this goes

Phase 2 adds the validator-to-validator layer, and with it the network-level
attacks that need peers rather than clients: eclipse, peer scoring, gossip
amplification. The harness is deliberately transport-free so it survives that
transition — the delivery rules in `sim.rs` are the same abstraction a real
network needs faults injected through.
