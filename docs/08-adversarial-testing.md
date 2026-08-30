# 08 — Adversarial testing: what it is, and the five defects it found

## What this is not

It is not a load test. There are no sockets yet, so hammering the in-process
simulator would measure the executor rather than the system, and any throughput
number it produced would be marketing.

It also would not be a *security* test if there were. Throughput tells you
nothing about whether a node can be **lied to**, and every security claim this
project makes is about exactly that.

## What it is

Two suites, both ordinary `cargo test`, both deterministic.

**Determinism is the design constraint.** Every case is a pure function of a
`u64` seed, so a failing assertion names the seed that produced it and re-running
that seed reproduces it on any machine, forever. No corpus directory to lose, no
"retry until it passes". That is also why the harness is hand-rolled rather than
a `proptest` or `cargo-fuzz` dependency — the same reason the codec is not serde.

### 1. `crates/fuzz` — bytes from a hostile peer

~112 000 inputs across 28 decoders, plus ~45 000 forged proofs. Three properties:

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

### 2. `crates/node/tests/adversarial.rs` — a hostile scheduler

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

## The five defects

All five were found on the first run, and all five share one root cause:
**a value that is not uniquely determined**, made safe by a convention enforced
somewhere else.

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

### 5. Header time was bounded in one direction only

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

- **No network.** Everything is in-process. Eclipse attacks, peer scoring,
  resource exhaustion and DoS are untestable until libp2p lands.
- **No staking or slashing**, so the *economic* half of the long-range defence is
  a documented parameter rather than an enforced one.
- **The scheduler explores randomly, not exhaustively.** It is not a model
  checker, and a rare interleaving may sit outside any seed tried. TLA+ or Stateright
  over the round state machine would be the honest next step.
- **No timing or side-channel analysis.**
- **The executor is not fuzzed against semantic invariants** — supply
  conservation under arbitrary transaction sequences is the obvious next
  property, and it is not written yet.

## Where this goes

Phase 2 adds libp2p, and with it the first testable network-level attacks. The
harness is deliberately transport-free so it survives that transition: the
delivery rules in `sim.rs` are the same abstraction a real network needs
faults injected through.
