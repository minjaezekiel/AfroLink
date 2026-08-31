# 08 — Adversarial testing: what it is, and the defects it found

## What this is not

It is not a load test. There are sockets now
([ADR-0013](adr/0013-http-transport.md)), so hammering one is finally possible —
and a throughput number from one process on one laptop would still be marketing.

It also would not be a *security* test. Throughput tells you nothing about
whether a node can be **lied to**, and every security claim this project makes
is about exactly that.

## What it is

Four suites, all ordinary `cargo test`, all deterministic.

**Determinism is the design constraint.** Every case is a pure function of a
`u64` seed, so a failing assertion names the seed that produced it and re-running
that seed reproduces it on any machine, forever. No corpus directory to lose, no
"retry until it passes". That is also why the harness is hand-rolled rather than
a `proptest` or `cargo-fuzz` dependency — the same reason the codec is not serde.

### 1. `crates/fuzz/tests/codec.rs` — bytes from a hostile peer

~232 000 inputs across 58 decoder fixtures, plus ~45 000 forged proofs. Three
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

`TxReceipt` joined with [ADR-0015](adr/0015-committed-outcomes-and-provable-history.md),
and is the sharpest instance of the canonicality rule yet: it is hashed into a
block header, and its `touched` field is a *set* encoded as a list. A decoder
that sorted it rather than refusing an out-of-order one would give two honest
nodes two `outcome_root`s for the same execution — a chain split, arriving
through a convenience.

### 3. `crates/fuzz/tests/ledger.rs` — valid transactions, in hostile sequences

The suite that asks the *second* question, written because §8–15 proved the
first one was not enough. It generates sequences of well-formed, correctly
signed transactions from a seed — transfers, group creation, contributions,
payouts, bonding, unbonding, flag changes, and sponsored fees both genuine and
forged — and asserts after **every block** that:

| Invariant | What it would have caught |
|---|---|
| Balances sum to the recorded supply, per denomination | Value appearing where none was destroyed |
| No account loses money unless a transaction in that block named it as sender, sponsor or source | The fee-payer drain of §7 |
| No account record has become unreadable or unsignable | A state a node can write but not read back |
| A group's members are within bounds and its rotation index is in range | §13 |
| No member is credited more cycles than the group has had | §10 |
| A history pointer never names a future block | A broken ADR-0015 chain |

**Writing down "who may lose money" was itself the point.** That model did not
exist anywhere before, which is precisely why §7 could happen: nothing in the
code or the docs said which accounts a block is entitled to debit.

The suite also **tests itself**. A property run whose inputs are all rejected
passes every invariant and proves nothing, and fails silently — the run still
goes green. So it counts what actually applied and asserts on it: at present
about a third of generated transactions apply, across seven distinct result
codes. If a change makes the generator degenerate into an endless run of
rejections, the run fails rather than quietly stopping to test anything.

### 4. `crates/node/tests/adversarial.rs` — a hostile scheduler

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
recorded alongside them because **those six share one root cause**: a value that
is not uniquely determined, made safe by a convention enforced somewhere else.

That is the finding worth carrying forward — not any individual bug, but that
the same shape keeps reappearing wherever untrusted input becomes a value.

A seventh, §7, is a **different** class and is recorded separately so the pattern
above is not stretched to cover it. It was not a decoder problem at all.

§8–15 are that same second class, found deliberately rather than by accident:
a session spent attacking the chain the way someone who wanted the money would.
None of them is a malformed input. Every one arrives as a well-formed
transaction, correctly signed, from an account entitled to send it — which is
exactly why no amount of fuzzing would have surfaced them.

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

### 7. A fee payer nobody asked

The most serious defect recorded here, and the only one no fuzzer would have
found: it was not a malformed input, it was a **missing check on a well-formed
one**.

`Fee::sponsored_by` lets a transaction name a third party as its fee payer —
the fee-abstraction primitive the whole "never need the native token" claim
rests on. The executor read that field and debited the named account:

```rust
let fee_payer = tx.body.fee.payer_or(tx.body.sender);
Bank::new(store).transfer(&fee_payer, &fee_collector_address(), …)
```

Nothing anywhere asked whether the payer had agreed. So **any address could
name any funded address as its sponsor and drain it, one fee at a time** — and
because fees are payable in any whitelisted denomination, in whichever
denomination the victim happened to hold. Every signature involved was
genuine; every byte was canonical.

Found while adding [ADR-0017](adr/0017-key-rotation-and-signer-lists.md), for a
reason worth naming: writing down *who is authorised to act for an account*
forced the question of every place the chain moves money, and this was the one
place the answer was "nobody asked".

**Fixed:** a transaction carries a second signature list for the fee payer,
required exactly when a payer is named, and checked against the payer's own
account record. `naming_a_stranger_as_the_fee_payer_does_not_charge_them`,
`a_sponsor_signature_from_the_wrong_key_is_refused`, and
`a_sponsor_who_signs_does_pay` for the half that must keep working.

**The lesson, and it is not the one above.** Canonicality testing asks *"can
this input be read two ways?"*. It cannot ask *"should this input have been
obeyed at all?"* Those are different questions, and the fuzz suite only answers
the first. What surfaced this was writing an explicit model of authorisation —
which is an argument for doing that for every capability, not only for signing.

### 8–15. What an attacker with a wallet could actually do

The fuzz suite asks *"can this input be read two ways?"*. It cannot ask *"should
this input have been obeyed?"* So the second question was asked directly: build
a chain, submit ordinary transactions, try to end up richer. The exploits are in
[`crates/executor/tests/heist.rs`](../crates/executor/tests/heist.rs), each
written to fail against the fixed code.

Seven attacks worked. **The savings group took the worst of it**, which is the
part that matters — a chama's money belongs to people for whom losing it is not
an inconvenience. Full reasoning in
[ADR-0018](adr/0018-savings-group-integrity.md); the shape of each is:

| # | What it was | Effect |
|---|---|---|
| **8** | `GroupPayout` had no clock: any member could call it, and an empty pot still advanced the cycle | **One member drains the group.** Spin the rotation for the price of fees until it points at you, then collect every cycle |
| **9** | `ContributeToGroup` never compared the amount sent against the amount agreed | Pay one shilling, be credited a full cycle, take the whole pot |
| **10** | No per-cycle contribution check | Pay ten times in one cycle, buy a reliability record you did not earn |
| **11** | `record_missed` was **never called from anywhere** | The credit signal could only ever say yes — about borrowers who can least afford a loan they should not get |
| **12** | `CreateGroup` overwrote any existing record at the derived address | Resets `last_txn`, orphaning the provable-history chain of ADR-0015 |
| **13** | No cap on group membership, and every member is filed in `touched_addresses` | One fee mints unbounded account records for strangers — the exact property ADR-0015 claims |
| **14** | No minimum fee | A failed transaction's only punishment is its fee. At zero, failure is free and unlimited |
| **15** | No fee-denomination whitelist | **Not currently exploitable** — minting needs an issuer, issuers come only from genesis. It is the check that keeps that true once issuers can be registered by transaction |

### 16. A loan the group's own rules made undue — found by the property suite

Not part of the red-team pass, and worth separating because of **how** it was
found. When accumulating groups were built
([ADR-0019](adr/0019-vikoba-accumulating-savings.md)), the property suite in
`crates/fuzz/tests/ledger.rs` failed on its first complete run with *"seed 6
height 28: a loan falls due after the round that would settle it."*

`ShareRules::validate` already refused a loan *term* longer than a savings round.
That is necessary and not sufficient: a term that fits still runs past the round's
end if the loan is granted late enough in it. Nothing fails at the time — the loan
is advanced, the borrower does exactly what the group asked, and then the
share-out arrives before the term does. The debt is outstanding, so the
borrower's savings are seized to settle it and they are **recorded as a
defaulter for a term the group itself granted**. That record is the thing a
lender reads.

This is the first defect the property suite has found on its own, and it is the
kind it was built for: a sequence of individually reasonable transactions
arriving somewhere nobody intended. Nobody would have written
`a_loan_is_refused_when_the_round_would_close_before_it_falls_due` by hand,
because nobody had noticed there was a question.

The finding also depended on a second guard. A property suite whose generator
never reaches a path passes every invariant over that path and goes green;
reaching a share-out means founding an accumulating group, buying shares, closing
every cycle of a round and then asking, and a uniform generator effectively never
walks that. `Coverage::assert_meaningful` now requires each of the seven vikoba
messages to have applied at least once. Wiring the suite up naively tripped that
guard four times in a row, each time on a different message — four silent
false-greens that would otherwise have shipped.

A further finding was the opposite of an exploit: `apply_rebind` was correct,
tested, and **reachable from no transaction at all**, so a rebinding that
survived its veto window sat pending forever and genuine recovery never
completed. The SIM-swap defence refused the attacker and the owner alike.

**What did *not* break, which is worth as much.** Supply conservation held under
every sequence tried — no transaction changed the recorded supply of an asset.
Naming the fee collector as a fee payer bought nothing, because module accounts
authorise no keys ([ADR-0017](adr/0017-key-rotation-and-signer-lists.md)). The
staking module's arithmetic and the bank's atomicity held up to inspection.

**The lesson, and it is the same one §7 taught at smaller scale.** Every defect
above lived in the gap between *what a message says* and *what the code does
with it* — an amount carried but never compared, a period agreed but never read,
a counter incremented but never balanced. Canonicality testing cannot see that
gap, because both sides of it are well-formed. What finds it is writing down
what a feature is supposed to guarantee and then trying to violate it.

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
- ~~The executor's semantic invariants are asserted, not fuzzed~~ — **closed**
  by `crates/fuzz/tests/ledger.rs`, above. What remains true, and matters: the
  suite works inside a **closed universe of addresses**, because a sparse Merkle
  store cannot be enumerated and conservation cannot be summed over a set you
  cannot list. A defect that moves value to an address the generator cannot name
  is a defect this cannot see.
- **The economic rules have no model.** A chama's payout rule is now enforced,
  and the vikoba invariants below check a group's savings arithmetic after every
  block, but nobody has written down the full set of states a group can be in and
  checked that none of them is a trap. `EmptyPot` at period expiry is one such
  state, named in [ADR-0018](adr/0018-savings-group-integrity.md) and not
  resolved. §16 is a second such state that *was* found — by the property suite
  rather than by anybody reasoning about it, which is the point.
- ~~History cannot be verified at all~~ — **closed** by
  [ADR-0015](adr/0015-committed-outcomes-and-provable-history.md). An account's
  history is now a chain of committed back-pointers, so a node that omits an
  entry produces a link that fails to verify rather than an invisible gap;
  `a_node_that_skips_a_payment_is_caught_rather_than_believed` is the test. What
  remains true is that **no test can make a node answer** — withholding is
  available to whoever holds the data. What is gone is withholding invisibly.
- **Authorisation is modelled but not fuzzed.** `Account::authorises` is
  unit-tested against master keys, rotated keys, quorums, strangers and mixed
  sets, but no adversarial harness throws arbitrary key sets at arbitrary
  account records. Given §7, a property-based check that *no set of keys the
  account does not name can ever authorise* is the obvious next thing to write.
- **The mempool is not fuzzed.** Its limits are unit-tested and its insert path
  runs full stateless verification, but nobody has thrown a hostile sequence of
  submissions at it under the scheduler.

## Where this goes

Phase 2 adds the validator-to-validator layer, and with it the network-level
attacks that need peers rather than clients: eclipse, peer scoring, gossip
amplification. The harness is deliberately transport-free so it survives that
transition — the delivery rules in `sim.rs` are the same abstraction a real
network needs faults injected through.
