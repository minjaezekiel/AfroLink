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
payouts, share purchases, loans and share-outs, minting, burning and freezing,
bonding, unbonding, flag changes, and sponsored fees both genuine and forged —
and asserts after **every block** that:

| Invariant | What it would have caught |
|---|---|
| Balances sum to the recorded supply, per denomination | Value appearing where none was destroyed |
| No account loses money unless a transaction in that block named it as sender, sponsor or source | The fee-payer drain of §7 |
| No account record has become unreadable or unsignable | A state a node can write but not read back |
| A group's members are within bounds and its rotation index is in range | §13 |
| No member is credited more cycles than the group has had | §10 |
| A history pointer never names a future block | A broken ADR-0015 chain |
| A vikoba's social fund never exceeds its balance | Insurance the group has already spent |
| No loan falls due after the round that settles it | §16, found here |
| Supply never exceeds a declared cap | An issuer quietly outrunning a promise holders can verify ([ADR-0020](adr/0020-sovereign-issuance.md)) |

**Writing down "who may lose money" was itself the point.** That model did not
exist anywhere before, which is precisely why §7 could happen: nothing in the
code or the docs said which accounts a block is entitled to debit.

The suite also **tests itself**, in two ways, and both have since earned their
keep.

A property run whose inputs are all rejected passes every invariant and proves
nothing, and fails silently — the run still goes green. So it counts what
actually applied and asserts on it: at present about a third of generated
transactions apply, across eight distinct result codes.

That is not enough on its own, because a generator can be busy and still never
walk a *particular* path. Reaching a share-out means founding an accumulating
group, buying shares, closing every cycle of a round and then asking; reaching a
mint means holding a minter allowance. So the suite also names the twelve
messages it claims to cover and requires each to have applied at least once.
Wiring that up caught four silent false-greens in a row, each on a different
message — four runs that would have shipped as "passing" while testing nothing
about the code they were written for.

Some of the generator therefore **aims** rather than guesses: it answers a
proposal it knows is open, repays a debt it knows the sender carries, shares out
a round it knows is complete. That is not marking its own homework — every
invariant still runs against whatever the executor actually did. It is the
difference between a suite that reaches the arithmetic and one that never does.

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

### 17. A vote that could have disarmed the light client

Not found by a fuzzer. Found by reading, while writing
[ADR-0022](adr/0022-governance.md), and it is the reason that ADR has a section
on floors rather than a paragraph.

Governance moved six compile-time constants into state, one of which was the
staking module's `unbonding_ms`. A light client does not read that value. It
compiles in `TRUSTING_PERIOD_MS`, derived from `UNBONDING_MS` — two thirds of
21 days — and refuses to verify a header older than that, which is the entire
long-range defence of [ADR-0010](adr/0010-long-range-attacks.md).

So a council able to set `unbonding_ms` to an hour would not have broken any
invariant the suite checks. It would have left every phone already in the field
verifying headers signed by validators whose stake was long since withdrawn and
unslashable — the exact attack ADR-0010 exists to prevent, arrived at by a
lawful vote instead of by force, with nothing on the chain looking wrong at any
point.

The fix is a floor: `ChainParams::validate` refuses any unbonding period below
the constant clients compile in. Lengthening stays allowed, because that only
makes a deployed client more conservative than it needs to be. The general rule
that came out of it is in ADR-0022 §5: **a tunable safety margin that may be
tuned to zero is a switch that turns the safety property off.**

Two more of the same shape were closed at the same time. `rebind_delay_blocks`
is the SIM-swap defence, and at zero it is not a defence. The council's own
jurisdiction cap is a ratchet rather than a floor — it may be tightened and never
loosened — because a cap the capped party can widen is not a cap.

### 18. A governance suite that would have held for the worst reason

The property suite grew governance invariants: the parameters in force always
clear their floors, the sitting council always satisfies the cap in force, the
proposal queue is bounded and canonical, and a scheduled proposal is never
executable before it was opened.

Every one of them passed on the first run, and every one of them was vacuous.

A voting period and a timelock are measured in thousands of blocks. The money
runs advance one height per block over forty blocks, so no proposal in any seed
ever closed its voting period, nothing was ever scheduled, and nothing was ever
executed. The invariants were checked against a governance module that had never
done anything.

That is the same failure `assert_every_path_ran` was added to catch on the vikoba
paths in §16, in a new place. The fix is the same shape: a separate
`GOV_KINDS` guard insisting `ExecuteGovAction` actually applied, and a run with a
large height stride so a generated sequence can outlast a voting period. The
group arithmetic degenerates at that stride — every cycle closes each block —
which is why it is a second run rather than a wider setting on the first.

Two attempts were needed to satisfy the new guard, both because a threshold needs
*three different seats to answer the same question inside one voting period* and a
uniform generator lands three on one about never. The generator now aims at open
proposals the way it already aims at open group proposals, and the invariants
still run against whatever the executor actually did.

**An invariant that is never reached always holds.** This is the third time that
sentence has earned its place in this document.

### 19. A dial that never returned

Not a security defect — a design one, found the first time the integration suite
was run, and it hung.

`Transport::dial` did the handshake on a spawned thread and then `join`ed it. But
the thread it joined ran the connection's *read loop*, which lives as long as the
peer does. So a dial that succeeded never returned, and a node could open exactly
one connection, in the sense that it could open one and then stop.

The fix is the seam the rest of the crate already draws: the handshake and the
manager's decision run on the calling thread, so a dial can report *why* it
failed, and everything after that is two threads. The general shape is worth
writing down because it is easy to get backwards — **a connection setup is
synchronous and a connection is not.**

The same run turned up a busy-wait next to it. When a peer was dropped, its
outbox sender went with it, so the writer thread's `recv_timeout` returned
`Disconnected` — and the loop, which only checked for a shutdown flag, treated
that as "nothing to send yet" and spun. It would not have failed a test. It would
have pegged a core per departed peer on a real node, which is the sort of thing
that gets found in production by a graph.

### 20. A rule that was right, and the fixtures that were not

Concentration rules kept refusing test fixtures across two phases, and each time
the first instinct was that the rule was too strict. It never was.

* **Councils of three equal jurisdictions**, three times over — refused, because
  a third of the weight is exactly enough to block a two-thirds threshold. That
  belongs to [ADR-0022](adr/0022-governance.md) and is the same shape as what
  follows.
* **The peer integration tests, where every node is on `127.0.0.1`** and the
  second dial was therefore into a group already used.

The second is the interesting one, because the honest fix is a carve-out and
carve-outs are how defences rot. `127.0.0.0/8` carries no information about
network diversity at all: treating it as one group stops a devnet forming its
second connection, and treating each socket as its own group is exactly as
meaningful, which is to say not at all. So loopback sockets are each their own
group, **and the port is ignored for every routable address** — because an
attacker who could split a subnet into many groups by opening many ports would
have bought diversity with nothing. Both halves are asserted:
`a_port_never_splits_a_routable_group` next to `loopback_sockets_are_each_their_own_group`.

The lesson is the one this document keeps arriving at from different directions:
when a rule refuses a fixture, the fixture is usually what is wrong.

### 21. An address book that recommended addresses nobody could dial

Found by reading the peer-exchange path rather than by running it.

`Manager::admit` recorded every connection in the address book and marked it
`tried` — inbound connections included. What an inbound connection tells you,
though, is the peer's **ephemeral source port**, which dials nothing. A node
would therefore have filled its tried table with unreachable addresses and then
handed them to every peer that asked for a sample, which is a slow, entirely
self-inflicted partition.

The fix is one line and it closes something larger than the bug: **only a peer
this node dialled enters the address book.** An attacker cannot reach a node's
gossip sample by connecting to it. They have to be reachable, and the node has to
have chosen to reach them. Bitcoin arrives at the same place from the same
direction.

### 22. A node that did not count its own vote

The most instructive defect in this document, because the test suite was the
thing hiding it.

`Node` returns its own votes as `Action::BroadcastVote`. The transport put them
on the wire and never fed them back into the node's own vote set. The
deterministic simulator, though, has always delivered a broadcast to its sender
as well as to everybody else — one line in `sim::dispatch`, written years of
commits ago and entirely correct. So **every consensus test in the workspace had
the rule, and the system under test did not.**

It is invisible on four validators: three votes from three peers is already more
than two thirds of four, so the missing self-vote is never the one that matters.
It is total on one validator, which can never reach a quorum it is not counted
in. The first devnet started by the node binary produced no blocks at all, and
950 passing tests said nothing, because every one of them drove consensus through
the simulator.

The general lesson is worth more than the fix: **a simulator more capable than
production is a simulator that hides bugs.** Every divergence between the harness
and the system is a defect the harness is guaranteed not to find, and the
divergences are invisible precisely because the harness passes. What caught this
was not a test but an artefact — running the thing.

**Where the fix went matters more than that it went in.** The first attempt made
the transport loop a node's own votes back through the state machine. It worked,
every test passed, and it was the wrong layer: a consensus invariant now depended
on a transport being present, so the next caller to drive `Node` without one would
break quorum again in exactly the same silent way.

CometBFT puts it in the state machine. `signAddVote` signs the vote and places it
on the node's own internal queue, so it reaches `addVote` by the same path a
peer's vote takes; gossip is *downstream* of consensus state rather than the
mechanism by which it changes. `Node::emit_vote` now does the same.

That let the divergence be **removed rather than mirrored**: `sim::dispatch` no
longer delivers a broadcast to its sender, and the full Byzantine suite passes
unchanged. The harness is no longer more capable than the system it tests, which
is the only property that makes it worth trusting.

Pinned by `crates/node/tests/quorum.rs` — five tests driven against the bare state
machine, with no transport and no simulator, because a test that reaches `Node`
through either would be testing the thing that hid this.

### 22a. And the fix moved a second bug into the open

Moving the vote moved *where a commit happens*. Persistence had been hung off the
transport's delivery path, which was complete only because the transport was where
votes were counted; now a lone validator commits inside `start_round`, and the
daemon — which called `Node::start_round` directly — persisted nothing.

The chain produced eighteen blocks and its store reported height zero. Again,
found by running the binary and diffing its log against its own query endpoint;
again, invisible to a suite that was by then at 986 tests.

The fix is structural rather than another hook: `Shared::drive` is the one path
from a node's actions to their effects, and `Transport::start_round` and
`Transport::timeout` route a driver through it. Two entry points meant one could
be forgotten, and one was.

### 23. Two constants that had to differ, and did not

`MAX_BLOCK_BYTES` bounds a block's transactions; `MAX_FRAME_LEN` bounds what a
peer may send. Both were written independently as `4 * 1024 * 1024`.

A block at the consensus limit could therefore be built, proposed and voted on —
and never sent, because every wrapper a block travels in is strictly larger than
the block, so `write_frame` refuses it. A proposer could have produced a legal
block that no peer could receive, and only at the limit, which is exactly where
nobody looks.

Found while writing the block-sync protocol, by asking how many blocks fit in one
frame. The fix is that there is now one number: `MAX_FRAME_LEN` is derived from
`MAX_BLOCK_BYTES` plus a stated headroom, and a `const` assertion fails the build
if the relationship is ever broken. Two constants that must not drift apart
should not be two constants.

**The constant was the smaller half.** Refusing an *absurd* length was already
tested; what was not is that a **legal** length costs memory before a single byte
of it arrives. `vec![0u8; len]` on a stranger's word is five mebibytes for a
four-byte header, and forty inbound slots is two hundred mebibytes an attacker
never has to send. Frames are now filled in 16 KiB chunks as bytes actually turn
up, so the memory taken is bounded by the bandwidth spent taking it.

Writing the test for that produced a small lesson of its own: the first version
cloned a `Cell` out of the fake reader to inspect it afterwards, which copies the
*value* rather than sharing it — so the assertion looked at a zero that never
changed, and passed against the very implementation it existed to catch. A test
that cannot fail is worse than no test, because it is counted.

### 24. A rate limit whose meaning depended on an unrelated loop

The peer limiter was written as "512 messages per tick", which is not a rate — it
is a rate multiplied by however often somebody calls. The daemon's loop wakes
every 20 ms so consensus timeouts fire close to when they are due; ticking the
peer manager on the same schedule turned the limit into ten thousand messages a
second. A security bound loosened tenfold by a decision about loop latency, with
nothing anywhere to notice.

Separating the two clocks fixed the symptom. The cause is that the unit was wrong.

CometBFT denominates the same thing as `SendRate`/`RecvRate` in **bytes per
second** against a real clock. `Limits` now carries `messages_per_second` and
`bytes_per_second` with a bounded burst, spent from two token buckets per peer
that are refilled by *elapsed time handed in* — so the policy still reads no
clock, exactly as `Node` takes time as `Event::Timeout`.

Both limits, because neither implies the other: a flood of tiny frames costs CPU
and lock contention, and one maximum-size frame a second saturates a link while
sitting far inside any message budget. That second hole was open the whole time
and no test had asked about it.

The property is now asserted directly — the same offered load gets the same
verdict at 1, 2, 10 and 50 ticks a second. Writing it also corrected a
misconception of mine: counting *accepted messages* across tick rates does not
measure the rate, because ticking more often means more refusals for the same
load, and refusals cost reputation. What is invariant is the verdict, not the
count.

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
- **The peer layer is fuzzed at its surface, not at its policy.** Around 12 000
  hostile inputs go at framing, the handshake and the message decoders, and
  nothing panics or allocates on a stranger's word. What is *not* fuzzed is the
  manager under adversarial sequencing — a scheduler that opens, floods, drops
  and reconnects peers while asserting that an attacker never holds more than one
  outbound slot. The invariant is unit-tested against a static ten-thousand
  address flood; it is not attacked over time.
- **There is no networked equivalent of the consensus simulator.** Agreement is
  attacked in `sim.rs`, which has no sockets; the socket layer is tested for
  refusal and delivery, not for whether four real nodes commit the same block
  under partition. Joining those two is the obvious next harness and it needs
  block sync first.
- **Governance is fuzzed for structure, not for capture.** The suite checks that
  a council cannot vote itself into a shape its own rules refuse and that no
  proposal moves money. It says nothing about whether the *seated body* is
  trustworthy — against a genuinely captured two-thirds, the timelock buys notice
  and nothing else, which [ADR-0022](adr/0022-governance.md) states plainly
  rather than tests around.

## Where this goes

The validator-to-validator layer has arrived
([ADR-0023](adr/0023-peer-to-peer.md)), and with it the network-level attacks
that need peers rather than clients. Eclipse resistance, peer scoring and gossip
amplification are now tested — but as *rules*, in a module with no sockets in it,
plus a dozen integration tests over loopback.

What is missing is the join between the two harnesses that already exist. The
deterministic simulator in `sim.rs` attacks agreement with partitions, loss and
reordering, and has no network. The peer suite attacks the wire, and has no
consensus. Neither asks the question a real testnet asks: **do four nodes on four
sockets commit the same block while an attacker holds one of them eclipsed?**

The harness was kept transport-free precisely so that it survives this
transition — the delivery rules in `sim.rs` are the same abstraction a real
network needs faults injected through. Block sync now exists
([ADR-0024](adr/0024-block-sync-and-the-node-binary.md)), so the blocker is gone:
a node can be partitioned, fall behind, and catch up again.

Defect 22 sharpens what that harness has to be. The simulator and the transport
disagreed about a consensus rule for as long as both existed, and the disagreement
was undetectable from inside either. A joined harness is not only a better test of
agreement — it is the only thing that can find the *next* place where the model
and the system quietly differ.
