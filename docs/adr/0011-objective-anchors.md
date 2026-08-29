# ADR-0011 — Objective anchors: getting a starting point a wallet can check

- **Status:** accepted
- **Date:** 2026-08-29
- **Relates to:** [ADR-0010](0010-long-range-attacks.md) (long-range attacks),
  [ADR-0007](0007-distribution-and-sybil-resistance.md) (attestors),
  [ADR-0008](0008-human-readable-addressing.md) (the attestor layer),
  `crates/witness`, `crates/light`

## Context

[ADR-0010](0010-long-range-attacks.md) closed the long-range attack for a client
that is already up to date, and was explicit about what it did not close:

> **Bad.** A wallet offline for more than 14 days needs a fresh checkpoint, which
> is real friction in a market with intermittent connectivity — precisely our
> users.

"Needs a fresh checkpoint" meant, concretely: a person reads a hash off a
website. That is a security assumption resting on a UX no one will perform, in a
market where the connectivity to perform it is exactly what is missing.

### What does not solve this

Worth stating plainly, because it is the usual suggestion and it is wrong.

Finality gadgets. Two-thirds quorums. "Never revert a finalised block."
Slashing. Validator attestations. Explicitly signed checkpoints. Every one of
these protects a node **that was online when finality happened**.

The long-range victim is, by definition, the node that was not.

A forged history is not short of signatures. It carries a full quorum at every
height, signed by validators who were legitimately entitled to sign at those
heights. A syncing client that applies all of the rules above accepts it without
complaint — and our own test says so: `a_forged_history_with_perfect_signatures_never_reaches_the_wallet`
constructs a forgery that passes `Commit::verify`, passes
`LightClient::from_checkpoint`, and proves a fabricated balance against its own
state root. Every check succeeds. The chain is a fiction.

The gap is not the acceptance rule. **It is the starting point the rule is
applied from.**

## The theorem this has to live inside

In any proof-of-stake chain where stake can eventually be withdrawn, a syncing
node with no recent information cannot distinguish the canonical chain from a
costlessly-forged one — unless it has an external source of *work*, *time*,
*erasure*, *statistics*, or *trust*. That list is exhaustive, and no amount of
protocol design escapes it.

| Anchor | Mechanism | Verdict |
|---|---|---|
| **Work** — Bitcoin timestamping | A forged history cannot appear in old Bitcoin blocks | **Take, as layer 2.** The only one that removes subjectivity rather than softening it |
| **Time** — VDF / sequential work | Forging a year needs a year of non-parallelisable compute | **No.** Degrades against hardware: a 10× faster evaluator forges a year in five weeks. New primitive, new node role, new incentive, and a guarantee that erodes with someone else's silicon budget |
| **Erasure** — key-evolving signatures | Old keys physically cannot re-sign | **Still deferred**, per ADR-0010. Silent operational failure |
| **Statistics** — Ouroboros Genesis | Honest chain is denser | **Still admired, still unshipped** |
| **Trust** — checkpoints | Someone tells you | What we had, and the thing to improve |

**On zero-knowledge recursion**, which is proposed often enough to record: a
recursive proof asserting *"validator set A validly signed the rotation to set
B"* is a proof **the attacker can also produce**, because the attacker holds A's
keys. Two 1 KB proofs, both verifying, attesting to two different current
validator sets — the original problem, now compressed. ZK makes verification
succinct; it creates no economic cost, and long-range defence is entirely a
question of economic cost. Mina is the usual precedent, and Mina's
bootstrappability comes from Ouroboros Samasika's density-based chain-selection
rule, not from the SNARK. Considered, and rejected on the grounds that the
security is attributed to the wrong component.

## The asset that makes a different answer possible

[ADR-0007](0007-distribution-and-sybil-resistance.md) and
[ADR-0008](0008-human-readable-addressing.md) already commit to **licensed
attestors** — mobile network operators, banks, national identity authorities —
for the alias layer. That decision was made for a completely unrelated reason.

It means AfroLink has something Ethereum and Cosmos structurally do not: a set of
jurisdictionally diverse entities with legal identities, banking licences, and a
commercial dependency on this chain.

Ethereum's checkpoint providers can only be socially shamed. Ours can lose a
licence. That is the difference between a transparency log as documentation and a
transparency log as an enforcement mechanism — and it is why Certificate
Transparency works: Google can enforce CT because it can distrust a certificate
authority.

## Decision

### Layer 1 — witness logs (built)

Each attestor operates an append-only Merkle log of `(height, block_id,
observed_at)` and publishes a signed tree head. The log is RFC 6962 shaped, so it
supports two proofs:

- **Inclusion** — this observation is in that tree.
- **Consistency** — the tree you showed me last time is still a prefix of this
  one.

**The second is the load-bearing one**, and it inverts the sync problem:

> A wallet remembers **forty bytes**: a log size and a root. On returning after
> six months it demands a proof that the log at that size is a prefix of the log
> today. A witness that rewrote history cannot produce one — the wallet's old
> entry is not in the attacker's log, and inserting it retroactively breaks
> append-onlyness, which the proof exposes.

This does not weaken with time. A proof spanning six months is exactly as
conclusive as one spanning an hour, because either the hashes reconcile or they
do not. That is the property the 14-day trusting period does not have, and the
reason this closes ADR-0010's stated cost rather than merely reducing it.

For a wallet with nothing remembered at all — a fresh install — `corroborate`
requires several witnesses across several jurisdictions to say the same thing.

### The checkpoint is now 32 bytes

`LightClient::from_checkpoint` demands a header and both validator sets, which is
far too much to scan or carry. But a header's identifier commits to its own
contents, **including both validator-set hashes**, and each set is checked
against those commitments.

So `LightClient::from_block_id` takes a chain, a height, and 32 bytes. The header
and both sets can then come from anybody at all — a hostile server, a stranger's
phone — because they are checked against the identifier. ADR-0010's doc comment
already claimed "a checkpoint is a height and a hash"; this is the API that makes
the claim true.

A checkpoint now fits in a QR code an agent prints once and hands out with no
network at all, which is the difference between a defensible security model and
one that strands users with intermittent connectivity.

### Corroboration raises the bar with staleness; it never lowers it

`Policy::for_age` demands one further independent witness, in one further
jurisdiction, per trusting period of staleness.

This is deliberately the *opposite* of degrading. Softening a single anchor
because time has passed is the failure ADR-0010 exists to prevent. Requiring more
independent anchors as staleness grows is its inverse. There is no code path in
which a wallet accepts something because it has waited long enough.

Two further rules, both about refusing rather than deciding:

- **Two witnesses minimum, in two jurisdictions.** One source is
  indistinguishable from no source. Two in the same jurisdiction is closer to one
  than to two, because collusion is cheapest under a single legal authority.
- **Any disagreement disqualifies the entire set.** If three witnesses agree and
  one dissents, the wallet refuses — it does not outvote the dissenter.
  Choosing which of two histories is real is precisely the judgement a light
  client is not equipped to make, and a wallet that guesses is a wallet that can
  be made to guess wrong.

The demand is capped at four
([`MAX_CORROBORATION`](../../crates/witness/src/policy.rs)) because an
unsatisfiable policy is a refusal dressed up as a rule: past a handful of
jurisdictions a wallet asks for more independent legal authorities than its
witness set contains, and strands the user permanently while looking principled.
Depth beyond that point is layer 2's job.

### Equivocation is compactly provable

Two signed heads at the same size with different roots, under one log's key, is a
self-contained proof of misbehaviour that anyone can check offline. That is what
a regulator acts on.

**What this cannot catch, stated precisely:** only *same-size* conflicts are
compactly provable. A witness that simply refuses to serve a consistency proof is
unavailable rather than provably dishonest, and the absence of a proof is not
itself a proof. That case is handled by corroboration instead — an unavailable
witness stops counting toward the policy, so the wallet refuses rather than being
misled.

### Layer 2 — Bitcoin-anchored log roots (specified, not built)

Aggregate the witness heads and anchor the aggregate into Bitcoin daily.

Bitcoin's real property here is usually stated too weakly. It is not "borrowed
security" — it is that **a Bitcoin header chain is verifiable from a hardcoded
genesis by cumulative work alone, with no social input**. That is objectivity.
Anchoring into it does not soften weak subjectivity, it deletes it, and it covers
the case layer 1 cannot: a fresh install with nothing remembered, where an
attacker's log has no Bitcoin history to show.

ADR-0010 deferred this over "a fee market we do not control". The answer is
architectural: **the dependency is one-directional and non-blocking.** Anchoring
is a strengthening layer, never a liveness input. If Bitcoin becomes unusable we
lose an anchor and fall back to layer 1; the chain does not notice. Daily
anchoring is one transaction per day.

Not built now because anchors need history to be worth anything, and the chain
has none yet.

## The hard limit

**Witnesses observe. They never cause.**

Nothing in `crates/witness` can halt the chain, reorganise it, censor a
transaction, or admit a block. A lying witness is caught with a proof; a vanished
witness stops counting and the wallet refuses rather than being misled.

This is the guardrail that keeps a permissioned set from becoming a federation,
and it is structural rather than a matter of care. **If any future change lets a
witness *do* something rather than *observe* something, this design has failed**
— and that is the review question for every change to this crate.

## Consequences

**Good.** ADR-0010's stated cost is retired: a wallet offline for six months
recovers from forty remembered bytes, and a fresh one from a QR code. The trust
model did not change to achieve it — corroboration automates the comparison
ADR-0010 already argued was the strong guarantee, rather than replacing it with
something weaker. Header time is now bounded in both directions, closing the
mirror of the rewind attack.

**Bad.** A permissioned set appears in the trust graph. It is bounded by the
observe-never-cause rule and by requiring jurisdictional diversity, but it is
there, and it is the thing to watch.

Enough colluding witnesses defeat layer 1. Bitcoin censorship or cost defeats
layer 2. These fail *independently*, which is the entire argument for having
both — an attacker must beat collusion resistance across jurisdictions and
Bitcoin's fee market simultaneously.

**Deliberately not done.** No networking: a witness log is a data structure and a
set of proofs, and how heads are fetched is the transport layer's problem, as it
is for `crates/rpc`. No on-chain registration of witnesses — the bootstrap list
ships in the wallet binary, auditable by anyone who reads it, and putting it on
chain would make the chain's own state load-bearing for bootstrapping the chain.
The witness log is rebuilt per proof rather than kept incrementally; correct, and
`O(n)`, which a production operator would replace.

## Revisit if

- The chain accumulates enough value to justify Bitcoin anchoring, which is the
  trigger for layer 2
- Witness availability in practice turns out to be worse than
  [`Policy::BASELINE`](../../crates/witness/src/policy.rs) assumes — the fix is
  a wider witness set, never a lower bar
- A witness is ever caught equivocating, which is the first real test of whether
  the licence consequence is enforceable rather than theoretical

## Sources

- [RFC 6962: Certificate Transparency](https://datatracker.ietf.org/doc/html/rfc6962) — log structure, inclusion and consistency proofs
- [RFC 9162: Certificate Transparency v2](https://datatracker.ietf.org/doc/html/rfc9162)
- [Ethereum: weak subjectivity](https://ethereum.org/developers/docs/consensus-mechanisms/pos/weak-subjectivity/)
- [Tendermint: light client core verification](https://docs.tendermint.com/master/spec/light-client/verification/)
- [Ouroboros Genesis (IACR 2018/378)](https://eprint.iacr.org/2018/378.pdf)
- [Ouroboros Samasika: bootstrapping a succinct blockchain (IACR 2020/352)](https://eprint.iacr.org/2020/352.pdf)
- [Babylon: Bitcoin-enhanced proof-of-stake security (arXiv 2207.08392)](https://arxiv.org/pdf/2207.08392)
- [OpenTimestamps: Bitcoin timestamping](https://opentimestamps.org/)
- [Certificate Transparency: gossip and detection](https://datatracker.ietf.org/doc/html/draft-ietf-trans-gossip-05)
