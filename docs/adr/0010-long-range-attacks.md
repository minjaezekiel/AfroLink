# ADR-0010 — Long-range attacks: closing the last hole in the proof-of-stake argument

- **Status:** accepted
- **Date:** 2026-08-29
- **Relates to:** [ADR-0002](0002-consensus.md) (consensus),
  [ADR-0004](0004-no-proof-of-work.md) (no PoW), `crates/light`

## Context

[ADR-0004](0004-no-proof-of-work.md) rejected proof of work, and the argument
holds. But proof of stake has one attack proof of work does not, and it was the
weakest point in that ADR's case:

> **Long-range attack** (also *posterior corruption*). An attacker acquires the
> private keys of validators who have since withdrawn their stake — bought
> cheaply, or leaked years later, because those keys secure nothing any more.
> With them, the attacker signs an entirely alternative history branching from a
> point where those keys were a legitimate majority, then presents it to a node
> that has been offline or is syncing for the first time.

The alternative chain is **cryptographically perfect**. Every signature
verifies. Every commit reaches a quorum of the set that was current at that
height. A client checking only signature arithmetic cannot tell it from the real
chain — and this is the crucial part: **the attack costs almost nothing**,
because the keys involved have nothing at stake.

Under proof of work, rewriting a year of history means redoing a year of work.
Under proof of stake, the equivalent is free unless something else makes it
expensive. This ADR is that something else.

## What the field actually does

| Approach | Who | How it works | Verdict for us |
|---|---|---|---|
| **Weak subjectivity checkpoints** | Ethereum | A syncing node needs a recent finalised checkpoint from a trusted source. Finalised blocks are never reorged | **Take.** The industry-standard answer |
| **Unbonding period** | Cosmos (21 days) | Stake stays slashable long after a validator exits, so forging recent history is still punishable | **Take.** This is the economic root everything else rests on |
| **Trusting period + skipping** | Tendermint light client | The client refuses to verify past a period shorter than unbonding, and can skip ahead when ≥⅓ of the trusted set signed | **Take.** Gives safety *and* the scalability requirement |
| **Chain density** | Ouroboros Genesis | A novel chain-selection rule lets a node bootstrap from genesis alone, with no checkpoint at all | **Admire, don't build.** Theoretically the strongest answer — it removes the trust assumption entirely — but Cardano's own implementation is still a prototype under audit after years. Not something to invent here |
| **Key-evolving signatures (KES)** | Cardano | Signing keys evolve forward and old ones are erased, so a leaked key *cannot* re-sign old slots | **Defer.** Genuinely closes posterior corruption at the cryptographic level. It also means every validator must correctly erase key material on schedule, and a mistake is silent. Revisit after mainnet |
| **Bitcoin timestamping** | Babylon | Checkpoint the PoS chain into Bitcoin, borrowing its history-rewrite cost | **Revisit.** Elegant, but it makes the network depend on a chain whose fee market we do not control |

## Decision

Four mechanisms, layered. Each is useless alone and they compose into a
defence with no single point of failure.

### 1. Unbonding period — the economic root

`UNBONDING_MS` = **21 days**, matching the Cosmos Hub. Stake remains slashable
for that long after a validator begins exiting.

The number is not arbitrary. It must exceed the time it takes humans to notice
an attack, agree that it happened, and act — because once it elapses, the
offender's stake is beyond reach and forging old history becomes free. Everything
below is a way of ensuring no client ever has to reason about a period longer
than this.

### 2. Trusting period — the client's deadline

`TRUSTING_PERIOD_MS` = **⅔ of unbonding** (14 days).

A light client whose trusted header is older than this **refuses to verify
anything** and returns [`LightError::TrustExpired`]. It does not degrade,
warn-and-continue, or make a best guess. Past that point it genuinely cannot
distinguish the real chain from a forged one, and pretending otherwise is the
failure mode this whole ADR exists to prevent.

The gap between trusting and unbonding is the margin for detection and slashing
while the offender's stake is still bonded. It is asserted at **compile time**
(`const _: () = assert!(TRUSTING_PERIOD_MS < UNBONDING_MS)`), so no later tuning
can silently close it.

`LightClient::is_trusted_at` lets a wallet check freshness *before showing a
balance*, not just before updating — a stale trusted header makes every proof
against it meaningless, however well-formed the proof is.

### 3. Validator set commitments in the header

This required a consensus change, and it is the piece that was structurally
missing. `BlockHeader` now carries:

- `validators_hash` — the set that signed **this** block
- `next_validators_hash` — the set entitled to sign the **next** one

**Why it matters.** Previously a light client held a fixed validator set and
could not follow a set change at all. Worse, any API that let a caller supply
the set alongside the header would validate nothing: the attacker supplies both,
and the signatures check out perfectly against the attacker's own set. The
header's commitment is what makes that substitution detectable, and
`a_substituted_validator_set_is_rejected` is the test.

Carrying `next_validators_hash` specifically is what makes §4 possible: a client
verifying header `h` learns from `h` itself who may sign `h+1`.

### 4. Skipping verification — the scalability requirement

At one-second blocks, a two-week-old checkpoint is **~1.2 million headers**.
Downloading them all on a phone over metered data is not a sync strategy.

`LightClient::verify_skipping` jumps directly to a distant header when **more
than ⅓ of the currently trusted voting power** signed it.

The safety argument in one line: *Byzantine power is bounded by ⅓, so above ⅓
at least one **correct** validator signed — and a correct validator does not
sign on a forked chain.*

Two thresholds are required, and both matter:

| Threshold | Against which set | What it establishes |
|---|---|---|
| `> 1/3` | the **trusted** set | ties the new header to history the client already believes |
| `> 2/3` | the **new** set | ordinary consensus validity |

When overlap is insufficient, `InsufficientOverlap` is returned as a *recoverable*
error carrying the numbers, so a caller can bisect — verify a header halfway
between and retry — rather than being told only "no".

Overlap counts each trusted validator at most once and only for signatures that
actually verify, so a commit padded with repeated or forged entries gains nothing.

### 5. Checkpoints as the intended onboarding path

`LightClient::from_checkpoint` starts from a recent header rather than genesis,
and validates both validator sets against the header's commitments immediately —
a bad checkpoint fails at construction rather than poisoning every later check.

**The honest framing of the trust involved:** a checkpoint is a height and a
hash. Every validator, exchange, wallet vendor and block explorer can publish it
independently. A user comparing two sources that do not collude has a stronger
practical guarantee than any purely cryptographic one available here. That is
what "weak subjectivity" means, and it is a social assumption — the same kind
Bitcoin users make when they trust that the binary they downloaded is the real
Bitcoin Core.

## Two supporting rules

**Header times are strictly monotonic.** Otherwise an attacker replays an
old-timestamped header to rewind the trusting-period clock and keep a stale
client alive indefinitely. `a_header_that_rewinds_time_is_refused`.

**The client never moves on failure.** Every rejection path leaves the trusted
header, both validator sets, and the height untouched, so a failed verification
cannot leave a wallet in a half-updated state an attacker can exploit.

## Consequences

**Good.** The last genuinely unanswered objection to ADR-0004 is now answered in
code rather than in prose. Syncing goes from O(chain length) to O(log n) with
bisection, which is the difference between a phone syncing in seconds and not
syncing at all. And a client that cannot verify safely now says so loudly instead
of quietly accepting whatever it is handed.

**Bad.** A wallet offline for more than 14 days needs a fresh checkpoint, which
is real friction in a market with intermittent connectivity — precisely our
users. Mitigations: checkpoints are tiny and cacheable, wallet vendors can ship
them with updates, and an agent can serve one offline. But it is friction, and
the alternative was accepting forged history.

We also now depend on a social assumption for first sync. This is honest rather
than avoidable: Ethereum has the same one, and Ouroboros Genesis — the only
design that removes it — remains an unshipped prototype after years of work.

**Deliberately not done.** Validator set *changes* are committed to in headers
but there is no mechanism to actually change the set yet — that is staking, and
it is Phase 2. The commitments are in place so that when it lands, light clients
already follow it safely. Slashing is likewise Phase 2, and until it exists the
unbonding period is a documented parameter rather than an enforced one.

## Revisit if

- Key-evolving signatures become well-trodden enough to adopt without inventing
  the operational discipline they require
- Ouroboros Genesis ships and holds up, which would remove the checkpoint
  assumption entirely
- Measured wallet behaviour shows 14 days is the wrong number for connectivity
  patterns in our markets

## Sources

- [Ethereum: weak subjectivity](https://ethereum.org/developers/docs/consensus-mechanisms/pos/weak-subjectivity/)
- [Ethereum: proof-of-stake attack and defense](https://ethereum.org/developers/docs/consensus-mechanisms/pos/attack-and-defense/)
- [Vitalik Buterin: proof of stake — how I learned to love weak subjectivity](https://blog.ethereum.org/2014/11/25/proof-stake-learned-love-weak-subjectivity)
- [Tendermint: light client core verification](https://docs.tendermint.com/master/spec/light-client/verification/)
- [A Tendermint Light Client (arXiv 2010.07031)](https://arxiv.org/pdf/2010.07031)
- [IBC ICS-007: Tendermint client](https://github.com/cosmos/ibc/blob/master/spec/client/ics-007-tendermint-client/README.md)
- [Cosmos: light-client unbonding period](https://github.com/cosmos/cosmos-sdk/issues/274)
- [Babylon: why are unbonding periods so long on proof of stake?](https://medium.com/babylonlabs-io/why-are-unbonding-periods-so-long-on-proof-of-stake-d44e863c5cb8)
- [Ouroboros Genesis: composable proof-of-stake blockchains (IACR 2018/378)](https://eprint.iacr.org/2018/378.pdf)
- [IOG: Ouroboros Genesis design update](https://iohk.io/en/blog/posts/2024/05/08/ouroboros-genesis-design-update/)
- [A survey on long-range attacks for proof-of-stake protocols](https://www.researchgate.net/publication/331313599_A_Survey_on_Long-Range_Attacks_for_Proof_of_Stake_Protocols)
- [Bitcoin-enhanced proof-of-stake security (arXiv 2207.08392)](https://arxiv.org/pdf/2207.08392)
