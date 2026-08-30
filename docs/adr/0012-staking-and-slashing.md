# ADR-0012 — Staking, unbonding and slashing: making the economic half real

- **Status:** accepted
- **Date:** 2026-08-30
- **Relates to:** [ADR-0002](0002-consensus.md) (consensus),
  [ADR-0007](0007-distribution-and-sybil-resistance.md) (concentration limits),
  [ADR-0010](0010-long-range-attacks.md) (long-range attacks),
  [ADR-0011](0011-objective-anchors.md), `crates/staking`

## Context

[ADR-0010](0010-long-range-attacks.md) built a light client that refuses to
verify past a trusting period, and derived that period from a 21-day unbonding
period. It then said plainly what it had not done:

> **Deliberately not done.** Validator set *changes* are committed to in headers
> but there is no mechanism to actually change the set yet — that is staking, and
> it is Phase 2. Slashing is likewise Phase 2, and until it exists the unbonding
> period is a documented parameter rather than an enforced one.

So the light client's safety argument rested on a number that nothing enforced.
Every ADR since has repeated the caveat. This closes it.

The header commitments ADR-0010 added (`validators_hash`, `next_validators_hash`)
were built specifically so that when this landed, light clients would already
follow set changes safely. They do; no light-client change was needed.

## Decision

### Bonded stake leaves the operator's balance

`bond` **transfers** AFRI to a module account. It does not set a "locked" flag.

A flag is one forgotten check away from being spendable, and the balance is what
every other module reads. Moving the money means every existing and future spend
path is correct by construction rather than by remembering.

### Slashing reaches stake that has already begun unbonding

This is the decision the whole unbonding period depends on, and the one that is
easy to get wrong.

A validator equivocates at height 10 and unbonds everything at height 11 — long
before anyone gathers the evidence. If queued stake were exempt, **21 days would
buy nothing at all**, and the light client's trusting period would be derived
from a guarantee that does not exist.

So every `Unbonding` entry records `started_at`, and an infraction at height `h`
reaches every entry with `started_at > h`: the stake left the active set, but it
had not left the period during which it answers for what it did.

The converse is enforced too. Stake that left *before* the infraction is
untouched — taking it would be confiscation rather than slashing.

| Test | What it fixes in place |
|---|---|
| `slashing_reaches_stake_that_has_already_begun_unbonding` | The attack above |
| `slashing_does_not_reach_stake_that_left_before_the_infraction` | Over-reach in the other direction |

### Concentration is capped, never refused

ADR-0007 sets a ceiling on any one validator's share. The obvious reading —
refuse to build a set that breaches it — **halts the chain**: validators leave,
the remaining set breaches the ceiling, and now no set can be formed at all.

A safety rule that stops block production is a liveness bug wearing a safety
rule's clothes.

Excess power is therefore *discarded*. Stake above the ceiling earns its operator
nothing, which pushes large holders to split or delegate — the behaviour the
limit exists to produce — while the chain keeps running. Capping lowers the
total, which can push the next validator over the line, so it iterates to a fixed
point.

The one genuine halt that remains is an empty candidate set, and it is honest: a
chain with no validators cannot produce blocks, and inventing power nobody staked
would be worse than saying so.

### Slashed stake is destroyed

Not paid to a treasury, not to the reporter, not to the remaining validators.

Paying it to anybody creates a party that profits from slashing, and therefore a
party with a reason to manufacture it. Burning leaves every holder better off in
proportion and nobody better off in particular. It is the only distribution with
no incentive to corrupt.

This needed a new bank operation: `burn` deliberately refuses the native coin,
because burning there is an *issuer* power over a sovereign stablecoin and no
issuer may ever touch AFRI. `slash_native` is the counterpart to `emit_native`
and the only path that reduces AFRI supply.

### Reporting is permissionless, and unpaid

Anyone may submit `ReportEquivocation`. The evidence proves itself — two
conflicting signatures verified against the validator set — so there is nothing
to gain by lying and no privileged reporter to capture.

The reporter is deliberately not paid, for the reason above.
`proves_equivocation` re-checks everything rather than trusting the struct:
`Equivocation` is a plain type anyone can build, and accepting it on faith would
let a caller destroy any validator's stake by asserting misbehaviour.

### Jailing and slashing are different things

Slashing takes money, once. Jailing stops the operator signing until governance
releases them.

Only the second protects the chain from a validator misbehaving *now* — a slashed
validator with stake remaining is still in the set unless jailing removes them.
There is no self-unjail message: an operator who can release themselves is not
jailed.

### 5% for equivocation

High enough that a validator accidentally running two machines feels it and fixes
the setup; low enough that one operational mistake is not fatal to a small
operator. That matters more here than on most chains: ADR-0007 wants a validator
set spread across countries where the capital involved is significant, and a
punitive rate selects for operators who can absorb it.

## Two things this forced elsewhere

**`UNBONDING_MS` moved to `crates/primitives`.** Defining it in `light` and
importing it into `staking` produced `staking → light → executor → staking`. The
cycle was a signal, not an obstacle: both crates need the number and they must
never disagree, so a shared protocol constant belongs at the bottom of the
dependency graph rather than in whichever crate happened to need it first.

**`execute_block` now takes a `BlockContext`.** Unbonding needs the height (what
a later slash measures against) *and* the time (when stake is released), and
execution only had the height. Bundled rather than passed as two scalars for the
same reason as `ValidatorSets` in ADR-0010: a caller can silently swap two
same-typed arguments and the compiler will not notice.

## Consequences

**Good.** The caveat repeated in ADR-0010, ADR-0011 and
[08](../08-adversarial-testing.md) is gone: unbonding locks real money and
equivocation costs its author 5%. Who signs blocks is now decided by who has
staked, through an ordinary transaction. Light clients needed no change.

**Bad.** The candidate list is a single state value rather than a scan, because
the sparse Merkle store answers point lookups with proofs and cannot be iterated.
That means a hard cap on candidates. `min_bond` is what makes squatting the slots
expensive — `max_candidates × min_bond` — but it is a cap, and a chain that
outgrows it needs a displacement rule this does not have.

**Deliberately not done.**

- **Delegation.** A holder cannot stake through someone else's validator. It is
  the largest addition to this module's surface — reward accounting, slashing
  split across delegators, reward withdrawal — and folding it in alongside the
  slashing rules above would make both harder to review. The state namespace is
  reserved.
- **Downtime slashing.** Liveness tracking needs the per-block vote history a
  networked node has and this one does not. Equivocation breaks *safety* and is
  provable from two signatures alone; downtime costs only liveness and needs a
  window of observations.
- **Rewards.** Emission belongs with the fee market, not here
  ([02](../02-tokenomics.md)).
- **Automatic set rotation.** `active_set()` derives the set, but nothing yet
  installs it at an epoch boundary — that is the node's job and it arrives with
  networking.

## Revisit if

- The candidate cap starts binding, which needs a displacement rule
- Measured validator behaviour shows 5% is the wrong rate for the operator base
  ADR-0007 targets
- Delegation lands, which changes how a slash is apportioned

## Sources

- [Cosmos SDK: x/staking specification](https://docs.cosmos.network/main/build/modules/staking)
- [Cosmos SDK: x/slashing specification](https://docs.cosmos.network/main/build/modules/slashing)
- [Tendermint: validator set changes and light clients](https://docs.tendermint.com/master/spec/light-client/verification/)
- [Babylon: why are unbonding periods so long on proof of stake?](https://medium.com/babylonlabs-io/why-are-unbonding-periods-so-long-on-proof-of-stake-d44e863c5cb8)
- [Ethereum: proof-of-stake rewards and penalties](https://ethereum.org/developers/docs/consensus-mechanisms/pos/rewards-and-penalties/)
