# ADR-0004 — No proof of work

- **Status:** accepted
- **Date:** 2026-08-28

## Context

The brief asks that "people should be able to mine it and get incentives in the
form of African Shillings". The goal is right and is a requirement of this
project (R6): **ordinary people, without capital, should be able to earn by
supporting the network.** The question is only whether proof of work achieves it
in this specific context.

It does not, and the reason is arithmetic rather than ideological.

## The arithmetic

PoW rewards flow to whoever produces hashes most cheaply. That is a pure function
of electricity price and hardware access.

| Factor | Reality in Africa |
|---|---|
| People without electricity | **~600 million** — 86% of the global access gap |
| Rural electrification | below 40% in many countries |
| Delivered cost per kWh | among the highest globally |
| ASIC manufacturing and distribution | effectively no African supply chain |
| Entry-level smartphone | 26% of monthly GDP per capita; up to 95% of monthly income for the poorest quintile |

A PoW chain "for Africa" would, within one difficulty epoch, have its issuance
and its security budget captured by industrial mining operations on cheap hydro
and stranded gas — none of it on the continent. Difficulty adjustment guarantees
this: it is not a risk, it is the mechanism working as designed.

The people the network is built for would be **buying** the coin, not earning it.
Mining would become a channel for extracting value *from* Africa while carrying
its name. That is the precise opposite of the intent behind the request.

Two further problems: PoW gives only probabilistic finality, which
[ADR-0002](0002-consensus.md) rules out for retail payments; and the energy
narrative would be an unnecessary obstacle in every central bank conversation in
Phase 5.

## Decision

**No proof of work.** Security comes from proof of stake
([ADR-0002](0002-consensus.md)).

The *goal* behind the request is kept in full, and met through four mechanisms
that reward contributions Africa actually has an advantage in — see
[04-earning-and-participation.md](../04-earning-and-participation.md):

| Mechanism | Capital needed | Power needed | Emission share |
|---|---|---|---|
| Staking / delegation | some AFRI | none | 55% |
| **Agent liquidity mining** | **small bond** | **a phone** | **25%** |
| Light node / relay | ~$50 | watts | 10% |
| Oracle / attestation | bond | none | 5% |

**Agent liquidity mining is the direct replacement for mining**, and it is a
better fit than PoW on its own terms. You contribute a scarce resource the
network needs and the protocol pays you newly issued AFRI for it. The scarce
resource is cash float and physical presence in underserved areas rather than
hashes — and unlike hashes, those are things an African trader has and a foreign
mining farm cannot acquire. Rewards are explicitly weighted toward rural and
underserved cells.

## Consequences

**Good:** **45% of issuance reaches participants with little or no capital**
(against 0% under PoW, where every coin goes to whoever bought the most
hardware). Rewards favour local presence, which cannot be offshored. Negligible
energy use. Deterministic finality. A far easier regulatory conversation.

**Bad:** PoS bootstrapping requires an initial distribution, which is a
governance and fairness problem PoW sidesteps — see the genesis allocation in
[02-tokenomics.md](../02-tokenomics.md). "You can mine it" is a simpler and more
emotionally resonant story than "you can run an agent node", and we lose that
marketing simplicity. Wealth concentration in PoS needs active countermeasures
(stake caps, low delegation minimums, geographic requirements).

## Confirmed empirically

This ADR argued from arithmetic. The experiment has since been examined:
**Pi Network** ran mobile-first "mining" for low-income markets at 70M+
registrations, with Nigeria as its third-largest market — and its own FAQ
confirms the phones never validated anything. It corroborates the demand side of
this decision (users did not care that consensus was not PoW) and supplies the
failure modes this ADR could only predict. What that binds us to, including the
Sybil-resistance question that removing PoW leaves open, is
[ADR-0007](0007-distribution-and-sybil-resistance.md).

**If the objection is that this departs from the brief:** it departs from the
stated *mechanism* in order to serve the stated *goal*. If the mechanism itself
is the requirement, the trade-off to accept knowingly is that issuance leaves the
continent. Worth deciding explicitly rather than by default.
