# ADR-0005 — Designed from African financial practice, not ported from Western markets

- **Status:** accepted
- **Date:** 2026-08-28

## Context

The direction is explicit: design a solution *for* Africa rather than adopting
solutions designed for Western markets. Acted on carelessly that principle
produces a worse system, so this ADR draws the line precisely — what gets
rejected, what gets kept, and what gets built instead.

The distinction that matters:

> **A market assumption is a design choice made about a context. A mathematical
> primitive is not.** We reject the first category aggressively. We keep the
> second, because rejecting it would mean inventing our own cryptography — which
> is the most reliable way ever discovered to build an insecure system.

## Decision

### A. Market assumptions we reject

Each of these is baked into mainstream fintech and crypto design because of where
it was built. Each is wrong here.

| Assumption | Reality here | What we do instead |
|---|---|---|
| **Always-on smartphone with cheap data** | ~24% smartphone ownership; ~600M without electricity | USSD/SMS path is a first-class client, not a fallback. Offline-capable authorisation that settles on reconnect. |
| **Finance is individual** | Hundreds of millions save in *groups*: chama, susu, stokvel, tontine, equb, ajo, harambee | **Group accounts as a native account type** — see §C |
| **Users hold the network's token** | Nobody will buy a governance token to send $5 home | Fee abstraction: pay fees in any whitelisted stablecoin; sponsors can pay for others |
| **Creditworthiness = bureau score + formal employment** | Most economic activity is informal; bureaus thin or absent | Community attestation and on-chain contribution history as the credit primitive |
| **KYC = street address + utility bill** | Frequently unavailable, and not how identity works | Tiered, risk-based verification; attestation-based, no PII on chain |
| **USD is the natural unit** | Pricing local trade in a third currency is a tax paid twice | Local currency is the default display and settlement unit; ASh basket for cross-border |
| **Big transactions matter most** | Median mobile money transaction is a few dollars | Fee floor and block-space policy tuned so a $1 payment is economic |
| **Interchange-style percentage fees** | 7.4% is the incumbent cost, and it is the enemy | Flat sub-cent fees, never proportional |
| **English-only tooling** | Excludes most of the continent's developers | Swahili, French, Arabic, Hausa, Amharic, Portuguese from launch |
| **Speculation-first token design** | Volatility is a barrier, not a feature | Utility-first; stable instruments kept structurally separate from AFRI |
| **DeFi = leveraged trading** | The demand is savings, working capital, crop insurance | Contract templates for what people actually need |

### B. What we deliberately keep, and why that is not a contradiction

Ed25519, BLAKE3, BFT consensus, Merkle trees, Rust, TCP/IP.

These are not Western products; they are mathematics and open standards, most of
them the work of international collaborations. There is no African alternative to
elliptic-curve arithmetic any more than there is an African alternative to prime
numbers.

The honest framing: **sovereignty means controlling the rails, the issuance, the
governance and the data — not re-deriving number theory.** A network that rolled
its own cipher to seem more independent would simply be a network that gets
drained, and the people harmed would be the ones it claimed to serve.

We are also not rejecting a technology merely because a Western institution also
uses it. That test would eliminate double-entry bookkeeping.

### C. What we build instead — group accounts as a native primitive

**The single most consequential design consequence of this ADR.**

Rotating savings and credit associations are how an enormous share of the
continent saves and borrows — *chama* (Kenya), *susu* (Ghana), *stokvel* (South
Africa), *tontine* (francophone West and Central Africa), *equb* (Ethiopia),
*ajo*/*esusu* (Nigeria), plus VSLAs everywhere. Members contribute a fixed amount
each period; the pot either rotates to one member per cycle or accumulates and
lends.

Western crypto's nearest equivalent is a multi-signature wallet, and it is not
close. A multisig models *joint custody*. A chama has a contribution schedule, a
rotation order, a treasurer role, defined joining and exit rules, and social
enforcement. Expressing that as "3-of-5 signatures" throws away everything that
makes it work.

So the protocol gets a **`GroupAccount`** account type carrying:

- **members** and their roles (treasurer, member),
- **contribution amount and period**,
- **payout policy** — rotation order (ROSCA) or accumulate-and-lend (ASCA/VSLA),
- **quorum rules** for extraordinary withdrawals,
- **a complete, member-owned contribution history**.

That last item is the sleeper. A five-year record of on-time contributions is the
best creditworthiness signal that exists for someone with no bureau file — and
because it is on-chain and user-owned, it is *portable* across providers and
borders. Today that history is either on paper in a notebook or trapped inside
one operator's database.

This is a primitive no chain designed for Western markets would think to build,
because the institution it models is not part of that context.

### D. Other African-first design consequences

1. **SIM-swap resistance is a first-class threat, not an afterthought.** Phone
   numbers are the natural identity anchor here, and SIM-swap fraud is
   correspondingly one of the dominant attacks in these markets. So a phone
   number is an *alias* that resolves to a key, never an authenticator: rebinding
   requires a time-lock plus social recovery, and high-value transfers stay
   unavailable during the rebinding window. A naive phone-to-key binding would be
   the most dangerous thing we could ship.
2. **Agent liquidity as protocol-level economics** — paying for the constraint
   that actually binds rural payments ([ADR-0004](0004-no-proof-of-work.md)).
3. **Validator geography enforced in-protocol** ([ADR-0002](0002-consensus.md))
   — a stake-weighted set with no distribution rule concentrates wherever power
   is cheapest, which for this network would be self-defeating.
4. **Proof of work rejected on the same grounds** — it exports issuance to
   wherever electricity is cheapest, which is not here.

## Consequences

**Good:** the design is shaped by how money actually moves on the continent
rather than by a port of somebody else's assumptions. Group accounts, agent
liquidity and fee abstraction are genuine differentiators that a US- or
EU-designed chain has no reason to build. The sovereignty argument in
[ADR-0001](0001-sovereign-rust-l1.md) gets teeth: these are protocol features,
and they are the reason a sovereign L1 is warranted.

**Bad, and worth being clear about:** every native primitive is protocol surface
we must specify, test, audit and maintain forever — group accounts are
considerably harder than a multisig contract. We diverge from tooling that
assumes a standard account model, so some wallets and indexers will need explicit
support. And "designed for Africa" is a claim that has to be continuously earned
against real usage: the failure mode is a team building what it *imagines* rural
users need. The mitigation is the Phase 4 corridor test and putting agents and
chama treasurers in the design loop early, not at launch.

## Revisit if

- Field testing shows group accounts are better served as a contract template
  than as a native account type
- Usage data contradicts any assumption in table A — these are hypotheses about
  people, and they should lose to evidence
