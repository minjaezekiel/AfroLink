# ADR-0001 — Build a sovereign Rust L1, reusing hardened components

- **Status:** **accepted and committed** by the project owner, August 2026
- **Date:** 2026-08-28

## Context

Four ways to get a chain for this project:

| Option | Language | Time to production | Sovereignty | Verdict |
|---|---|---|---|---|
| A. Deploy on Celo/Stellar | Solidity / — | months | none | rejected |
| B. Cosmos SDK appchain | **Go** | ~9 months | full | strong, wrong language |
| C. Polkadot SDK parachain | Rust | ~12 months | shared security | **rejected — see below** |
| D. Sovereign Rust L1, hardened parts | Rust | ~18 months | full | **accepted** |

**Option C collapsed during research.** ink!, Polkadot's Rust smart contract
language, has been unmaintained since January 2026. Its replacement, PolkaVM, is
new enough that peer-reviewed evaluation is essentially absent, and XCMP is still
rolling out in phases. That removes the main reason to pick the Polkadot stack —
it was going to be the "Rust-native" answer, and it no longer is.

**Option A is the honest baseline and deserves to be taken seriously.** Deploying
on Celo would put a working product in users' hands in months. What it cannot
deliver is the actual thesis from research §3.2: those rails are dollar rails
operated from elsewhere. Sovereign issuance, fee abstraction in local currency,
and an agent-liquidity module are not app-layer features — they are protocol
changes. On someone else's chain we can build a wallet; we cannot build the
monetary layer.

**Option B is the strongest rejected option.** Cosmos SDK is battle-tested, has
the most widely deployed interop stack in production, and would ship sooner. It
is Go. The brief specifies Rust, and — more substantively — CosmWasm gives us
Rust contracts regardless, so the Rust developer story does not depend on the
node being Rust.

## Decision

Build a sovereign L1 in Rust, reusing hardened components rather than writing
everything from scratch:

- **Consensus:** Tendermint-class BFT, informed by Malachite (Rust, ~780ms
  finality at 100 validators). See [ADR-0002](0002-consensus.md).
- **Contracts:** CosmWasm. See [ADR-0003](0003-contract-vm.md).
- **Interop:** IBC.
- **Custom:** bank, sovereign issuance, agent registry, fee abstraction,
  identity — the parts that are the actual thesis.

## Consequences

**Good:** full sovereignty over the monetary modules; Rust throughout; mature
consensus and VM rather than novel ones; IBC from day one.

**Bad, and stated plainly:** ~18 months to production. Requires a team that can
build and *operate* an L1. We own the security of every line. Bootstrapping a
validator set and liquidity is harder than any of the code.

## Why the alternatives were declined

Option A (deploy on Celo or Stellar) would put a product in users' hands sooner.
It was declined on the merits, not overlooked: those are dollar rails operated
from outside the continent, and the modules that constitute this project's
thesis — sovereign issuance, fee abstraction denominated in local currency,
agent liquidity mining, group accounts as a native account type — are protocol
changes, not application features. On someone else's chain we could ship a
wallet. We could not ship the monetary layer. Building for African conditions
rather than adapting infrastructure designed for Western markets is the point of
the exercise; see [ADR-0005](0005-african-first-design.md).

Option B (Cosmos SDK) remains technically excellent and is in Go. CosmWasm gives
us Rust contracts either way, so the Rust developer story never depended on it.

## The risk this decision accepts

L1s do not usually fail on engineering; they fail by launching a technically
excellent chain nobody switches to. That risk is now **owned rather than
avoided**, and the roadmap is structured around retiring it early:
Phase 4's exit criterion is one real remittance corridor, end to end, under 1%
total cost — deliberately placed *before* mainnet and before any token event, so
that real demand is demonstrated while the cost of learning is still low.

That milestone is a validation gate, not an escape hatch. Passing it is what
converts the sovereignty argument from a thesis into a fact.

## Revisit if

- ink!/PolkaVM matures and the Polkadot stack becomes credible for the contract layer
- A Rust Cosmos SDK reaches production quality and could replace hand-built modules
