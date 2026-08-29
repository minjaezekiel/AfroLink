# ADR-0009 — The developer payment surface, and what we take from Ethereum, Polkadot and XRPL

- **Status:** accepted
- **Date:** 2026-08-29
- **Relates to:** [ADR-0002](0002-consensus.md) (finality),
  [ADR-0003](0003-contract-vm.md) (CosmWasm),
  [ADR-0008](0008-human-readable-addressing.md) (aliases)

## Context

Three questions, and they have different answers:

1. How does a developer accept AFRI or a stablecoin in an online product?
2. How does a developer build a dApp on this chain?
3. Is it as fast as XRP?

The third is settled and the answer is yes — see §4. The first is where almost
all the adoption risk sits, and it is the one most chains answer badly.

## 1. Accepting payment: the integration must be a string, not an SDK

**The failure mode to avoid is well documented.** A chain that requires an SDK,
an API key, or an account with the foundation has built the thing it set out to
replace. Adoption is decided by how much work the *second* hour of integration
is.

The primitive that made this work elsewhere is the **payment request URI** —
BIP-21 for Bitcoin, [ERC-681](https://eips.ethereum.org/EIPS/eip-681) for
Ethereum. One string, emitted by a merchant into a link, a QR code or an HTTP
response, understood by any wallet. It is the reason "scan to pay" exists.

**Decision: `afri:` URIs, implemented in `crates/pay`.**

```text
afri:@duka-la-amina?denom=sov/ke/kes&amount=250.00&ref=88121&label=Duka%20la%20Amina
```

Design rules, each closing a specific failure:

| Rule | Why |
|---|---|
| The payee may be an alias | A merchant publishing `afri1qzp8h4c…` on a shopfront publishes nothing anyone can check ([ADR-0008](0008-human-readable-addressing.md)) |
| The wallet resolves and signs an **address** | A URI is untrusted input from a poster or a compromised page. It is a request, never an instruction |
| The amount is optional | A tip jar, a donation link and a market stall all mean "pay me, you decide" |
| The denomination is **never defaulted** | Guessing AFRI would turn a request for 250 shillings into 250 AFRI — orders of magnitude apart, unrecoverable |
| Duplicated parameters are refused, not resolved | `amount=1&amount=1000` means different things to different parsers; a wallet disagreeing with the merchant's till is a dispute nobody can settle afterwards |
| Unknown parameters are ignored | A wallet shipped today must keep working against a merchant that adds a field tomorrow |

Parsing a request needs no network, no key, and no account with us.

### 1.1 Payment references — XRPL's destination tag

**Taken from XRPL, and it is the single most underrated feature in payments.**
One exchange address serves millions of customers because each deposit carries a
machine-readable integer saying which account to credit.

`Message::Transfer` now carries `reference: Option<PaymentReference>`, a `u64`.
It is a **field, not a convention inside `memo`**, and that distinction is the
whole point: free text gets truncated, re-encoded, auto-corrected by a phone
keyboard and pasted with a trailing space. An exchange crediting accounts from
memo text is doing string matching on user input, which is why "I sent it but it
never arrived" is the most common support ticket in the industry.

The protocol never reads it. It is data for the recipient's systems — the same
position XRPL takes, and the reason the feature stays simple enough to be
reliable.

### 1.2 Paying for things online: HTTP 402

**[x402](https://www.x402.org/x402-whitepaper.pdf)** revives the long-unused
`402 Payment Required` status code: a server answers a request with `402` plus
payment instructions, the client pays and retries, the server verifies and
serves. As of March 2026 it has processed over 119 million transactions on Base
and 35 million on Solana, roughly $600M annualised, with zero protocol fees.

This is exactly "AFRI as a payment method in any online service", and it is
already an open standard with adoption. **We do not invent a competitor.** An
`afri:` request is already the right payload for a `402` challenge, and the
remaining work is a facilitator that verifies payment — which needs the RPC
transport (Phase 1) before it can exist.

Worth stating plainly: x402's momentum comes from autonomous software agents
paying for APIs. That is not our market. But the *mechanism* — a machine-checkable paywall with no
account, no card and no subscription — is a very good fit for a continent where
card penetration is low and cross-border card acceptance is worse.

### 1.3 What we already had, and did not need to import

| Ethereum needs | We have |
|---|---|
| ERC-20, because assets are contracts | **Native multi-denom assets** (`crates/bank`). A stablecoin is a first-class ledger object, not a contract someone might have written wrong. This is the Stellar/XRPL model, and it removes an entire class of token bugs |
| ERC-4337 / EIP-7702 account abstraction, to pay gas in something other than ETH | **Fee abstraction in the base protocol** (`Fee { denom, payer }`). Any whitelisted denom, and a third party may pay. No bundler, no paymaster, no entry-point contract |
| EIP-3009 / ERC-2612, so a user without ETH can move a stablecoin | Same — the problem does not arise |

Ethereum's account-abstraction stack is impressive engineering aimed at a problem
we do not have, because we made a different choice at layer one. That is worth
recording precisely so nobody later mistakes the absence of ERC-4337 for a gap.

## 2. Building dApps: what Polkadot contributes

[ADR-0003](0003-contract-vm.md) already chose CosmWasm. Two Polkadot ideas are
worth taking regardless, and one is worth refusing.

**Take: forkless runtime upgrades.** Polkadot stores its runtime on-chain as
WASM and swaps it by governance-approved extrinsic, so upgrades need no
coordinated flag day. [docs/06](../06-adopted-practices.md) already flagged that
**we have no upgrade governance at all**. For a payments network the argument is
sharper than for a general L1: a flag-day upgrade means every mobile-money agent
in a corridor stops working at once if a validator misses the notice.

The mechanism we adopt is XRPL's amendment voting — activation once a
supermajority has sustained support over a period — with Polkadot's on-chain
WASM runtime as the *unit* being switched. Phase 3.

**Take: pallets as the module shape.** Polkadot's separation between a runtime
and the pallets composing it is the same shape as our `bank` / `alias` /
`consensus` split, arrived at independently. Worth noting the convergence and
keeping the discipline: a module owns a namespace and its own invariants.

**Refuse: shared security and parachains.** Excellent engineering for renting
security to many chains. We are one chain, and the parachain-slot economy is a
capital barrier — precisely the kind of assumption
[ADR-0005](0005-african-first-design.md) rejects. Interop is IBC (ADR-0001).

## 3. Cross-currency payments — XRPL's pathfinding

**The best idea in this document, and the one most specific to our problem.**

XRPL's DEX can route a payment through intermediate assets, using XRP as a
bridge when direct liquidity is thin: `A → XRP → B`. The sender pays in one
currency, the recipient receives another, and the ledger finds the path.

Now read [research §3.2](../00-research.md): the strategic gap is that African
cross-border settlement routes through USD, paying an FX spread twice on
transactions that never needed a third currency. **XRPL's pathfinding is the
mechanism that removes the third currency** — or rather, replaces a foreign one
with a neutral one that the network itself issues.

A Kenyan trader paying a Nigerian supplier sends `sov/ke/kes` and the supplier
receives `sov/ng/ngn`, routed directly if a KES/NGN pair has liquidity and
through AFRI if it does not. That is the corridor product, expressed as a
protocol feature rather than a partnership.

This is a **decision to build it**, not a decision to have built it. It needs an
order book, path-finding, and slippage bounds, and it is the largest single item
added to the roadmap by this ADR. Phase 4, alongside the corridor exit criterion.

## 4. Speed: we are already ahead of XRP, and the decision was made in ADR-0002

| Network | Finality | Kind |
|---|---|---|
| Bitcoin | ~60 min (6 conf) | probabilistic |
| Ethereum | ~6.4–12.8 min (2 epochs) | probabilistic then final |
| Polkadot (GRANDPA) | ~12–60s | deterministic |
| **XRP Ledger** | **3–5s** | **deterministic** |
| **AfroLink target** | **~1s** | **deterministic** |

XRPL's insight — that payments need *deterministic* finality, because a market
trader handing over goods cannot reason about reorg probability — is the same
reasoning in [ADR-0002](0002-consensus.md), reached independently. XRPL closes a
ledger every 3–5 seconds with ~80% agreement across each validator's UNL. We use
Tendermint-class BFT at a 1s block time with a `>2/3` quorum; Malachite, a Rust
BFT engine, reports ~780ms average finality at comparable validator counts.

So the answer to "as fast as XRP" is **already yes, on the axis that matters**,
and it was decided before this ADR. What is *not* yet proven is that we hold that
number under real network conditions with geographically distributed validators —
Phase 2's exit criterion, and the honest caveat.

One difference worth keeping: XRPL's UNL is a subjective trust list, ours is an
explicit staked validator set with published concentration metrics
(`crates/consensus/src/decentralization.rs`). Comparable speed, more legible
security argument.

## Decision summary

| # | Decision | Where |
|---|---|---|
| 1 | `afri:` payment request URIs | `crates/pay/src/request.rs` — **built** |
| 2 | Payment references on transfers | `crates/types`, `crates/pay` — **built** |
| 3 | x402 facilitator, not a competing standard | Phase 2, after RPC transport |
| 4 | No ERC-20 / ERC-4337 equivalent — native assets and fee abstraction already cover it | already built |
| 5 | Forkless WASM runtime upgrades, activated by XRPL-style amendment voting | Phase 3 |
| 6 | Cross-currency payments with pathfinding, AFRI as bridge asset | Phase 4 |
| 7 | Reject parachains/shared security | — |

## Consequences

**Good.** A merchant who can print a QR code can accept payment, and a developer
who can parse a string can integrate. The cross-currency decision turns our
central strategic claim into a protocol feature instead of a business-development
plan. And several things other chains treat as hard problems are simply absent
here because of layer-one choices already made.

**Bad.** Pathfinding is a large, genuinely difficult feature with real failure
modes — thin books, slippage, and an entire order-book implementation that does
not exist yet. Committing to it in Phase 4 is committing to the largest
engineering item on the roadmap. Forkless upgrades add a governance attack
surface we currently do not have, in exchange for removing a coordination
failure we currently cannot survive.

**Honest gap.** Everything in §1 is a string format and a type. None of it is
reachable over a network until the RPC transport lands, so "a developer can
integrate today" is not yet true — the pieces are correct, the door is not open.

## Sources

- [ERC-681: URL format for transaction requests](https://eips.ethereum.org/EIPS/eip-681)
- [x402 whitepaper](https://www.x402.org/x402-whitepaper.pdf)
- [Coinbase: introducing x402](https://www.coinbase.com/developer-platform/discover/launches/x402)
- [Allium: x402 explained, adoption figures](https://www.allium.so/blog/x402-explained-the-internet-native-payments-standard-for-apis-data-and-agent-commerce/)
- [XRPL: source and destination tags](https://xrpl.org/docs/concepts/transactions/source-and-destination-tags)
- [XRPL: advanced payment features (pathfinding, auto-bridging)](https://learn.xrpl.org/lesson/advanced-xrpl-payment-features/)
- [RippleX: behind the scenes of the XRPL DEX](https://medium.com/ripplexdev/behind-the-scenes-of-the-xrpl-dex-c42f4d33a2ef)
- [XRPL: consensus principles and rules](https://xrpl.org/docs/concepts/consensus-protocol/consensus-principles-and-rules)
- [Polkadot: runtime upgrades](https://wiki.polkadot.com/learn/learn-runtime-upgrades/)
- [Polkadot developer docs: parachains overview](https://docs.polkadot.com/reference/parachains/)
- [Trail of Bits: the engineer's guide to blockchain finality](https://blog.trailofbits.com/2023/08/23/the-engineers-guide-to-blockchain-finality/)
- [Moonbeam: consensus and finality](https://docs.moonbeam.network/learn/core-concepts/consensus-finality/)
