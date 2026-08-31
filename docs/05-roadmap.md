# 05 — Roadmap

Sequenced so that **the riskiest assumption in each phase is tested before the
next phase is funded**. The riskiest assumptions here are not technical.

---

## Phase 0 — Foundations ✅ *in progress*

Cryptographic and state primitives, with adversarial tests.

- [x] Canonical consensus codec — one encoding, bounded, strict *(21 tests)*
- [x] Hashing with domain separation; Ed25519 with `verify_strict` *(32 tests)*
- [x] Bech32m addresses, tested against BIP-350 vectors
- [x] RFC 6962 Merkle trees (no CVE-2012-2459 collision), with **consistency
      proofs** — what makes an append-only log unrewritable *(ADR-0011)*
- [x] Sparse Merkle state with membership **and non-membership** proofs *(18 tests)*
- [x] Transaction types, signing, replay protection *(33 tests)*
- [x] Group accounts — chama/susu/stokvel as a native type *(ADR-0005)*
- [x] Fee abstraction types — pay fees in any denom, sponsored fees
- [x] Bank module: multi-denom balances, supply tracking, sovereign issuance *(18 tests)*
- [x] Deterministic block executor, blocks and headers *(11 tests)*

**Exit criterion:** a light client verifies a balance against a state root, and
provably cannot be lied to. *(The proof machinery for this is done and tested;
the transaction path is not.)*

## Phase 1 — Single-node chain

- [x] Ubuntu-BFT round state machine (propose / prevote / precommit, lock & valid) *(40 tests)*
- [x] Validator set, voting power, +2/3 quorum, equivocation evidence
- [x] Genesis, block production and application *(distribution limits enforced)*
- [x] Durable storage backend (redb): blocks, commits, genesis *(10 tests)*
- [x] Content-addressed state persistence — O(1) startup *(ADR-0006)*
- [ ] Retention and garbage collection over shared node structure
- [ ] Incremental copy-on-write node writes (currently O(n) CPU per commit)
- [ ] Node roles: validator / archive / serving
- [ ] Pruning
- [x] Proof-carrying query verification (light client) *(20 tests)*
- [x] **Long-range attack defence** — trusting period, validator-set commitments
      in headers, skipping verification, checkpoint onboarding
      *(ADR-0010, 8 adversarial tests)*
- [x] Decentralisation measured, not claimed — stake and **geographic**
      concentration, Nakamoto coefficients *(ADR-0007, 8 tests)*
- [x] Query protocol — typed queries, proof-carrying answers, adversarial tests
      *(`crates/rpc`, 14 tests)*
- [x] Served from durable storage end to end *(`ChainStore` → `ServedChain` →
      light client, 5 tests)*
- [x] **HTTP transport around the protocol** — strict, hand-written, blocking,
      no async runtime and no new dependency. Integrity stays in the proof, so
      the transport is allowed to be untrusted *([ADR-0013](adr/0013-http-transport.md),
      `crates/http` 65 tests, plus ~110 000 malformed requests in the fuzz suite)*
- [x] **Mempool and transaction submission** — bounded, validated, per-sender
      capped; `POST /v1/transactions` answers 202 with the id. Writing is a
      different trait from reading, so a query still cannot reach the mempool
      *([ADR-0014](adr/0014-payment-history-and-the-mempool.md))*
- [x] **Payment history** — block bodies and a transaction index over RPC, with
      Merkle inclusion proofs against `tx_root`. The index itself is a hint and
      says so; the proof is what makes an entry true *(ADR-0014)*
- [x] **Block size limits** — a consensus rule that was missing. Validators
      re-execute every proposal, so an unbounded block was unbounded work for
      the price of one message *(ADR-0014)*
- [x] **Committed execution outcomes** — `outcome_root` in the header, so "your
      payment succeeded" is a proof rather than a claim
      *([ADR-0015](adr/0015-committed-outcomes-and-provable-history.md))*
- [x] **Provable history** — a committed back-pointer per account, so a node
      omitting a payment produces a *broken chain* rather than an invisible gap.
      Closes the one thing [ADR-0014](adr/0014-payment-history-and-the-mempool.md)
      could not prove *(ADR-0015)*
- [x] **Required payment references** — an account flag the *ledger* enforces,
      so a deposit with no reference to a flagged address fails instead of
      arriving unattributable. The requirement, the refusal and the reason are
      all provable *([ADR-0016](adr/0016-required-payment-references.md))*
- [x] **Key rotation, master-key disable and signer lists** — an address now
      outlives its key, an exposed seed can be retired without moving the money,
      and M-of-N social recovery is a protocol primitive rather than a contract.
      Authorisation moved from the transaction to the account record
      *([ADR-0017](adr/0017-key-rotation-and-signer-lists.md))*
- [x] **Savings-group integrity** — a red-team pass found seven working attacks,
      the worst of them one member draining a chama by spinning the rotation. A
      cycle now closes only when it is actually over, a contribution must be the
      amount agreed, and the credit record can go down as well as up
      *([ADR-0018](adr/0018-savings-group-integrity.md))*
- [x] **Vikoba** — accumulating groups, which is what the word means in
      Tanzania and a different instrument from a rotation. Members buy shares,
      the group lends its savings to members at a service charge, and the round
      ends in a share-out proportional to what each member saved — so a member
      takes out more than they paid in. `Quorum` finally governs something
      *([ADR-0019](adr/0019-vikoba-accumulating-savings.md))*
- [ ] **Subscriptions** — a wallet polls today, which is tolerable at one-second
      blocks and is the next thing to want
- [ ] Fee-based replacement and priority ordering in the mempool — premature
      until congestion is real; selection is nonce-order, first come
- [ ] Emit the decentralisation report at startup and over RPC

**Exit criterion:** ✅ *met and exceeded* — four validators propose, vote and
commit, agreeing on both the block and the resulting state root, verified by the
deterministic simulator in `crates/node/src/sim.rs`; and a wallet sends a
payment over a real socket, finds it in its history, and proves it against a
header it verified itself, trusting nothing about the node in between.

## Phase 2 — Multi-node testnet

- [ ] **Validator-to-validator networking** — a separate layer from the client
      RPC above, as it is in CometBFT: a known, bounded, keyed validator set on
      one side and anonymous strangers on the other are different threat models.
      Authenticated handshake (an audited Noise implementation, never a
      hand-rolled one), gossip, peer scoring
- [x] Byzantine testing — partitions, packet loss, message reordering and
      injected equivocation, all against the agreement invariant *([08](08-adversarial-testing.md))*
- [ ] Model checking the round state machine (TLA+ / Stateright). The randomised
      scheduler explores, it does not enumerate — a rare interleaving can sit
      outside every seed tried
- [x] Staking and validator set changes — bonding, unbonding and set derivation
      from stake. The headers already committed to set transitions, so light
      clients needed no change *([ADR-0012](adr/0012-staking-and-slashing.md))*
- [x] Slashing for double-sign, and enforcing the 21-day unbonding period the
      trusting period is derived from. Slashing reaches stake that has already
      begun unbonding, which is what makes the window worth anything
      *([ADR-0012](adr/0012-staking-and-slashing.md))*
- [ ] Downtime slashing — needs the per-block vote history a networked node has
- [ ] Delegation — stake through another operator. Deliberately deferred:
      reward accounting and slashing across delegators is the largest addition
      to the staking surface *(ADR-0012)*
- [ ] Epoch rotation — `active_set()` derives the set; nothing yet installs it
      at a boundary. That is the node's job and arrives with networking
- [ ] Bisection helper for skipping sync — the protocol supports it; the retry
      loop that halves the gap on `InsufficientOverlap` is not written
- [ ] **Witness log transport** — `crates/witness` is transport-free by design;
      fetching signed tree heads and proofs is now a matter of adding routes to
      `crates/http` *(ADR-0011)*
- [ ] **Bitcoin anchoring of witness roots** — layer 2 of ADR-0011, and the only
      mechanism that removes the social assumption outright rather than
      narrowing it. Deliberately deferred: an anchor needs history worth forging
      before it is worth paying for
- [ ] Fast sync and state sync
- [ ] **Free transaction quota per account** — TRON's bandwidth model, so an
      ordinary user needs neither AFRI nor a sponsor to transact *(R2; the gap
      surfaced by [06](06-adopted-practices.md))*
- [ ] State-bloat pricing that is **not** XRPL-style account reserves — a
      minimum balance to exist excludes the users this chain is for
- [ ] **x402 facilitator** — verify an `afri:` payment against an HTTP 402
      challenge, so any online service can charge in AFRI or a stablecoin
      *(ADR-0009; the RPC transport it was waiting on now exists)*
- [ ] Explorer, faucet, monitoring — the block, transaction and history
      endpoints they need now exist *(ADR-0014)*

**Exit criterion:** 20 geographically distributed validators; the chain survives
a partition and a deliberate 1/3-minus-one Byzantine coalition.

## Phase 3 — Programmability

- [ ] CosmWasm integration, gas metering, deterministic execution
- [ ] **Fee abstraction** — pay gas in any whitelisted stablecoin *(R2)*
- [x] **Human-readable addressing** — usernames, phone and email aliases with
      time-locked, vetoable rebinding *(ADR-0008, `crates/alias` 44 tests, plus 8 end-to-end)*
- [x] **`afri:` payment request URIs and payment references** — a merchant emits
      one string; any wallet understands it *(ADR-0009, `crates/pay`)*
- [ ] Off-chain resolver service *(specified in [07](07-resolver-service.md))*
- [x] **Key rotation and signer lists** — XRPL's regular key, master-key disable
      and M-of-N signer list. Rotation matters more here than elsewhere because
      the addressing layer is aliases people have already shared, and it is the
      correct answer to "recover from something I remember"
      *([ADR-0017](adr/0017-key-rotation-and-signer-lists.md))*
- [ ] **Time-locked recovery** — the mechanism is built; what is missing is a
      delay, so a signer list stolen whole is not an account stolen whole. The
      shape is the one `crates/alias` already uses for contact rebinding
      *(ADR-0017, "Revisit if")*
- [ ] Sponsored fees
- [ ] Contract templates: savings, escrow, payroll, rotating savings (chama/susu)
- [ ] SDKs: Rust, TypeScript, Kotlin, Flutter
- [ ] **Upgrade governance** — XRPL-style amendment voting over a Polkadot-style
      on-chain WASM runtime: no flag day, because a flag day stops every agent in
      a corridor at once *(ADR-0009 §2)*
- [ ] Name the funding model for the public-goods side of the network.
      [ADR-0007](adr/0007-distribution-and-sybil-resistance.md) rules out Pi's
      answer (monetising users' attention) without yet naming ours
- [ ] Local-language docs (Swahili, French, Arabic, Hausa, Amharic, Portuguese)

**Exit criterion:** an external developer ships a working app in a weekend
without talking to the core team.

## Phase 4 — The money layer

- [ ] Sovereign issuance module: mint, burn, freeze, caps, audit trail
- [ ] Proof-of-reserve attestation framework
- [ ] Agent registry, bonding, liquidity mining, ratings
- [ ] USSD gateway *(feature phones — R10)*
- [ ] First mobile-money bridge (one corridor, licensed and bonded)
- [ ] **Cross-currency payments with pathfinding** — send KES, receive NGN,
      routed directly or bridged through AFRI. XRPL's mechanism applied to the
      strategic gap in research §3.2: removing the USD leg. The largest single
      engineering item on this roadmap *(ADR-0009 §3)*
- [ ] IBC

**Exit criterion:** **one real remittance corridor, end to end, under 1% total
cost.** Kenya↔Tanzania and Nigeria↔Ghana are the strongest candidates.

## Phase 5 — Mainnet

- [ ] ≥ 2 independent security audits
- [ ] Public bug bounty
- [ ] Formal verification of consensus safety and the bank module's supply invariant
- [ ] Genesis ceremony; ≥ 40 validators across ≥ 15 countries
- [ ] Governance live
- [ ] Regulatory engagement: Kenya (CMA/CBK), Nigeria (SEC), South Africa (FSCA), Ghana

**Exit criterion:** mainnet running with no critical findings outstanding.

## Phase 6 — Scale

- [ ] More corridors, more issuers
- [ ] PAPSS settlement integration
- [ ] EVM compatibility layer (for liquidity, not ideology)
- [ ] AFRI basket unit
- [ ] Horizontal scaling once real load justifies the complexity — not before

---

## Deliberately not scheduled

Things that look like progress and are not: a token sale before Phase 4,
"partnerships" that are press releases, and any scaling work before measured
demand requires it.

**Exchange listing** sits differently now that adoption by a large exchange is a
stated goal. The work an exchange actually needs — destination tags
([ADR-0009](adr/0009-developer-payment-surface.md)), a ledger that enforces them
([ADR-0016](adr/0016-required-payment-references.md)), deposit detection and a
history a node cannot quietly truncate
([ADR-0015](adr/0015-committed-outcomes-and-provable-history.md)) — is scheduled
and mostly built. What stays off the list is *pursuing a listing* ahead of a
working corridor: a listed token with nowhere to spend it is a speculative
instrument, which is the opposite of what this chain is for. Build the
integration surface early; seek the listing when there is a corridor behind
it.

---

## What actually decides whether this succeeds

The engineering plan above is the tractable part. It is not the risk.

| Risk | Severity | Honest assessment |
|---|---|---|
| **Nobody uses it** | 🔴 critical | The default outcome. Mobile money already works domestically; we must be dramatically better on the *cross-border* leg or there is no reason to switch. |
| **Regulatory rejection** | 🔴 critical | One central bank declaring it illegal closes a market. Mitigation: engage before launch, build compliance in, position as complementing PAPSS rather than replacing national systems. |
| **Dollar rails win first** | 🟠 high | Visa/Yellow Card and Onafriq/Circle are laying USD rails *now*. Ours is the sovereignty argument; it only lands if the product is competitive. |
| **Validator centralisation** | 🟠 high | Cheap power and bandwidth are unevenly distributed. Mitigation: stake caps and geographic requirements enforced in-protocol. |
| **Consensus bug** | 🟠 high | Mitigated by boring, well-understood consensus; audits; formal verification. |
| **Bridge compromise** | 🟠 high | Bridges are the most-exploited component in the industry. Mitigation: bonded operators, conservative caps, and honest labelling of trust assumptions. |
| **Funding runs out** | 🟡 medium | 18–24 months to Phase 4 with a serious team. |

**The first row is the one that kills projects like this**, and no amount of Rust
addresses it. The strongest mitigation available is sequencing: Phase 4's exit
criterion is one real corridor at under 1% cost, deliberately placed *before*
mainnet and before any token event. If that corridor cannot be made to work, the
project should stop there — that is a far better outcome than launching a network
nobody needs.
