# 05 — Roadmap

Sequenced so that **the riskiest assumption in each phase is tested before the
next phase is funded**. The riskiest assumptions here are not technical.

---

## Phase 0 — Foundations ✅ *in progress*

Cryptographic and state primitives, with adversarial tests.

- [x] Canonical consensus codec — one encoding, bounded, strict *(21 tests)*
- [x] Hashing with domain separation; Ed25519 with `verify_strict` *(32 tests)*
- [x] Bech32m addresses, tested against BIP-350 vectors
- [x] RFC 6962 Merkle trees (no CVE-2012-2459 collision)
- [x] Sparse Merkle state with membership **and non-membership** proofs *(18 tests)*
- [x] Transaction types, signing, replay protection *(33 tests)*
- [x] Group accounts — chama/susu/stokvel as a native type *(ADR-0005)*
- [x] Fee abstraction types — pay fees in any denom, sponsored fees
- [ ] Bank module: multi-denom balances, supply tracking
- [ ] Deterministic block executor

**Exit criterion:** a light client verifies a balance against a state root, and
provably cannot be lied to. *(The proof machinery for this is done and tested;
the transaction path is not.)*

## Phase 1 — Single-node chain

- [ ] Ubuntu-BFT round state machine (propose / prevote / precommit, lock & valid)
- [ ] Validator set, voting power, +2/3 quorum
- [ ] Genesis, block production and application
- [ ] Storage backend (RocksDB), pruning
- [ ] JSON-RPC + gRPC, with proof-carrying queries

**Exit criterion:** one node produces and applies blocks; state root is
reproducible from genesis on any machine.

## Phase 2 — Multi-node testnet

- [ ] libp2p networking, gossip, peer scoring
- [ ] Byzantine testing: equivocation, censorship, network partition, clock skew
- [ ] Slashing for double-sign and downtime
- [ ] Fast sync and state sync
- [ ] Explorer, faucet, monitoring

**Exit criterion:** 20 geographically distributed validators; the chain survives
a partition and a deliberate 1/3-minus-one Byzantine coalition.

## Phase 3 — Programmability

- [ ] CosmWasm integration, gas metering, deterministic execution
- [ ] **Fee abstraction** — pay gas in any whitelisted stablecoin *(R2)*
- [ ] Account abstraction: phone-number aliases, social recovery, sponsored fees
- [ ] Contract templates: savings, escrow, payroll, rotating savings (chama/susu)
- [ ] SDKs: Rust, TypeScript, Kotlin, Flutter
- [ ] Local-language docs (Swahili, French, Arabic, Hausa, Amharic, Portuguese)

**Exit criterion:** an external developer ships a working app in a weekend
without talking to the core team.

## Phase 4 — The money layer

- [ ] Sovereign issuance module: mint, burn, freeze, caps, audit trail
- [ ] Proof-of-reserve attestation framework
- [ ] Agent registry, bonding, liquidity mining, ratings
- [ ] USSD gateway *(feature phones — R10)*
- [ ] First mobile-money bridge (one corridor, licensed and bonded)
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

Things that look like progress and are not: a token sale before Phase 4, an
exchange listing before there is a working corridor, "partnerships" that are
press releases, and any scaling work before measured demand requires it.

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
