# 06 — Adopted practices: what each system we studied contributed

Research is only worth the time if it changes the build. This document is the
audit trail: for every network, payment system and standard we studied, what
practice we took from it, **where that practice actually lives**, and what we
rejected with the reason.

It exists to make one specific failure impossible — the failure where a project
cites a dozen influences in its docs and none of them are visible in the code.

**Status vocabulary**

| Status | Meaning |
|---|---|
| **In code** | Implemented and covered by tests today |
| **Decided** | An ADR commits us; implementation is scheduled |
| **Open** | Identified, not yet decided — with the phase it belongs to |
| **Rejected** | Deliberately not taken, with the reason recorded |

---

## XRP Ledger — [ADR-0006](adr/0006-state-persistence-and-retention.md)

| Practice | Decision | Where it lives | Status |
|---|---|---|---|
| **Content-addressed node store** — a node's key is its own hash, so immutable subtrees are shared between versions | Taken wholesale | `crates/state/src/nodes.rs`, `crates/store/src/lib.rs` | **In code** |
| Startup by loading a root hash rather than replaying history | Taken | `ChainStore::open_state` | **In code** |
| Historical versions addressable by root, making archive nodes a config flag | Taken | `ChainStore::load_state` | **In code** |
| **Node roles** — validating, archiving and serving are different jobs | Taken | ADR-0006 §2 | **Decided** |
| `online_delete`-style bounded retention | Taken in principle | ADR-0006 §3 | **Open** — needs reference tracking first; GC over shared structure fails silently |
| **History sharding** — volunteers each hold a range, so the network retains everything without every node doing so | Taken, but paid rather than volunteered | ADR-0006 §5, [04](04-earning-and-participation.md) | **Decided** |
| **Clio** — a read-optimised server that does not join P2P | Taken as the "serving" role | ADR-0006 §2 | **Decided** |
| Amendment voting — on-chain upgrade activation at a supermajority held over a period | Worth taking; we have no upgrade governance yet | — | **Open** (Phase 3) |
| Account reserves to prevent state bloat | **Rejected as specified.** A minimum balance to *exist* excludes exactly the users this chain is for. State bloat is real, so the cost must fall somewhere else — sponsored or fee-side | [ADR-0005](adr/0005-african-first-design.md) | **Open** (Phase 2) |

**The single most valuable thing XRPL taught us** is that full history at ~39 TB
is a role almost nobody performs, and a protocol should be designed for that to
be fine rather than pretending otherwise.

---

## TRON — [ADR-0006](adr/0006-state-persistence-and-retention.md)

| Practice | Decision | Where it lives | Status |
|---|---|---|---|
| **Checkpointing for atomic multi-store writes** | **Not needed** — redb gives us real multi-table transactions, so `put_block` is atomic by construction. Recorded because it is a place our storage choice is genuinely ahead | `crates/store/src/lib.rs` | **In code** |
| Archive nodes distinct from full nodes | Taken (see XRPL row) | ADR-0006 §2 | **Decided** |
| **Free daily bandwidth quota** so ordinary users transact without holding the native token | Strongly aligned with R2; our fee abstraction and sponsored fees cover part of it, a free tier is the missing piece | `crates/types/src/tx.rs` (fee payer), [02](02-tokenomics.md) | **In code** (partial) / **Open** (free tier, Phase 2) |
| Lite-fullnode snapshot datasets | **Rejected.** Solves the same problem as content addressing but adds a tooling surface — generate, distribute, verify, re-prune — to reproduce what we get for free | ADR-0006 | **Rejected** |
| Geographic node concentration (TRON's is heavy in one country) | Taken as a *warning*, and turned into a measurement | `crates/consensus/src/decentralization.rs` | **In code** |

---

## Pi Network — [ADR-0007](adr/0007-distribution-and-sybil-resistance.md)

The only project to have run this project's premise at scale. It supplied more
adopted practice than any other single source, in both directions.

| Practice | Decision | Where it lives | Status |
|---|---|---|---|
| **App-store onboarding instead of seed phrases** — the highest-leverage decision they made | Taken | [01](01-architecture.md), R10 | **Open** (Phase 4, wallet) |
| **A bundled builder stack** (browser, wallet, app studio, domains) rather than asking developers to assemble one | Taken | [05](05-roadmap.md) Phase 3 | **Open** |
| Zero-energy consensus is acceptable to users — 70M+ of them did not care | Confirms [ADR-0004](adr/0004-no-proof-of-work.md) from the demand side | — | **Decided** |
| **Decentralisation published as a measurement, not a claim** | Taken, and it is why the module below exists | `crates/consensus/src/decentralization.rs` | **In code** |
| **Referral and circle-size reward multipliers** | **Rejected permanently.** Pays for recruiting rather than for anything the network needs; it is why Pi's growth was spectacular and its usage was not | ADR-0007 §4 | **Rejected** |
| Distribution years ahead of utility | **Rejected.** Issuance accrues against measured work and continued service, never a signup date or a streak | ADR-0007 §3, [04](04-earning-and-participation.md) | **Decided** |
| KYC run by the project, gating whether balances exist | **Rejected.** Identity is attested by licensed issuers; biometrics never touch the chain; no chain-level entity can withhold a user's AFRI | ADR-0007 §5 | **Decided** |
| Ad-funded monetisation of the user base | **Rejected**, with the honest caveat that we have not yet named the funding source we *will* use | ADR-0007, [05](05-roadmap.md) | **Open** |
| A community price myth ("GCV", $314,159) filling the vacuum where price discovery should be | Taken as vindication of the AFRI/ASh split — merchants live on the stable unit | [02](02-tokenomics.md) §1 | **Decided** |

---

## Tendermint / Cosmos — [ADR-0002](adr/0002-consensus.md), [ADR-0003](adr/0003-contract-vm.md)

| Practice | Decision | Where it lives | Status |
|---|---|---|---|
| Propose → prevote → precommit with lock and valid rules | Taken | `crates/consensus/src/round.rs` | **In code** |
| `floor(2·total/3) + 1` quorum — never `>=` and never `2·total/3` | Taken, tested against every total from 1 to 1000 | `crates/consensus/src/validator.rs` | **In code** |
| Equivocation evidence as a first-class object | Taken | `crates/consensus/src/vote.rs` | **In code** |
| Commit certificates a light client can verify | Taken | `crates/consensus/src/commit.rs`, `crates/light` | **In code** |
| **State sync** — join in minutes by verifying state against a header you checked independently | Taken; we already have every piece | ADR-0006 §4, `crates/light` | **Decided** |
| CosmWasm as the contract VM | Taken (ink! unmaintained since Jan 2026) | ADR-0003 | **Decided** |
| IBC for interop | Taken | ADR-0001, Phase 4 | **Open** |
| The Cosmos SDK itself | **Rejected** — Go, and the monetary modules we need cannot live at application layer | ADR-0001 | **Rejected** |

---

## Stellar, Celo and the stablecoin rails — [00 §3.2](00-research.md)

| Practice | Decision | Where it lives | Status |
|---|---|---|---|
| **Issuer-controlled asset flags** (authorise, freeze) as a protocol feature, not a contract | Taken — a sovereign issuer needs this to be legally viable | `crates/bank/src/issuer.rs` | **In code** |
| Namespaced denominations, so `sov/ke/kes` is unambiguous about who issued it | Taken | `crates/primitives/src/denom.rs` | **In code** |
| Payments-first L1 design; assets as a native concept rather than a token contract | Taken | `crates/bank` | **In code** |
| Celo's **phone-number addressing** — the address a user already knows | Taken in principle; alias resolution is not built | [01](01-architecture.md) | **Open** (Phase 3) |
| Celo's mobile-first, light-client-first posture | Taken | `crates/light`, R3 | **In code** |
| Federated Byzantine agreement (Stellar's SCP) | **Rejected.** Sound protocol, but its decentralisation is entirely a function of who holds the quorum slices — Pi demonstrated the failure mode. An explicit, published validator set is more honest and more testable | ADR-0002, ADR-0007 §2 | **Rejected** |
| USD-denominated rails (Visa×Yellow Card, Onafriq×Circle) | **Rejected as the default denomination.** This is the strategic gap the project exists to close, not a model to copy | [00 §3.2](00-research.md) | **Rejected** |

---

## African payment systems — [00 §2, §3.1, §3.3](00-research.md)

| Practice | Decision | Where it lives | Status |
|---|---|---|---|
| **PAPSS as the settlement anchor**, not a competitor | Taken — it has the political mandate we would otherwise spend a decade earning | ADR-0001, Phase 5 | **Decided** |
| **Agent float is the binding constraint**, not technology — so pay for float | Taken; this is the mechanism that replaces mining | [04](04-earning-and-participation.md) §2 | **Decided** |
| **Group savings** (chama, susu, stokvel, tontine, equb, ajo, VSLA) as a native account type rather than a contract pattern | Taken — the clearest case of designing from African financial practice | `crates/types/src/group.rs` | **In code** |
| **Users must never need the native token to transact** — the eNaira and dormancy lesson | Taken | `crates/types/src/tx.rs`, `crates/executor` | **In code** |
| USSD and feature-phone fallback | Taken | R10 | **Open** (Phase 4) |
| eNaira's launch model — build the rail, assume adoption | **Rejected.** The failure was distribution and incentives, never technology. Any "let governments issue stablecoins" story without a distribution answer repeats it | [00 §3.1](00-research.md) | **Rejected** |

---

## Cryptographic standards

| Practice | Decision | Where it lives | Status |
|---|---|---|---|
| **RFC 6962 Merkle hashing** — leaf and node prefixes, which is what makes Bitcoin's CVE-2012-2459 duplicate-node collision impossible | Taken | `crates/crypto/src/merkle.rs` | **In code** |
| Length-prefixed domain separation on every hash | Taken | `crates/crypto/src/hash.rs` | **In code** |
| bech32m (BIP-350) addresses, checksummed and human-readable | Taken, with the BIP's own test vectors | `crates/crypto/src/bech32.rs` | **In code** |
| Ed25519 with `verify_strict` — rejecting the malleable and small-order edge cases | Taken | `crates/crypto/src/keys.rs` | **In code** |
| **Absence proofs**, not only membership proofs | Taken — a phone must be able to verify that something is *not* there | `crates/state/src/smt.rs`, `crates/light` | **In code** |
| Proof of work | **Rejected** on arithmetic grounds | [ADR-0004](adr/0004-no-proof-of-work.md) | **Rejected** |

These are the primitives [ADR-0005](adr/0005-african-first-design.md) declines to
reject. The line it draws: *a market assumption is a design choice made about a
context; a mathematical primitive is not.*

---

## What this audit surfaced

Writing the ledger exposed gaps that reading the research had not:

1. **Geographic concentration was counted but never measured.** `ValidatorSet`
   knew how many countries were represented and nothing about how power was
   distributed across them — so a set with nine validators in one jurisdiction
   and three spread across three others passed every check while a single
   country could halt the chain. Now measured, with that exact case as a test:
   `crates/consensus/src/decentralization.rs`.
2. **We have no upgrade governance at all.** XRPL's amendment process is the
   model worth copying, and nothing in the roadmap named it. Phase 3.
3. **TRON's free bandwidth quota is a better answer to R2 than we have.** Fee
   abstraction and sponsored fees let *someone else* pay; a free tier means
   nobody has to. Phase 2.
4. **We reject Pi's funding model without naming ours.** Recorded as open in
   ADR-0007 rather than left implicit.

Items 2–4 are in [05-roadmap.md](05-roadmap.md). This document is updated
whenever an ADR is accepted; a practice cited nowhere in a status column is a
practice we have not actually taken.
