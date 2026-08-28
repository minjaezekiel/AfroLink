# ADR-0003 — CosmWasm as the smart contract VM

- **Status:** accepted
- **Date:** 2026-08-28

## Context

The brief requires that people "write smart contracts easily", in Rust. Options
as of August 2026:

| VM | Language | Maturity | Verdict |
|---|---|---|---|
| **CosmWasm** | Rust → Wasm | production across dozens of chains (Osmosis, Neutron, Injective, Secret, Terra) | **accepted** |
| ink! | Rust → Wasm | **unmaintained since January 2026** | rejected |
| PolkaVM | Rust → RISC-V | new; industrial deployment has outpaced academic evaluation by 2–3 years | rejected for v1 |
| EVM | Solidity | most mature ecosystem, largest liquidity | deferred to a compatibility layer |
| MoveVM | Move | strong asset safety | rejected — small ecosystem, not Rust |

The decisive finding: **ink! is no longer actively maintained**, as of January
2026. It was the obvious "Rust-native contracts" answer and it is now a
liability. Choosing it would mean building the developer story on a dead
toolchain.

PolkaVM is the plausible successor and is genuinely faster (RISC-V beats a Wasm
interpreter on both throughput and cost). It is too new to carry a payments
network in v1 — we should watch it, not bet on it.

## Decision

**CosmWasm.** It is the only mature, actively maintained, production-proven Rust
contract platform available.

- Contracts in Rust, compiled to WebAssembly
- Deterministic execution with gas metering
- An existing corpus of audited contracts and libraries
- Native IBC awareness, which fits [ADR-0001](0001-sovereign-rust-l1.md)
- A developer population that already exists — we are not asking anyone to learn
  a new language for an unproven chain

CosmWasm is consumed as a Rust library (`cosmwasm-vm`); it does **not** require
adopting the Cosmos SDK or writing the node in Go.

### Developer experience commitments

The VM choice alone does not make contracts easy to write. These do:

- Audited templates for the products people actually want here: savings groups
  (chama/susu), escrow, payroll, invoice factoring, parametric crop insurance
- SDKs in Rust, TypeScript, Kotlin and Flutter
- A local simulator requiring no testnet tokens
- Documentation in Swahili, French, Arabic, Hausa, Amharic and Portuguese —
  English-only documentation silently excludes most of the continent's developers
- Contracts callable through the fee-abstraction module, so an end user never
  needs AFRI to interact with one

## Consequences

**Good:** mature and audited; large existing developer base; strong tooling;
Rust's memory safety in the contract layer; IBC-native.

**Bad:** Wasm is slower than RISC-V or a native VM. Not the largest developer
ecosystem — that is Solidity's, which is why an EVM compatibility layer is on the
Phase 6 roadmap, for liquidity access rather than ideology.

## Revisit if

- PolkaVM reaches production maturity with independent security review
- Contract execution becomes a measured bottleneck
- The EVM layer proves more used than CosmWasm, which would be a signal about
  where developers actually are
