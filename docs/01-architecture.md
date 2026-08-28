# 01 — Architecture

Derived from the requirements table in [00-research.md](00-research.md#7-design-requirements-derived-from-the-above).

---

## 1. Shape of the system

```
┌──────────────────────────────────────────────────────────────────┐
│  ACCESS          USSD gateway  ·  smartphone wallet  ·  POS/QR   │
│                  merchant SDK  ·  agent app                      │
├──────────────────────────────────────────────────────────────────┤
│  APPLICATION     CosmWasm contracts (Rust)                       │
│                  DeFi · savings · payroll · escrow · insurance   │
├──────────────────────────────────────────────────────────────────┤
│  PROTOCOL        bank · sovereign-issuance · staking · gov       │
│  MODULES         fee-abstraction · agent-registry · identity     │
├──────────────────────────────────────────────────────────────────┤
│  EXECUTION       deterministic block executor                    │
│                  authenticated state (sparse Merkle tree)        │
├──────────────────────────────────────────────────────────────────┤
│  CONSENSUS       Ubuntu-BFT — Tendermint-class, PoS, ~1s final   │
├──────────────────────────────────────────────────────────────────┤
│  NETWORK         libp2p gossip  ·  IBC  ·  PAPSS settlement leg  │
└──────────────────────────────────────────────────────────────────┘
```

Everything is Rust. The rationale for building a sovereign chain rather than
deploying on an existing one is in [ADR-0001](adr/0001-sovereign-rust-l1.md);
it is a decision worth revisiting at each phase gate.

## 2. Consensus: Ubuntu-BFT

Tendermint-class BFT over proof of stake. Not novel, and deliberately so — this
is the layer where novelty is punished. See [ADR-0002](adr/0002-consensus.md).

| Property | Target |
|---|---|
| Block time | 1s |
| Finality | **deterministic, 1 block** |
| Fault tolerance | < 1/3 of stake Byzantine |
| Validator set | 100 → 150 by governance |
| Throughput target | 3,000–5,000 TPS sustained |

**Why deterministic finality is non-negotiable here.** A market trader handing
over goods cannot wait six blocks and reason about reorg probability. When a
block commits, it is final — the same guarantee a POS terminal gives today.
Probabilistic finality (Nakamoto-style) is unusable at a market stall.

**Validator geography.** A naive stake-weighted set concentrates in whichever
country bootstraps fastest. Governance caps stake share per validator and
requires the active set to span at least 15 countries, enforced in the
validator-selection module rather than left to good intentions.

## 3. Execution and state

State is a single compact sparse Merkle tree; the 32-byte root goes in every
header. Implemented and tested in [`crates/state`](../crates/state).

**Why this is the load-bearing choice.** It is what allows a $40 handset to hold
32 bytes and verify any claim about the ledger from a server it does not trust,
including *negative* claims ("this issuance never happened"). Without provable
absence, a light client can be lied to by omission — it just never sees the data.
The tests in `smt.rs` assert exactly these adversarial properties:
`a_server_cannot_forge_a_balance`, `a_server_cannot_deny_a_funded_account`.

Keyspace is namespaced per module with length-prefixed parts, so no module can
forge another's keys (`store.rs::key_parts_are_length_prefixed`).

## 4. The modules that make this different

Consensus and state are table stakes. These four are where the actual thesis
lives.

### 4.1 Fee abstraction — *"never make a farmer buy a governance token"*

**The problem.** On every existing chain, to send $5 of stablecoin you must first
acquire the native gas token. That is a second onboarding, a second exchange
account, a second KYC, and a second thing to understand. It is the largest single
cause of drop-off in crypto payments, and it is entirely self-inflicted.

**The design.** Fees are payable in any governance-whitelisted denomination.
A transaction names its fee denom; validators accept it, and the protocol swaps
to AFRI through a module-owned liquidity pool at settlement. Validators are still
paid in AFRI; the user never learns AFRI exists.

A sponsor may also pay another account's fees — the merchant, the employer, or an
NGO covers gas for its users. Combined with phone-number aliases and social
recovery, this is what makes the wallet feel like M-Pesa rather than like a
wallet.

> This single feature does more for adoption than any throughput number.
> Requirement R2 exists because of it.

### 4.2 Sovereign issuance — designed around why the eNaira failed

A permissioned module where an authorised issuer (central bank, or a licensed
institution under it) controls a `sov/<cc>/<unit>` denom — for example
`sov/ke/kes`. The namespace is enforced in the type system, so no contract can
mint an asset that renders in a wallet as a national currency
(`crates/primitives/src/denom.rs`).

Per-issuer, per-denom controls: mint/burn authority, supply caps, pause,
account freeze, allow/deny lists, and a full audit trail.

**Freeze and blacklist are politically dangerous, and we implement them anyway.**
A central bank will not issue on rails where it cannot comply with a court order.
Refusing to build the capability does not produce a freedom-preserving network;
it produces a network with no sovereign issuers on it. What we can do is make the
power *legible*: every freeze is an on-chain event, attributable to a named
issuer, permanently auditable, and scoped strictly to that issuer's own denom. An
issuer can freeze its own stablecoin. It can never touch AFRI, another country's
currency, or a user's other assets. Discretion is bounded by the protocol and
visible to everyone. That is a materially better arrangement than the invisible
discretion in today's correspondent banking, and it is the honest trade.

**Distribution is the product.** Issuance is the easy half. The module ships
with the redemption path, the agent network (§4.3), and merchant acceptance —
because the eNaira proved that an issued-but-undistributed currency is a museum
piece.

### 4.3 Agent registry — paying for the bottleneck that actually binds

From research §2.3: rural payments are limited by agent cash/float, not by
technology. Agents stake AFRI, are rated on-chain by completed cash-in/cash-out
volume, earn a protocol-funded liquidity reward on top of their commission, and
are slashed for failed settlements.

This is the mechanism that lets someone with no capital and no grid power earn —
requirement R6, and the honest answer to "people should be able to mine it".
See [04-earning-and-participation.md](04-earning-and-participation.md).

### 4.4 Identity and portable credit history

Today a user's transaction history is an asset owned by their mobile operator and
non-portable, which is why switching costs are high and credit is expensive.
Here: user-owned, selectively disclosed (attestation-based, no PII on-chain),
portable across borders and providers. A Kenyan trader's five-year repayment
record travels with them to Tanzania.

## 5. Smart contracts

**CosmWasm** — Rust contracts compiled to WebAssembly. See
[ADR-0003](adr/0003-contract-vm.md). The short version: it is the only mature
Rust contract platform still under active development. ink!, the obvious
alternative, **stopped being actively maintained in January 2026**, which
removed the main reason to choose the Polkadot stack.

A later EVM-compatibility layer is planned, not for ideology but for liquidity:
Solidity is where the audited DeFi primitives and the existing capital are.

## 6. Interoperability

- **IBC** for chain-to-chain. Most widely deployed interop protocol in
  production, now extending beyond Cosmos.
- **PAPSS settlement leg** — the strategic one. Settling into the AU/Afreximbank
  system positions AfroLink as a programmable retail layer over sanctioned
  infrastructure rather than as a rival to national payment systems. This is a
  legal and political posture as much as a technical one.
- **Mobile money bridges** — licensed, bonded operators bridging M-Pesa, MTN
  MoMo, Airtel Money. Trust-minimised where possible, honestly labelled as
  trusted where not.

## 7. Security posture

| Layer | Approach |
|---|---|
| Memory safety | `unsafe_code = "forbid"` workspace-wide |
| Panics | `unwrap`/`expect`/`panic` denied by lint in all crates |
| Arithmetic | `Amount` is checked; overflow checks on in release |
| Encoding | One canonical encoding; trailing bytes rejected; all lengths bounded |
| Signatures | Ed25519 `verify_strict`; domain-separated so no signature crosses contexts |
| Hashing | Length-prefixed domain separation on every hash |
| Merkle | RFC 6962 split — avoids Bitcoin's CVE-2012-2459 duplicate-node collision |
| Keys | `SecretKey` has no `Debug`, `Clone`, or serialisation |

Every one of these is asserted by a test, not just documented. The threat model
assumes the node's peers are hostile and its RPC provider is lying.

## 8. What is built today

| Component | Status |
|---|---|
| Canonical codec | **done**, 21 tests |
| Hashing, keys, addresses, bech32m, Merkle | **done**, 32 tests |
| Sparse Merkle state + proofs | **done**, 18 tests |
| Accounts, group accounts, transactions | **done**, 33 tests |
| Bank: balances, supply invariant, issuance | **done**, 18 tests |
| Deterministic block executor, blocks | **done**, 22 tests |
| Genesis, with distribution limits enforced | **done** |
| Ubuntu-BFT: validators, votes, round machine | **done**, 40 tests |
| Consensus driver + deterministic simulator | **done**, 10 tests |
| Commit certificates | **done**, 10 tests |
| Light client (header + state proof verification) | **done**, 12 tests |
| Durable storage: blocks, commits, content-addressed state | **done**, 17 tests |
| RPC, CLI | next |
| libp2p networking | not started |
| CosmWasm integration | not started |

241 tests passing. See [05-roadmap.md](05-roadmap.md) for sequencing.
