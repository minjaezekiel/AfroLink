# AfroLink

**A settlement network designed for African payments, written in Rust.**

Not another general-purpose L1. A chain built around four facts that most
blockchain designs ignore:

1. **Africa already won at digital payments.** $1.4 trillion moved through
   sub-Saharan mobile money in 2025 — 66% of global mobile money value. Nobody
   here is waiting to be "banked".
2. **The failure is at the border.** Sending money to Africa costs **7.4%** on
   average, the highest of any region. Routing payments *within* Africa costs an
   estimated **$5 billion a year**. That is where the network competes.
3. **~600 million people have no electricity.** So the phone must be able to
   verify the chain, and proof of work is disqualified by arithmetic
   ([ADR-0004](docs/adr/0004-no-proof-of-work.md)).
4. **The rails are being laid right now — in dollars.** Visa/Yellow Card and
   Onafriq/Circle are building African stablecoin rails today. The gap worth
   filling is not "Africa lacks a blockchain"; it is **sovereignty over the
   rails**.

Full evidence and sourcing: **[docs/00-research.md](docs/00-research.md)**.

---

## What makes it different

| | |
|---|---|
| **Never need the native token** | Fees payable in any whitelisted stablecoin, and payable *by someone else*. A user sends money without knowing AFRI exists. The biggest adoption blocker in crypto payments, removed. |
| **Savings groups are a native account type** | Chama, susu, stokvel, tontine, equb, VSLA — with contribution schedules, rotation order and a treasurer, not bolted on as a multisig. The contribution history is user-owned and portable: a credit file for people with no credit file. |
| **Sovereign stablecoins** | Countries issue `sov/ke/kes`, `sov/ng/ngn` with their own controls — enforced in the type system, so no contract can mint something that looks like a national currency. |
| **Agent liquidity mining** | Rewards the bottleneck that actually binds rural payments: agent cash float. Earn with a phone and a small bond — no capital, no grid power. |
| **Two lines to accept payment** | A merchant emits one `afri:` URI into a link or a QR code; any wallet understands it. No SDK, no API key, no account with us. Payments carry an XRPL-style reference, so one address serves millions of customers. |
| **Send to `@amina`, not to `afri1qzp8h4c…`** | Usernames, phone numbers and email addresses resolve to addresses — *with a proof*. An alias resolves; it never authorises, so a stolen SIM cannot touch the money. Raw addresses keep working for exchanges and existing tooling. |
| **Verifiable from a $40 phone** | All state under one Merkle root. A wallet holding 32 bytes verifies any balance from a server it does not trust — and can prove a *negative*, so it cannot be lied to by omission. Implemented and tested end to end in `crates/light`. |
| **Recovers from a QR code after six months offline** | Bootstrapping costs 32 scannable bytes, and returning costs forty remembered ones — checked against append-only witness logs in different jurisdictions, so no single party's word is load-bearing. Built for intermittent connectivity rather than apologising for it. |
| **Instant finality** | ~1s deterministic. A market trader cannot reason about reorg probability. |

## Status

**Phase 1 in progress.** Fourteen crates, **407 tests passing**. A working chain:
four validators propose, vote and commit blocks; a light client verifies a
payment holding nothing but a 32-byte header; the chain survives a restart; and
a node answers queries with proofs. Still in-process — no sockets yet.

```
crates/
  primitives/   canonical consensus codec, checked amounts, denoms      21 tests ✅
  crypto/       BLAKE3 + Ed25519, bech32m, RFC 6962 Merkle + consistency 38 tests ✅
  state/        sparse Merkle state, membership + absence proofs        26 tests ✅
  types/        accounts, group accounts, transactions, fee abstraction 33 tests ✅
  bank/         balances, supply invariant, sovereign issuance          18 tests ✅
  executor/     block execution, blocks, genesis                         26 tests ✅
  consensus/    validator sets, votes, rounds, decentralisation report   58 tests ✅
  node/         consensus driver, proposals, deterministic simulator     10 tests ✅
  light/        commit + proof verification, long-range defence         25 tests ✅
  store/        durable storage, and the view that serves queries       26 tests ✅
  rpc/          proof-carrying query protocol (no networking)           14 tests ✅
  alias/        usernames, phone/email bindings, SIM-swap defence        50 tests ✅
  pay/          afri: payment URIs, payment references                   16 tests ✅
  witness/      append-only witness logs, corroborated checkpoints        38 tests ✅
```

A node can now answer a wallet's question from disk with a proof, and every way
of lying about the answer is a named test. Next: an HTTP/gRPC transport around
the protocol, then libp2p to replace the in-process simulator with a real
network.
See **[docs/05-roadmap.md](docs/05-roadmap.md)**.

```bash
cargo test --workspace
```

## Security posture

Consensus code must not panic on hostile input, and must never disagree with
itself byte-for-byte. Enforced at the workspace level:

```toml
unsafe_code   = "forbid"
unwrap_used   = "deny"     # in library paths
expect_used   = "deny"
panic         = "deny"
```

- **One canonical encoding.** Trailing bytes rejected, all lengths bounded,
  `bool` is injective. Two nodes cannot disagree about what a transaction is.
- **Domain separation on every hash and signature.** A transaction signature
  cannot be replayed as a consensus vote.
- **Ed25519 `verify_strict`.** Lenient verification would let validators disagree
  about signature validity — a chain split.
- **RFC 6962 Merkle split**, avoiding Bitcoin's CVE-2012-2459 duplicate-node
  collision.
- **Checked arithmetic on all balances.** Overspending errors; it never wraps.

The tests are written adversarially and named for the attack they prevent —
`a_server_cannot_inflate_a_balance_it_reports`, `a_server_cannot_deny_a_balance_that_exists`,
`a_proof_for_one_account_cannot_be_replayed_for_another`,
`a_sim_swap_alone_cannot_redirect_an_alias`, `a_confusable_name_cannot_be_registered`,
`a_client_outside_the_trusting_period_refuses_to_verify`, `a_substituted_validator_set_is_rejected`,
`a_validator_count_hides_geographic_concentration`,
`odd_width_does_not_collide_like_bitcoins_duplicate_rule`.

## Documentation

| | |
|---|---|
| [00 — Research](docs/00-research.md) | The evidence base. What holds up, what doesn't, and what we should not claim. |
| [01 — Architecture](docs/01-architecture.md) | System design, modules, security posture. |
| [02 — Tokenomics](docs/02-tokenomics.md) | AFRI vs ASh, supply, fees, sovereign stablecoins. |
| [04 — Earning](docs/04-earning-and-participation.md) | How people earn without capital or grid power. |
| [05 — Roadmap](docs/05-roadmap.md) | Phased plan, exit criteria, and the risks that actually matter. |
| [06 — Adopted practices](docs/06-adopted-practices.md) | What each system we studied contributed, and where it lives in the code. |
| [07 — Resolver service](docs/07-resolver-service.md) | How a phone number becomes a lookup, and the wallet screen that stops mistakes. |
| [ADR-0001](docs/adr/0001-sovereign-rust-l1.md) | Why a sovereign Rust L1, and why the alternatives were declined. |
| [ADR-0002](docs/adr/0002-consensus.md) | Ubuntu-BFT: why boring consensus. |
| [ADR-0003](docs/adr/0003-contract-vm.md) | CosmWasm (ink! went unmaintained in Jan 2026). |
| [ADR-0004](docs/adr/0004-no-proof-of-work.md) | Why no mining — and what replaces it. |
| [ADR-0005](docs/adr/0005-african-first-design.md) | What "designed for Africa" rejects, keeps, and builds instead. |
| [ADR-0006](docs/adr/0006-state-persistence-and-retention.md) | State persistence, drawn from XRPL's NodeStore and TRON's lite fullnode. |
| [ADR-0007](docs/adr/0007-distribution-and-sybil-resistance.md) | What Pi Network's 70M-user experiment proved, and what it rules out. |
| [ADR-0008](docs/adr/0008-human-readable-addressing.md) | Usernames, phone and email — and why an alias never authorises. |
| [ADR-0009](docs/adr/0009-developer-payment-surface.md) | Accepting payment, building dApps, and what we take from Ethereum, Polkadot and XRPL. |
| [ADR-0010](docs/adr/0010-long-range-attacks.md) | Long-range attacks — the one thing proof of stake has to answer, and how. |
| [ADR-0011](docs/adr/0011-objective-anchors.md) | Witness logs: a starting point a wallet can check, not one it is told. |

## Decisions taken

1. **The asset model is split, and settled.** **AFRI** is the free-floating
   native coin — gas, stake, governance, and everything people earn. **ASh (the
   African Shilling)** is the basket-referenced pan-African settlement unit,
   backed by the sovereign stablecoins on the network. Attaching the currency
   name to the *stable, asset-backed* unit puts it where it is accurate, and
   keeps a launching network out of an argument it does not need under Nigeria's
   ISA 2025 and Kenya's VASP Act 2025.
   → [02-tokenomics.md §1](docs/02-tokenomics.md#1-the-asset-model--decided)
2. **Sovereign L1, committed.** The monetary modules — sovereign issuance, fee
   abstraction in local currency, agent liquidity, group accounts — cannot exist
   at application layer on somebody else's chain. Building them is the project.
   → [ADR-0001](docs/adr/0001-sovereign-rust-l1.md)
3. **Designed from African financial practice, not ported from Western markets.**
   What that means concretely, and where the line falls between a market
   assumption worth rejecting and a mathematical primitive worth keeping.
   → [ADR-0005](docs/adr/0005-african-first-design.md)

## The honest caveat

The engineering is the tractable part. The risk that kills projects like this is
that **nobody uses it** — domestic mobile money already works, so AfroLink has to
be dramatically better on the cross-border leg or there is no reason to switch.

The roadmap is sequenced around this: Phase 4's exit criterion is **one real
remittance corridor, end to end, under 1% total cost** — deliberately placed
before mainnet and before any token event. If that cannot be made to work, the
right decision is to stop there.

## Licence

Apache-2.0
