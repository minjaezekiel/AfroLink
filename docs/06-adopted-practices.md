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
| **History sharding** — volunteers each hold a range, so the network retains everything without every node doing so | Taken, but **paid rather than volunteered** — and that distinction now looks load-bearing: XRPL built a volunteer shard store and later removed it | ADR-0006 §5, [04](04-earning-and-participation.md), [09](09-what-xrpl-answers.md) §2.6 | **Decided** |
| **Clio** — a read-optimised server that does not join P2P | Taken as the "serving" role; the query protocol is already transport- and consensus-free, so a serving node is a `ChainView` without a validator | ADR-0006 §2, `crates/rpc` | **In code** (partial) |
| Amendment voting — on-chain upgrade activation at a supermajority held over a period | Taken, over a Polkadot-style on-chain WASM runtime | [ADR-0009](adr/0009-developer-payment-surface.md) §2 | **Open** (Phase 3) |
| **Destination tags** — one machine-readable integer, so a single address serves millions of customers | Taken. A field on `Transfer`, not a convention inside `memo`, because free text gets mangled in transit | `crates/types/src/tx.rs`, `crates/pay/src/reference.rs` | **In code** |
| **Pathfinding and auto-bridging** — pay in one currency, recipient receives another, routed through a neutral bridge asset | Taken, and it is the mechanism that removes the USD leg from intra-African settlement | [ADR-0009](adr/0009-developer-payment-surface.md) §3 | **Open** (Phase 4) |
| Deterministic finality for payments, because a trader cannot reason about reorg probability | Reached independently; we target ~1s against XRPL's 3–5s | [ADR-0002](adr/0002-consensus.md) | **In code** |
| **`PreviousTxnID` on every ledger object** — a committed back-pointer chain, so an account's whole history is provable and a gap in it is *detectable* | Taken. This is the answer to the one thing ADR-0014 could not prove: a node omitting a payment from your history | [09](09-what-xrpl-answers.md) §2.1 | **Open** — next |
| **Transaction metadata committed alongside transactions** — so "this payment had exactly these effects" is a compact proof | Taken. Our header commits to transaction *ids* and to resulting state, but throws the per-transaction outcome away | [09](09-what-xrpl-answers.md) §2.2 | **Open** — next |
| **`RequireDestinationTag`** — an account flag the *ledger* enforces, so an untagged deposit fails instead of arriving unattributable | Taken. `RequiresReference` is no longer advisory: `AccountFlag::RequireReference` is in state, provable before sending, and the executor refuses without one | [ADR-0016](adr/0016-required-payment-references.md) | **In code** |
| **Regular keys, master-key disable, and signer lists** — rotate the signing key without changing the address, neutralise an exposed seed, and do M-of-N recovery natively | Taken. Rotation matters more here than usual, because our addressing layer is aliases people have already shared. Signers are keys rather than accounts, which keeps authorisation a pure function of one record | [ADR-0017](adr/0017-key-rotation-and-signer-lists.md) | **In code** |
| **Fee escalation with a transaction queue** — congestion produces a predictable price and a wait, not a blind auction | Taken in principle, for when congestion is real. A remittance sender cannot reason about a fee market | [09](09-what-xrpl-answers.md) §2.5 | **Open** |
| Unique Node Lists — each operator subjectively chooses whom to believe | **Rejected.** Weaker and less legible than a stake-weighted quorum with slashing. One piece kept: signed, versioned, expiring lists from several publishers, as the shape for distributing the witness bootstrap set | [ADR-0012](adr/0012-staking-and-slashing.md), [ADR-0011](adr/0011-objective-anchors.md) | **Decided** |
| Account reserves to prevent state bloat | **Rejected as specified.** A minimum balance to *exist* excludes exactly the users this chain is for. Partly answered instead by charging for the scarce *public good* — a short username, which expires and renews | [ADR-0005](adr/0005-african-first-design.md), `crates/alias/src/registry.rs` | **In code** (partial) / **Open** (Phase 2) |

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

## Cardano / Ouroboros — [ADR-0010](adr/0010-long-range-attacks.md)

| Practice | Decision | Where it lives | Status |
|---|---|---|---|
| **Ouroboros Genesis chain-density rule** — bootstrap from genesis with no checkpoint at all | **Admired, not built.** Theoretically the strongest answer, and it removes the social trust assumption entirely. Cardano's own implementation is still a prototype under audit after years; inventing our own would be worse | [ADR-0010](adr/0010-long-range-attacks.md) | **Rejected** (revisit) |
| **Key-evolving signatures (KES)** — old keys are erased, so a leaked key cannot re-sign old slots | Deferred. Closes posterior corruption cryptographically rather than economically, but requires every validator to erase key material correctly on schedule, and a mistake is silent | [ADR-0010](adr/0010-long-range-attacks.md) | **Open** (post-mainnet) |
| **Ouroboros Samasika / Mina-style recursive proofs** — one small proof of the whole chain | **Rejected, on grounds of misattribution.** A recursive proof that set A signed the rotation to set B is a proof the *attacker* can also produce, since they hold A's keys. ZK makes verification succinct; it creates no economic cost, and long-range defence is entirely a question of cost. Mina's bootstrappability comes from Samasika's density rule, not from the SNARK | [ADR-0011](adr/0011-objective-anchors.md) | **Rejected** |

---

## Certificate Transparency — [ADR-0011](adr/0011-objective-anchors.md)

The one system studied here that is not a blockchain, and the closest match to
the problem a returning wallet actually has.

| Practice | Decision | Where it lives | Status |
|---|---|---|---|
| **Append-only Merkle logs with signed tree heads** | Taken wholesale. A witness records what it saw and signs a head; the shape is RFC 6962's | `crates/witness/src/log.rs`, `head.rs` | **In code** |
| **Consistency proofs** — prove the log you saw is still a prefix of the log now | Taken, and it is the load-bearing mechanism. A wallet remembers 40 bytes and can check six months of growth against them; a rewritten log has no proof that reconciles | `crates/crypto/src/merkle.rs`, `crates/witness/src/audit.rs` | **In code** |
| **Non-equivocation by detection, not prevention** | Taken with the limit stated: only same-size conflicts are compactly provable. An unavailable log is unavailable, not provably dishonest, and is handled by corroboration instead | `crates/witness/src/head.rs` (`Equivocation`) | **In code** |
| **A consequence that bites** — CT works because Google can distrust a CA | Taken, and it is why this design fits *here* specifically: [ADR-0007](adr/0007-distribution-and-sybil-resistance.md)'s attestors are licensed entities. The penalty is a licence, not a slashed bond | [ADR-0011](adr/0011-objective-anchors.md) | **Decided** (enforcement is off-chain by design) |
| Gossip between clients to detect a split view | Taken in a narrower form: corroboration across jurisdictions, and any disagreement refuses outright rather than picking a winner | `crates/witness/src/policy.rs` | **In code** |

---

## Bitcoin — [ADR-0011](adr/0011-objective-anchors.md)

Rejected as a consensus mechanism in [ADR-0004](adr/0004-no-proof-of-work.md);
taken here for the one property proof of work has that proof of stake cannot.

| Practice | Decision | Where it lives | Status |
|---|---|---|---|
| **An objectively verifiable header chain** — checkable from a hardcoded genesis by cumulative work alone, with no social input | Taken as the layer-2 anchor. This is the only mechanism that *removes* weak subjectivity rather than narrowing it | [ADR-0011](adr/0011-objective-anchors.md) | **Decided** (Phase 2) |
| **Timestamping** (Babylon, OpenTimestamps) — publish a digest into a chain nobody can rewrite | Taken, with ADR-0010's objection answered architecturally: the dependency is one-directional and non-blocking, so Bitcoin becoming unusable costs an anchor and not liveness | [ADR-0011](adr/0011-objective-anchors.md) | **Open** (Phase 2) |
| **Verifiable delay functions as a history anchor** | **Rejected.** Would convert forgery cost from zero back to wall-clock time, and a VDF used only for anchoring is not mining. But it degrades against hardware — a 10× faster evaluator forges a year in five weeks — and costs a new primitive, a new node role and a new incentive | [ADR-0011](adr/0011-objective-anchors.md) | **Rejected** |

---

## Ethereum — [ADR-0009](adr/0009-developer-payment-surface.md)

| Practice | Decision | Where it lives | Status |
|---|---|---|---|
| **ERC-681 payment request URIs** — one string a merchant emits, any wallet understands | Taken as the `afri:` scheme. The integration is a string, never an SDK | `crates/pay/src/request.rs` | **In code** |
| **x402 / HTTP 402** — a machine-checkable paywall with no account, card or subscription | Taken. We build a facilitator rather than a competing standard | [ADR-0009](adr/0009-developer-payment-surface.md) §1.2 | **Open** (Phase 2) |
| **Weak subjectivity checkpoints** — a syncing node needs a recent finalised checkpoint | Taken, with the social assumption named rather than hidden | `LightClient::from_checkpoint`, [ADR-0010](adr/0010-long-range-attacks.md) | **In code** |
| ERC-20 — assets as contracts | **Not needed.** Assets are native ledger objects, so a stablecoin is not a contract someone might have written wrong | `crates/bank` | **In code** |
| ERC-4337 / EIP-7702 account abstraction, to pay gas in something other than the native coin | **Not needed.** Fee abstraction is in the base protocol: any whitelisted denom, and a third party may pay | `crates/types/src/tx.rs` (`Fee`) | **In code** |
| EIP-3009 / ERC-2612 gasless approvals | **Not needed** — same reason | — | **Rejected** |

Ethereum's account-abstraction stack is fine engineering aimed at a problem we do
not have, because layer one made a different choice. Recorded so nobody later
mistakes the absence of ERC-4337 for a gap.

---

## Polkadot — [ADR-0009](adr/0009-developer-payment-surface.md)

| Practice | Decision | Where it lives | Status |
|---|---|---|---|
| **Forkless runtime upgrades** — the runtime is on-chain WASM, swapped by governance | Taken. A flag-day upgrade stops every mobile-money agent in a corridor at once. *Parameters are now governed without a fork; the runtime code is not yet* | [ADR-0009](adr/0009-developer-payment-surface.md) §2, [ADR-0022](adr/0022-governance.md) | **Partly in code** (Phase 3) |
| **OpenGov's arc** — a Council and Technical Committee first, stake-weighted referenda once a distribution exists to vote with | Taken, including the honesty about which stage we are at. A token vote at launch, when the founders hold nearly everything, is a vote whose result is known in advance | [ADR-0022](adr/0022-governance.md) §2 | **In code** (council); **Open** (opening it) |
| The **Fellowship** — an expert body with no power to change parameters or move assets | Convergent, and taken further: *our* council changes parameters but can move no assets either, and the list of what it may do is a six-item enum with no escape hatch | `crates/gov/src/proposal.rs` | **In code** |
| Governance dispatching an arbitrary runtime `Call` | **Rejected.** It makes "what can governance do?" answer "anything the chain can do". A seventh power here is a code change that must be argued for, not a proposal that must be noticed | `Action` | **Rejected** |
| **Pallets** — a runtime composed of modules owning their own namespace and invariants | Convergent: our `bank` / `alias` / `consensus` split is the same shape, reached independently | `crates/*` | **In code** |
| Parachains and shared security | **Rejected.** Excellent for renting security to many chains; we are one chain, and the slot economy is a capital barrier of the kind ADR-0005 rejects | [ADR-0001](adr/0001-sovereign-rust-l1.md) | **Rejected** |

---

## Pi Network — [ADR-0007](adr/0007-distribution-and-sybil-resistance.md)

The only project to have run this project's premise at scale. It supplied more
adopted practice than any other single source, in both directions.

| Practice | Decision | Where it lives | Status |
|---|---|---|---|
| **App-store onboarding instead of seed phrases** — the highest-leverage decision they made | Taken | [01](01-architecture.md), R10 | **Open** (Phase 4, wallet) |
| **Human-readable addresses as the default** — send to a username, never see an address | Taken, with the anchor changed: Pi binds a name to a company-certified identity, we bind it to a key, and the answer arrives under a proof | `crates/alias`, [ADR-0008](adr/0008-human-readable-addressing.md) | **In code** |
| A username namespace with no confusable rules and no on-chain commitment | **Rejected.** `@arnina` beside `@amina` is a live attack on a user base recruited for being non-technical | ADR-0008 §3 | **Rejected** |
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
| **Trusting period and skipping verification** — refuse to verify past a deadline shorter than unbonding; skip ahead on ⅓ overlap | Taken wholesale. This is the long-range attack defence, and the reason a phone can sync at all | `crates/light`, [ADR-0010](adr/0010-long-range-attacks.md) | **In code** |
| **21-day unbonding period** (Cosmos Hub) | Taken as the economic root the trusting period is derived from | `crates/light` (`UNBONDING_MS`) | **In code** (parameter) / **Open** (enforcement, Phase 2) |
| CosmWasm as the contract VM | Taken (ink! unmaintained since Jan 2026) | ADR-0003 | **Decided** |
| IBC for interop | Taken | ADR-0001, Phase 4 | **Open** |
| **MConnection channel multiplexing** — several streams over one TCP connection, each with a priority | **Open.** Peers here are trusted equally and consensus traffic does not outrank mempool gossip, so a saturated node misses votes. The right fix, not yet earned | [ADR-0023](adr/0023-peer-to-peer.md) | **Open** |
| **Secret Connection** — station-to-station over X25519, ChaCha20-Poly1305, identities exchanged inside the encrypted channel | Taken, including the fix it needed: the sorted-transcript defence against ephemeral-key malleability, and refusal of every low-order point rather than only the all-zero key that was reported | `crates/p2p/src/handshake.rs` | **In code** |
| **PEX in seed / crawler mode** | **Open.** No longer blocked — block sync exists, so a seed can serve history; what is missing is the crawler mode itself | ADR-0023, [ADR-0024](adr/0024-block-sync-and-the-node-binary.md) | **Open** |
| **Block sync as request/response, one block per message** | **In code.** A block travels with the certificate that finalised it, and one maximum-size block fills a frame, so batching was never available. Parallelism is one request in flight per peer, across many peers | [ADR-0024](adr/0024-block-sync-and-the-node-binary.md) | **In code** |
| **State sync from snapshots** — start near the tip without the history | **Open.** A new node replays every block from genesis. Needs the state tree served in verifiable chunks rather than blocks served whole | ADR-0024 | **Open** |
| **`priv_validator_state.json`** — a record of what this validator has already signed, so a restart cannot double-sign | **Open**, and the most serious operational gap left. Nothing here survives a restart, so a validator restored from a stale store could equivocate against itself | ADR-0024 | **Open** |
| **A genesis document every node agrees on byte for byte** | **In code, and harder than Tendermint's.** Genesis is canonical bytes rather than JSON, so agreement is not a question about parsers; `init` prints a hash for operators to compare, and `start` refuses a genesis that does not match the store it sits beside | ADR-0024 | **In code** |
| **`x/gov`'s quorum, threshold and voting period** | Taken in shape, not in electorate: a threshold in basis points and a deadline, over a seated council rather than bonded stake. Cosmos's own documented failure mode — low turnout making a coordinated minority decisive — is an argument against stake-weighting *at this stage*, not against voting | [ADR-0022](adr/0022-governance.md), `crates/gov` | **In code** |
| `NoWithVeto` and an explicit vote against | **Rejected.** With a threshold to clear and a deadline to clear it by, silence already means no. A proposal nobody answers lapses, which is the same shape a savings group's quorum takes | `crates/gov/src/proposal.rs` | **Rejected** |
| The Cosmos SDK itself | **Rejected** — Go, and the monetary modules we need cannot live at application layer | ADR-0001 | **Rejected** |

---

## Bitcoin's peer layer — [ADR-0023](adr/0023-peer-to-peer.md)

| Practice | Decision | Where it lives | Status |
|---|---|---|---|
| **Address groups** — count `/16`s, not addresses | Taken, and every diversity rule in the crate is written in terms of it. Holding many addresses in one group costs nothing; holding them across groups costs money and relationships | `crates/p2p/src/peer.rs` | **In code** |
| **Tried / new tables with source-group bucketing** — the post-Heilman addrman | Taken, including the two-hash construction that bounds one source to 32 of 256 buckets. Flooding therefore costs address *diversity* rather than address *count* | `crates/p2p/src/addrbook.rs` | **In code** |
| **A secret salt on bucket placement** | Taken, derived from the node's own secret key. A salt an attacker can compute is not a salt — they would work out offline which addresses collide and craft the cheapest flood | `AddrBook::new` | **In code** |
| **Diversify outbound connections by group** | Taken as the rule the rest exists to serve: a subnet holding ten thousand addresses is worth one of eight outbound slots | `Manager::wants_outbound` | **In code** |
| **asmap** — bucket by ASN rather than by prefix | **Open.** Erebus is mounted by an adversary that already holds many prefixes, so grouping by prefix does nothing against it. Bitcoin ships an IP-to-ASN map; that is a data-distribution problem we have not solved, and calling a /16 an AS would be worse than saying so | ADR-0023 | **Open** |
| **Anchor connections** — keep slots for peers you had before a restart | **Open.** A restart is exactly when an eclipse pays off, and this is the cheap defence | ADR-0023 | **Open** |
| **Inbound eviction preferring group diversity** | **Open.** Capping inbound without evicting means an attacker who opens forty connections keeps honest peers out | ADR-0023 | **Open** |
| **BIP324** — encrypt a public ledger's gossip | Taken, and for BIP324's reasons rather than for confidentiality: an authenticated channel makes a node id mean something, tamper-evidence stops an ISP editing what it cannot stop it dropping, and identities inside the channel make topology mapping cost an active attack | `crates/p2p` | **In code** |
| **Fixed-size padded frames** | **Rejected for now.** Message sizes are visible and a block is distinguishable from a vote by length. Padding costs bandwidth on exactly the links that have least of it | ADR-0023 | **Rejected** (revisit) |

---

## Stellar, Celo and the stablecoin rails — [00 §3.2](00-research.md)

| Practice | Decision | Where it lives | Status |
|---|---|---|---|
| **Issuer-controlled asset flags** (authorise, freeze) as a protocol feature, not a contract | Taken — a sovereign issuer needs this to be legally viable | `crates/bank/src/issuer.rs` | **In code** |
| Namespaced denominations, so `sov/ke/kes` is unambiguous about who issued it | Taken | `crates/primitives/src/denom.rs` | **In code** |
| Payments-first L1 design; assets as a native concept rather than a token contract | Taken | `crates/bank` | **In code** |
| Celo's **phone-number addressing** — the address a user already knows | Taken, and hardened: an alias resolves but never authorises, and rebinding is time-locked and vetoable | `crates/alias`, [ADR-0008](adr/0008-human-readable-addressing.md) | **In code** |
| Celo's **ODIS** — peppered commitments so a small identifier space cannot be enumerated | Taken. v1 uses a per-issuer pepper; the threshold-OPRF hardening is specified with its known `t`-of-`n` weakness recorded | `crates/alias/src/contact.rs`, [07](07-resolver-service.md) | **In code** (v1) / **Open** (v2) |
| Celo's **federated attestation issuers** (SocialConnect) | Taken — the attestors are the licensed parties ADR-0007 already commits to, so it adds no new trust assumption. Licensed at genesis since [ADR-0021](adr/0021-licensing-attestors.md); before that the registry had no writer and the whole contact half was unreachable | `crates/alias/src/rebind.rs`, `crates/executor/src/genesis.rs` | **In code** |
| Celo's **attestation service**, where controlling the number completed verification | **Rejected.** SIM-swap is up to 43% of mobile-money fraud here; possession of a number must never be possession of an account | ADR-0008 §5 | **Rejected** |
| Celo's mobile-first, light-client-first posture | Taken | `crates/light`, `crates/rpc`, R3 | **In code** |
| Federated Byzantine agreement (Stellar's SCP) | **Rejected.** Sound protocol, but its decentralisation is entirely a function of who holds the quorum slices — Pi demonstrated the failure mode. An explicit, published validator set is more honest and more testable | ADR-0002, ADR-0007 §2 | **Rejected** |
| USD-denominated rails (Visa×Yellow Card, Onafriq×Circle) | **Rejected as the default denomination.** This is the strategic gap the project exists to close, not a model to copy | [00 §3.2](00-research.md) | **Rejected** |

---

## African payment systems — [00 §2, §3.1, §3.3](00-research.md)

| Practice | Decision | Where it lives | Status |
|---|---|---|---|
| **PAPSS as the settlement anchor**, not a competitor | Taken — it has the political mandate we would otherwise spend a decade earning | ADR-0001, Phase 5 | **Decided** |
| **Agent float is the binding constraint**, not technology — so pay for float | Taken; this is the mechanism that replaces mining | [04](04-earning-and-participation.md) §2 | **Decided** |
| **Group savings** (chama, susu, stokvel, tontine, equb, ajo, VSLA) as a native account type rather than a contract pattern | Taken — the clearest case of designing from African financial practice | `crates/types/src/group.rs` | **In code** |
| **The VSLA/VICOBA methodology** — one to five shares a meeting, a share-out proportional to shares, a separate social fund at an equal premium | Taken whole. Modelling it as a rotation would have thrown away the part that makes it *banking* rather than redistribution | `crates/types/src/group.rs`, [ADR-0019](adr/0019-vikoba-accumulating-savings.md) | **In code** |
| **VICOBA lending rules** — the borrower's own savings cover a third of the loan, two member guarantors, a flat service charge quoted as one number | Taken. Guarantors are recorded and not enforced, because a chain cannot make one pay and pretending otherwise would be worse than naming the limit | `crates/types/src/group.rs` | **In code** |
| **M-Koba's three signatories** — Secretary initiates, Treasurer verifies, Chairperson approves | **Deferred.** A quorum over the whole membership does the same job with fewer named roles and is what the group already votes with; whether groups migrating from M-Koba want the flow they already trust is untested | [ADR-0019](adr/0019-vikoba-accumulating-savings.md) | **Open** |
| **Users must never need the native token to transact** — the eNaira and dormancy lesson | Taken | `crates/types/src/tx.rs`, `crates/executor` | **In code** |
| USSD and feature-phone fallback | Taken | R10 | **Open** (Phase 4) |
| eNaira's launch model — build the rail, assume adoption | **Rejected.** The failure was distribution and incentives, never technology. Any "let governments issue stablecoins" story without a distribution answer repeats it | [00 §3.1](00-research.md) | **Rejected** |

---

## Stablecoin issuance — [ADR-0020](adr/0020-sovereign-issuance.md)

| Practice | Decision | Where it lives | Status |
|---|---|---|---|
| Circle's **role separation** — owner, masterMinter, minters, pauser, blacklister as distinct keys | Taken, condensed to three: authority, minter, freezer. A single all-powerful issuer address is the finding every stablecoin audit opens with | `crates/bank/src/issuer.rs` | **In code** |
| Circle's **minter allowance** — a finite, spend-down authorisation per hot key | Taken, and it is the most valuable single idea here: it converts "a stolen minting key is unbounded" into "a stolen minting key costs what was left on it" | `Issuer::spend_allowance` | **In code** |
| Circle's **burn from the caller's own balance** — no `from` argument | Taken. Redemption is a holder-signed transfer followed by a burn, so consent is on the chain; there is no message that destroys a holder's balance | `Bank::burn` | **In code** |
| Stellar and XRPL's **one-way issuer flags** — a power over holders may be renounced but never granted | Taken as a general principle and applied to the supply cap, which ratchets. A promise the promiser can revoke is not a promise | `Issuer::tighten_cap` | **In code** |
| XRPL/Stellar **clawback** — an issuer reclaiming a holder's tokens | **Deferred, not rejected.** Freeze plus a court order plus a holder-signed transfer covers the ground while leaving consent on the chain. If added, the ratchet rule says it must be declared before issuance and be renounceable but not grantable | ADR-0020 | **Open** |
| **Per-period mint ceilings** as a circuit breaker | **Open.** The allowance bounds total damage, not damage per day; a window needs a clock the issuer record does not carry | ADR-0020 | **Open** |
| **Two-tier CBDC distribution** — the central bank runs the ledger, licensed intermediaries reach end users | Taken, expressed in keys rather than institutions: the authority is the central bank, minters are the intermediaries | `crates/bank` | **In code** |
| **Proof of reserve** | **Open.** The chain proves how much exists and cannot prove what backs it. A cap narrows the gap without closing it | Phase 4 | **Open** |
| OpenZeppelin's **`Ownable2Step`** — the successor must accept before the role moves | Taken for issuer authority. A one-step transfer to a mistyped address ends a currency's governance permanently; the acceptance is proof a key exists on the other end | `Issuer::accept_authority`, [ADR-0022](adr/0022-governance.md) §6 | **In code** |
| OpenZeppelin's **`TimelockController`** — a delay between a governance decision and its effect | Taken. The delay is notice, not deliberation: everyone who has to live with the decision learns of it while it is still reversible. Cancellation is a vote at the same threshold rather than a guardian key, because a key that can cancel anything can deny governance entirely | `crates/gov`, ADR-0022 §3 | **In code** |
| BIS **mBridge** — a shared multi-CBDC platform where each central bank is the exclusive issuer of its own currency and a separate committee sets platform rules | Taken as the organising principle of the whole governance design: the platform is governed collectively, the money on it is not | ADR-0022 §1 | **In code** |

---

## Cryptographic standards

| Practice | Decision | Where it lives | Status |
|---|---|---|---|
| **RFC 6962 Merkle hashing** — leaf and node prefixes, which is what makes Bitcoin's CVE-2012-2459 duplicate-node collision impossible | Taken | `crates/crypto/src/merkle.rs` | **In code** |
| Length-prefixed domain separation on every hash | Taken | `crates/crypto/src/hash.rs` | **In code** |
| bech32m (BIP-350) addresses, checksummed and human-readable | Taken, with the BIP's own test vectors | `crates/crypto/src/bech32.rs` | **In code** |
| Ed25519 with `verify_strict` — rejecting the malleable and small-order edge cases | Taken | `crates/crypto/src/keys.rs` | **In code** |
| **Absence proofs**, not only membership proofs | Taken — a phone must be able to verify that something is *not* there | `crates/state/src/smt.rs`, `crates/light`, `crates/rpc` | **In code** |
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
2. **We had no governance at all.** XRPL's amendment process is the model worth
   copying, and nothing in the roadmap named it. *Parameter and role governance
   landed in [ADR-0022](adr/0022-governance.md); amending the runtime code is
   still Phase 3.*
3. **TRON's free bandwidth quota is a better answer to R2 than we have.** Fee
   abstraction and sponsored fees let *someone else* pay; a free tier means
   nobody has to. Phase 2.
4. **We reject Pi's funding model without naming ours.** Recorded as open in
   ADR-0007 rather than left implicit.
5. **The light client's own documentation over-promised.** `from_checkpoint`
   said "a checkpoint is a height and a hash" while requiring a header and both
   validator sets. The doc comment described the trust model correctly and the
   API did not express it. `LightClient::from_block_id` now does, which is what
   makes a scannable checkpoint possible: `crates/light/src/lib.rs`.
6. **Header time was bounded in one direction only.** Monotonicity stops an
   attacker rewinding the trusting-period clock; nothing stopped a header dated
   next year parking the deadline in the future and keeping a client trusting a
   dead chain. Now `MAX_CLOCK_DRIFT_MS`, with
   `a_header_dated_in_the_future_is_refused`.

Items 2–4 are in [05-roadmap.md](05-roadmap.md). This document is updated
whenever an ADR is accepted; a practice cited nowhere in a status column is a
practice we have not actually taken.
