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
- [x] **Sovereign issuance** — mint, burn, freeze, pause and a supply cap, as
      messages. Before this the chain could not create money at all: the bank
      module was written and tested and reachable from nothing but genesis, so
      every denomination's supply was fixed forever at block zero. The keys are
      split — a cold authority that configures and never issues, hot minters
      with finite allowances, a separate compliance key — so a stolen minting
      key costs a bounded amount
      *([ADR-0020](adr/0020-sovereign-issuance.md))*
- [x] **Attestors licensed at genesis** — the contact half of `crates/alias`
      was inert: `AttestContact` checks an attestor registry that nothing
      populated, so no phone number could ever be bound and the SIM-swap defence
      guarded a feature nobody could switch on. Genesis licenses attestors the
      way it licenses issuers, and `CountryCode` moved to `crates/primitives` so
      a jurisdiction has one spelling rather than three
      *([ADR-0021](adr/0021-licensing-attestors.md))*
- [x] **Governance** — until this, every trusted role on the chain was fixed at
      genesis and could not be rotated, added or revoked: a lost issuer key
      stayed lost, a withdrawn attestor licence stayed licensed on-chain, and
      every parameter was a `const` whose change meant a flag day. A seated
      council decides network questions at two thirds behind a timelock, with no
      jurisdiction able to block and no two able to decide. It can license
      attestors, admit a currency and tune parameters — and it can reach nobody's
      money: a currency's authority moves only by a two-step handover signed at
      both ends *([ADR-0022](adr/0022-governance.md))*
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

- [x] **Validator-to-validator networking** — a separate layer from the client
      RPC, as it is in CometBFT. An authenticated, encrypted transport
      (station-to-station over X25519 and ChaCha20-Poly1305, with the
      ephemeral-key malleability bug that broke Tendermint 0.32 refused at the
      exchange), an eclipse-resistant address book following Bitcoin's tried/new
      bucketing, and one rule above them: no two outbound connections into the
      same address group. The consensus driver did not change a line
      *([ADR-0023](adr/0023-peer-to-peer.md))*
- [x] **Block sync** — a node that fell behind asks its peers for the heights it
      missed. A block travels with the commit certificate that finalised it, and
      is applied only after that certificate verifies against this node's own
      validator set *and* re-execution reproduces the header's state root — so a
      peer is a source of blocks, never an authority about them
      *([ADR-0024](adr/0024-block-sync-and-the-node-binary.md))*
- [x] **A node binary** — `afrolinkd`: keys, a genesis document whose hash
      operators compare, a durable store, both transports, a consensus loop that
      owns the only clock in the workspace, and a clean stop. A second node
      joins a running chain from genesis and catches up *(ADR-0024)*
- [ ] **State sync** — a new node still replays every block from genesis. Needs
      the state tree served in verifiable chunks rather than blocks served whole
      *(ADR-0024)*
- [ ] **Block gossip as parts** — a `PartSet` of 64 KiB pieces with its own
      Merkle root, as Tendermint does, so the largest thing a peer can ask a node
      to hold is a constant rather than a whole block. Frames are already read
      incrementally, which bounds the memory; this bounds the *message*
      *(ADR-0024)*
- [ ] **Channel priorities** — consensus traffic does not currently outrank
      mempool gossip, so a node whose link is saturated by transactions misses
      votes. CometBFT multiplexes with per-channel priority for exactly this
      *(ADR-0023)*
- [x] **Double-signing protection across a restart** — the last signed
      `(height, round, step)`, written and `fsync`ed *before* the signature is
      released, refused if it is not strictly after the last, and fail-closed if
      it cannot be written. Beside the consensus key so the two cannot be copied
      apart *([10](10-network-hardening.md) §2)*
- [x] **Equivocation reported by the network rather than by a human** — a node
      that sees two conflicting votes files the `ReportEquivocation` transaction
      itself. Until this, `Staking::slash` was reachable only from a
      hand-crafted transaction, so the chain's economic security argument
      described code that never ran *([10](10-network-hardening.md) §1)*
- [x] **A joined harness** — N real nodes, N sockets, N databases, real
      consensus. Agreement, catch-up after a healed partition, a late joiner from
      genesis, and a restart rejoining. Found four defects in its first hour, and
      two more in itself: it never re-dialled where the daemon does, and it threw
      away the `halted` flag the daemon treats as fatal, so a failed store write
      was silent *([10](10-network-hardening.md) §15, §15a)*
- [ ] **Seed nodes and peer exchange in crawler mode** — no longer blocked on
      block sync, which now exists; what is missing is the crawler mode itself
      *(ADR-0023)*
- [x] **Inbound eviction preferring group diversity** — the inbound cap alone
      meant an attacker who could open forty connections kept honest peers out,
      which is an inbound cap of zero reached by an attacker rather than by
      configuration. A full node now takes a seat back from an over-represented
      address group instead of refusing everyone, so a subnet buys one inbound
      seat as well as one outbound one *([10](10-network-hardening.md) §3)*
- [x] **Anchor connections across a restart** — two outbound peers written at
      shutdown and dialled before the address book, then the file deleted, so a
      restart is no longer a fresh draw at every outbound slot from a book an
      attacker has had hours to shape. Bitcoin PR #17428, sized to eight slots
      *([10](10-network-hardening.md) §4)*
- [x] **Bans that expire** — an hour of accumulated tick time, swept rather than
      merely ignored, and deliberately still not persisted: a saved ban list is a
      saved mistake, and anchors cover the reason Bitcoin persists one
      *([10](10-network-hardening.md) §5)*
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
- [ ] Downtime slashing — needs the per-block vote history a networked node has.
      No longer blocked: the votes now arrive over a wire *(ADR-0023)*
- [ ] **Network hardening, the rest** — address advertisement, channel priority,
      a seen-set keyed by height, retention, a metrics endpoint, state sync and
      validator set rotation, each with its reference design and its reasoning
      *([10](10-network-hardening.md))*. Also open, and named there rather than
      hidden: a saturated node refuses new inbound peers, whose answer is
      dial-side backoff plus address advertisement, not more eviction
- [ ] Delegation — stake through another operator. Deliberately deferred:
      reward accounting and slashing across delegators is the largest addition
      to the staking surface *(ADR-0012)*
- [ ] Epoch rotation — `active_set()` derives the set; nothing yet installs it
      at a boundary. No longer blocked: the node binary exists, and this is now
      the change that also forces block sync to follow validator set transitions
      the way `crates/light` already does *(ADR-0024)*
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
- [ ] Off-chain resolver service *(specified in [07](07-resolver-service.md))* —
      the chain-side half is now reachable, so what remains is the service that
      turns a number a user types into the commitment the chain stores
      *(ADR-0021)*
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
- [ ] **Runtime upgrade governance** — parameter governance is built
      *([ADR-0022](adr/0022-governance.md))*; what remains is amending the
      *code*: XRPL-style amendment voting over a Polkadot-style on-chain WASM
      runtime, so a change of rules is not a flag day that stops every agent in
      a corridor at once *(ADR-0009 §2)*
- [ ] **Open the network track to a stake-weighted vote**, once there is a real
      distribution to vote with. The council is the honest answer at launch and
      says so; Polkadot ran one for years before OpenGov, and skipping that
      stage does not skip it *(ADR-0022, "Revisit if")*
- [ ] Name the funding model for the public-goods side of the network.
      [ADR-0007](adr/0007-distribution-and-sybil-resistance.md) rules out Pi's
      answer (monetising users' attention) without yet naming ours
- [ ] Local-language docs (Swahili, French, Arabic, Hausa, Amharic, Portuguese)

**Exit criterion:** an external developer ships a working app in a weekend
without talking to the core team.

## Phase 4 — The money layer

- [x] Sovereign issuance: mint, burn, freeze, caps, audit trail — built early
      because without it the chain's whole purpose was unreachable
      *([ADR-0020](adr/0020-sovereign-issuance.md))*
- [ ] **Clawback**, if a central bank asks for it as a condition of issuing.
      Deliberately absent: freeze plus a court order plus a holder-signed
      transfer covers the same ground and leaves the consent on the chain
      *(ADR-0020)*
- [ ] **Per-period mint ceilings** — the allowance bounds total damage, not
      damage per day *(ADR-0020)*
- [x] **A currency's authority can be handed on** — two steps, both signed, so a
      transfer to a mistyped address does not end a currency's governance
      forever. Governance cannot do it: the council admits currencies the chain
      has never seen, and from that moment each currency governs itself
      *([ADR-0022](adr/0022-governance.md))*
- [ ] **Delisting a currency** — deliberately not expressible. A rogue authority
      can pause and freeze its own denomination and reach nothing else; what
      happens to holders of a denomination the network stops accepting is a
      harder question than the mechanism *(ADR-0022)*
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
