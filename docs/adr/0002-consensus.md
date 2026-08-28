# ADR-0002 — Ubuntu-BFT: Tendermint-class BFT over proof of stake

- **Status:** accepted
- **Date:** 2026-08-28

## Context

The chain settles retail payments. That imposes a requirement most chains do not
have: **a market trader handing over goods cannot reason about reorg
probability.** When the phone says paid, it must be paid.

That single requirement eliminates every Nakamoto-style (probabilistic) consensus
and points at BFT with deterministic finality.

Options considered:

| Family | Finality | Verdict |
|---|---|---|
| Nakamoto PoW/PoS longest-chain | probabilistic | rejected — unusable at a market stall |
| **Tendermint-class BFT** | **deterministic, 1 block** | **accepted** |
| DAG-based (Narwhal/Bullshark) | deterministic, higher throughput | rejected for v1 — complexity |
| Solana-style (Alpenglow, ~150ms) | deterministic | rejected — hardware requirements |

**Alpenglow deserves a note**, since 100–150ms finality is genuinely impressive
and would be lovely to have. It is rejected because Solana-class validators
require hardware and bandwidth that would concentrate our validator set in a
handful of data centres — the exact centralisation the geographic distribution
requirement exists to prevent. Our latency floor is set by intercontinental
network round-trips anyway; ~1s is well past the point of diminishing returns for
a payment.

**DAG-based BFT** is the credible future upgrade if throughput ever binds. It is
not v1: formal verification of DAG protocols is recent, and the complexity is not
justified before there is load to justify it.

## Decision

**Ubuntu-BFT** — Tendermint-class BFT over proof of stake.

| Parameter | Value |
|---|---|
| Block time | 1s |
| Finality | deterministic, 1 block |
| Safety threshold | < 1/3 stake Byzantine |
| Validator set | 100, → 150 by governance |
| Rounds | propose → prevote → precommit, with lock & valid rules |

Reference point: Malachite (Rust BFT engine) reports ~780ms average finality at
100 validators with 1MB blocks — evidence the target is achievable at our set
size.

**Novelty budget: zero.** Consensus is the one layer where being interesting is a
liability. Every departure from a well-studied protocol is a departure from its
proofs and its decade of adversarial review.

### Two deliberate additions

1. **Geographic distribution, enforced in-protocol.** Per-validator stake caps,
   and the active set must span ≥ 15 countries. A stake-weighted set with no such
   rule concentrates wherever power and bandwidth are cheapest — which for a
   network built for Africa would be a self-inflicted wound. This is a
   requirement, not an aspiration, and so it lives in validator selection.
2. **Delegation with a very low minimum** (1 AFRI), so security participation is
   not gated on wealth.

## Consequences

**Good:** instant finality suited to payments; well-understood safety proofs; a
known operational profile; slashing for equivocation is straightforward.

**Bad:** the validator set is bounded (BFT is O(n²) in messages) — 100–150, not
thousands. **The chain halts rather than forks if ≥ 1/3 of stake goes offline.**
That is the correct trade for money (a halt is recoverable; a double-spend is
not), but it must be understood as an operational commitment: validator uptime is
a first-class concern, not an afterthought.

## Revisit if

- Throughput demand exceeds ~5,000 TPS sustained → evaluate DAG-based consensus
- The validator set needs to exceed ~200 → evaluate committee sampling
