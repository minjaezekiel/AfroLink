# 02 — Tokenomics and the asset model

## 1. The asset model — decided

The original brief used one name, "African Shilling (ASh)", for two things: the
thing people *mine and earn*, and the currency that *simplifies payments across
Africa*. Those are two assets with opposite requirements, and conflating them is
the most common way token designs fail.

| | Must be | Because |
|---|---|---|
| A **reward** token | free-floating, issued by protocol emission | you cannot mint a stable asset as a reward without backing it; that is how algorithmic stablecoins die |
| A **payment** unit | stable against what people buy | nobody prices bread in something that moves 15% a week |

**Decision (owner, August 2026): the network has both, under separate names.**

### AFRI — the native protocol coin

Gas, staking, governance, and reward emission. **Free-floating.** This is what
validators, delegators, agents, light nodes and oracles earn — the "mining"
reward from the brief. Smallest unit: the **sente** (10⁹ sente = 1 AFRI).
Addresses carry the `afri1…` prefix.

### ASh — the African Shilling, pan-African settlement unit

A basket-referenced unit of account composed of the national stablecoins on the
network (`sov/ke/kes`, `sov/ng/ngn`, `sov/tz/tzs`, …), weighted by intra-African
trade share and rebalanced by governance. Fully backed by the basket it
references — a claim on assets that exist on-chain, not an algorithmic peg.

ASh is the unit for cross-border invoicing and settlement: it lets a Tanzanian
exporter and a Nigerian importer agree a price without either taking the other's
currency risk and without routing through dollars.

**Why this way round.** Naming a free-floating token the "African Shilling"
invites the reading that it is money issued by an authority — which attracts
scrutiny under Nigeria's ISA 2025 and Kenya's VASP Act 2025 that a launching
network does not need. Attaching the name to the *stable, asset-backed* unit
puts it where it is accurate. AFRI carries no such implication: it is plainly a
network resource token, and should always be described as one.

This decision is now baked into the code — the denom `afri`, the `afri1` address
prefix, `SENTE_PER_AFRI` — and changing it after mainnet would mean reissuing
every address. It is settled.

## 2. Supply and issuance

| Parameter | Value |
|---|---|
| Genesis supply | 1,000,000,000 AFRI |
| Smallest unit | sente (10⁻⁹ AFRI) |
| Initial inflation | 7% |
| Long-run inflation | 2% floor |
| Schedule | declines ~0.5pp/year to the floor |

Inflation is **not** a target on its own — it funds the reward mechanisms in
[04-earning-and-participation.md](04-earning-and-participation.md), 45% of which
go to participants who need no significant capital.

### Genesis allocation

| Allocation | Share | Vesting |
|---|---|---|
| Ecosystem & developer grants | 25% | 5y, governed |
| Community & agent bootstrap | 20% | 4y, usage-triggered |
| Core contributors | 15% | 4y, 1y cliff |
| Foundation treasury | 15% | 5y |
| Public sale / liquidity | 12% | partly unlocked |
| Strategic partners (telcos, banks, PAPSS) | 8% | 3y, 1y cliff |
| Validator bootstrap | 5% | 2y |

**Community + ecosystem + agent bootstrap = 45%.** Insider allocation (core +
partners) is 23%, below the ~35–40% typical of recent L1s. That ratio is the
number sophisticated observers check first, and it should stay defensible.

## 3. Fees

Deliberately near-zero, because the competitor is a 7.4% remittance fee, not
another blockchain.

| Transaction | Target fee |
|---|---|
| Transfer | ~$0.001 |
| Cross-border | ~$0.005 |
| Contract call | metered by gas |

Fee distribution: **50%** to validators and delegators, **30%** burned, **20%**
to the public-goods fund.

The burn matters: at scale it makes AFRI deflationary against usage, which is what
ties the token's value to the network being *used* rather than to it being
*held*. A token whose value comes only from staking yield is paying itself with
its own inflation.

**Fees are payable in any whitelisted stablecoin** — see architecture §4.1. A
user never needs to hold AFRI. This is the single most important adoption
decision in the design, and it is worth more than any throughput figure.

## 4. Sovereign stablecoins

Countries issue their own: `sov/ke/kes`, `sov/ng/ngn`, `sov/gh/ghs`. Each is
controlled solely by its authorised issuer, enforced by the denom namespace in
the type system (`crates/primitives/src/denom.rs`).

**Reserve models** — the protocol supports all three and does not pick for the
issuer:

1. **Central bank direct** — a true CBDC, 1:1 against central bank liability.
2. **Licensed issuer, 100% reserved** — commercial issuer, T-bill/cash reserves,
   on-chain proof of reserve, independently attested. This is the cNGN model, and
   the research says it is the one that actually shipped.
3. **Overcollateralised synthetic** — for currencies where neither of the above
   is available yet.

**What the protocol demands regardless of model:** published reserve
attestations, a redemption guarantee, and a public audit trail for every mint,
burn, freeze and blacklist action.

## 5. The value accrual question, answered plainly

An honest statement of why AFRI should be worth anything:

1. **Security budget.** Staked AFRI secures a network settling real payment value.
   The stake must be worth more than what an attacker gains from reversing a
   block.
2. **Fee burn.** 30% of every fee is destroyed; usage reduces supply.
3. **Governance.** Control over stablecoin issuer admission, reward splits, and
   basket weights is a genuinely valuable right.

And what should *not* be claimed: AFRI is not backed by anything, it is not a
claim on the foundation, and its price will be volatile. The stable instruments
on this network are the sovereign stablecoins and ASh — which is exactly why the
design keeps them separate from AFRI rather than blurring the two.
