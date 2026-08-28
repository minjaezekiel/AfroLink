# 04 — How people earn AFRI

> **This document answers a request directly.** The brief asked that "people
> should be able to mine it and get incentives in the form of African Shillings".
> The goal behind that — *ordinary people, without capital, should be able to
> earn by supporting the network* — is right and central to the project. Mining
> is the wrong mechanism for it in this specific context, for reasons that are
> arithmetic rather than ideological. What follows is the goal, kept; the
> mechanism, replaced with four that work better here.

---

## Why not proof of work

Full reasoning in [ADR-0004](adr/0004-no-proof-of-work.md). In brief:

PoW rewards flow to whoever has the cheapest electricity per hash. That is
industrial-scale hydro and stranded gas — not Africa, where **~600 million people
have no electricity at all** and grid power is among the most expensive in the
world per kWh delivered.

A PoW "African cryptocurrency" would, within one difficulty epoch, have its
security budget and its issuance captured by mining farms outside the continent.
The people it was built for would be buying its coin, not earning it. Mining
would be a mechanism for extracting value *from* Africa while carrying its name.

The goal is that ordinary people earn. PoW defeats that goal here. So we use
mechanisms that do not.

---

## The four ways to earn

### 1. Staking and delegation — *earn from a phone, no hardware*

Hold AFRI, delegate to a validator, earn a share of issuance and fees. No node, no
electricity, no technical skill. Minimum delegation is deliberately tiny (1 AFRI)
so this is not a rich-person's mechanism.

- **Capital needed:** some AFRI
- **Power needed:** none beyond charging a phone
- **Realistic return:** 8–12% nominal early, declining as staking ratio rises

### 2. Agent liquidity mining — *earn with no capital, from a market stall*

**The one that matters most, and the closest honest analogue to "mining".**

Research §2.3: the binding constraint on rural payments is agent cash and float,
not technology. So the protocol pays for exactly that.

An agent registers, stakes a small bond, and does cash-in/cash-out. On top of the
commission they already charge, they earn a **protocol-funded liquidity reward**
in AFRI, scaled by:

- volume settled,
- **service in underserved geographies** (a rural cell earns a multiplier over a
  saturated urban one),
- uptime and completion rate,
- customer rating.

Failed settlements are slashed against the bond.

This is mining in the sense that matters: you contribute a scarce resource the
network needs, and the protocol pays you in newly issued AFRI. The scarce resource
is float and physical presence rather than hashes — which is the whole point,
because float and presence are things an African trader *has* and a foreign
mining farm does not.

- **Capital needed:** a small bond, refundable
- **Power needed:** a phone
- **Who this is for:** the ~1 million+ existing mobile money agents

### 3. Light-node and relay rewards — *earn from a $50 device*

Run a light node that serves Merkle proofs, relays transactions, or provides
data-availability sampling. Rewards are paid for provably-served queries.

Deliberately cheap: a Raspberry Pi on solar, or a phone left plugged in. Bandwidth
is affordable in Africa (~2% of monthly income) even where power is not — which is
why the incentive targets bandwidth and availability, not computation.

- **Capital needed:** ~$50 of hardware
- **Power needed:** watts, not kilowatts

### 4. Oracle and attestation rewards — *earn with local knowledge*

FX rates between African currency pairs are thin, badly quoted, and poorly
served by global oracles. Contributors post signed price observations and
attestations (merchant verification, agent ratings) and earn for accuracy,
measured against the eventual consensus. Wrong or manipulated data is slashed.

- **Capital needed:** a stake bond
- **Who this is for:** anyone with reliable local market knowledge

---

## Comparison

| Mechanism | Capital | Power | Hardware | Location matters | In the brief? |
|---|---|---|---|---|---|
| Proof of work | high | **kilowatts** | ASICs | only via electricity price | ❌ rejected |
| Staking | some AFRI | none | phone | no | ✅ |
| **Agent liquidity** | **small bond** | **phone** | **phone** | **yes — favours underserved areas** | ✅ |
| Light node / relay | ~$50 | watts | Pi or phone | somewhat | ✅ |
| Oracle / attestation | bond | none | phone | yes | ✅ |

Every row except the rejected one is reachable by someone with a phone and no
capital. That is the requirement the brief was actually expressing (R6), and it
is met more completely without PoW than with it.

---

## Emission split

Of the AFRI issued as rewards each epoch:

| Destination | Share |
|---|---|
| Validators and delegators (consensus security) | 55% |
| Agent liquidity mining | 25% |
| Light nodes, relays, data availability | 10% |
| Oracles and attestations | 5% |
| Ecosystem and public-goods fund (governed) | 5% |

**45% of all issuance goes to participants who need no significant capital.** On
a PoW chain that figure is zero — every coin goes to whoever bought the most
hardware. That difference is the entire argument of this document, expressed as a
number.

Splits are governance parameters and will be tuned with real usage; the intent
is that they may be adjusted but that the no-capital share is not cut without a
supermajority.
