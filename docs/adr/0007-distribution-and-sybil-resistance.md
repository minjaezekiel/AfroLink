# ADR-0007 — Distribution and Sybil resistance: what Pi Network settles

- **Status:** accepted
- **Date:** 2026-08-29
- **Relates to:** [ADR-0004](0004-no-proof-of-work.md) (no PoW),
  [ADR-0005](0005-african-first-design.md) (African-first design),
  [02-tokenomics.md](../02-tokenomics.md),
  [04-earning-and-participation.md](../04-earning-and-participation.md)

## Context

[ADR-0004](0004-no-proof-of-work.md) rejected proof of work on arithmetic
grounds and replaced it with four earning mechanisms. That ADR argued from first
principles. It did not have an empirical test to point at.

There is one. **Pi Network ran this experiment at scale**, and it is the only
project that has: mobile-first "mining", rewards aimed at low-income markets,
growth by referral, tens of millions of users, with Nigeria as its
third-largest market worldwide. Evidence and sources: [§3.4 of the research
doc](../00-research.md).

Pi is usually discussed as either a revolution or a scam. Both readings waste
it. The useful reading is that Pi **validated the demand side of our thesis and
falsified the mechanism**, and it did so in our market. Ignoring that because
the project is unfashionable would be a failure of engineering.

The problem Pi actually hit is one we have not yet answered: **if issuance goes
to people rather than to capital or hashes, what stops one person from being ten
thousand people?** PoW answers it with electricity; PoS answers it with stake.
We rejected the first and cannot rely only on the second without recreating the
"rich get richer" outcome ADR-0004 warns about. Pi answered it with corporate
KYC, and that answer is what we must not copy.

## What Pi got right

Recorded deliberately, because the failures are easier to remember:

- Onboarding via an app store rather than a seed phrase produced 70M+
  registrations and ~16.5M migrated accounts.
- Nigeria at ~2M users and ~850k daily actives — with no local partnerships and
  no regulatory approval — is a stronger demand signal for this project than any
  market study we could commission.
- Users did not care that consensus was not PoW.
- A bundled builder stack (browser, wallet, app studio, domains) beat asking
  developers to assemble one.

## The five failures, and what each one binds

### 1. Phones did not validate; the marketing said they did

Pi's own FAQ states that consensus runs on computer nodes and that a mobile
miner contributes "trust relationships". The app was a daily check-in button
called mining.

**Binds:** we do not use the word "mining" for anything a phone does. The one
mechanism that legitimately resembles mining — **agent liquidity mining** — is
named for a real contribution (cash float, physical presence) that the protocol
measures and pays for. Every reward path in
[04-earning-and-participation.md](../04-earning-and-participation.md) must name
the resource it buys. If a mechanism cannot name what it purchases, it is a
signup bonus and must be labelled one.

### 2. Federated consensus without distributed trust is a permissioned database

SCP/FBA is a sound protocol. Its decentralisation is entirely a function of who
holds the quorum slices, and Pi's were held by one organisation — reportedly
~43 nodes and 3 validators, with community nodes not validating mainnet.

**Binds:** [ADR-0002](0002-consensus.md)'s explicit, published validator set with
weights is the right call, and honesty about it is a feature. We add a
requirement: **decentralisation must be a measured, published metric, not a
claim** — validator count, Nakamoto coefficient, stake and geographic
concentration, emitted by the node and served over RPC. A chain that reports
"3 validators" honestly is in better shape than one that says "decentralised"
and means the same thing.

**Implemented:** `crates/consensus/src/decentralization.rs`. Writing it exposed
a real gap — geographic distribution was *counted* and never *measured*, so a
set of twelve validators with nine in one jurisdiction passed the 10% stake cap
and the 15-country minimum while a single country could halt the chain. That
case is now a test. The report carries Nakamoto coefficients for both halting
and control, over validators and over countries, plus an HHI that captures the
shape of the distribution rather than only its head — all in integer arithmetic,
because a metric two nodes can disagree about is not a metric.

### 3. Distribution before utility guarantees the collapse

~100B PI allocated to tens of millions before there was anything to buy. The
unlock schedule then met no demand: **−97% from peak to a ~$0.076 low**.

**Binds:** three rules on AFRI issuance.

- **Earned against measured work, never against a signup date or a streak.**
  Volume settled, proofs served, uptime, attestation accuracy — quantities the
  chain can verify without trusting the claimant.
- **Vesting tracks continued service, not calendar time.** A cliff plus a clock
  converts every recipient into a scheduled seller. Rewards that keep accruing
  only while the service continues do not.
- **Issuance is capped against realised network usage**, so emission cannot run
  years ahead of the thing it is supposed to be paying for. The parameter belongs
  in [02-tokenomics.md](../02-tokenomics.md); the principle belongs here.

### 4. Referral multipliers pay for recruiting

+25% of base rate per active referral, +20% per security-circle member up to
+100%. Growth was spectacular; usage was not. Those two facts are the same fact.

**Binds:** **no referral multiplier on AFRI issuance. Ever.** Growth incentives,
if we want them, are funded from the governed ecosystem fund as a budgeted
expense — visible, capped, and revocable — never from the protocol's reward
emission. This is a hard constraint, not a default: an issuance curve that pays
for headcount is a pyramid regardless of the intent behind it.

### 5. Corporate KYC as the gate on whether your money exists

Pi holds government IDs and biometrics (facial recognition, later palm print),
and passing its internal verification determines whether your balance is
transferable. That is a single point of failure for tens of millions of people,
and under Nigeria's NDPA, Kenya's DPA and South Africa's POPIA it is a legal
exposure as much as a trust one.

**Binds:** **identity is attested, never custodial.**

- The chain verifies **credentials issued by licensed parties** (banks, MNOs,
  national ID authorities) — it does not run KYC and does not hold documents.
- Biometric templates and identity documents **never touch the chain**, in any
  form, hashed or otherwise. A hashed biometric is still a biometric.
- **No chain-level entity can withhold, freeze or void a user's AFRI balance.**
  Issuer-level freeze on a sovereign stablecoin is a deliberate feature of that
  asset ([R9](../00-research.md)) and is scoped to that issuer's own denom. It
  does not extend to the native coin, and there is no equivalent power over it.
- Where a compliance gate is legally required, it sits at the **regulated edge**
  (the VASP, the agent, the issuer), which is where the licence and the
  liability already are.

## The unanswered question: Sybil resistance without a gatekeeper

Removing corporate KYC leaves Pi's actual problem on our desk. Our answer is to
**never pay for personhood in the first place.**

Each no-capital mechanism in ADR-0004 buys a resource that is *inherently
costly to fake*, so one person operating ten thousand identities gains nothing:

| Mechanism | What is bought | Why Sybils gain nothing |
|---|---|---|
| Agent liquidity | settled cash volume, presence in a cell | real float and real counterparties; splitting across identities splits the same volume |
| Light node / relay | provably served queries | serving is measurable work; ten identities serve no more than one machine can |
| Oracle / attestation | accuracy vs eventual consensus, bonded | wrong data is slashed; ten identities means ten bonds at risk |
| Staking | stake at risk | already Sybil-proof by construction |

The general rule: **reward the resource, not the account.** A reward that splits
cleanly across identities cannot be farmed by creating identities. This is why
ADR-0004's mechanisms survive the removal of the gatekeeper, and a per-person
airdrop or check-in reward would not.

Two consequences we accept. Bonded mechanisms are not strictly zero-capital, so
bonds must stay small enough not to become the exclusion they were meant to
prevent — a parameter to watch with real data. And sock-puppet collusion within
a *single* mechanism (an agent cycling float with a confederate) is a real
attack that the resource framing does not fully close; it is an anomaly-detection
and slashing problem, tracked as a Phase 3 item.

## Consequences

**Good:** the earning design in ADR-0004 gains empirical support rather than only
an arithmetic argument. Three concrete failure modes — referral emissions,
distribution ahead of utility, custodial KYC — are ruled out in writing before
anything ships, which is the only point at which ruling them out is cheap.
Refusing to hold identity documents removes a whole category of legal and
breach exposure across every jurisdiction we intend to operate in.

**Bad:** we give up the growth mechanism that made Pi grow. Referral emissions
work — that is exactly the problem — and we will grow more slowly than a project
willing to use them. Attested identity requires issuer partnerships that are
slower to obtain than running verification ourselves, and in the meantime some
compliance-gated features cannot launch in some jurisdictions. Sybil resistance
by resource-pricing is stronger in the steady state than during bootstrap, when
volumes are small and a determined actor can be a large fraction of a cell.

**Also bad, and worth stating plainly:** Pi's ad-funded model exists because
running this costs money and nobody was paying. We have named a funding source
we will not use without naming the one we will. Sustainable funding for the
public-goods side of the network is an open question, tracked in
[05-roadmap.md](../05-roadmap.md), not a solved one.

## Revisit if

- A Sybil attack succeeds against a resource-priced mechanism in practice, in
  which case bonded-only participation for that mechanism is the fallback
- Attested-credential issuers prove unobtainable in a target jurisdiction, which
  would force a choice between delayed launch and a compliance model we have
  ruled out here — to be made explicitly, not by drift
- Pi publishes independently verifiable usage data that contradicts the picture
  in §3.4

## Sources

- [Pi Network FAQ: How can Pi be mined on mobile phones without energy consumption?](https://minepi.com/faqs/how-can-pi-be-mined-on-mobile-phones-without-energy-consumption-typically-known-in-crypto-mining/)
- [Pi Network: Pi Node](https://minepi.com/pi-blockchain/pi-node/)
- [Pi Network white paper](https://minepi.com/white-paper/)
- [Pi Whitepaper chapters: token model, mining mechanism, roadmap](https://pinetwork-official.medium.com/pi-whitepaper-chapters-mainnet-token-model-mining-and-roadmap-19f4a6774e71)
- [crypto.news: How does Pi mining work? The Stellar Consensus Protocol explained](https://crypto.news/how-does-pi-mining-work-stellar-consensus-protocol-explained/)
- [crypto.news: Pi coin vs its own halving — the mining rate math](https://crypto.news/pi-coin-halving-mining-rate-math/)
- [Coin Bureau: Is Pi Network legit in 2026?](https://coinbureau.com/analysis/is-pi-coin-legit)
- [Coin Bureau: Pi Network explained — mobile mining, KYC, legitimacy](https://coinbureau.com/education/pi-network-explained)
- [Yellow: Pi Network faces scrutiny as core team controls 83% of token supply](https://yellow.com/news/pi-network-faces-scrutiny-as-core-team-controls-83-of-token-supply)
- [Coinfomania: Pi Network's centralization controversy](https://coinfomania.com/pi-networks-centralization-controversy-as-core-team-retains-82-8b-can-it-regain-user-trust/)
- [crypto.news: Pi Network just hit a new all-time low](https://crypto.news/pi-network-just-hit-a-new-all-time-low/)
- [crypto.news: Pi Network price prediction July 2026 — unlocks vs utility](https://crypto.news/pi-network-price-prediction-july-2026-unlocks-products/)
- [KuCoin: Pi Network — a test of survival under the unlock flood](https://www.kucoin.com/news/articles/pi-network-a-test-of-survival-under-the-unlock-flood)
- [BeInCrypto: Pi Network users receive legal warning from Vietnam police](https://beincrypto.com/pi-network-legal-warning-from-vietnam-police/)
- [VietnamNet: Hanoi police warn of risks in Pi Network cryptocurrency trading](https://vietnamnet.vn/en/hanoi-police-warn-of-risks-in-pi-network-cryptocurrency-trading-2376809.html)
- [BeInCrypto: Pi Network's GCV debate — is $314,159 the real value of PI?](https://beincrypto.com/pi-network-gcv-code-debate/)
- [Gate: Pi coin in Nigeria — from grassroots mining to cross-border payment ecosystem](https://www.gate.com/learn/articles/pi-coin-in-nigeria-from-grassroots-mining-to-cross-border-payment-ecosystem/6855)
- [Bitget: Pi Network users by country](https://www.bitget.com/wiki/pi-network-users-by-country)
- [Pi Network blog: Ad Network expansion](https://minepi.com/blog/ad-network-expansion/)
- [AIMultiple: Will Pi Network make you rich?](https://aimultiple.com/pi-network)
