# 00 — Research: What problem is actually worth solving?

*Compiled August 2026. Every figure below is sourced; see [Sources](#sources).*

The premise of this project is that Africa needs its own settlement network. That
premise is defensible, but only for a narrow set of reasons. This document
separates the parts that hold up under evidence from the parts that do not,
because building against the wrong problem is the most expensive mistake
available to us.

---

## 1. The market is already enormous and already digital

This is the single most important fact, and it cuts against the usual framing of
Africa as "unbanked and waiting for crypto":

| Metric | Value | Year |
|---|---|---|
| Mobile money transaction value, sub-Saharan Africa | **$1.4 trillion** | 2025 |
| Share of *global* mobile money value | **66%** | 2025 |
| Registered mobile money accounts, SSA | **~1.1 billion** | 2025 |
| M-Pesa transaction volume alone | **$295 billion** | 2025 |
| Time to go from $1T to $2T globally | **4 years** (the first $1T took 20) | 2021–2025 |

Africa is not waiting for digital payments. **It already won at digital
payments.** M-Pesa solved domestic retail payments in 2007 and the rest of the
continent followed.

**Implication for us:** any pitch built on "banking the unbanked" is fifteen
years out of date and will be beaten by an incumbent with 60 million users and a
USSD shortcode. We must compete where mobile money is *weak*, not where it is
strong.

## 2. Where mobile money is genuinely weak

### 2.1 Crossing a border

Mobile money is a set of ~250 national walled gardens. M-Pesa Kenya to MTN Ghana
is not a payment; it is a correspondent-banking round trip, usually through USD.

- Remittances into sub-Saharan Africa: **~$54 billion/year**.
- Average cost of sending money to Africa: **7.4%** — the highest of any region
  on earth, against a global average of 6.36% and an SDG target of 3%.
- Onafriq and Circle put the cost of *routing payments within Africa* at
  **$5 billion per year**.

At 7.4%, roughly **$4 billion a year** is taken out of the pockets of the people
least able to afford it. Cutting that to under 1% is worth ~$3.5B/year returned
to households. **This is the strongest single case for the network, and it is a
sufficient reason to build on its own.**

### 2.2 Dormancy — the number nobody quotes

Only **25.7%** of registered mobile money accounts are active in a given month.
Roughly three-quarters sit idle. Wallets are opened for one transfer and
abandoned, because a wallet that only sends money to other customers of the same
operator in the same country is not very useful.

**Implication:** the scarce resource is not *accounts*, it is *reasons to hold a
balance*. Interest-bearing savings, merchant acceptance, and cross-border utility
are what convert a dormant account into a used one.

### 2.3 Agent float, not technology

Cash-in/cash-out depends on human agents holding enough cash and enough
e-float. Agent liquidity — not bandwidth, not cryptography — is the binding
constraint on rural payments. No blockchain fixes this by existing. A network
that *pays agents for provable liquidity provision* might.

## 3. What has been tried, and how it went

### 3.1 Central bank digital currencies: a cautionary tale

- **eNaira** (Nigeria, Oct 2021) — first CBDC in Africa. Four and a half years
  on, technically operational and **widely regarded as having failed** its stated
  objectives.
- **eCedi** (Ghana, piloted 2023–24) — still in limbo as of early 2026, no retail
  rollout date.
- The era of big-bang retail CBDC launches has given way to quiet
  experimentation.

Meanwhile **cNGN**, a *private-sector* naira stablecoin, shipped and is used.

**The lesson is precise and we should absorb it:** the failure was never
technical. It was distribution and incentives. Central banks built a product with
no reason for a merchant to accept it and no margin for an agent to promote it.
**Any "let governments issue stablecoins" story that does not solve distribution
repeats the eNaira.**

### 3.2 Stablecoin rails are being built right now, by others

- **Visa × Yellow Card** — stablecoin settlement across 20 African countries.
- **Onafriq × Circle** — USDC pilot for intra-African payments.
- **Stellar** — payments-first L1, hosts USDC/EURC, running a 2026 Africa
  accelerator with CV Labs.
- **Celo** — mobile-first, phone-number addressing, ~$150M TVL concentrated in
  exactly our target use cases (remittances, payroll, savings).

**This is the most important competitive fact in this document.** The rails are
being laid *now*, mostly denominated in **US dollars**. If nothing changes,
Africa's digital settlement layer will be a dollar layer operated from
elsewhere — the eurodollar system with better latency.

That, and not "Africa lacks a blockchain", is the actual strategic gap:
**monetary sovereignty over the rails**. It is also the one gap a
foreign-operated dollar network structurally cannot close.

### 3.3 The public-sector rail that already exists: PAPSS

**PAPSS** — the Pan-African Payment and Settlement System, launched January 2022
by the African Union and Afreximbank — is a real-time gross settlement system for
cross-border payments in local currencies, explicitly built to support AfCFTA and
to cut the USD leg out of intra-African trade.

PAPSS has the political mandate we would otherwise spend a decade earning. It is
bank-centric, batch-oriented at the edges, and has no programmability, no retail
reach, and no developer surface.

**Strategic conclusion:** PAPSS is not a competitor. It is the single most
valuable potential *partner* and the natural settlement anchor. Positioning
AfroLink as the programmable retail layer that settles into PAPSS is far more
credible — legally and politically — than positioning it as a replacement for
national payment systems.

## 4. The regulatory window is open (and it was not, two years ago)

| Jurisdiction | Status |
|---|---|
| **Nigeria** | ISA 2025 (signed 29 Mar 2025) classifies digital assets as securities; VASPs register with the SEC. Licensing has been slow. |
| **Kenya** | VASP Act 2025 in force 4 Nov 2025; dual CMA/CBK supervision. Implementing regulations still pending — licensing in limbo. |
| **South Africa** | Most mature: 533 CASP licence applications, **310 approved** as of 31 Mar 2026. Travel Rule enforced. |

Two things follow. First, "is this legal?" now has an answer in the largest
markets, which it did not in 2023. Second, **licensing is a moat**: it is slow,
expensive, and jurisdiction-by-jurisdiction. A protocol designed from day one to
make a licensed issuer's compliance obligations *easy* has a durable advantage
over one that treats regulation as an afterthought.

## 5. The hardware and energy reality

This section exists to kill bad design ideas early.

| Constraint | Figure |
|---|---|
| People in Africa without electricity | **~600 million** (86% of the global access gap) |
| Rural electrification | below 40% in many countries |
| Smartphone share of connections | 63% (2025), but only ~24% of *population* owns one |
| Entry-level smartphone cost | **26% of monthly GDP per capita**; up to **95% of monthly income** for the poorest quintile |
| Mobile data cost | ~2% of monthly income — meets the ITU affordability standard |

Three hard design constraints fall out:

1. **Proof of work is disqualified.** Not on ideological grounds — on arithmetic.
   Mining rewards flow to whoever has the cheapest electricity, which is not
   Africa. A PoW chain "for Africa" would export its security budget to
   industrial miners abroad on day one. See [ADR-0004](adr/0004-no-proof-of-work.md).
2. **The phone is the node.** Not "phones can use a wallet" — the protocol must
   be verifiable from a device that cannot store the chain. This is why state is
   committed to a sparse Merkle root and every query is provable
   (`crates/state`).
3. **Data is affordable; devices and power are not.** Optimise aggressively for
   bytes-per-verification and for feature-phone/USSD fallback. Do not assume a
   smartphone, and never assume mains power.

## 6. What this network should and should not claim

Being honest here protects the project from its own marketing.

**Defensible:**
- Cutting a 7.4% remittance fee to under 1%. (~$3.5B/yr to households.)
- Removing the USD leg from intra-African trade settlement — an FX spread paid
  twice on transactions that never needed a third currency.
- Giving national stablecoin issuers rails with actual distribution, which is
  precisely what the eNaira lacked.
- A portable, user-owned transaction history that can underwrite credit —
  today that history is trapped inside one operator.
- Programmability: payroll, escrow, insurance payouts, and savings products that
  currently need a bank partner per country.

**Not defensible, and we should not say it:**
- "Blockchain reduces poverty." It does not. Cheaper remittances, cheaper
  merchant settlement, and portable credit history plausibly do, at the margin,
  and only if adopted. The chain is a cost-reduction mechanism, not a
  development programme.
- "Uniting Africa with one currency." A single currency is a *political* project
  with a hard macroeconomic problem at its centre (see the CFA franc and the ECO's
  repeated delays). A shared *settlement layer* on which fifty-four currencies
  interoperate is achievable. A single currency replacing them is not, and
  promising it would make every central bank on the continent an opponent.
- "Decentralisation solves corruption." Auditable public records help. They do
  not survive contact with an authority that controls who may transact.

## 7. Design requirements derived from the above

| # | Requirement | Driven by |
|---|---|---|
| R1 | Sub-second to ~1s **deterministic finality**; no probabilistic settlement | Retail payments, POS |
| R2 | Users must **never need the native token** to transact | §2.2 dormancy; onboarding |
| R3 | Every state read must be **provable to a phone** | §5 hardware reality |
| R4 | **Sovereign stablecoin issuance** with per-issuer controls | §3.1, §4 |
| R5 | **No proof of work** | §5 energy |
| R6 | Earning must be possible **without capital or grid power** | §5, user's "mining" goal |
| R7 | **Rust smart contracts** with a mature toolchain | Developer adoption |
| R8 | **IBC/interop** and PAPSS settlement path | §3.3 |
| R9 | Compliance hooks (Travel Rule, issuer freeze) as **protocol features** | §4 |
| R10 | USSD/feature-phone path; offline-capable authorisation | §5 |

R2 and R6 are the ones most often skipped, and they are the two that decide
whether this is used by anyone who is not already a crypto holder.

---

## Sources

- [GSMA: Mobile money accounted for $2 trillion in transactions in 2025](https://www.gsma.com/newsroom/press-release/mobile-money-accounted-for-2-trillion-in-transactions-in-2025-doubling-since-2021-as-active-accounts-continue-to-grow/)
- [Connecting Africa: $1.4T flowed through mobile money in sub-Saharan Africa in 2025](https://www.connectingafrica.com/mobile-money/-1-4t-flowed-through-mobile-money-in-sub-saharan-africa-in-2025-gsma)
- [Forbes Africa: Sub-Saharan Africa dominates global mobile money with 1.1 billion accounts](https://www.forbesafrica.com/current-affairs/2025/04/09/sub-saharan-africa-dominates-global-mobile-money-landscape-with-1-1-billion-accounts-new-report-finds)
- [WeeTracker: Africa drove mobile money to $2T — now most accounts sit idle](https://weetracker.com/2026/03/30/mobile-money-africa-inactivity-gsma-report-2026/)
- [World Bank: The cost of sending remittances is higher than 3% in 28 countries](https://blogs.worldbank.org/en/opendata/the-cost-of-sending-remittances-is-higher-than-3--in-28-countrie)
- [Migration Data Portal: Remittances overview](https://www.migrationdataportal.org/themes/remittances-overview)
- [TechKudi: Remittances to Africa in 2026](https://techkudi.com/news/remittance-corridors-africa-2026/)
- [PAPSS — About us](https://papss.com/about-us/)
- [Wikipedia: Pan-African Payment and Settlement System](https://en.wikipedia.org/wiki/Pan-African_Payment_and_Settlement_System)
- [TechKudi: African CBDCs in 2026 — lessons from the eNaira and eCedi](https://techkudi.com/news/african-cbdc-tracker-2026/)
- [All Business Africa: African CBDCs and the adoption problem](https://allbusiness.africa/insights/african-cbdcs-enaira-ecedi-2026)
- [Bank of Ghana: Design paper of the digital cedi (eCedi)](https://www.bog.gov.gh/news/design-paper-of-the-digital-cedi-ecedi/)
- [Benzinga: Visa taps Yellow Card for stablecoin payments across 20 African nations](https://www.benzinga.com/content/46018036/visa-taps-yellow-card-for-stablecoin-payments-push-across-20-african-nations)
- [CCN: Africa's largest payment network taps USDC for cross-border payments](https://www.ccn.com/news/crypto/africa-largest-network-usdc-revolutionize-cross-border-payments/)
- [Mariblock: Stellar deepens its Africa push with CV Labs accelerator](https://www.mariblock.com/stories/stellar-deepens-africa-push-with-cv-labs-accelerator-as-competition-for-stablecoin-rails-grows)
- [EY: Kenya enacts Virtual Asset Service Providers Act, 2025](https://taxnews.ey.com/news/2025-2314-kenya-enacts-virtual-asset-service-providers-act-2025-a-new-regulatory-era)
- [Cryptoverse Lawyers: Nigeria crypto regulation — ISA 2025 explained](https://www.cryptoverselawyers.io/nigeria-crypto-regulation-isa-2025)
- [DLA Piper Africa: FSCA update on licensing and supervision of CASPs](https://www.dlapiperafrica.com/en/south-africa/insights/2026/FSCA_Update_on_Licensing_and_Supervision_of_Crypto_Asset_Service_Providers)
- [IEA: Access to electricity — SDG7 data and projections](https://www.iea.org/reports/sdg7-data-and-projections/access-to-electricity)
- [Energy Transition Africa: Africa is home to 86% of the world's electricity access gap](https://www.energytransitionafrica.com/insights/article/africa-electricity-access-gap-sdg7-report-2026)
- [GSMA: Accelerating smartphone adoption in Africa (PDF)](https://www.gsma.com/about-us/regions/africa/wp-content/uploads/2025/11/GSMA-SmartPhone_Adoption_Report_sm.pdf)
- [Brookings: Accelerating digital inclusion in Africa](https://www.brookings.edu/articles/accelerating-digital-inclusion-in-africa/)
