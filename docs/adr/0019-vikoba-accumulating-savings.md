# ADR-0019 — Vikoba: accumulating savings, lending, and the share-out

- **Status:** accepted
- **Date:** 2026-08-31
- **Relates to:** [ADR-0005](0005-african-first-design.md) §C (why groups are a
  native account type), [ADR-0018](0018-savings-group-integrity.md) (which built
  the rotation and named this gap), [08](../08-adversarial-testing.md) §16,
  `crates/types/src/group.rs`, `crates/executor/tests/vikoba.rs`

## Context

Everything before this ADR modelled one instrument: a **rotation**. Members pay a
fixed sum each cycle and the whole pot goes to one of them in turn. That is a
real and widespread arrangement — Tanzanians call it *upatu* or *mchezo*, Kenyans
a chama — and it works.

It is not what **vikoba** means.

*Vikoba* is Village Community Banking. Members buy **shares**, the accumulated
savings are **lent to members at a service charge**, and at the end of a
nine-to-twelve-month round everything is **divided in proportion to what each
member saved** — including everything the fund earned. Tanzania's Microfinance
Act 2018 puts VICOBA, VSLAs and ROSCAs together in Tier 4 as *community
microfinance groups*, and over 48,000 are now registered with the Bank of
Tanzania through PO-RALG. Vodacom's **M-Koba**, built on M-Pesa, has digitised
more than 200,000 groups.

The distinction is not academic. A rotation **redistributes**: what one member
receives, the others paid in, and the sum never grows. A vikoba **earns**: the
service charge a borrower pays returns to the fund every member owns a share of,
so a member takes out more than they put in.

`PayoutPolicy::Accumulate` existed and its own doc comment said *"the pot
accumulates and is lent out"*. The lending did not exist. Neither did the
share-out. `next_recipient()` returned `None` and no other message paid an
accumulating group — so a vikoba on AfroLink was **a pot money went into and
never came out of**. Every real VICOBA ends its round in a full distribution;
ours could not end at all.

## The model

Two clocks, because a vikoba has two.

| | Length | What closes it |
|---|---|---|
| **Cycle** | `Contribution::period_blocks` — a meeting, weekly to monthly | `CloseCycle`, when everyone has paid or the period has run |
| **Round** | `ShareRules::cycles_per_round` — nine to twelve months | `ShareOut`, which divides the fund and starts the next |

`ShareRules` is the group's constitution, and every field in it is a number a
real VICOBA writes down and signs — not a protocol constant, because groups
genuinely differ. A weekly urban group and a seasonal farming group agree
different numbers for the same reasons.

### 1. Members save by buying shares, not by paying a fixed sum

The VSLA methodology is *one to five shares per meeting*, at a share value the
group sets at the start of the round. So `BuyShares { group, shares }`, bounded
by `min_shares` and `max_shares`.

**The ceiling is load-bearing, not tidiness.** The share-out divides the fund *in
proportion to shares*, so without a ceiling the member who can afford the most
takes a growing slice of a fund that everybody's repayments built. It is checked
across the whole cycle rather than per message — two purchases that are each
legal and together are not must be refused, or the limit is only a limit on
people who cannot afford a second fee.

The share **value** is `Contribution::amount`, the same field a rotation uses for
its fixed contribution. One field rather than two, so the exact-amount rule of
[ADR-0018](0018-savings-group-integrity.md) §2 and the share price can never
disagree about what a cycle costs.

Note what this does **not** do: it does not loosen §2. Both regimes are real —
VICOBA mandatory savings genuinely are *"5,000 to 100,000 TSh per month, and
every member must pay that amount"* — so the group declares which one it is in
and that one is enforced strictly.

### 2. The group lends its own savings, by quorum

`ProposeGroupAction` puts a loan or a social grant to the group;
`ApproveGroupAction` records an approval, and **the approval that reaches the
quorum carries the proposal out**. No separate execution message, because a
decided question left unexecuted is how a group's money gets stuck — which is
exactly the defect [ADR-0018](0018-savings-group-integrity.md) §9 found in the
rebinding path.

This is where `Quorum` finally does work. It has been stored, validated and read
by nothing since it was written; [ADR-0018](0018-savings-group-integrity.md)
recorded it as *"a promise with nothing behind it"*. It now governs the only two
ways money leaves an accumulating fund other than a share-out.

Loans carry the rules the research describes:

- **Cover.** The borrower's own shares must already cover `cover_bps` of the
  principal — the one-third rule. This is what lets a group lend with no court
  behind it: the worst case is already in the group's hands.
- **Guarantors.** `required_guarantors` other members, each named once, none of
  them the borrower. **Recorded rather than enforced**: the chain cannot make a
  guarantor pay, and pretending otherwise would be worse than naming the limit.
  What it can do is make the guarantee public, which is the sanction a real group
  actually relies on.
- **A flat service charge**, computed once at issue and never compounding. Not a
  simplification — it is how a VICOBA quotes a loan (*"10% of what you borrow"*),
  and a member who cannot read an amortisation schedule can still check one
  number.
- **One late fine, on the outstanding debt.** Once, not once per cycle: the group
  agreed a fine on the debt, not a second interest rate that grows while a member
  is already struggling to pay the first.

### 3. The social fund is insurance, and is kept apart

A separate pot, a **flat premium equal for every member** — the equality is what
makes it insurance rather than saving — spent by grant on a funeral, an illness,
a school fee. Tanzanians know this obligation as *kufa na kuzikana*.

It is tracked as `GroupAccount::social_fund`, a claim against the group's one
balance rather than a second address, so a group still sees one account and one
history. The rule that makes it a fund rather than a label is enforced at every
point money leaves: **a loan is advanced only from `balance − social_fund`, and a
share-out divides only `balance − social_fund`.** A group that lends its funeral
money has no funeral money, and the member who finds out is the one burying
somebody.

A group may agree to have no social fund at all, which the methodology allows.

### 4. The share-out is the moment the whole thing exists for

`ShareOut` divides the fund in proportion to shares. Because service charges and
fines returned to that same fund, the division automatically distributes the
earnings — a member takes out more than they paid in, and the arithmetic needs no
separate notion of profit.

A member who still owes anything has it **deducted from their entitlement**,
which is precisely how a real VICOBA settles: the savings a member invested over
the year are used to pay the loan they did not. The shortfall stays in the group
and opens the next round, so a default is a loss the whole membership carries in
proportion rather than a hole in one member's payout.

`Member::repayment_bps` is the borrowing counterpart to `reliability_bps`, and it
is the number an outside lender actually wants: paying into a pot proves
discipline, repaying a loan proves the thing being predicted. Like its
counterpart it returns `None` for a member who has never borrowed, because
reporting a perfect record for someone who has never repaid anything would let a
fresh account present itself as a proven borrower — the §4 mistake, not repeated.

## What the property suite found

One defect, and it was not visible by hand.

**A loan granted late in a round falls due after the share-out that settles it.**
`ShareRules::validate` already refuses a *term* longer than a round. That is
necessary and not sufficient: a term that fits still runs past the round's end if
the loan is granted late enough in it. Nothing fails at the time — the loan is
advanced, the borrower does everything the group asked, and then the share-out
arrives before the term does. The debt is outstanding, so their savings are
seized to settle it and they are **recorded as a defaulter for a term the group
itself granted**. That record is the thing a lender reads.

`GroupError::TooLateInRound` refuses it, at the proposal and again when the
proposal passes — cycles close while a group is deciding, so a loan that had time
when it was asked for may have none by the time it is agreed. A real VSLA stops
lending in the weeks before a share-out for exactly this reason.

The property suite in `crates/fuzz` caught it on the run in which it was written.
That is the first defect it has found, and it is the kind it was built for: a
sequence of individually reasonable transactions that arrives somewhere nobody
intended.

**The guard that made it findable is worth naming separately.** A property suite
whose generator never reaches a code path passes every invariant over that path
and goes green. Reaching a share-out means founding an accumulating group, buying
shares in it, closing every cycle of a round and then asking — and a uniform
random generator effectively never walks that. So the generator **aims**: it
answers a proposal it knows is open, repays a debt it knows the sender carries,
and shares out a round it knows is complete. `Coverage::assert_meaningful` then
requires every one of the seven vikoba messages to have applied at least once, so
the suite fails rather than quietly stopping to test anything. Wiring it up
naively produced exactly that failure four times in a row, each time on a
different message.

## Consequences

**Good.** A vikoba is a vikoba: members buy shares, the group lends to itself,
the fund earns, and the round ends in a distribution that pays out more than went
in. The social fund is separate and cannot be lent. `Quorum` governs something.
A member's borrowing record is portable and can say no.

**Bad, and worth being clear about.**

- **One proposal at a time.** A real meeting decides several loans. One keeps the
  record bounded — a hundred members each holding an open proposal is unbounded
  state bought with one fee — and matches a group deciding sequentially, but it
  is a restriction rather than a model of the meeting.
- **A proposal lapses when its cycle closes.** Necessary, or one member holding an
  open question freezes every later one. It also means a group that closes cycles
  quickly may never agree anything, which is a rule the chain now has and no real
  group does.
- **Guarantors cannot be made to pay.** Recorded, never enforced. This is the
  honest limit of putting a social institution on a ledger.
- **Membership is still frozen.** No member may join or leave and the share value
  cannot be renegotiated between rounds. Real groups do all three, and a round
  boundary is the obvious place to allow it.
- **Officers do nothing.** `Role::Treasurer` is still decorative, and there is no
  chairperson or secretary. M-Koba requires three signatories — the Secretary
  initiates, the Treasurer verifies, the Chairperson approves — and a quorum is
  arguably a better answer than three named officers, but that is a claim this
  ADR has not tested against a group that uses M-Koba today.
- **The empty-pot stall of [ADR-0018](0018-savings-group-integrity.md) is
  unchanged** for rotating groups. `CloseCycle` gives accumulating groups a way
  through that a rotation still does not have.

## Revisit if

- Groups want more than one open question at a meeting, which is the first
  complaint anyone running a real meeting will have
- A group wants to admit a member at a round boundary, which is when a real one
  does it
- Officers turn out to matter to groups migrating from M-Koba, where the
  three-signatory flow is what they already trust

## Sources

- [VSLA.net, *The VSLA methodology*](https://www.vsla.net/the-vsla-methodology/)
  and [CARE, *VSLA Training Manual* (2024)](https://www.care-international.org/sites/default/files/2024-05/VSLA%20Training%20Manual_2024.pdf)
  — share purchase of one to five, share-out in proportion to savings, the social
  fund as a separate equal-premium pot
- Kaindi et al., *Exploring the potential of village community banking as a
  community-based financing system in rural Tanzania*, [PLOS Global Public Health
  (2023)](https://pmc.ncbi.nlm.nih.gov/articles/PMC10624283/) — group size 10–30,
  mandatory monthly savings, 10% interest, two guarantors, savings of at least a
  third of the loan, the twelve-month cycle and the annual share-out
- [GSMA, *M-Koba: Vodacom Tanzania's innovation to digitise savings groups*](https://www.gsma.com/solutions-and-impact/connectivity-for-good/mobile-for-development/blog/m-koba-vodacom-tanzanias-innovation-to-digitise-savings-groups/)
  and [Tanzania Commercial Bank, *M-KOBA*](https://www.tcbbank.co.tz/page/en/m-koba)
  — the three-signatory control, and members voting on loans
- [Microfinance Act 2018 (TanzLII)](https://tanzlii.org/akn/tz/act/2018/10) and
  [Bank of Tanzania on community microfinance groups](https://ippmedia.co.tz/the-guardian/business/read/community-microfinance-groups-dominatingtanzanias-financial-inclusion-drive-says-bot-2026-07-09-105449)
  — Tier 4, and 48,659 registered groups
- [FB Attorneys, *Rotational savings schemes 'mchezo'*](https://fbattorneys.co.tz/rotational-savings-schemes-mchezo/)
  — the legal grey area these groups operate in, and the pyramid-scheme line
  under Penal Code s.171A that a savings product must stay the right side of
