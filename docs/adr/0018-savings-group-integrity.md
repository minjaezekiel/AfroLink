# ADR-0018 — Savings-group integrity, and what a red-team pass found

- **Status:** accepted
- **Date:** 2026-08-31
- **Relates to:** [ADR-0005](0005-african-first-design.md) §C (why groups are a
  native account type), [ADR-0015](0015-committed-outcomes-and-provable-history.md)
  (the anti-spam property this restores), [08](../08-adversarial-testing.md) §8–15,
  `crates/types/src/group.rs`, `crates/executor`

## Context

Everything before this ADR tested the chain against **malformed input**: bytes
that decode two ways, forged proofs, hostile schedules, smuggled requests. That
work found real defects and it is worth what it cost.

It could not find any of the defects below, because every one of them arrives as
a **perfectly well-formed transaction, correctly signed, from an account
entitled to send it**. The question those tests ask is *"can this input be read
two ways?"*. The question nobody had asked is *"should this input have been
obeyed?"*

So a session was spent attacking the chain the way someone who wanted the money
would: build a chain, submit ordinary transactions, and try to end up richer. It
found seven ways, plus a feature that could not run at all. The exploits live in
[`crates/executor/tests/heist.rs`](../../crates/executor/tests/heist.rs), each
written to fail against the fixed code.

**The savings group took the worst of it**, which is the part that matters:
groups are the feature ADR-0005 leads with, and the money in a chama belongs to
people for whom losing it is not an inconvenience.

## The defects, and the decisions that close them

### 1. One member could drain the group — `GroupPayout` had no clock

`GroupPayout` paid out the pot and advanced the rotation. Two things were
missing, and together they were fatal:

- **any member could call it at any time**, and
- **an empty pot still advanced the cycle**.

So a member called it repeatedly against an empty pot — costing only fees —
until `next` pointed at themselves, then waited for everyone else to contribute
and collected. Every cycle. Forever.

`Contribution::period_blocks` existed and **nothing read it**. The group agreed
on a cycle length that the chain never enforced.

**Decision.** A cycle closes when *either* every member has paid *or* the agreed
period has elapsed, and a payout of nothing is refused outright.

```rust
pub fn payout_due(&self, now: Height) -> bool {
    self.everyone_has_paid() || now.0 >= self.period_ends().0
}
```

Both halves are load-bearing. Requiring full payment alone lets one member hold
the group hostage by never paying; requiring the period alone stops a group that
has all paid from closing early, which is not how a real chama behaves.

This needed `GroupAccount::cycle_started`, because "the period has elapsed" has
no meaning without a height to measure from.

### 2. A member could pay one shilling and be credited a full cycle

`ContributeToGroup` carried an amount, transferred it, and then recorded a
contribution — **without ever comparing the two**. A member sent one unit, was
recorded as having met a 1,000 KES obligation, and collected the full pot when
the rotation reached them.

**Decision.** The amount must equal the amount the group agreed, and the
contribution is recorded *before* the money moves, so a member who has already
paid this cycle is refused before being charged.

The message keeps carrying the amount rather than reading it from the group,
because the signer should be committing to what they are about to pay.

### 3. Paying ten times in one cycle bought a credit record

`Member::contributions_made` was incremented on every contribution with no
per-cycle check. Ten payments in one cycle read as ten honoured obligations.

**Decision.** `Member::last_paid_cycle`, and a second contribution in one cycle
is refused. The record is the thing a lender reads; buying it is buying credit.

### 4. The credit signal could only ever flatter

`record_missed` existed and **was never called from anywhere**. So
`contributions_missed` was always zero and `reliability_bps()` returned a
perfect 100% for every member who had ever contributed once.

This is the defect that should worry us most, and it is not a theft. ADR-0005
§C describes this record as *"the best creditworthiness signal that exists"* for
someone with no bureau file. A lender acting on it was reading a number that
could only ever say yes — about borrowers who can least afford a loan they
should not have been given.

**Decision.** `advance_cycle` records a miss for every member who did not pay
into the cycle being closed. The signal now has a denominator that can grow.

### 5. Creating a group could erase an account's history

A group's address is derived from `(creator, nonce)`, so anyone can compute it
before the group exists and pay it. `CreateGroup` wrote a fresh record over
whatever was there — resetting `last_txn`, and orphaning every payment already
made to that address.

That silently breaks the chain [ADR-0015](0015-committed-outcomes-and-provable-history.md)
built, at an account whose owner has no way to notice.

**Decision.** The record is **converted, not replaced**: history and flags
survive, only `kind` changes. Converting rather than refusing also avoids a
griefing move — refusing would let anyone block a group creation by paying its
future address first.

An existing record that is already a group or a module account is refused, since
that is a genuine collision rather than a pre-payment.

### 6. One fee could mint account records for a crowd

[ADR-0015](0015-committed-outcomes-and-provable-history.md) states the property
plainly: *"a spammer cannot mint state entries for addresses it merely names."*
`CreateGroup` names its members, every member is filed in `touched_addresses`,
and being filed **creates an account record** — and the member list had no upper
bound.

**Decision.** `MAX_GROUP_MEMBERS = 100`, enforced in the constructor and at the
decode boundary. Far above any real savings group: a VSLA is 15–30 people by
design, because the model depends on members knowing one another.

### 7. A transaction offering no fee executed for free

Nothing required a fee to be greater than zero. The fee is the entire cost of
making every validator on the network execute a transaction, and it is the
**only punishment a failed one carries** — so at zero, failure was free and one
account could make the whole network re-execute indefinitely.

**Decision.** `TxError::ZeroFee`, refused statelessly.

This is a floor, not a fee market. Escalation and a queue are
[09](../09-what-xrpl-answers.md) §2.5, still deliberately deferred until
congestion is real.

### 8. Fees in a denomination nobody agreed to accept

[ADR-0005](0005-african-first-design.md) §4.1 says fees are payable in any
*governance-whitelisted* stablecoin. Nothing checked a whitelist.

**Not currently exploitable**, and it is worth saying so rather than inflating
it: minting requires a registered issuer, issuers exist only through genesis,
and a denom with no issuer has no units for anyone to spend. The check is what
keeps that true once issuers can be registered by transaction, which the roadmap
intends.

**Decision.** A fee denomination must be the native coin or have a registered
issuer. The issuer registry *is* the whitelist.

### 9. The SIM-swap defence could not complete a recovery

Not an exploit — the opposite. `Bindings::apply_rebind` was correct, tested, and
**reachable from no transaction at all**. A rebinding that survived its 72-hour
veto window sat pending forever, so a user who had genuinely lost their key
never got their number back.

**Decision.** `Message::ApplyRebind`, and deliberately **permissionless**: by the
time it can succeed, the delay has run and the veto window has closed, so
whoever pays to finish the job changes nothing about the outcome. Requiring the
*new* owner to send it would defeat the purpose, since the case this exists for
is a user who has lost the key the account is moving away from.

## Consequences

**Good.** A chama now behaves like a chama: contributions are the agreed amount,
once per cycle; a payout happens when the cycle is actually over; and the
contribution record means something to a lender. The provable-history chain
survives group creation. Genuine recovery completes.

**Bad, and worth being clear about.**

- ~~**`Quorum` is still stored and never enforced.**~~ **Closed** by
  [ADR-0019](0019-vikoba-accumulating-savings.md): it now governs loans and
  social-fund grants in an accumulating group, which are the "extraordinary
  withdrawals" it was always documented for. It remains unused by a *rotating*
  group, which still has no message that moves the pot other than the rotation.
- **A group can still stall.** If the pot is empty when the period expires,
  `EmptyPot` refuses the payout and the cycle cannot close. That is the safe
  direction, but a group where nobody pays is stuck rather than gracefully
  skipping a cycle.
- **Attestors still cannot be registered by any transaction**, so contact
  bindings remain unreachable on a real chain despite §9. That needs a
  governance authority the chain does not have yet, and inventing one here would
  be worse than naming the gap.
- **Groups cannot change.** No member may join or leave, and the contribution
  cannot be renegotiated. Real groups do all three. Still true after
  [ADR-0019](0019-vikoba-accumulating-savings.md), which adds a round boundary —
  the obvious place to allow it.

## Revisit if

- Real groups find the "everyone paid or the period expired" rule too rigid —
  the likely first complaint is a member who wants to pay late rather than be
  marked absent
- A governance authority arrives, at which point attestor registration and the
  fee whitelist both become live rather than latent

## Sources

- Vasek et al., *The Bitcoin Brain Drain* (FC 2016) — the methodological point
  that only end-to-end economic attacks find economic defects
- [FSD Kenya, *Financial Diaries*](https://www.fsdkenya.org/) — on how chama
  rotation and reputation actually work, and why a flattering credit signal is
  worse than none
