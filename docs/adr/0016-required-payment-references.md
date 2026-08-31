# ADR-0016 — Required payment references, enforced by the ledger

- **Status:** accepted
- **Date:** 2026-08-31
- **Relates to:** [09](../09-what-xrpl-answers.md) §2.3 (where this comes from),
  [ADR-0009](0009-developer-payment-surface.md) (the reference itself),
  [ADR-0015](0015-committed-outcomes-and-provable-history.md) (why the refusal
  is provable), `crates/types`, `crates/executor`, `crates/pay`

## Context

One exchange deposit address serves millions of customers. Which customer a
deposit belongs to is carried in the payment's **reference** — XRPL's
destination tag, which [ADR-0009](0009-developer-payment-surface.md) already
built as a `u64` field inside the signed document.

A reference the sender omits is the other half of the same problem, and until
now nothing prevented it. `crates/pay` had
[`RequiresReference`](../../crates/pay/src/reference.rs) and it was **advice**: a
recipient's stated preference that a wallet might honour, that nothing checked,
and that no code outside its own module read.

So the money arrived. It was credited to nobody, sat in limbo, and someone
filed a support ticket. *"I sent it but it never arrived"* is the most common
ticket in the industry, and this is most of it.

XRPL answers with an account flag, `asfRequireDest`, that **the ledger
enforces**: a payment with no destination tag to a flagged account fails.

## Decision

### 1. Flags on the account record, refusing unknown bits

```rust
pub struct Account {
    // …
    pub flags: AccountFlags,
}

pub enum AccountFlag {
    RequireReference,   // bit 0
}
```

A bitfield rather than a struct of booleans, because it is encoded into state
and a word has exactly one spelling.

`AccountFlags::from_bits` **refuses** any bit this version does not understand
rather than masking it away, and that half is consensus-critical. A node that
masked would store a different account record — and so compute a different
`app_hash` — than one that kept the bit, and neither could see anything wrong
with what it held. Refusing turns the disagreement into a decode error at the
boundary, which is the same rule the codec follows everywhere else and the same
rule `TxReceipt` follows for its `touched` list.

A flag travels on the wire as its **bit**, not as a separate discriminant, so a
message naming a flag and the record holding it use one number. Two numberings
for one concept is how they drift.

### 2. `SetAccountFlag` names one flag, and only the sender's own account

```rust
Message::SetAccountFlag { flag: AccountFlag, enabled: bool }
```

**No address argument.** A message that could flag someone *else's* account
would let a stranger make their payments start failing.

**One flag per message**, rather than assigning a whole flags word — XRPL's
`SetFlag`/`ClearFlag` shape. The reason is upgrades: a wallet built before a
flag existed, submitting an absolute assignment, would silently clear the flag
it has never heard of. Naming one flag means a message can only change what it
names.

It is idempotent. A wallet that never saw the result of its first submission
will send a second, and that must not toggle the setting back off.

### 3. The executor checks the recipient, before moving anything

```rust
if !load_account(store, to)?.requires_reference().accepts(*reference) {
    return Err(ExecError::ReferenceRequired);
}
```

Checked **before** the transfer, so a refused payment costs the sender a fee and
nothing else — the money never moves. That is the whole trade: *a failed payment
the sender can retry is enormously better than a successful payment nobody can
attribute.*

The protocol still never reads the reference's **value**. It does not route on
it, index it, or give it meaning. The only question asked is whether one is
present, and only when the recipient has said in state that it must be.

### 4. `ResultCode::Reference` — its own code

The receipt is committed under `outcome_root`
([ADR-0015](0015-committed-outcomes-and-provable-history.md)), so *"you forgot
the reference"* arrives as a **proof**, not as a claim by whichever node the
wallet happened to ask.

It gets its own code rather than a shade of `Account`, which is a deliberate
exception to that ADR's coarseness rule. The justification is narrow: this is
the only execution failure a wallet can act on without asking anything further —
prompt for the reference, resend. Making the wallet fetch the recipient's flags
to work out *why* would put a round trip on the exact path the flag exists to
smooth.

### 5. Discovery is already provable

`Query::Account` returns the account record, and the record now carries the
flags. So a wallet proves *"this address requires a reference"* against a header
it trusts, **before** sending. That matters in both directions: a node that lied
either way could otherwise make a payment fail, or make a wallet skip the prompt
on an address that genuinely needs one.

`Account::requires_reference` is the only bridge between the state bit and
`crates/pay`'s advisory type, so the wallet's warning and the ledger's refusal
read the same bit and cannot disagree.

## Consequences

**Good.** The largest operational win per line of code on
[09](../09-what-xrpl-answers.md)'s list, and the one that most directly serves
adoption by a large exchange: it is the difference between fielding
unattributable-deposit tickets and not having the problem. The refusal, the
reason, and the requirement are all provable.

**Bad, and worth being clear about.**

- **It only guards `Message::Transfer`.** Value can also reach an account as a
  `GroupPayout` or a `ContributeToGroup`, and those carry no reference field to
  require. Enforcing there would freeze a group's rotation rather than protect
  anyone, so the rule is: *the flag protects the deposit path*, and a savings
  group must not name a tag-requiring address as a rotation recipient. Recorded
  rather than left to be discovered.
- **A batch fails whole.** One untagged leg takes the transaction down, good
  legs included. That is the existing sandbox semantics and it is the safe
  direction — the alternative would let the flag be bypassed by ordering a good
  payment first.
- **A user can flag their own account by mistake** and see payments to them
  fail. They hold the key, so they can clear it; a module account cannot sign,
  so it can never set it at all.
- **Adding a second flag is a consensus change**, by construction. That is the
  price of refusing unknown bits, and it is the right price.

**Deliberately not done.** No `DisallowIncoming`-style flags — worth having if
licensed entities need them, not worth guessing at now. No per-denomination
requirement: an address that needs a tag needs it for everything it holds.

## Revisit if

- A payment path other than `Transfer` becomes a real deposit route, which is
  when the group-account gap stops being theoretical
- A second flag arrives that is *not* consensus-visible, which would argue for
  splitting advisory settings out of this word rather than growing it

## Sources

- [XRPL: source and destination tags](https://xrpl.org/source-and-destination-tags.html)
- [XRPL: `AccountSet` flags, including `asfRequireDest`](https://xrpl.org/accountset.html)
- [Stellar: memo IDs, the same answer reached separately](https://developers.stellar.org/docs/encyclopedia/memos)
