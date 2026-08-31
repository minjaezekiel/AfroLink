# ADR-0017 — Key rotation, master-key disable, and signer lists

- **Status:** accepted
- **Date:** 2026-08-31
- **Relates to:** [09](../09-what-xrpl-answers.md) §1 and §2.4 (where this comes
  from, and the question it answers),
  [ADR-0005](0005-african-first-design.md) (social recovery, promised and
  unbuilt), [ADR-0008](0008-human-readable-addressing.md) (why an address must
  outlive a key), `crates/types`, `crates/executor`, `crates/node`

## Context

An account had exactly one key, and losing it lost the account permanently. That
is a poor arrangement anywhere. Here it is worse than usual, for two reasons
this project created for itself.

**Addresses are meant to be shared and remembered.**
[ADR-0008](0008-human-readable-addressing.md) built a whole layer so that people
send to `@amina` rather than to `afri1qzp8h4c…`, and
[ADR-0009](0009-developer-payment-surface.md) built `afri:` URIs so a merchant
can print a QR code once. Every one of those artefacts is bound to an address.
If the only way to change a key is to change the address, then a compromised
phone invalidates a username, a printed sign, and every payment instruction the
user has ever handed out.

**The recovery question was still open.** [09](../09-what-xrpl-answers.md) §1
took a careful look at whether a password hashed into a block could let a user
recover their account, and answered no — a low-entropy verifier on a public
ledger is a published oracle with unlimited free guesses, and the Bitcoin
brain-wallet literature is what happens next. But the *need* underneath was
real, and §1 said where the sound answer lives:

> This is what ADR-0005's social-recovery item should be built on, and it is a
> strictly better answer to "recover from something I remember" than any
> password scheme.

XRPL separates three things we conflated into one: a **master key** that derives
the address and can be disabled, a **regular key** that is rotatable at will, and
a **signer list** of weighted signers with a quorum.

## Decision

### 1. Authorisation leaves the transaction and moves to the account

This is the change everything else rests on. Stateless verification used to end
with:

```rust
if Address::from_public_key(&self.public_key) != self.body.sender {
    return Err(TxError::KeyAddressMismatch);
}
```

That check *is* the thing rotation abolishes: a regular key does not derive the
address, and a signer-list key never could. So verification splits in two.

| | |
|---|---|
| `Transaction::verify_stateless` | Structure, chain, expiry, and that every signature is genuine. **Authentication** |
| `Account::authorises(&keys)` | Whether those keys may act for this account. **Authorisation** |

The names carry the distinction, and `verify_stateless` returns no evidence a
caller could mistake for permission — the keys come from `signing_keys()`, which
says what it is. Removing the old `verify` outright, rather than leaving it as a
weaker synonym, made the compiler visit every call site.

**Both call sites do both checks.** The executor is the one that matters for
correctness. The mempool matters for denial of service: without a stateful check
there, anyone could sign a body naming any address and make a node hold, gossip
and re-check it forever. So `Mempool::insert` now takes the sender's `Account`
rather than its nonce — the record carries both facts, which also stops them
being read at two different heights.

### 2. Three authorities, and they do not mix

| Authority | Satisfied by |
|---|---|
| **Master key** | The key the address was derived from, unless `MasterKeyDisabled` |
| **Regular key** | One rotatable key, if set |
| **Signer list** | Weighted keys reaching a quorum |

A set combining a master key with signer-list keys satisfies **nothing**, and an
unrecognised key in a signer set disqualifies the whole attempt. Both refusals
are the same defence: an extra signature that changes a transaction's id without
changing what it authorises is malleability, and one body with many authorising
sets is one payment with many ids.

The address remains the commitment to the master key — it is a hash of it — so
no stored copy of that key is consulted and none can go stale.

Module accounts authorise nothing, whatever is written into their records. Their
addresses come from a domain-separated hash of a name, so the check is already
unsatisfiable; stating it means a future refactor cannot quietly make the fee
pool spendable.

### 3. Transactions carry a list of signatures

```rust
pub struct Transaction {
    pub body: TxBody,
    pub signatures: Vec<TxSignature>,   // sorted by key, unique, 1..=32
    // …and a second list, for the reason in §6
}
```

An M-of-N arrangement needs M signatures. The ordinary payment is a list of one.

Sorted, unique and non-empty are enforced **at the decode boundary**, not left to
the verifier, because the transaction's id is a hash of this encoding: a second
ordering would be a second id for one signed transaction, and deduplication by
id is what stops a replay. `sign_with` sorts and de-duplicates so a caller
cannot produce a non-canonical transaction by accident, and so one signer cannot
reach a quorum by repeating itself.

### 4. Signers are keys, not accounts

XRPL lists accounts, which lets a signer rotate their own key without the list
changing. That costs a state read per signer on the hot path and opens the
question of whether a signer's own list may authorise — a recursion XRPL has to
cap explicitly.

Listing keys keeps authorisation a pure function of one account record. **The
cost is real: a signer who loses their key must be replaced**, by a quorum of
the remaining signers. For a recovery list of family and an agent, that is the
ordinary case rather than the exceptional one, and the people who need to act
are exactly the people the list already names.

Weights rather than a plain count, because the arrangements people ask for are
not symmetric — *"my agent, or any two family members"* cannot be expressed with
equal votes.

### 5. One lock-out invariant, checked in one place

There are three ways to make an account permanently unspendable: disable the
master key with no replacement, clear the regular key while it is disabled, or
remove the signer list while it is disabled. They are one rule seen from three
sides.

Every message that touches a signing arrangement goes through `change_account`,
which applies the change and then asks `Account::has_a_usable_authority()`. If
the answer is no, the whole transaction is refused. Checking each case at its own
call site is how a fourth authority arrives without one.

The same rule is enforced on **decode**: an account record nobody can sign for is
not a state this chain can produce, so it can only be corruption or a hostile
peer — and serving it to a wallet would tell that wallet its money is frozen.

Two narrower refusals sit alongside it. A signer list whose quorum exceeds its
total weight is a locked account that looks perfectly well-formed, so it is
refused at construction. And a regular key equal to the master key is refused
because it *looks* like rotation and provides none — a user who did it would
believe an exposed seed had been retired when it had not.

### 6. A fee payer must consent — a defect this work surfaced

Writing down *who may act for an account* forced the question of every place the
chain moves money, and one place had no answer at all.

`Fee::sponsored_by` lets a transaction name a third party as its fee payer. The
executor read that field and debited the named account. **Nothing asked whether
the payer had agreed** — so any address could name any funded address as its
sponsor and drain it, one fee at a time, in whichever denomination the victim
held. Every signature was genuine and every byte canonical, which is why no
amount of fuzzing would have found it ([08](../08-adversarial-testing.md) §7).

The fix uses the machinery this ADR was already building:

```rust
pub struct Transaction {
    pub body: TxBody,
    pub signatures: Vec<TxSignature>,           // must satisfy the sender
    pub sponsor_signatures: Vec<TxSignature>,   // must satisfy the fee payer
}
```

**Two lists rather than one**, because they answer different questions and the
answers belong to different accounts. A single list would force the verifier to
search for a partition — and, worse, would let a key recognised by one account be
counted toward the other's quorum.

The sponsor list is non-empty **exactly when** a payer is named. Both halves are
enforced: a sponsored fee with no sponsor signature would spend a stranger's
money, and sponsor signatures on an unsponsored fee are bytes that change the
transaction's id while authorising nothing. Naming yourself as your own sponsor
is refused too — it is a second spelling of an ordinary fee.

Sponsorship reads the payer's account record, so it inherits rotation for free:
an NGO can change its signing key without every wallet that names it as sponsor
having to be updated.

### 7. Authorisation is checked before the nonce

"Wrong nonce" is a misleading answer to a forgery, and it reports the account's
sequence number to someone who has just proved they do not hold its keys. An
unauthorised transaction also consumes nothing — no fee, no nonce — so an
attacker cannot burn the sequence numbers a victim is about to use.

## Consequences

**Good.**

- **Rotation without migration.** The address, the username, and every printed
  QR code survive a key change. On a chain built around shared identifiers, this
  is the difference between a key change and an account migration.
- **Compromise has a response short of a race.** A user who suspects their seed
  is exposed disables it, rather than racing the attacker to move funds.
- **Social recovery is a protocol primitive**, not a contract — which is what
  [ADR-0005](0005-african-first-design.md) always intended, and a strictly
  better answer to *"recover from something I remember"* than anything involving
  a password on a ledger.
- **A wallet can prove who may sign**, because the account record is served with
  a proof. An exchange deciding whether a withdrawal instruction is genuine can
  establish the answer against a header it verified itself.
- **A serious pre-existing defect is closed** (§6). Fee sponsorship debited a
  named third party with no consent check at all.

**Bad, and worth being clear about.**

- **This is the most security-critical change in the project so far.** It moves
  the check that decides who can spend. The mitigation is structural — the old
  method is gone rather than deprecated, so every call site was revisited — but
  the risk is real and it belongs in an audit's first chapter.
- **A signer who loses their key must be replaced**, per §4.
- **Verifying up to 32 signatures costs 32 signature checks.** Bounded by
  `MAX_SIGNATURES`, charged for by the fee, and refused by the mempool before it
  is gossiped — but it is more work per transaction than before.
- **No recovery *delay*.** A quorum acts immediately. A signer list stolen whole
  is an account stolen whole. A time-locked variant, in the shape
  `crates/alias` already uses for contact rebinding, is the obvious next step and
  is not built.
- **Nothing rate-limits authority changes** beyond the fee and the nonce.
- **Sponsorship now needs a round trip.** A wallet whose fees are covered must
  get the sponsor's signature over the exact body before submitting, where
  before it could name them unilaterally. That is the cost of the fix in §6 and
  it is not optional; a standing on-chain allowance would remove the round trip
  and is a larger design than this ADR should decide.

**Deliberately not done.** No account-based signers, per §4. No nested signer
lists. No per-message authority — XRPL can restrict a regular key to some
transaction types, which is worth having and is not the first thing to want. No
change to `AccountKind::Individual`'s revealed public key, which remains unused
by authorisation precisely because the address is the better commitment.

## Revisit if

- Sponsored fees prove awkward in practice because of the co-signing round trip,
  which is the argument for a standing on-chain sponsorship allowance
- A stolen signer list becomes a real loss pattern, which is the argument for a
  time-locked recovery path rather than an immediate one
- Signers need to rotate their own keys often enough that listing accounts pays
  for the state reads
- An authority needs to be scoped to particular messages — the point at which
  "who may sign" stops being one question

## Sources

- [XRPL: `AccountSet` flags, including `asfDisableMaster`](https://xrpl.org/accountset.html)
- [XRPL: `SetRegularKey`](https://xrpl.org/setregularkey.html)
- [XRPL: multi-signing and `SignerListSet`](https://xrpl.org/multi-signing.html)
- [RFC 8032: Ed25519, and why its signatures are deterministic](https://datatracker.ietf.org/doc/html/rfc8032)
- Vasek, Bonneau, Castellucci, Keith, Moore, *The Bitcoin Brain Drain* (FC 2016)
  — the empirical case, recorded in [09](../09-what-xrpl-answers.md) §1, against
  the password-shaped alternative this replaces
