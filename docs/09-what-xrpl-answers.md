# 09 — What the XRP Ledger answers for us, and what it does not

[06-adopted-practices](06-adopted-practices.md) already takes several things from
XRPL. This document goes back to it with a specific list of open problems, and
comes away with four designs worth building and two worth refusing.

It also answers a question that prompted the review — whether a user-supplied
password, hashed into a block, could establish that history belongs to its owner
rather than to an attacker. It cannot, and §1 is why. But the intuition behind it
points at two real problems, and XRPL has a good answer to one of them.

---

## 1. The password idea, and what it is reaching for

> *"If a user passes a password which is hashed within the block, wouldn't that
> let a user recover history — a block validated by the network, but the
> authenticity of history backed by a user password inside blocks showing a block
> belongs to a certain user instead of a hacker?"*

### Why hashing a password into a block is worse than doing nothing

**A hash on a public ledger is a published verifier with unlimited free guesses.**
Everything on this chain is downloadable by anyone. A password hash committed at
height 5 hands every attacker an oracle they can attack offline, at their own
pace, on their own hardware, forever. There is no rate limiting available,
because there is no server in the loop — the attacker has the file.

Human-chosen passwords carry roughly 20–40 bits of entropy. A consumer GPU tests
billions of candidates per second against a fast hash, and even a deliberately
slow one only moves the number, not the shape of the problem. This is not
theoretical: Bitcoin "brain wallets" put exactly this construction on a public
ledger, and a 2016 study found the overwhelming majority drained — some within
*minutes* of first being funded, by attackers running dictionaries against the
chain continuously.

**It cannot be rotated.** A leaked password database can be invalidated. An
immutable ledger cannot. A password committed once is exposed for the life of the
chain, including after the user has changed it everywhere else.

**It also adds nothing.** Authorship is already settled: every transaction
carries `sender: Address` and an Ed25519 signature over a domain-separated
document, which is ~128-bit security that no password approaches. And a block is
not *owned* by anyone — it is a batch of transactions, each independently
authorised. "This block belongs to me rather than to a hacker" has no meaning to
attach a mechanism to.

**The general rule this is an instance of:** never put a low-entropy secret's
verifier where an attacker can hold it. A public blockchain is the worst possible
such place, because publication is the whole point of the system.

### The two real problems underneath

**(a) "I want to recover my account from something I remember."** Genuinely hard,
genuinely important here — [ADR-0005](adr/0005-african-first-design.md) is
written for users who will lose devices.

The sound version of the password intuition already has a home in this project.
[07-resolver-service](07-resolver-service.md) specifies a **threshold OPRF** for
phone-number peppers, in ODIS's shape. The same construction turns a password
into a key safely:

- The password never leaves the device.
- The device blinds it and asks *t*-of-*n* attestors to evaluate a keyed
  function on the blinded value. They learn nothing about the password.
- The result is stretched into a key. An attacker cannot precompute, because the
  attestors' key is not public — and cannot brute-force, because every guess
  costs a rate-limited network round trip to several jurisdictions.
- Fewer than *t* compromised attestors reveals nothing.

That is one piece of infrastructure serving two purposes, and it is the only
construction in which "a password recovers my account" is not a trap. Recorded
here with its known weakness, which 07 already states: compromise of *t*
operators breaks it for everyone.

**(b) "How do I know this history is really mine and complete?"** This one XRPL
answers well, and it is the most valuable thing in this document.

---

## 2. What to take

### 2.1 Provable history — the `PreviousTxnID` chain ✅ *built*

**The problem.** [ADR-0014](adr/0014-payment-history-and-the-mempool.md) shipped
a transaction index and was explicit that it is the first answer here that cannot
be verified: the index is not consensus state, no header commits to it, and **a
node can omit an entry** — hide a payment from you — with nothing in the response
revealing it.

**XRPL's answer.** Every ledger object carries `PreviousTxnID` and
`PreviousTxnLgrSeq`: the transaction that last modified it, and where. Because
the object lives *in the state tree*, that pointer is committed to by the state
root and is therefore provable. Walking backwards through those pointers
reconstructs an account's entire history as an unbroken, committed chain — and
an unbroken chain is exactly what a node cannot fake a gap in.

**What it needs here.** Two changes, and the second is a consensus change.

```rust
// crates/types/src/account.rs
pub struct Account {
    pub address: Address,
    pub nonce: u64,
    pub kind: AccountKind,
    /// The transaction that last touched this account, and its height.
    ///
    /// In state, so it is provable against a header. This is the head of the
    /// chain a wallet walks backwards.
    pub last_txn: Option<(Hash32, Height)>,
}
```

The back-pointer for *older* entries cannot live in the account record — the
record only ever holds its current value. XRPL solves this by putting it in the
transaction's **metadata**, which is committed separately. So:

```rust
// crates/executor — committed, not discarded
pub struct TxOutcome {
    pub tx_id: Hash32,
    pub result: Result<(), ExecError>,
    pub fee_charged: Amount,
    /// For each account this transaction touched, what its `last_txn` was
    /// *before* this transaction. The link that makes the chain walkable.
    pub touched: Vec<(Address, Option<(Hash32, Height)>)>,
}
```

and a new header field:

```rust
pub struct BlockHeader {
    // …
    /// Merkle root over per-transaction outcomes.
    pub outcome_root: Hash32,
}
```

**The walk, from a wallet's point of view.** Prove your `Account` against a
header you trust; it names `T₄₂`. Prove `T₄₂`'s outcome against `outcome_root`;
it names the account's previous pointer, `T₄₁`. Repeat. Every link is proved, so
**a missing entry is a broken chain, which is detectable** rather than invisible.

**One prerequisite in our code:** `Bank::transfer` currently writes balance keys
only, so a pure recipient may have no `Account` record at all. Receiving would
have to touch the record — which is what XRPL does, since the AccountRoot's
`Balance` field changes on receipt.

**Why not put the whole history in state instead?** Considered and rejected. A
state key per account per transaction is simpler, gives random access, and makes
omission impossible by absence proof — but it grows state permanently and
without bound, which is the one cost this project has repeatedly refused to
accept ([06](06-adopted-practices.md) on reserves and state bloat). XRPL keeps
state small and puts the pointers in metadata, which is retained only as long as
history is. Twelve years of production is a reasonable argument.

**The existing index survives as the fast path.** This is the Clio split
[06](06-adopted-practices.md) already adopted: a convenience index for speed, a
committed structure for audit. The index answers instantly; the pointer chain is
what you use when the answer matters.

### 2.2 Commit execution outcomes — "your payment succeeded" as a proof ✅ *built*

Independently valuable, and a prerequisite for 2.1.

Today the header commits to `tx_root` (transaction ids) and `app_hash` (resulting
state). `TxOutcome` — whether a transaction applied, why it failed, what fee it
was charged — is computed by the executor and **thrown away**. So a node can tell
a wallet its payment failed when it succeeded, and the wallet cannot check.

The state root does contradict a sufficiently determined lie eventually, but only
by diffing two full states — which is not something a phone does.

XRPL commits transactions *and their metadata* in one tree, so
"this transaction had exactly these effects" is a compact proof. Committing an
`outcome_root` gives us the same, and turns `ProvedTransaction` from
*"this is in the block"* into *"this is in the block and it worked"*.

### 2.3 `RequireDestinationTag`, on-ledger ✅ *built*

Smallest change here, largest operational effect.
Built as [ADR-0016](adr/0016-required-payment-references.md).

`crates/pay` has [`RequiresReference`](../crates/pay/src/reference.rs), and it is
advisory — a recipient's stated preference that a wallet may honour. XRPL makes
it an account flag (`asfRequireDest`) and the **ledger enforces it**: a payment
without a destination tag to a flagged account fails.

That single flag is the difference between an exchange fielding "I sent it but it
never arrived" tickets and not having the problem. A failed payment the sender
can retry is enormously better than a successful payment nobody can attribute.

```rust
// A flag on the account record; the executor refuses the transfer.
Message::Transfer { to, reference: None, .. } if flags(to).requires_reference
    => Err(ExecError::ReferenceRequired)
```

Pair it with `DisallowIncoming`-style flags later if licensed entities need them.

### 2.4 Key rotation and signer lists — the *correct* answer to §1(a)

XRPL accounts separate three things, and we conflate all of them into one key:

| XRPL | What it buys |
|---|---|
| **Master key** | Derives the address. Can be **disabled** (`asfDisableMaster`), so a seed that may have been exposed is neutralised without moving funds |
| **Regular key** | The day-to-day signing key, rotatable at will (`SetRegularKey`) |
| **Signer list** | Up to 32 weighted signers with a quorum — multisig, and the substrate for social recovery |

Our `Account` holds one revealed public key, and losing it loses the account
permanently. Adopting this shape gives:

- **Rotation without migration.** Change the signing key; the address, the
  username, and every printed QR code stay valid. On a chain whose addressing
  layer is built around aliases people have shared, that matters more than usual.
- **Social recovery** as a native primitive rather than a contract — an M-of-N
  signer list of family, an agent, and an attestor.
- **Compromise response.** A user who suspects their phone was cloned disables
  the old key rather than racing an attacker to move funds.

This is what [ADR-0005](adr/0005-african-first-design.md)'s social-recovery item
should be built on, and it is a strictly better answer to "recover from something
I remember" than any password scheme.

### 2.5 Fee escalation and a transaction queue

[ADR-0014](adr/0014-payment-history-and-the-mempool.md) records that the mempool
selects in nonce order, first come, and that fee replacement is premature until
congestion is real. XRPL's model is the one to reach for when it is:

The **open ledger cost** rises sharply as a ledger fills and decays back
afterwards. Transactions that do not meet it are **queued** for a later ledger
rather than dropped. The result is that congestion produces a predictable price
and a wait, instead of silent failure or a blind bidding war.

That is a better fit here than Ethereum-style tip auctions, because a user
sending remittance money cannot reason about a fee market and should not have to.

### 2.6 Retention: `online_delete`, and the sharding they withdrew

Nothing is ever deleted in `crates/store`, and ADR-0014's index now grows with
history too. XRPL's default is to keep a rolling window of recent ledgers
(`online_delete`) and let separate infrastructure hold full history.

The instructive part is the failure: XRPL also built a **history shard store**,
distributing ranges of history across volunteer nodes, and eventually removed it.
Voluntary distribution of unprofitable data did not hold up. The lesson for our
retention work is to plan for *someone specific* to keep full history — an
archive role with a reason to — rather than assuming the network will.

---

## 3. What not to take

**Account reserves.** XRPL requires a minimum XRP balance to hold an account, plus
more per owned object. [06](06-adopted-practices.md) already rejected this and the
rejection stands: a minimum balance to exist excludes exactly the users this chain
is for. XRPL itself has reduced its reserve over time, which suggests the cost is
felt. Charge for genuinely scarce public goods — short usernames, which
`crates/alias` already does with expiry and renewal — not for existing.

**The UNL trust model.** XRPL validators are chosen by each operator's Unique
Node List, a subjective list of who to believe. It works, but it is a weaker and
much less legible trust model than a stake-weighted BFT quorum with slashing, and
adopting it would undo [ADR-0012](adr/0012-staking-and-slashing.md). *One* piece
is worth borrowing: XRPL publishes signed, versioned, expiring validator lists
from multiple publishers, which is a sensible shape for distributing the witness
bootstrap set in [ADR-0011](adr/0011-objective-anchors.md).

---

## 4. What XRPL does not answer for us

- **Long-range attacks.** XRPL is not proof of stake, so it has no equivalent
  problem and no lesson. Ours stays as [ADR-0010](adr/0010-long-range-attacks.md)
  and [ADR-0011](adr/0011-objective-anchors.md) leave it.
- **The peer-to-peer layer.** XRPL's is bespoke and tightly coupled to its
  consensus. It confirms the general shape — a separate validator network and a
  separate client API — which we already follow, and little else transfers.
- **Human-readable addressing.** XRPL has no equivalent of `crates/alias`;
  its X-addresses merely fold a destination tag into the address string. Worth
  noting as a compact encoding idea, nothing more.
- **Cross-currency pathfinding**, which is the largest thing we intend to take
  from XRPL, is already scheduled as Phase 4 and is out of scope here.

---

## 5. Order of work

| # | Change | Cost | Why now |
|---|---|---|---|
| ~~1~~ | ~~Commit `outcome_root` in the header~~ | **Built** — [ADR-0015](adr/0015-committed-outcomes-and-provable-history.md) | |
| ~~2~~ | ~~`last_txn` and previous pointers~~ | **Built** — [ADR-0015](adr/0015-committed-outcomes-and-provable-history.md) | ADR-0014's stated weakness is closed |
| ~~3~~ | ~~`RequireDestinationTag` account flag~~ | **Built** — [ADR-0016](adr/0016-required-payment-references.md) | The requirement, the refusal and the reason are all provable |
| 4 | Regular keys, master-key disable, signer lists | Large; new message types, account model | The real answer to recovery, and to §1 |
| 5 | Fee escalation and a queue | Medium | When congestion is real, not before |
| 6 | Retention with a named archive role | Large | When storage growth is measured, not assumed |

1 and 2 were one project and were done together, for the reason given: they
change the header, so they were cheapest before a network carries headers
between machines. 3 followed on its own — it needed only an account field and
one check, and it stands alone because nothing else depends on it.

4 is next, and it is the largest of the six. It is also the one §1 has been
pointing at from the start: the *correct* answer to "recover my account from
something I remember" is a rotatable signing key and a signer list, not a
password anywhere near a ledger.

## Sources

- [XRPL: ledger object common fields (`PreviousTxnID`, `PreviousTxnLgrSeq`)](https://xrpl.org/ledger-entry-common-fields.html)
- [XRPL: transaction metadata](https://xrpl.org/transaction-metadata.html)
- [XRPL: ledger header and the transaction tree](https://xrpl.org/ledger-header.html)
- [XRPL: source and destination tags](https://xrpl.org/source-and-destination-tags.html)
- [XRPL: `RequireDest` and account flags](https://xrpl.org/accountset.html)
- [XRPL: `SetRegularKey`](https://xrpl.org/setregularkey.html)
- [XRPL: multi-signing and signer lists](https://xrpl.org/multi-signing.html)
- [XRPL: transaction cost and fee escalation](https://xrpl.org/transaction-cost.html)
- [XRPL: transaction queue](https://xrpl.org/finality-of-results.html)
- [XRPL: online deletion and history](https://xrpl.org/online-deletion.html)
- [XRPL: reserves](https://xrpl.org/reserves.html)
- [Vasek, Bonneau, Castellucci, Keith, Moore — *The Bitcoin Brain Drain* (FC 2016)](https://link.springer.com/chapter/10.1007/978-3-662-54970-4_36)
- [Celo ODIS: threshold OPRF for identifier peppers](https://docs.celo.org/protocol/identity/odis)
- [OPAQUE: an asymmetric PAKE (IETF CFRG)](https://datatracker.ietf.org/doc/draft-irtf-cfrg-opaque/)
