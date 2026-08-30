# ADR-0014 — Payment history, and letting money move

- **Status:** accepted
- **Date:** 2026-08-31
- **Relates to:** [ADR-0013](0013-http-transport.md) (the transport),
  [ADR-0009](0009-developer-payment-surface.md) (payment references),
  `crates/store`, `crates/rpc`, `crates/node`, `crates/http`

## Context

[ADR-0013](0013-http-transport.md) gave the query protocol a socket, and left
two things a payments network cannot be without.

**A wallet could not see a payment arrive.** The transport served headers and
state proofs — enough to prove *a balance*, not enough to show *a payment*.
`ChainStore` kept `BLOCKS`, `COMMITS`, `META` and `NODES`: full block bodies
were on disk with no route to them, and no index from an address to the
transactions touching it. A recipient does not know the id of a transaction sent
to them, so with no index there was no question they could ask.

The same gap blocks everything downstream: an explorer has nothing to list, an
exchange cannot detect a deposit, and a wallet's main screen — *what happened to
my money* — cannot be drawn.

**A wallet could not send one.** `Node` held `pub mempool: Vec<Transaction>`: an
unbounded, unvalidated, publicly-writable vector. Harmless while the only caller
was a test in the same process; a remote denial of service the moment a socket
existed.

## Decision

### 1. A history index, and it is honest about what it is

`ChainStore` gains two tables, written **in the same transaction as the block**:

| Table | Key | Answers |
|---|---|---|
| `TX_LOCATION` | transaction id | "where is this payment?" |
| `TX_BY_ADDRESS` | `address ‖ height ‖ index` | "what touched this account?" |

Both are big-endian and fixed-width at every position, so one address's keys
form a contiguous range no other address can fall inside, and byte order equals
chronological order — one range scan returns an account's history oldest-first
with no sorting.

They join the block's write transaction rather than following it because a block
that is present but unindexed reads to a wallet as *"you received nothing"*,
which is the most damaging thing a partial write could say.

Which addresses a transaction is filed under comes from
[`Transaction::touched_addresses`](../../crates/types/src/tx.rs), an **exhaustive**
match over `Message`. A new variant that moves value must not silently become
invisible to its recipient, and an exhaustive match means adding one fails to
compile until someone decides who should see it.

### 2. History is a hint. Inclusion is a proof.

This is the part worth being careful about, because it is the first answer in
this project that **cannot be verified**.

A transaction index is a node's private convenience. It is not in the state
tree, no header commits to it, and two honest nodes may keep different ones. So
a server can **omit entries** — hide a payment from you — and nothing in the
response reveals that.

What it cannot do is invent one. Every entry names a transaction id, and that id
turns into a proof. So the protocol splits into three, and the split is the
design:

| Query | What you get |
|---|---|
| `History` | *Where to look.* Unproved, and the accessor is `entries_unverified()` |
| `Transaction` | One transaction with a Merkle inclusion proof against the block's `tx_root` |
| `Block` | The whole body, so a client recomputes `tx_root` itself and knows it received **all** of it |

`ProvedTransaction` is precise about its own limits. The leaf is the
transaction's own id, so **inclusion** is proved and a substituted transaction
cannot survive. But the verifier knows the root and the id, not the position —
so `index` and `total` come from the prover, and a server can claim a truthful
inclusion at a false position. That is a display detail, not a value bug, and it
is recorded rather than glossed for the same reason `MerkleProof::verify` was
changed to take sizes as parameters ([08](../08-adversarial-testing.md) §3 & 4).
A client that needs the position verified asks for the block.

A node with no index answers **501, not an empty list**. "I do not index
history" and "you have received nothing" are different answers, and a wallet
that cannot tell them apart shows a user an empty account.

### 3. A mempool that is mostly refusals

Every limit answers a specific way of making a node do unpaid work:

| Limit | The attack |
|---|---|
| `max_transactions`, `max_bytes` | Fill memory with valid-looking junk |
| `max_per_sender` | One account monopolising the queue, so nobody else's payment is proposed |
| Stateless verification on insert | Make a node hold and gossip what could never apply |
| Nonce floor | Replay something already committed |
| Expiry eviction | Park a transaction with a distant `valid_until` and never collect it |

Checks run cheapest-first, so a hostile peer pays for signature verification
only after everything free has passed.

**It does not check balances.** A balance is a fact about state at a height, and
the height moves; a transaction that cannot pay now may be able to by the time
it is proposed. Nonce and signature are stable facts about the transaction
itself. Balance is not, and the executor charges the fee regardless.

**It does not replace by fee.** Fee replacement needs a minimum-bump rule or it
becomes free churn, and getting it wrong is worse than not having it. A stuck
transaction expires at its own `valid_until`.

**Selection does not drain.** `select` returns transactions without removing
them; `remove_committed` forgets them. The old code did `mem::take` at proposal
time — so a round that failed to commit, which is ordinary under a partition or
a timeout, silently lost every transaction in it. The user's payment would
simply never arrive, with nothing anywhere to say why.

### 4. Blocks have a size limit — a consensus rule that was missing

There was none. Every validator re-executes every proposal before voting, so a
single proposer could make the whole network do unbounded work for the cost of
one message. No signature or stake check catches this: the proposer is
*entitled* to propose.

`MAX_BLOCK_TRANSACTIONS` (10 000) and `MAX_BLOCK_BYTES` (4 MiB) bound different
attacks — a count limit alone admits ten thousand maximum-size transactions, a
byte limit alone admits a million tiny ones. Checked **before** execution, never
after: a check that runs afterwards has already paid for the work.

This changes block validity. There is no live chain, so the cost is nothing
today, and the hole becomes exploitable exactly when the peer layer lands.

### 5. Writing is a different trait from reading

`crates/rpc`'s `ChainView` documentation says a query must not be able to reach a
node's mempool, and the way to guarantee it is to make it unreachable. So
submission is a separate trait, `Submit`, and the read path cannot see it
whatever a future caller does. `Server::run` takes both, and a deployment with
no consensus role passes `ReadOnly` — which **refuses** rather than silently
discarding a payment.

`Submit` takes `&self`: a server shares one node across connection threads, and
requiring `&mut` would serialise every balance lookup behind writes.
`SharedNode` holds the lock, and holds it only for one mempool insertion — never
across I/O.

Submission answers **202, not 200**. The node holds it; no block contains it. A
wallet that reads acceptance as settlement tells someone their money arrived
when it has not.

## Consequences

**Good.** A wallet can now show a payment arriving and prove it, and can send
one. That is the whole user-facing loop, and it was the thing standing between
this project and being usable by a person. An exchange integration is now a
matter of ordinary work — deposit addresses, destination tags, block scanning —
rather than of missing endpoints. The proposal path lost a real bug: transactions
no longer vanish when a round fails to commit.

**Bad.** History is unverifiable, and that is a genuine step down from every
other answer this chain gives. It is bounded by naming (`entries_unverified`),
by the note in the JSON view, and by the fact that every entry is checkable —
but a node that omits an entry is not caught by anything here. The honest
mitigation is the same one `crates/witness` uses where a proof cannot exist:
compare several independent nodes. Nothing automates that yet.

Index storage is unbounded and grows with history, alongside the retention work
[ADR-0006](0006-state-persistence-and-retention.md) already lists as not done.

**Deliberately not done.** No fee-based replacement, no priority ordering — the
selection is nonce-order, first come. No mempool gossip policy beyond
"broadcast what was newly accepted". No WebSocket or subscription, so a wallet
polls; that is fine at one-second blocks and is the next thing to want. ~~No completeness proof for history~~ — **built**, as
[ADR-0015](0015-committed-outcomes-and-provable-history.md).

## Revisit if

- ~~A node is caught omitting history entries~~ — **answered before it happened**,
  by [ADR-0015](0015-committed-outcomes-and-provable-history.md)
- Mempool congestion becomes real, which is when fee replacement and priority
  ordering stop being premature
- Index growth becomes the dominant storage cost, which is when it needs the
  same retention policy as the chain itself

## Sources

- [XRPL: destination tags](https://xrpl.org/source-and-destination-tags.html)
- [Cosmos SDK: transaction indexing and events](https://docs.cosmos.network/main/learn/advanced/events)
- [CometBFT: mempool](https://docs.cometbft.com/main/explanation/core/mempool)
- [Ethereum: transaction pool policy and replacement rules](https://geth.ethereum.org/docs/faq)
- [RFC 6962: Merkle inclusion proofs](https://datatracker.ietf.org/doc/html/rfc6962)
