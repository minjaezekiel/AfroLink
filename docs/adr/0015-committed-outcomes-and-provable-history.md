# ADR-0015 — Committed outcomes, and history a node cannot quietly truncate

- **Status:** accepted
- **Date:** 2026-08-31
- **Relates to:** [ADR-0014](0014-payment-history-and-the-mempool.md) (the
  weakness this closes), [09](../09-what-xrpl-answers.md) §2.1–2.2 (where the
  design comes from), `crates/executor`, `crates/rpc`, `crates/store`

## Context

[ADR-0014](0014-payment-history-and-the-mempool.md) shipped payment history and
said plainly what it could not do:

> A transaction index is a node's private convenience. It is not in the state
> tree, no header commits to it… So a server can **omit entries** — hide a
> payment from you — and nothing in the response reveals that.

Going back to the XRP Ledger with that as a specific question produced a
specific answer ([09](../09-what-xrpl-answers.md) §2.1). It also surfaced a
second gap nobody had named: **`TxOutcome` was computed and thrown away.** The
header committed to which transactions ran (`tx_root`) and to the state they
produced (`app_hash`), but not to *what any of them did*. A node could tell a
wallet its payment failed when it succeeded, and the wallet had no way to check
short of diffing two entire states — which is not something a phone does.

## Decision

### 1. `outcome_root` — a second tree, beside `tx_root`

`BlockHeader` gains a Merkle root over per-transaction **receipts**.

```rust
pub struct TxReceipt {
    pub tx_id: Hash32,
    pub code: ResultCode,
    pub fee_charged: Amount,
    pub touched: Vec<TouchedAccount>,
}
```

Two trees rather than one, with the same leaves in the same order. Folding
receipts into `tx_root` would have broken the property that file already
documents — *"a light client can prove inclusion of a transaction it knows the
id of without holding the block"* — because the leaf would then require the
receipt too.

Sharing the ordering means one `(index, total)` serves both proofs, and a
receipt proved at a different position than its transaction is a receipt for
someone else's payment. `ProvedTransaction::verify` checks both roots *and* that
`receipt.tx_id == transaction.id()`, because both proofs can succeed against a
well-formed block while describing different rows if a server pairs them wrongly.

### 2. `ResultCode` is deliberately coarse

It names **which subsystem refused**, not why:

| | |
|---|---|
| `Success` | applied |
| `Transaction` | stateless verification — signature, chain, expiry, structure |
| `Nonce`, `Bank`, `Group`, `Staking`, `Registry`, `Binding`, `Account`, `State` | that component said no |

The code goes into a header, so its meaning is consensus. Making it a mirror of
`ExecError`'s full detail would make every new `BankError` variant a consensus
change. Mapping to the top-level shape instead means subsystem errors stay
ordinary code. XRPL's `tec`/`tem` result codes take the same position for the
same reason.

The rich `ExecError` survives in `TxOutcome` for local use — logs, a node's own
diagnostics — and is never committed and never on the wire.

### 3. `Account::last_txn` — the head of the chain

```rust
pub struct Account {
    // …
    pub last_txn: Option<TxPointer>,   // (tx_id, height)
}
```

In state, so it is proved against `app_hash`. Each receipt's `touched` list
records, for every account the transaction moved, **what that account's pointer
was before**. So:

```text
  Account (proved against app_hash)
       └── last_txn ─────► T₄₂  (proved against tx_root + outcome_root)
                            └── receipt.previous_for(me) ─► T₄₁ ─► … ─► None
```

Every link is committed and signed by two thirds of voting power. A node can
decline to serve a link; it cannot produce a receipt naming a different
predecessor.

**The failure mode changes shape.** A hidden payment stops being an invisible
gap and becomes a refusal to answer. A client that reaches the end of the chain
knows it has everything; one that is stonewalled knows it is being stonewalled.
Neither was possible with an index alone, and
[`HistoryCursor`](../../crates/rpc/src/history.rs) is the piece that enforces it
— it refuses any answer that does not continue the committed chain.

### 4. Which accounts a transaction moves, and why failures are narrower

- A **successful** transaction moves the pointer of every address in
  `touched_addresses()`.
- A **failed** one moves only the sender's and the fee payer's.

Two reasons, and the second is the load-bearing one. A failed transfer did not
pay the recipient, so it does not belong in their history. And recording a
pointer *creates an account record* — so the narrower rule means a spammer
cannot mint state entries for addresses it merely names. To appear in a
stranger's history you must actually pay them, which funds them.

This is the one place the design deviates from XRPL, which avoids the question
entirely through reserves — the mechanism
[06](../06-adopted-practices.md) rejects for excluding the users this chain is
for.

### 5. Receipts are persisted, atomically with the block

`ChainStore::put_block` now takes them, and refuses a list whose length does not
match the block's. A receipt list that disagrees with its block is worse than no
receipts: it produces proofs against a root the header does not carry, and the
wallet blames itself.

## Consequences

**Good.** The weakness ADR-0014 shipped with is closed, and closed by a
mechanism rather than by a promise. "Your payment succeeded" is now a proof;
so is "this is all of my history". A wallet's main screen — *what happened to my
money* — can be drawn without trusting the node that drew it.

**Bad, and worth being clear about.**

- **Walking is `O(number of your transactions)` round trips.** The index from
  ADR-0014 remains the fast path: ask it where to look, walk the chain when the
  answer matters. That is the same split the Clio-shaped serving role already
  takes ([06](../06-adopted-practices.md)).
- **A node can still refuse to answer.** Withholding is available to whoever
  holds the data, on any protocol. What is gone is withholding *invisibly*.
- **Every account that receives money now has an account record**, where before
  a pure recipient might have had only a balance entry. That is real state
  growth, and it lands on the retention work
  [ADR-0006](0006-state-persistence-and-retention.md) already lists as not done.
- **Receipts are a third thing to retain**, alongside blocks and commits.

**Deliberately not done.** `Query::Block` returns a block without its receipts,
so a client can recompute `tx_root` but not `outcome_root` for a whole block.
Per-transaction proofs cover the history walk, which is what this ADR is for;
a whole-block receipt fetch is a small addition when something needs it. No
forward index from an account to its *next* transaction — the chain runs
backwards only, which is the direction a wallet reads.

## Revisit if

- Round trips make the walk too slow on real connectivity, which would argue for
  a batched "walk me *n* links" response rather than a different structure
- Receipt retention becomes the dominant storage cost, which is when it needs
  its own policy rather than the chain's

## Sources

- [XRPL: ledger object common fields (`PreviousTxnID`)](https://xrpl.org/ledger-entry-common-fields.html)
- [XRPL: transaction metadata](https://xrpl.org/transaction-metadata.html)
- [XRPL: transaction results](https://xrpl.org/transaction-results.html)
- [RFC 6962: Merkle inclusion proofs](https://datatracker.ietf.org/doc/html/rfc6962)
