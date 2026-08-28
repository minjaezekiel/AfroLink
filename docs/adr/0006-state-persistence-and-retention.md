# ADR-0006 — State persistence: content-addressed nodes, not replay

- **Status:** accepted
- **Date:** 2026-08-28
- **Supersedes:** the replay-only design documented in `crates/store`

## Context

[ADR-0001](0001-sovereign-rust-l1.md) committed us to operating our own L1, which
means we own this problem. The current store persists blocks and commits but not
the state tree, rebuilding state by replaying every block from genesis. Startup
is `O(chain length)`.

At 1s blocks that is ~31 million blocks per year. Replay is fine for a devnet and
unshippable for anything else. Two mature networks solved exactly this, and they
chose different answers.

## What XRP Ledger does

XRPL's state is a **SHAMap** — a hybrid Merkle–Patricia trie — persisted through a
**NodeStore** abstraction onto NuDB (an append-only, SSD-optimised key-value
store with near-constant performance and memory footprint regardless of size) or
RocksDB.

The important property is that the NodeStore is **content-addressed**: a node's
key is its own hash. Because the trie is immutable, two consecutive ledgers share
every subtree that did not change. Committing a ledger writes only the nodes on
changed paths — `O(log n)` — and every historical ledger remains addressable by
its root hash.

There is therefore **no separate snapshot mechanism**. State is persisted
continuously, and "the state at version R" is just "the tree reachable from root
R". Startup is loading a root hash.

The cost is growth, which XRPL manages with three separate mechanisms:

- **Online deletion** — the default config keeps the most recent 2,000 ledgers
  and deletes older data automatically.
- **History sharding** — volunteers store random *ranges* of history, so the
  network collectively retains everything without every node doing so.
- **Clio** — a read-optimised API server storing validated data ~4× more
  compactly, backed by Cassandra/ScyllaDB, which does **not** join the P2P
  network. Serving is separated from validating.

The number that settles the argument: **full XRPL history was ~39 TB as of
January 2026**, and must sit on SSD. Almost nobody runs it, and the protocol is
explicitly designed for that to be fine.

## What TRON does

TRON's world state is a Merkle Patricia Trie reducible to a single root hash.
Its answer to startup cost is the **Lite FullNode**: a node starts from a
*Snapshot Dataset* — the latest state plus the most recent **65,536 blocks** —
rather than syncing from genesis. Full node data splits into a Snapshot Dataset
and a History Dataset, produced by a pruning tool, and operators re-prune
periodically (monthly is the common cadence) to keep disk bounded.

TRON also carries a **checkpoint** mechanism, because its underlying stores
cannot guarantee atomicity across multiple databases; the checkpoint makes
persistence atomic.

Archive nodes retain per-block historical state; ordinary full nodes keep only
the latest state needed to validate new blocks.

## The comparison that decides it

| | XRPL | TRON |
|---|---|---|
| State structure | SHAMap trie | Merkle Patricia Trie |
| Persistence | content-addressed nodes, continuous | latest state + recent history |
| Historical versions | free (addressable by root hash) | archive nodes only |
| Startup | load a root hash | load a snapshot dataset |
| Retention | online delete + sharding | periodic re-prune |
| Extra machinery | none for snapshots | pruning tool, snapshot/history split |
| Atomicity | storage layer | explicit checkpoint mechanism |

**XRPL's model is the better fit, and it is barely more work than what we have.**
Our state is already a sparse Merkle tree whose nodes are already
domain-separated hashes of their contents — we are one persistence layer away
from a NodeStore. TRON's snapshot-dataset approach solves the same problem but
adds a whole tooling surface (generate, distribute, verify, re-prune) to
reproduce what content-addressing gives for free.

TRON's checkpoint mechanism we do **not** need: it exists because LevelDB cannot
make one atomic write across several stores. redb gives us real multi-table
transactions, and `ChainStore::put_block` already uses one. That is a place where
our storage choice is genuinely ahead, and worth not throwing away.

## Decision

**1. Persist SMT nodes content-addressed, keyed by node hash.**
A commit writes only nodes not already present. Unchanged subtrees are already
stored under their existing hashes, so writes are `O(log n)` per changed key.
Startup becomes "load the tip's `app_hash`" — `O(1)` — and replay is demoted from
the normal path to a repair and audit tool.

**2. Adopt node roles rather than one node type.** Both networks converged here
independently, and for a chain whose users are on cheap hardware it matters more
than for either of them:

| Role | Keeps | For |
|---|---|---|
| **Validator** (default) | latest state + recent history | consensus |
| **Archive** | everything | explorers, regulators, dispute resolution |
| **Serving** | read-optimised, no P2P | proof-serving to wallets at scale |

The default profile is deliberately the cheap one. [ADR-0005](0005-african-first-design.md)
rejects designs that assume abundant hardware, and "every node stores 39 TB" is
exactly such an assumption.

**3. Bounded retention by default**, in XRPL's `online_delete` style: keep the
last N versions of state, garbage-collect nodes unreachable from any retained
root. N is a config value, not a constant.

**4. Verified state sync for joining nodes.** A new node downloads state at a
height and checks it against the `app_hash` in a header it verified
independently. **We already have every piece of this**: `crates/light` verifies
commit certificates and Merkle proofs today. A joining node is a light client
that then downloads the state its verified header commits to. Cosmos's state sync
cuts joining from days to minutes; ours gets the trust argument for free from
machinery already written and tested.

**5. Archival as a paid role.** XRPL relies on volunteers for history sharding,
and full history is correspondingly rare. We have a reward system
([04-earning-and-participation.md](../04-earning-and-participation.md)) with a
category for exactly this shape of contribution — serving data others need.
Paying for provable archival storage is strictly better than hoping.

## Consequences

**Good:** startup goes from `O(chain)` to `O(1)`. Historical state becomes
addressable by root hash at no extra cost, which makes archive nodes a config
flag rather than a separate codebase. No snapshot tooling to build or maintain.
Cheap hardware stays viable, which is a requirement here rather than a nicety.

**Bad:** the state tree must be restructured to materialise nodes — today it
recomputes the root recursively and never names its internal nodes. Retention and
garbage collection are new, and GC over a shared-structure store is genuinely
easy to get wrong: deleting a node still reachable from a retained root is silent
corruption that only surfaces on a later read. It needs reference tracking and
adversarial tests before it is enabled by default.

**Known gap after the first implementation step:** writing only *new* nodes makes
disk writes `O(log n)`, but recomputing the node set still costs `O(n)` CPU per
commit. Incremental copy-on-write updates are the follow-up; the structure this
ADR introduces is what makes them possible.

## Revisit if

- Measured state size makes per-version retention impractical, pushing us toward
  TRON's snapshot-dataset model after all
- A read-serving bottleneck justifies a Clio-style separate store sooner

## Sources

- [XRPL: Online Deletion](https://xrpl.org/online-deletion.html)
- [XRPL: Configure Full History](https://xrpl.org/docs/infrastructure/configuration/data-retention/configure-full-history)
- [XRPL: Ledger History](https://xrpl.org/docs/concepts/networks-and-servers/ledger-history)
- [XRPL: Introducing History Sharding](https://xrpl.org/blog/2018/introducing-history-sharding)
- [XRPL: The Clio Server](https://xrpl.org/docs/concepts/networks-and-servers/the-clio-server)
- [XRPL Commons: Data Architecture — SHAMap and NodeStore](https://www.xrpl-commons.org/core-dev-module/data-architecture)
- [XRPL Commons: The NodeStore](https://docs.xrpl-commons.org/core-dev-bootcamp/module03/nodestore-architecture)
- [java-tron: Lite FullNode](https://tronprotocol.github.io/documentation-en/using_javatron/litefullnode/)
- [TRON: Main Net Database Snapshots](https://developers.tron.network/docs/main-net-database-snapshots)
- [TRON: Toolkit node maintenance suite](https://tronprotocol.github.io/documentation-en/using_javatron/toolkit/)
- [TIP-128: Lite Fullnode implementation](https://github.com/tronprotocol/tips/issues/128)
- [java-tron: Implementation of Archive Node](https://github.com/tronprotocol/java-tron/issues/6289)
- [Cosmos SDK State Sync Guide](https://blog.cosmos.network/cosmos-sdk-state-sync-guide-99e4cf43be2f)
- [Cosmos SDK: snapshots README](https://github.com/cosmos/cosmos-sdk/blob/825245d/store/snapshots/README.md)
