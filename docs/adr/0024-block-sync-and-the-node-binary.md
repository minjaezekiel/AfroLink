# ADR-0024 — Block sync, and the node binary

- **Status:** accepted
- **Date:** 2026-09-02
- **Relates to:** [ADR-0023](0023-peer-to-peer.md) (the transport this extends,
  and the two gaps it named), [ADR-0006](0006-state-persistence-and-retention.md)
  (the durable store a node resumes from), [ADR-0010](0010-long-range-attacks.md)
  (verifying a commit against a validator set, which is what makes a synced block
  safe), [ADR-0013](0013-http-transport.md) (the query server the daemon runs),
  `crates/p2p/src/sync.rs`, `crates/daemon`, `crates/node/tests/sync.rs`

## Context

[ADR-0023](0023-peer-to-peer.md) closed with two things named as the distance
between this project and a testnet, and this ADR is both of them.

**No block sync.** A node that missed a height could never reach the tip again.
There was no message that asks for a block, so a restarted node was a node that
had permanently left the network, and a node that fell behind under load stayed
behind. Consensus gossip carries only what is happening *now*; nothing carried
what had already happened.

**No node binary.** Every crate was a library that `cargo test` drove. The
executor could execute, the consensus driver could decide, the transport could
gossip, the store could persist — and no artefact in the workspace put them in
one process and let go. That is the same defect class this codebase has now met
five times: *correct, tested code reachable from no caller*, at the largest scale
it can occur, where the thing unreachable is the whole system.

The two are one piece of work rather than two, because each is what makes the
other testable. A daemon without sync cannot rejoin anything; sync without a
daemon is a protocol nobody runs.

## Decisions

### 1. A synced block is proved, not trusted

This is the one path where a node takes a whole block from a stranger, and the
tempting reading is that the peer is an authority: it says this is height nine,
so this is height nine.

What travels instead is a `SyncBlock` — **a block and the commit certificate that
finalised it** — and `Node::apply_synced` checks that certificate against *this
node's own validator set*, exactly as `crates/light` does for a phone. Forging
one needs more than two thirds of the validators' signing keys, and anyone
holding those has no need to lie to a syncing node.

Then the block is re-executed anyway, against a **copy** of state. The two checks
answer different questions and neither replaces the other:

- the certificate proves the *network* finalised this block;
- re-execution is how this node ends up *holding the state* rather than a root
  hash somebody sent it.

The sharpest case is the one that shows they are independent. In
`a_genuine_certificate_over_a_false_state_root_is_still_refused`, all four
validators genuinely sign a header claiming an `app_hash` its transactions do not
produce. The certificate verifies perfectly, and the block is still refused —
because that is either a fork or a consensus-breaking bug in this build, and in
both cases writing a state nobody else has is worse than staying behind.

The checks run cheapest-first, and the order is load-bearing: a peer must not be
able to buy dozens of signature verifications, or a whole block execution, with a
header field that costs one comparison to refuse.

**A refusal costs nothing.** Execution goes into a clone that is discarded unless
the root matches. A node that cannot verify a height stays at the height before
it, which is recoverable; a node that half-applied a block it then rejected is in
a state no other node shares, which is not.

### 2. One block per frame, and a reader that allocates what arrives

`MAX_BLOCK_BYTES` bounds a block's transactions and `MAX_FRAME_LEN` bounds a
frame. Batching several blocks into one response was never available: one
maximum-size block plus its certificate fills a frame on its own.

So the parallelism comes from somewhere else — **one request in flight per peer,
across many peers**. That is slower than a batching protocol on a fast link and
more robust on a slow one, because a stalled peer costs one outstanding request
rather than a whole batch window. Requests go out lowest-height-first, which is
what keeps the staging buffer small: a syncer that asks for the *tip* first holds
every block it receives and applies none of them.

**A defect found while writing this.** The two constants were written
independently and were both exactly `4 * 1024 * 1024`. A block at the consensus
limit could therefore be built and voted on but never *sent* — every wrapper a
block travels in, a proposal included, is strictly larger than the block, so
`write_frame` would have refused it. A proposer could have produced a legal block
that no peer could receive. `MAX_FRAME_LEN` is now derived from `MAX_BLOCK_BYTES`
plus a stated headroom, with a `const` assertion: two numbers that must not drift
apart should not be two numbers.

**And the bound itself was the smaller half of the problem.** A reader that
allocates the length a stranger *announced* hands out five mebibytes for a
four-byte header — announce the maximum, send nothing, and a node with forty
inbound slots is holding two hundred mebibytes it will never receive. Frames are
now filled in `READ_CHUNK` steps as bytes actually arrive, so the memory an
attacker can take is bounded by the bandwidth they spend taking it.

CometBFT reaches the same place from the other end and more thoroughly:
`MaxPacketMsgPayloadSize` means a peer never announces more than one small packet,
and a block is a `PartSet` of 64 KiB parts rather than one message, so the largest
thing a peer can ask a node to hold is a constant. Adopting that here means
splitting proposals and sync responses into parts with their own Merkle root —
the right long-term shape, and a change to the consensus wire format. This is the
bound that does not need one.

### 3. The sync policy is pure, and the store is a trait

Everything that decides — am I behind, whom do I ask, what may I stage, when do I
give up on a request — lives in `Manager`, which still has no sockets and now has
no database either. Serving a block is a `Directive::ServeBlock(peer, height)`
that the transport fulfils; where blocks are kept is the transport's business.

`BlockSource` and `CommitSink` are traits in `crates/p2p`, implemented over
`ChainStore` in `crates/daemon`. Neither crate could implement the other's trait
without taking on the other's dependency — `crates/store` would grow a
Diffie–Hellman implementation to serve a block — so the join lives in the one
place that already depends on both, and is three newtypes with no logic in them.

**Served from the durable store, not from the running node's memory.** A node
serving from memory could only help peers who fell behind while it happened to be
up, which is precisely the case where they needed least help, and every sync
request would queue behind the consensus lock.

### 4. A peer that sends an unverifiable block pays for it

Verification happens after staging, so without care the sender is anonymous by
the time the failure is known — and a peer could feed a node unverifiable blocks
indefinitely for free. The peer id travels with the staged block, and:

- a certificate that does not verify is `Unforgivable` — one is enough, because
  it is not a mistake anybody makes by accident;
- everything else is `BadBlock`, which costs reputation without cutting the peer
  off on the first one, because a peer on a fork sends real blocks that simply do
  not fit here.

An unsolicited block is penalised on the same rule as an unsolicited address
list, at a heavier price: it is up to four mebibytes a peer decided this node
should spend memory and a certificate verification on.

### 5. `Status` carries what a node *has*, not what it is working on

A node driving consensus at height 42 has committed 41. Announcing 42 would have
every peer ask it for a block that does not exist yet, on every tick, for as long
as they stayed connected. The distinction is easy to get backwards and is now
written into the message's own documentation and into a test.

A peer's status is believed only as far as it is useful for routing. Claiming too
high earns requests it cannot answer; claiming too low means it is never asked.
Neither buys anything, because what makes a block acceptable is the certificate
on it.

`NoBlock` exists as its own message rather than as silence, because silence and
"I do not have it" are different facts. A syncer that cannot tell them apart
burns a request window waiting out a timeout on every pruned peer it meets.

### 6. A node that is behind does not propose

The rule that makes sync and consensus fit together. A validator that has fallen
behind is entitled to propose the moment its turn comes, and a block built on
stale state is one that everybody who is *not* behind votes down — costing a
round and, on a small validator set, stalling the chain while it happens. So the
daemon catches up first and proposes second.

### 7. The genesis file is bytes, and its hash is what operators compare

Every node on a chain must agree byte for byte on its genesis. A text format
makes that a question about parsers: two implementations that disagree about a
duplicate key or a number's range produce two chains from one file, and the
operators find out at the first block.

So genesis is written with the same canonical codec the ledger uses, and `init`
prints its hash. Two operators compare one 64-character string. That is a better
property than a file they can read and misread.

`start` adopts the file into the store on a fresh directory, and on every start
afterwards **compares** them. A mismatch is fatal — copying a colleague's genesis
into a directory that already holds blocks is an easy mistake, and without this
check the node starts and discovers it at the first state root it computes.

### 8. Configuration refuses what it does not understand

`key = value`, one per line, `#` to end of line. No serde, no TOML crate: three
subcommands and eleven settings do not justify one, and a payments daemon's
dependency tree is a supply-chain surface.

Unknown keys are an **error**. A parser that ignores what it does not understand
is how an operator sets `max_peers` in a file whose field is `max_inbound` and
never finds out — the node runs, reports nothing wrong, and is configured as
though the line were absent. The same rule applies to command-line flags: a node
started with a misspelled `--dir` writes a whole new chain into a whole new
directory and says nothing.

**Consensus rules are not configurable.** Block size, the unbonding period and
the quorum threshold live in genesis and in governance. A node that could be told
its own consensus parameters by a local file is a node an editing mistake can
fork off the network.

### 9. Two key files, and a refusal rather than a warning

A network key identifies a node to peers; a consensus key signs votes. Separate
files, because relaying blocks requires no stake and signs nothing slashable, and
because that is what lets the consensus key move to a remote signer later without
the network key going with it.

A key file readable by anyone but its owner is **refused**, not warned about. A
warning about a signing key's permissions is a line an operator scrolls past
once, and by then every other account on the machine can sign as that node. An
existing key is never overwritten: it is the one file in a data directory that
cannot be regenerated.

**No encryption at rest**, stated plainly rather than implied otherwise. A
passphrase on a file a daemon must read unattended at boot protects against
someone reading the disk and not against someone who has the machine. A validator
key that matters belongs behind an HSM or a remote signer.

### 10. Failing to persist is fatal

A node that cannot write its own chain stops. Carrying on would mean serving
queries about blocks that will not survive a restart, and voting on a history
only this process can see.

## What this found

**A node did not count its own vote.** `Node` returns its own votes as
`Action::BroadcastVote`; the transport put them on the wire and never fed them
back into the node's own vote set. The deterministic simulator has always
delivered a broadcast to its sender as well as to everybody else — so every
consensus test in the workspace had the rule, and the transport did not.

It is invisible on four validators: three votes from three peers is already more
than two thirds. It is total on one, which cannot reach a quorum it is not
counted in. The first `devnet` started by the node binary produced no blocks at
all, and nothing in a 950-test suite covered it, because every consensus test
drove the simulator that had the rule.

This is the same shape as the four defects before it, inverted: not correct code
nothing reaches, but a rule that existed in the test harness and not in the
system. A simulator that is more capable than production is a simulator that
hides bugs, and the fix is now pinned by
`a_lone_validator_counts_its_own_vote_and_commits` — which fails without it.

**The frame bound could not carry a legal block**, as described in §2.

**Peer housekeeping was running at the poll rate.** The daemon's loop wakes every
20 ms so a consensus timeout fires close to when it was due. Ticking the peer
manager on the same schedule would have quietly turned a limit of 512 messages
*per tick* into ten thousand messages a second, and put a status announcement and
an address request on every connection twenty times a second. The two clocks are
now separate, and the reason is written where the constant is.

## Consequences

A node can be started, stopped, restarted and caught up. Verified end to end,
against the real binary rather than a test harness:

- a single node produces blocks at its configured interval, and after a restart
  resumes from the state tree rather than replaying — `resuming at height 8
  (loaded from the state tree)` — and continues;
- a second node, initialised with `--join` against the first node's genesis and
  given it as a seed, catches up from genesis at roughly twice block-production
  speed, reaches the tip, and then tracks it live;
- the query server answers with proofs against the current tip while the chain
  advances underneath it.

## What this does not do

- **No state sync.** A new node replays every block from genesis. Tendermint and
  Cosmos offer a snapshot path so a node can start near the tip without the
  history; that is a real gap at scale and a separate piece of work, because it
  needs the state tree served in verifiable chunks rather than blocks served
  whole.
- **Validator set changes are not followed across a sync.** `apply_synced` checks
  a commit against the set the node currently holds. That is sound today because
  the set is fixed at genesis and every header carries it forward unchanged. The
  moment set changes exist, this path needs what `crates/light` already has —
  verification that walks the set forward across the heights being skipped. Until
  then a node syncing across a set change refuses the blocks rather than
  accepting the wrong ones, which is the safe direction to be wrong in.
- **No retention.** Nothing is ever deleted, so a node serves every height it has
  ever had and its disk grows without bound. Already named in
  [ADR-0006](0006-state-persistence-and-retention.md); block sync makes it more
  pressing, because serving history is now something peers actually ask for.
- **The daemon has no metrics endpoint and no structured logging.** One line of
  text with a millisecond timestamp to standard error. Adequate to watch a devnet
  and not adequate to operate a validator.
- **`init` builds a one-validator devnet genesis.** One validator means one
  country, no fault tolerance and a set that cannot lose anybody. A real chain's
  genesis is negotiated between its founding validators and adopted with
  `--join`, not generated by whoever ran `init` first. There is no tool for that
  negotiation.
- **No slashing evidence travels over the network.** An equivocating validator
  produces two conflicting votes; nothing gathers them into evidence and nothing
  submits it. `crates/staking` can punish what it is told about and is told
  nothing.
- **A restarting validator has no signing protection.** Nothing records what this
  node has already signed at a height, so a validator restarted from a stale
  store could double-sign. Tendermint keeps a write-ahead log for exactly this,
  and it is the most serious operational gap remaining in this ADR's territory.
- **One signal handler, one dependency.** The workspace forbids `unsafe`, and
  installing a signal handler needs it, so `ctrlc` is the one dependency the
  daemon adds beyond the workspace's own. A daemon that can only be stopped with
  `SIGKILL` leaves its peers holding half-open connections and its operator
  unable to tell a clean stop from a crash.

## Revisit if

- **Validator set changes ship**, which is the day `apply_synced` needs skipping
  verification rather than a single-set check
- **A chain grows past what a new node will replay**, which is when state sync
  stops being optional
- **A validator double-signs after a restart**, which the write-ahead log above
  is meant to prevent and which nothing currently does
- **Retention is implemented**, at which point `NoBlock` stops being rare and the
  syncer's peer selection starts mattering

## Sources

- [Tendermint block sync](https://docs.cometbft.com/v0.38/spec/p2p/legacy-docs/messages/block-sync)
  — the request/response shape, and the reasoning for one request in flight per
  peer
- [CometBFT state sync](https://docs.cometbft.com/v0.38/spec/p2p/legacy-docs/messages/state-sync)
  — the snapshot path this deliberately does not implement yet
- [Tendermint's `priv_validator_state.json`](https://docs.cometbft.com/v0.38/core/validators)
  — the double-signing protection a restarting validator needs and does not have
  here
- [Bitcoin Core headers-first sync](https://developer.bitcoin.org/devguide/p2p_network.html#headers-first)
  — the argument for validating a chain of headers before spending bandwidth on
  bodies, which a BFT chain with commit certificates gets differently
- [CometBFT `signAddVote`](https://github.com/cometbft/cometbft/blob/main/internal/consensus/state.go)
  — a validator's own vote goes onto its internal queue and through the same
  `addVote` path as a peer's, which is why gossip is downstream of consensus
  state and never the mechanism by which it changes
- [CometBFT MConnection](https://docs.cometbft.com/v0.38/spec/p2p/legacy-docs/connection)
  — `SendRate`/`RecvRate` in bytes per second against a real clock, and
  `MaxPacketMsgPayloadSize`, which together mean no peer can announce more than a
  small constant
- [Tendermint `PartSet`](https://github.com/tendermint/tendermint/blob/master/types/part_set.go)
  and `BlockPartSizeBytes = 65536` — validators agree on a `BlockID` and gossip
  the block as Merkle-ized 64 KiB parts, so a whole block never has to fit in one
  message. The structural answer to §2, deferred
