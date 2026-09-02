# 10 — Network hardening: what is missing, and what to do about each

A working list, not a roadmap. Every entry is something the network layer does
not do today, what the field's reference implementations do instead, what we
should do given what this chain is *for*, and what it costs.

The audit that produced it is in the commit history: `crates/p2p` and
`crates/daemon` were built in three passes, and each pass found defects in the
one before it. Two of the last four were found by **running the binary**, not by
a test suite that was by then at 987 tests. That is the single most important
input to how this document orders things.

---

## The ranking principle

"Worst" is not a property of a bug in the abstract. It depends on what the system
is for, and this one is described plainly enough in
[01-architecture.md](01-architecture.md) and [ADR-0005](adr/0005-african-first-design.md):

- **It settles money.** A market trader takes ~1s finality as final. So a defect
  that lets value move wrongly outranks one that costs throughput, always.
- **Its security is economic.** [ADR-0012](adr/0012-staking-and-slashing.md)
  rests on equivocation costing 5% of stake and a jailing. If nothing can
  actually impose that cost, the security argument is a description of code that
  never runs.
- **Bandwidth costs money by the gigabyte, and links are intermittent.**
  ([ADR-0005](adr/0005-african-first-design.md)) A defence that assumes a fat,
  always-on link is not a defence here — it is a reason nodes cannot run here.
- **Validator geography is enforced in protocol** ([ADR-0002](adr/0002-consensus.md)).
  A network layer that lets an attacker choose whom a node talks to undoes the
  distribution rule the consensus layer paid for.

So the order is: **things that break the money**, then **things that break the
economic argument**, then **things that let an attacker degrade a node**, then
**things that stop it working at scale**, then **capability**.

One rule cuts across all of it, learned the hard way five times in this codebase:
**correct, tested code reachable from no caller is not a feature.** Every fix
below has to end at something that runs in `afrolinkd`, not at a passing test.

---

# P0 — The economic argument does not currently run

## 1. Equivocation evidence is built, then dropped — **done**

**What is wrong.** `VoteSet::add` already detects a validator signing two
different values for one `(height, round, type)` and returns
`VoteOutcome::Equivocated(evidence)` with a complete `Equivocation`. `Node::on_vote`
throws it away:

```rust
if set.add(&self.validators, signed).is_err() {   // Ok(VoteOutcome) discarded
```

The rest of the path is finished and tested: `Message::ReportEquivocation`
carries it, `proves_equivocation` verifies it, `Staking::slash` applies the 5%
and the jail. **The only way a validator gets slashed today is if a human
hand-crafts the transaction.** This is the whole of ADR-0012's security argument
sitting behind a caller that does not exist.

**What the field does.** CometBFT keeps an **evidence pool**. A node that sees
two conflicting votes builds `DuplicateVoteEvidence`, gossips it on a dedicated
evidence channel, and the next proposer includes pending evidence *in the block*.
Evidence is validated (same validator, height, round and type; different
`BlockID`; validator was in the set at that height), deduplicated by hash against
already-committed evidence, and **expires**: past `MaxAgeNumBlocks` *and*
`MaxAgeDuration` it is ignored, because after the unbonding period there is no
stake left to slash.

**What we do.** The same shape, minus the separate channel, because we already
have a transaction that does the job.

1. `Node::on_vote` matches on `VoteOutcome::Equivocated(evidence)` and emits a
   new `Action::Equivocation(Box<Equivocation>)`.
2. The node **self-submits** it: builds a `ReportEquivocation` transaction signed
   by its own key, puts it in its own mempool, and returns
   `Action::BroadcastTransaction` — so it travels by the path transactions
   already travel, gets included by whoever proposes next, and is deduplicated by
   nonce and by the mempool's own id set. No new peer message, no new reactor.
3. Expiry comes free from `valid_until`: evidence older than the unbonding
   window cannot be included because the transaction cannot be.
4. The **executor** already refuses to slash twice (a jailed validator is
   jailed), so a second report of the same equivocation is a no-op rather than a
   double punishment. This is asserted, not assumed.

Reporting is permissionless and *any* node that saw both votes will report, so a
single honest observer is enough. The reporter pays the fee, which is the honest
cost of the design — and it is small against a 5% slash.

**Why not a separate evidence channel.** CometBFT needs one because its evidence
is not a transaction. Ours is. Adding a channel would mean a second gossip path,
a second dedup set and a second bound to get wrong, for no property we do not
already have.

**Cost.** Small. One match arm, one transaction builder, and
`crates/node/tests/evidence.rs`.

**Built.** `Node::on_vote` now keeps the `VoteOutcome` it used to throw away and
`report_equivocation` files the transaction. Two things surfaced while building
it that the plan above had not accounted for:

* **Two offenders in one height collided on a nonce.** Both reports were built
  with the node's committed nonce, so the mempool — correctly — held only the
  first, and the second equivocator went unreported. Reports are now numbered
  from the committed nonce, which the mempool accepts as a future nonce.
* **The reporter must be funded.** A validator with no balance cannot pay the fee
  and therefore cannot report, which makes the chain's security depend on
  somebody's bank balance. Validators are funded at genesis for now; the real fix
  is evidence in the block, as Cosmos does it, and that is a block-format change.

---

## 2. A restarted validator can double-sign against itself — **done**

**What is wrong.** Nothing records what this validator has already signed. A node
restarted from a stale store — a rolled-back disk, a restored snapshot, a
mis-copied data directory, an operator running the same key in two places —
replays a height it has already voted on and signs a *different* value for it.
That is equivocation by the honest operator, and with §1 fixed it is now
correctly punished: **the first thing we build makes the second thing fatal.**
They ship together or not at all.

**What the field does.** Tendermint keeps `priv_validator_state.json` holding
the last-signed **height, round and step**, and refuses to sign anything not
strictly greater than it. The file is written **before** the signature is
released. TMKMS moves the same state to a hardware signer. The known failure mode
is the state file and the key file getting out of sync, which is why they should
not have been split.

**What we do.** A `SignGuard` in `crates/node`, holding `(Height, Round, Step)`,
consulted inside `emit_vote` and `start_round` before a signature is produced —
the same place the vote is counted, so there is one door and it is guarded.

- Persisted through a trait (`SignRecord`), for the same reason `BlockSource` is
  a trait: `crates/node` does not learn what a file is. The daemon implements it
  over a small file, `fsync`ed before the signature is returned.
- **Fail closed.** If the guard cannot be written, the node does not sign. A
  validator that cannot record what it signed must not sign; the cost is missed
  blocks, and the alternative cost is the whole stake.
- The state file lives beside the consensus key and is written by `init`, so the
  two cannot get out of sync by being created at different times — Tendermint's
  documented mistake, avoided by construction.

**Cost.** Small, and it is the highest-value small thing in this document.

**Built.** `crates/node/src/signing.rs` holds the rule and an in-memory record —
so a `Node` is never *unguarded* — and `crates/daemon/src/signing.rs` holds the
durable one: temp file, `fsync`, rename, written before the signature is
released. `init` creates it beside the consensus key so the two cannot be copied
apart.

A file that exists and cannot be parsed **stops the node**. The tempting reading
is "no usable record, so assume nothing was signed", and that assumption is
precisely what produces a double-sign.

Verified live: a validator run to height 4 left `4 0 2` on disk, and the restart
logged `last signed height 4 round 0 Precommit` before carrying on.

---

# P1 — An attacker can degrade a node cheaply

## 3. No inbound eviction: forty connections keep everyone else out

**What is wrong.** `max_inbound: 40` is a cap and nothing more. An attacker who
opens forty connections holds every inbound slot until they choose to leave, and
honest peers are refused with `NoRoom`. Refusing inbound *by group* was correctly
rejected as itself a denial-of-service vector — but refusing *everyone* once full
is the same denial with extra steps.

**What the field does.** Bitcoin's `AttemptToEvictConnection`: when full, accept
the new peer and **evict an existing one**, protecting a set chosen so an
attacker cannot predict or occupy it — four peers protected **by netgroup**,
then peers protected by longest uptime allocated evenly across networks, and
never evicting the most recently useful peers. The point is stated explicitly by
the Bitcoin developers: *favour the diversity of peer connections.*

**What we do.** Evict rather than refuse, protecting in this order:

1. **One peer per address group, by longest uptime.** The direct analogue of
   netgroup protection, and it reuses the `AddrGroup` the eclipse defence already
   depends on. An attacker with one subnet can hold exactly one protected slot,
   however many connections they open.
2. **Peers that have served a block**, which an attacker filling slots has not.
   Cheap to track — the sync path already knows.
3. Of the rest, evict the **youngest**, because a connection that just arrived
   has demonstrated nothing and a long-lived one has.

Outbound connections are never evicted: they are the eclipse-relevant ones and
this node chose them.

**Cost.** Moderate, and entirely inside `Manager`, so it is unit-testable without
a socket. The test that matters: *forty attacker connections from one group must
not stop an honest peer from a new group getting in.*

## 4. No anchors: a restart is when an eclipse is cheapest

**What is wrong.** On restart a node dials from its address book, and the book is
rebuilt from a seed list plus whatever is gossiped. An attacker who can influence
that — and an attacker who has been feeding us addresses for hours can — gets a
fresh draw at every one of our outbound slots at the moment we are most
vulnerable.

**What the field does.** Bitcoin PR #17428: persist two outbound peers to
`anchors.dat` on shutdown and **dial them first** on startup, before anything
from the address book. A later change deletes the file after use, so a crash-loop
cannot pin a node to the same peers forever.

**What we do.** The same, sized to our eight outbound slots: persist **two**
outbound peers at shutdown, dial them before the book on startup, and **delete
the file once read**. Two rather than all eight, because anchoring every slot
would mean an attacker who captured us once keeps us; two means an attacker who
did not capture us before the restart cannot capture us during it.

**Cost.** Small. A file, a startup dial, a shutdown write.

## 5. Bans do not decay and do not survive a restart

**What is wrong.** `banned: BTreeSet<PeerId>` lives in one process. A restart
forgives everybody, and nothing ever forgives anybody within a process. Both
directions are wrong: an attacker gets a clean slate for free, and a peer that
was briefly overloaded is exiled forever.

**What we do.** Reputation already decays per-misbehaviour; give the *ban* a
clock too. A ban expires after a bounded period (default: one hour of accumulated
tick time), and bans are **not** persisted across restarts — deliberately, and
this is the one place we depart from Bitcoin's `banlist.dat`. A persisted ban
list is a persisted mistake: a bug in our own scoring, or a peer wrongly punished
during a partition, becomes permanent and unobservable. Anchors already cover the
restart-eclipse case, which is the reason `banlist.dat` exists.

**Cost.** Small.

## 6. No channel priorities: mempool gossip can starve votes

**What is wrong.** One `SyncSender` per peer, FIFO, `OUTBOX_DEPTH: 256`. A node
whose link is saturated by transaction gossip queues its votes behind them. On a
link that costs money by the gigabyte and drops out — exactly the link this chain
is designed for — that is not a corner case, it is Tuesday.

**What the field does.** CometBFT's `MConnection` multiplexes channels over one
TCP connection with per-channel priority, and drains higher-priority channels
first.

**What we do.** Not full multiplexing — that is a wire-format change. Instead
**two queues per peer** and a writer that drains the urgent one first:

- **Urgent:** proposals, votes, and the sync messages that let a node catch up.
  Consensus stops without them.
- **Bulk:** transactions and address gossip. Delay costs latency, not safety.

A bounded queue each, so the bulk queue filling still drops the peer rather than
growing memory. This gets the property that matters — *a node never misses a vote
because somebody was flooding it with payments* — for a fraction of the cost of a
multiplexed connection.

**Cost.** Moderate, confined to `transport.rs` and the outbox.

## 7. No address advertisement: the inbound-reachable set never grows

**What is wrong.** Only peers this node *dialled* enter the address book — the
correct fix for the inbound-source-port defect, and it has a consequence nobody
has paid for yet. A node's listening address becomes known **only** if somebody
already dialled it. Nothing ever tells the network "I am reachable at X". So the
set of dialable nodes is the seed set plus whatever those seeds gossip, forever,
and a node that joins by dialling out is never dialled by anyone.

For this network that is worse than it sounds: it means the topology is
permanently anchored on whoever ran the seeds, which for a chain whose whole
consensus argument is geographic distribution is close to self-defeating.

**What the field does.** Bitcoin's `VERSION` message carries the sender's
`addr_me`, and nodes self-advertise periodically with `ADDR`. The address is
*claimed*, never trusted — it only ever becomes `tried` after somebody
successfully dials it.

**What we do.** The handshake already authenticates an identity; extend it to
carry the peer's **claimed listening address**. That claim goes into the `new`
table only, never `tried`, and is only promoted once this node has itself dialled
it successfully. So the rule that closed the original defect is kept intact —
*an address is only trusted after we have reached it* — while giving the network
a way to learn about a node at all.

A node that does not want to be dialled (behind NAT, or deliberately private)
advertises nothing and is simply never in anyone's book, which is the correct
outcome rather than a broken one.

**Cost.** Moderate: a handshake field, so it is a wire-format change to the
handshake, and it must be `PROTOCOL_VERSION`-gated.

## 8. The seen-set is forgetful

**What is wrong.** 8,192 gossip ids, evicted oldest-first. A patient attacker
replaying just outside the window makes a node relay the same message again. It
is a bandwidth cost rather than a correctness one — consensus ignores what it
already has — but bandwidth is the scarce thing here.

**What we do.** Nothing yet, and say so. The right fix is to key the seen-set by
height and drop whole heights as they commit, which makes "recently enough"
precise instead of a count. It is cheap but it interacts with §6, so it belongs
in the same pass.

---

# P2 — Will stop working at scale

## 9. No retention: the disk grows forever

**What is wrong.** Nothing is ever deleted. Named in
[ADR-0006](adr/0006-state-persistence-and-retention.md) before block sync
existed; block sync made it sharper, because serving history is now something
peers actually ask for and a node that keeps everything is the only node that can
answer.

**What the field does.** XRPL's `online_delete` keeps the most recent ~2,000
ledgers by default; its full history had reached ~39 TB by January 2026. Cosmos
nodes prune all but a rolling window and rely on archive nodes for the rest.

**What we do.** A retention window in the config, defaulting to keeping
everything (so no operator is surprised by data disappearing), with pruning of
blocks, commits and receipts below the window — never of the state tree at the
tip. `NoBlock` already exists as the honest answer for a height we no longer
hold, so the sync protocol needs no change: this is exactly the case it was
written for.

Archive nodes are then a configuration rather than a separate build.

**Cost.** Moderate, in `crates/store`. Needs care: pruning must be atomic with
respect to a concurrent sync request, or a peer gets a block without its commit.

## 10. No state sync: a new node replays from genesis

**What is wrong.** Fine at height 20. Not fine at height 20 million, and the
people who most need to run a node here have the least bandwidth and the slowest
machines.

**What the field does.** CometBFT state sync: a node fetches a **snapshot** of
application state in chunks, verifies it against an `app_hash` from a header it
trusts through the light-client path, and starts near the tip with no history.

**What we do.** We are unusually well placed for this and should say why: the
state tree is already content-addressed (ADR-0006), so a "snapshot" is a root
hash plus the nodes reachable from it, and **every chunk is self-verifying** —
each node hashes to the id it was requested by. There is no need for a separate
chunk-hash manifest, which is the fiddly part of the Cosmos design.

So: `GetStateChunk(root, cursor)` returning a bounded batch of tree nodes, a
receiver that verifies each node against its own hash and refuses anything it did
not ask for, and a trusted `app_hash` obtained by verifying a commit exactly as
`apply_synced` already does.

**Cost.** Large. This is the biggest single item here and it should not be
started until P0 and P1 are done.

## 11. The validator set is frozen at genesis

**What is wrong.** `ValidatorSets::unchanged` is the only thing that ever builds
a header. `staking::active_set()` derives a set from bonds and nothing installs
it. So bonding, unbonding and slashing all work and none of them can change who
validates — which also means §1's jailing removes stake and not the validator.

It has a second consequence: `apply_synced` verifies a commit against the set the
node holds *now*, which is sound only while that set is constant. The moment sets
change, syncing across a change needs what `crates/light` already implements —
verification that walks the set forward.

**What we do.** Epoch rotation: at a fixed block interval, `active_set()` is
computed and installed as `next_validators`, which the header already commits to
([ADR-0010](adr/0010-long-range-attacks.md) built this in). Then `apply_synced`
follows set transitions by the header chain instead of assuming one set.

**Cost.** Large, and it touches consensus, executor, light client and sync at
once. It is the correct thing to do *after* state sync, not before, because
getting it wrong is a chain split rather than a slow node.

---

# P3 — Capability and operability

## 12. No metrics, no structured logging

One line of text to stderr with a millisecond timestamp. Adequate to watch a
devnet; not adequate to operate a validator, and *definitely* not adequate to
debug a partition in a country you are not in. Needs at minimum: height, peer
count, per-peer state, mempool depth, and whether this node is behind — over the
existing HTTP server, since it is already there and already bounded.

## 13. No PEX crawler mode, no compact block relay, no `PartSet` gossip

All real, none urgent. `PartSet` is the one with a security dimension — it makes
the largest thing a peer can ask a node to hold a constant rather than a whole
block — and it is a consensus wire-format change, so it waits for a version bump.

## 14. No ASN bucketing

Prefix grouping does nothing against an adversary who already holds many prefixes
(Erebus). Bitcoin ships an IP-to-ASN map; distributing and agreeing on one is a
data problem we have not solved, and calling a /16 an AS would be worse than
saying we do not do it.

---

# P4 — The testing gap that would have caught most of this

## 15. Nothing tests real nodes doing consensus over real sockets

`sim.rs` attacks agreement with partitions, loss and reordering and **has no
network**. The peer suite attacks the wire and **has no consensus**. Neither asks
the question a testnet asks: *do four nodes on four sockets commit the same block
while an attacker holds one of them eclipsed?*

This is not a nice-to-have and the evidence is in this project's own history:
**two of the last four defects were found by running the binary**, after a suite
of 987 tests passed. Both were in the seam between layers that each suite tests
in isolation — a vote that was counted by the harness and not by the system, and
a commit that was persisted on one path and not the other. That seam is exactly
what a joined harness covers and neither existing suite can.

**What we do.** A `crates/daemon` integration harness that starts N real
`afrolinkd`-shaped nodes on N loopback sockets, runs real consensus over the real
transport, and asserts:

- **agreement** — no two nodes commit different blocks at one height;
- **liveness under a healed partition** — a node cut off falls behind and, once
  reconnected, catches up through block sync to the same state root;
- **a restart rejoins** — a node killed and restarted resumes and reaches the tip;
- **a Byzantine node is punished** — an equivocator's stake is actually slashed,
  which is §1 asserted end to end rather than in a unit test.

Plus a `scripts/stress.sh` that runs the real binaries, drives load, and prints
heights and state roots — because the lesson of this project so far is that the
binary finds what the tests do not.

**This is built first**, before P0, so that every fix below it is validated by it.

**Built**, as `crates/daemon/tests/cluster.rs`, and it earned its place inside an
hour. Four defects, none of which 987 tests had seen:

1. **A driver could make an honest proposer equivocate.** `start_round` built a
   fresh block on every call — new timestamp, new header, new block id — so a
   polling driver signed two values for one `(height, round)`. The node's own
   vote set detected it, withdrew its power, and a three-of-four majority could no
   longer reach quorum: it presented as a liveness bug and was a slashable
   offence. Guarded now the way CometBFT guards `enterNewRound`.
2. **Rounds advanced but were never begun.** `ScheduleTimeout(Propose, r)` meant
   both "wait for someone else's proposal" and "the round moved on" — opposite
   instructions from one action. Split out as `Action::StartRound`. The
   prevote/precommit wait timers were missing entirely, so a round whose prevotes
   divided had nothing left that could end it.
3. **`drop_peer` never closed the socket.** A disconnect the other end cannot
   observe is not a disconnect: the peer kept a thread and a descriptor, and
   neither side would re-establish, so a partition was permanent.
4. **A reset connection was scored `Unforgivable`** — a permanent ban. On links
   where connectivity is assumed intermittent, a node would ban the entire
   network over a bad afternoon.

The first is the one worth dwelling on. It was not a protocol bug; it was in the
loop that drives the protocol, which is exactly the seam no unit test covers and
exactly what this harness exists to reach.

---

# Order of work

| # | Item | Why here | Size | State |
|---|---|---|---|---|
| 15 | Joined harness | Validates everything after it; the thing that catches seam defects | M | **done** |
| 1 | Equivocation evidence end to end | The economic security argument did not run | S | **done** |
| 2 | Double-sign guard | §1 makes an honest operator's mistake fatal; ships with it | S | **done** |
| 3 | Inbound eviction | Cheapest attack on a node's usefulness | M | open |
| 4 | Anchor connections | Restart is when an eclipse is cheapest | S | open |
| 5 | Ban decay | Small, and wrong in both directions today | S | open |
| 7 | Address advertisement | Topology cannot grow past the seeds without it | M | open |
| 6 | Channel priority | Votes must not queue behind payments | M | open |
| 8 | Seen-set by height | Same pass as §6 | S | open |
| 9 | Retention | Before a chain gets long, not after | M | open |
| 12 | Metrics endpoint | Needed to operate anything real | S | open |
| 10 | State sync | Large; needs P0/P1 stable first | L | open |
| 11 | Validator set rotation | Largest; a mistake here is a chain split | L | open |

---

# The verification standard

Every item above is done when **all four** hold, and not before:

1. **Unit tests** for the rule, in a module with no sockets, named for the attack
   they prevent.
2. **A test that fails without the fix** — verified by reverting the fix, not
   assumed. This project has already shipped one test that passed against the
   implementation it existed to catch.
3. **The joined harness passes**, so the fix works across the seam between layers
   rather than only inside one.
4. **A live run of the real binaries** shows the property, and the log agrees with
   the node's own query endpoint. This is the step that found two of the last four
   defects and it is not optional.
