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

## 3. No inbound eviction: forty connections keep everyone else out — **done**

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

**What we did.** Evict rather than refuse. `Manager::eviction_candidate` decides,
and outbound connections are never candidates: they are the eclipse-relevant ones
and this node chose them, so letting a stranger's arrival displace one would hand
that choice back to whoever dialled in.

**The plan above was wrong, and building it is what showed why.** It said to
protect *one peer per address group*. That protects an unbounded number of peers:
a node whose forty inbound slots hold forty distinct groups has forty protected
peers, nothing is ever evictable, and the node is closed to new peers forever —
which is the same denial of service the item was written to fix, reached by the
fix itself. Bitcoin avoids this by protecting a *fixed* four netgroups out of
125, but a fixed number is a number an attacker can count and fill.

So the rule is written in terms of the thing being defended, and needs no
constant at all: **eviction happens only to take back a seat from an
over-represented address group.** If some group holds two or more inbound peers,
the youngest of that group makes way. If every group holds exactly one, nothing is
evicted and the newcomer is refused. A peer that has served a block goes after one
that has not — a tiebreak and never protection, because one block is cheap and
anything an attacker can buy for one block is not a defence.

A first draft went further, evicting whenever the newcomer brought a group the
node did not have, on Bitcoin's reasoning that a new listening node should always
be able to find a slot somewhere. **Running it is what showed that to be wrong
here.** `Transport::dial_out` refills its outbound slots twice a second, so a peer
evicted to make room re-dials immediately and displaces another — a permanent
rotation among honest peers on a *healthy* network, costing a handshake and a TCP
connection each time on links metered by the gigabyte, and destroying the one
thing the rest of the rule treats as evidence: that a long-lived connection means
something. Bitcoin gets away with the aggressive version because its nodes do not
re-dial the way ours do.

**The cost of refusing, recorded rather than hidden.** A network whose nodes are
all saturated stops accepting new inbound peers, so a new node can dial out but is
not itself reachable. That is a real gap, and the answer to it is not eviction: it
is dial-side backoff — a peer that just dropped us should not be re-dialled within
the second — plus address advertisement (§7), so that the set of reachable nodes
grows instead of being fought over. Both are open.

**Verified.** Twelve tests in `crates/p2p/src/manager.rs`, each checked to fail
against a reverted or mutated fix — including two that did *not* discriminate when
first written, and were rewritten until they did. The one that matters is
`forty_connections_from_one_subnet_do_not_keep_an_honest_peer_out`; the one that
matters second is `an_outbound_peer_is_never_evicted_by_a_stranger_dialling_in`.

**What is not verified over sockets, and why.** `crates/p2p/tests/network.rs`
cannot construct an eviction at all: every node in it is on loopback, and the
loopback carve-out in `AddrGroup::of` makes each socket its own group, so two
inbound connections there can never share one. The refusal path is asserted over
real sockets (`a_refused_peer_is_told_rather_than_left_hanging`); the eviction
path is asserted only against routable addresses, in unit tests.

## 4. No anchors: a restart is when an eclipse is cheapest — **done**

**What is wrong.** On restart a node dials from its address book, and the book is
rebuilt from a seed list plus whatever is gossiped. An attacker who can influence
that — and an attacker who has been feeding us addresses for hours can — gets a
fresh draw at every one of our outbound slots at the moment we are most
vulnerable.

**What the field does.** Bitcoin PR #17428: persist two outbound peers to
`anchors.dat` on shutdown and **dial them first** on startup, before anything
from the address book. A later change deletes the file after use, so a crash-loop
cannot pin a node to the same peers forever.

**What we did.** The same, sized to our eight outbound slots: `crates/daemon`
persists **two** outbound peers to `<data-dir>/anchors` at shutdown,
`Manager::seed_anchors` puts them ahead of the address book on startup, and the
file is **deleted the moment it is read** — before any dial — so a crash-loop
cannot be pinned to two peers that may be why it is looping. Two rather than all
eight, because anchoring every slot would mean an attacker who captured us once
keeps us; two means an attacker who did not capture us before the restart cannot
capture us during it.

An anchor is dialled, never trusted: it passes the ban check, the
self-connection check and the group rule like any other candidate, and it is
*consumed* whether or not it turns out to be usable — a dead anchor re-offered on
every pass would spend the whole dial budget. A file that cannot be parsed yields
no anchors rather than refusing to start; unlike the signing record, an anchor is
a hint, and refusing to start over a bad hint turns a hardening measure into an
outage.

**Verified.** `crates/p2p/src/manager.rs` (four tests) and
`crates/daemon/src/anchors.rs` (six), each checked against a reverted fix.

## 5. Bans do not decay and do not survive a restart — **done**

**What is wrong.** `banned: BTreeSet<PeerId>` lives in one process. A restart
forgives everybody, and nothing ever forgives anybody within a process. Both
directions are wrong: an attacker gets a clean slate for free, and a peer that
was briefly overloaded is exiled forever.

**What we did.** `banned` is now a map from peer to the uptime stamp its ban
expires at, denominated in the same tick time every other limit here uses, so it
still reads no clock. `BAN_DURATION` is one hour; an expired entry is swept on
the next tick rather than merely ignored, so the set cannot grow for as long as
an attacker keeps poking.

Bans are still **not** persisted across restarts — deliberately, and this is the
one place we depart from Bitcoin's `banlist.dat`. A persisted ban list is a
persisted mistake: a bug in our own scoring, or a peer wrongly punished during a
partition, becomes permanent and, since nothing here surfaces a ban to an
operator, invisible. The reason `banlist.dat` exists is that a restart is when an
eclipse is cheapest, and §4 answers that directly.

**Verified.** Three tests, checked against a reverted fix.

## 5a. A node stopped the way a service manager stops it did not stop cleanly

Found while verifying §4 against real binaries, and not on the list before that.

The daemon installs a signal handler so it can close its peers, flush its store
and — now — write its anchors. It handled **SIGINT only**, which is what a
terminal sends on Ctrl-C and what nothing in production sends: systemd, Docker
and Kubernetes all send SIGTERM and then SIGKILL a few seconds later. So the
clean-stop path existed, was tested, and was never taken in the one situation it
was written for. A node stopped by its own service manager simply died, leaving
its anchors unwritten and its peers holding connections nobody would close.

The fix is one line — the `termination` feature of `ctrlc` — and it is the same
defect class as the six before it: correct, tested code that nothing reached. It
is recorded here because *how it was found* is the point. No test in this
workspace would have caught it; stopping a running node the way an operator's
tooling stops one did.


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

## 15a. The harness was less capable than the daemon, twice

Both found by chasing one intermittent failure —
`a_node_that_joins_late_reaches_the_tip_from_genesis`, which failed only under
full-workspace parallelism and passed alone. Neither is a defect in the network.
Both are the *inverse* of the §15 hazard: where a simulator more capable than
production hides bugs, a harness **less** capable than production invents them.

**The harness never re-dialled.** `run::drive` calls `Transport::dial_out` every
five seconds, so a peer lost to a full outbox or a read timeout comes back. The
cluster dialled once, at construction, and never again — so under CPU starvation
a node that lost a connection was one peer short for the rest of the run. Fixed
by giving `ClusterNode::step` the daemon's dial timer, and by giving `Cluster` a
`partition`/`heal` pair: a deliberate partition now suspends re-dialling, because
a partition every peer can dial straight through is not a partition.

**The harness threw away the `halted` flag.** `Persist` sets it when a block or a
state root cannot be written, and `run::drive` treats it as fatal — a node that
cannot write its own chain stops rather than voting on a history only it can see.
The cluster passed `halted` to `Persist` and dropped its own handle. A failed
write was therefore *silent*: the node carried on with a store one block behind
its consensus state, and the symptom surfaced much later, and elsewhere, as a
node that would not settle. `quiesce` now fails on it by name.

The general point is the one §15 was written for. A harness earns trust by being
**exactly** as capable as the thing it stands in for — no more, and no less.

# 16. The class itself: correct code that nothing reaches

Seven times now, this workspace has held code that was written, reviewed and
tested, and that no caller ever executed: the address book that recorded
undialable peers, the frame limit that made a legal block unsendable, the node
that did not count its own vote, the persistence orphaned by moving that vote,
the equivocation evidence that was built and dropped, the signal handler that
took the wrong signal — and, in the harness itself, a dropped halt flag and a
missing re-dial. Every one was found by **running the artefact**, never by
adding another test of the kind that already existed.

Fixing them one at a time is not a strategy. This is the pass that goes after
the class, and the three defects that prompted it are the worked examples.

## The research

**Signals.** `ctrlc` handles `SIGINT` only unless the `termination` feature is
on, which adds `SIGTERM` and `SIGHUP`; `signal-hook` is the crate to reach for
when a daemon needs per-signal semantics. The contract the platforms hold us to
is explicit and has numbers in it: `docker stop` waits **10s**, Kubernetes waits
`terminationGracePeriodSeconds` (**30s** by default), `systemd` waits
`TimeoutStopSec` (**90s** by default) — then each sends `SIGKILL`.

**Harness fidelity.** The state of the art is deterministic simulation testing:
FoundationDB, and TigerBeetle after it, make every nondeterministic input
*pluggable* so the simulator drives the real code rather than a model of it.
Antithesis takes the other route — a deterministic hypervisor around unmodified
binaries — precisely because retrofitting the first approach is usually
impractical. CometBFT sits between: `test/e2e` runs the **real node binaries**
under Docker Compose from a testnet manifest.

The general failure mode has a name outside distributed systems too: a test
double that duplicates contract details with no guarantee of fidelity to the
real implementation. Google's testing book and the contract-testing literature
both land in the same place — a double earns trust only from a mechanism that
keeps it aligned, never from having been correct when it was written.

## What we do, and why not the alternatives

**Not madsim or turmoil.** They are the obvious Rust answer and they do not fit:
both are built on `async` and Tokio, and this workspace has neither by
[ADR-0001](adr/0001-sovereign-rust-l1.md). The seam they need also has to reach
below the crate — a library that calls `Instant::now` out of band breaks
determinism regardless — which is why the serious versions end up overriding
libc symbols. We already have the FoundationDB property where it counts, and got
it by design rather than by tooling: `Node` takes time as `Event::Timeout` and
`Manager` takes it as `on_tick(elapsed)`.

**Not a Docker e2e rig.** CometBFT's is the right shape at CometBFT's scale. Ours
would add a container toolchain to a workspace whose whole dependency argument is
that a payments daemon's supply chain is an attack surface.

So: **apply the seam we already believe in one layer higher, and put the entry
point under test.**

### 16.1 One loop, not two

`run::drive` was the loop and `crates/daemon/tests/cluster.rs` had a hand-written
copy of it — the timers, the round bookkeeping, `begin_round`, `schedule`,
`wants_new_round`. Two copies of a loop are two loops, and they drifted: the copy
never re-dialled where the daemon does every five seconds, so a peer lost under
load was gone for the run, and the symptom surfaced far away as an intermittent
sync stall that read as a defect in block sync.

That is the exact inverse of the §15 hazard. A simulator *more* capable than
production hides bugs; a harness *less* capable than production invents them.

`crates/daemon/src/driver.rs` is now the only copy. The clock arrives as
`Driver::step(now, …)` and the periods arrive as `Timings`, so the daemon and the
harness run **the same code** at different speeds — the same treatment `Node` and
`Manager` already had, applied to the layer above them. 102 lines of duplicated
loop deleted.

### 16.2 A halt is in the return type, and `unused_must_use` is denied

`Persist` sets a flag when a write fails and `run::drive` treats it as fatal. The
harness held the same flag and dropped it, so a failed write there was silent.

A convention both callers must remember is a convention one of them will forget.
`Driver::step` now returns `Result<Beat, Halted>`, and `unused_must_use = "deny"`
is set for the workspace — so a caller that drives a node without confronting the
one condition that means it must stop **does not compile**. Verified by writing
that caller and watching the build fail.

### 16.3 The entry point is under test

`crates/daemon/tests/shutdown.rs` spawns the **real binary**, lets it commit
blocks, signals it the way a service manager would, and asserts on what an
operator would see: exit status, the clean-stop log lines, a bounded stop time,
and — because asserting the words alone would pass against a shutdown that
printed them and flushed nothing — that a restart resumes from the state tree
rather than replaying genesis.

This is the cheap version of CometBFT's `test/e2e`, and it is the generalisation
of all seven defects: **the entry point is tested, not only the library behind
it.** Two of its four tests fail against the original `SIGINT`-only handler,
verified by reverting the feature flag.

### 16.4 Stopping is bounded

`StopWatchdog` bounds the stop sequence at 8s — inside `docker stop`'s ten, the
tightest of the three contracts. A shutdown slower than that has lost the work it
was trying to finish anyway, and an exit we choose can say why in the log where a
`SIGKILL` cannot.

Its firing path ends in `process::exit`, so it cannot be exercised in-process.
The *other* direction is covered and it is the dangerous one: a watchdog that
fired on a healthy shutdown would kill good nodes.

## What is honestly not verified

The re-dial fix is **not** covered by a deterministic test. Removing it again
leaves the cluster suite green in isolation, because the failure it prevents only
appears under CPU contention. The evidence for it is empirical and reproducible
rather than assertional: under full-workspace parallelism the cluster suite went
from 67s and failing to 23s and passing, and the same failure reproduced
identically on the tree before any of this work. Recorded as such rather than
claimed as tested.

---

# 17. A late joiner stalls one block short — **fixed**

A node that joined late reached a height one or two short of the validators and
stayed there, with peers connected and `is_behind()` true.

**Found by making the failure explain itself.** Printing the scheduler's state
every tick slowed the loop enough that the bug stopped happening — six runs in a
row passed. Pulling the same state *on failure* instead cost nothing and
reproduced it on the first run. `Manager::sync_snapshot` exists for that, and the
line it printed was the whole diagnosis:

```
node 9: need=7 best=Some(8) behind=true staged=[7, 8] peers=[... score=40 | score=40 | score=40 | score=25]
```

**The blocks it was waiting for were already in its own staging buffer.**

**Root cause.** `drain_staged` had exactly one caller, inside `on_block`, so a
staged block was only ever released by the arrival of *another* block. Every
other way the height moves — `set_height`, called after every apply, succeeded or
failed — left applicable blocks sitting in the buffer. And `schedule_sync` counts
staged heights as already claimed, so it asked for nothing, so nothing arrived,
so `on_block` never ran again. A node holding the blocks it needed, waiting
forever for a message that could not come.

**Fixed** by draining on the tick, so release depends on the height being right —
the actual condition — rather than on a message happening to arrive.

**The second defect in the same line.** Those peer scores of 40 were honest peers
five points of misbehaviour from a ban. A request abandoned on timeout is handed
to somebody else, and the original peer's reply then lands against a cleared
slot, scoring `BadBlock` — twenty points, five of them a ban. A node stuck on the
above re-asked repeatedly and drove all four of its peers to 40: three answers
short of banning the only nodes it could have caught up from, for the offence of
being slow on links this network *assumes* are slow.

Fixed narrowly. A timed-out request is remembered as `abandoned`, and only that
exact height from that exact peer is forgiven, once. The rule that a peer must
not get to choose which heights this node holds in memory is untouched — the two
tests stating it still pass, and both fixes were verified by reverting them.

# 18. A node's published state can lag the block it has committed — **open**

Found by the load test in the same pass, and **separate** from the ordering guard
in `Persist` (which is fixed, and which reverting does not make this go away).

**What happens.** After the chain settles, a node's durable store holds block N
and its state root, while the `published` state the query server answers from is
still at N−1. Observed on all four nodes at once, with `halted=None`, so no write
failed:

```
node 1: node-state e2da9c6b published e65077bc stored-tip e2da9c6b h=13 stored=13 halted=None
sink saw [1:… 12:got=e65077bc want=e65077bc]     <- and never height 13
```

Every entry the sink recorded matches its block's `app_hash` exactly, so nothing
is corrupt: block 13 simply never reached `Persist::committed`, while its
`put_block` plainly did. That combination is not yet explained.

**Why it matters.** `published` is what a wallet's balance query is answered
from. A node in this state serves an answer one block stale, indefinitely, while
looking healthy from every other angle — its store is correct, its peers agree,
and it keeps committing.

**Why the load test no longer fails on it.** Because it was asking the wrong
question through the wrong door: "did the ledger move the money" is a question
about the store, and it was being asked of a cache. It now reads the ledger, and
`Cluster::published_vs_decided` reports the divergence as its own concern rather
than as an arithmetic error.

**Next step.** Record an entry on *entry* to `Persist::committed`, not only after
both writes, to establish whether the call happens at all for the missing height.

---

# Order of work

| # | Item | Why here | Size | State |
|---|---|---|---|---|
| 15 | Joined harness | Validates everything after it; the thing that catches seam defects | M | **done** |
| 1 | Equivocation evidence end to end | The economic security argument did not run | S | **done** |
| 2 | Double-sign guard | §1 makes an honest operator's mistake fatal; ships with it | S | **done** |
| 3 | Inbound eviction | Cheapest attack on a node's usefulness | M | **done** |
| 4 | Anchor connections | Restart is when an eclipse is cheapest | S | **done** |
| 5 | Ban decay | Small, and wrong in both directions today | S | **done** |
| 7 | Address advertisement | Topology cannot grow past the seeds without it | M | open |
| 6 | Channel priority | Votes must not queue behind payments | M | open |
| 8 | Seen-set by height | Same pass as §6 | S | open |
| 9 | Retention | Before a chain gets long, not after | M | open |
| 12 | Metrics endpoint | Needed to operate anything real | S | open |
| 10 | State sync | Large; needs P0/P1 stable first | L | open |
| 11 | Validator set rotation | Largest; a mistake here is a chain split | L | open |
| 16 | The defect class itself | Seven instances; one loop, a halt in the type, the entry point under test | M | **done** |
| 17 | Late-joiner sync stall | Staged blocks never drained; honest peers punished | S | **done** |
| 18 | Published state lags the store | Queries answered one block stale | ? | **open** |

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
