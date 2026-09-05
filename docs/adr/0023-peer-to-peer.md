# ADR-0023 — Peer-to-peer networking

- **Status:** accepted
- **Date:** 2026-09-02
- **Relates to:** [ADR-0002](0002-consensus.md) (the geographic rule this borrows
  for peers), [ADR-0007](0007-distribution-and-sybil-resistance.md) (counting
  groups rather than addresses), [ADR-0010](0010-long-range-attacks.md) (what an
  eclipsed light client can be shown), [ADR-0013](0013-http-transport.md) (the
  same thread-per-connection model, and why the client surface came first),
  `crates/p2p`, `crates/fuzz/tests/p2p.rs`

## Context

**Nodes could not talk to each other.**

`Node::handle` had produced `Action::BroadcastProposal`, `Action::BroadcastVote`
and `Action::BroadcastTransaction` since the consensus driver was written. Every
one of them was returned to a caller that dropped it on the floor, because the
only caller outside the deterministic simulator was a test. The one TCP listener
in the workspace was `crates/http`, which serves *clients*.

So the chain worked, and there was exactly one machine on it. Everything that
depends on more than one — downtime slashing, epoch rotation, witness-log
transport, the off-chain resolver, any testnet at all — was blocked behind this.

It is also the largest single security surface the project has added. A peer
transport is the first thing an anonymous stranger reaches: before a signature is
checked, before a proof is verified, before the node has any idea who is talking.

## Decisions

### 1. The policy has no sockets in it, and the sockets decide nothing

`crates/p2p` splits the way `crates/http` splits at `respond` and `crates/node`
splits at `Node::handle`:

| Pure | I/O |
|---|---|
| `handshake`, `secret`, `wire`, `addrbook`, `peer`, `manager` | `transport` |
| 67 unit tests, no port bound | 12 tests over real loopback TCP |

`Manager` is a pure function of `(state, event) → directives`. Time arrives as
`on_tick`, exactly as it arrives at `Node` as `Event::Timeout`. So an eclipse
attempt, a gossip storm and a flooding peer are unit tests rather than flaky
integration runs, and the module that binds ports has almost no logic left to be
wrong about.

This also keeps **`crates/node` synchronous**, which is what makes the
deterministic Byzantine simulator possible. Reaching for an async runtime here
would have cost that, and it is the single most valuable testing asset the
project has.

Threads, not futures: two blocking threads per peer over a cloned `TcpStream`.
A validator holds tens of peers, not tens of thousands of idle sockets, and the
expensive work on this path is verifying signatures and re-executing blocks —
CPU, not waiting. Same reasoning as [ADR-0013](0013-http-transport.md), and the
dependency tree does not grow by two orders of magnitude to open a socket.

### 2. The channel is encrypted and mutually authenticated

Station-to-station: an ephemeral X25519 exchange, then each side signs the
**transcript** with its long-term key. ChaCha20-Poly1305, one key per direction,
a 64-bit counter that closes the connection rather than wrapping. It is
Tendermint's Secret Connection, including the fix it needed.

**The bug being avoided, named.** Tendermint 0.32 and earlier were vulnerable to
ephemeral-key malleability: *"if the connection is intercepted and an ephemeral
key consisting of all zeros is injected then the secret from `computeDHSecret`
will be the same for both parties for every handshake with any key"* — both sides
derive a secret the attacker also knows. Two defences, and this has both:

1. **The shared secret must be contributory.** Every low-order point is refused
   at the exchange, not after. `every_low_order_ephemeral_key_is_refused` walks
   the full Curve25519 blacklist, because refusing only the all-zero key would
   leave the same bug reachable by six other spellings.
2. **The transcript covers both ephemeral keys, sorted.** Sorting is what makes
   it one agreed value rather than one each side computes its own way. It is
   exactly the fix Tendermint applied, expressed with BLAKE3 rather than Merlin
   because this codebase already hashes everything that way.

The transcript also covers the **chain id**, and that turns out to be stronger
than it sounds: the chain id feeds the *key derivation*, not only the signature,
so a peer from another chain cannot even decrypt our identity frame. There is
nothing left for it to check a signature on.

**Why encrypt a public ledger at all.** Not confidentiality of content —
everything gossiped is public and signed and will be in a block within a second.
Three other things, which are why Bitcoin adopted BIP324 after fifteen years
without it: the channel is *authenticated*, so dialling a node id means
something; it is *tamper-evident*, so an on-path ISP can drop packets but not
edit them; and it resists *topology mapping*, which is the reconnaissance step of
an eclipse attack. Identities travel inside the encrypted channel, so a packet
capture shows two ephemeral keys and no idea whose.

### 3. Identity is a key of its own

A `PeerId` is a node's long-term Ed25519 public key — not an account address and
not a validator's consensus key. Running a relay should not require holding money
or signing votes.

The key itself rather than a hash of it, because the handshake verifies a
signature from it anyway. A shortened id would add a lookup, and a lookup is a
place for a node to be confused about who it is talking to.

### 4. Eclipse resistance, in four rules that each do separate work

An [eclipse attack][heilman] breaks no cryptography. It fills a victim's address
book, waits for a restart, and then owns every connection the victim makes. From
inside one, a validator can be shown a partial view, fed a stale height, or
partitioned from the two thirds it needs — and every message it receives is
perfectly well signed. Heilman et al. did it to Bitcoin with a few thousand
addresses. The defences Bitcoin adopted afterwards are the ones here, because
they are the ones that worked.

1. **Addresses are bucketed by the group that told us**, through Bitcoin Core's
   two-hash construction. One source group reaches at most 32 of 256 new buckets,
   so filling the table costs address *diversity* — which costs money and
   relationships — rather than address *count*, which costs nothing.
2. **Bucket placement is salted from the node's own secret key.** Without it an
   attacker computes offline exactly which addresses collide and crafts the
   cheapest possible flood. Deriving it deterministically also means the layout
   survives a restart, so a node does not forget the network every upgrade.
3. **Tried and new are separate**, and only a completed handshake reaches tried.
   Flooding costs a sentence; answering costs a real reachable host.
4. **No two outbound connections into one group.** The rule that makes the other
   three matter: a subnet holding ten thousand addresses is worth exactly one of
   a node's eight outbound slots.

`an_attacker_holding_one_subnet_gets_one_outbound_slot` is that property as a
test — ten thousand attacker addresses against eight honest ones — and it asserts
both halves: the attacker takes at most one slot, *and* the node still fills its
others. A diversity rule that leaves a node unable to connect is not a defence.

**And a fifth rule that fell out of writing it.** Only a peer this node
*dialled* enters the address book. An inbound connection announces its ephemeral
source port, which dials nothing; recording it would fill the tried table with
addresses nobody can reach and then recommend them to everyone who asks. Closing
that also closes a class of poisoning: an attacker cannot reach a node's gossip
sample by connecting to it. They have to be reachable, and the node has to have
chosen to reach them.

### 5. Gossip that cannot eat the network

**Relayed once**, keyed on the canonical encoding — which is why the codec
refusing second spellings matters here and not only in a block: two encodings of
one vote would be two ids, and a node would relay both. **Never back to the
sender.** **A per-tick message budget**, counted rather than timed, so the policy
has no clock in it; a peer that will not slow down is scored down and dropped.

Transactions are the exception that proves the design: the manager does *not*
relay them. `Node` emits a broadcast action only for a transaction it **newly
accepted**, which is what stops one submission becoming a storm — so the decision
belongs there, and repeating it here would relay transactions the node refused.

### 6. Every bound is checked before the allocation it protects

A frame's length is in the clear, because a reader must know how many bytes to
take before it can decrypt anything, and it is **authenticated as associated
data** — an on-path attacker who rewrites it gets a failed tag and a dead
connection, not a reader hunting the wrong number of bytes. TLS record headers
are in the clear for the same reason.

The limit is checked *before* the `Vec` is allocated. Reading a length,
allocating, and then discovering the peer lied is the oldest bug in network code,
and `a_frame_header_alone_never_causes_an_allocation` is the test that says so.

Each peer's outbox is a bounded channel; a peer that stops reading fills its own
queue and is dropped. Slowness is indistinguishable from an attack here, and
treating them the same is the safe direction — a slow peer reconnects, a node out
of memory does not.

### 7. What is deliberately not here

**No block sync.** There is no `GetBlock`, so a node that falls behind cannot
catch up and a restarted node cannot rejoin a running chain. This is the biggest
remaining gap and it is the next thing to build, not an oversight: catch-up needs
a request/response pattern with its own bounds, its own scoring, and a decision
about serving from the durable store rather than from memory.

**No seed or crawler mode.** A node bootstraps from addresses an operator gives
it. Seed nodes are the standard answer and need block sync first, since a seed
that cannot serve history is a phone book with no numbers in it.

**No ASN-aware bucketing.** Groups are `/16` and `/32`. The [Erebus
attack][erebus] is mounted by an adversary that already holds many prefixes, and
grouping by prefix does nothing against it. Bitcoin's answer is a shipped
IP-to-ASN map; that is a data-distribution problem this project has not solved,
and pretending a /16 is an AS would be worse than saying so.

**No fixed-size frames.** Message sizes are visible, so an observer can tell a
block from a vote by length. Tendermint pads to hide it; the cost is bandwidth on
exactly the links that have least of it, which is not a trade this network should
make by default.

**No anchor connections, no NAT traversal, no rekeying, no compact blocks.** Each
is a real improvement and none is load-bearing yet.

## Consequences

**Good.** Two nodes on two sockets exchange a transaction, and a third receives
it relayed through the second without the first ever talking to it. The handshake
refuses a wrong identity, another chain, itself, and every low-order point. A
node survives HTTP requests, random bytes and silence on its peer port without
panicking, hanging, or registering a peer. `crates/fuzz/tests/p2p.rs` throws
around 12 000 hostile inputs at the surface an anonymous stranger reaches first.

The consensus driver did not change at all. That is the strongest evidence the
seam was drawn in the right place: a whole network layer arrived and `Node` never
learned what a peer is.

**Bad, and worth being clear about.**

- **No node binary exists.** Nothing in this workspace is a daemon; every
  transport, including the HTTP one, is driven by tests. The p2p layer is
  reachable from a caller, and that caller is `cargo test`. Assembling a node —
  a genesis file, a store, a transport, a timer loop and a signal handler — is a
  separate piece of work and it is now the one thing standing between this
  project and a testnet.
- **The 12 integration tests use loopback**, where every socket is its own group
  by an explicit carve-out. The eclipse rule itself is asserted against routable
  addresses in the manager's own tests, because on `127.0.0.0/8` it cannot be:
  treating loopback as one group would stop a devnet forming its second
  connection. The carve-out is documented at the one place it applies and does
  not touch routable addresses, where the port is ignored precisely so an
  attacker cannot buy diversity by opening ports.
- **Peers are trusted equally.** There is no distinction between a validator and
  a relay, no preference for peers that have served us well, and no
  prioritisation of consensus traffic over transaction gossip. CometBFT
  multiplexes channels with per-channel priority for exactly this reason, and a
  node here whose bandwidth is saturated by mempool traffic will miss votes.
- **A ban is per identity and lasts as long as the process.** There is no
  persistence, no decay, and no eviction policy for inbound peers beyond the cap
  — so an attacker who can open forty connections can keep honest peers out.
  Bitcoin evicts inbound peers preferring group diversity; that is the right fix
  and it is not written.
- **The seen-set is bounded and therefore forgetful.** A message older than 8 192
  gossip ids can be relayed again. That is a bandwidth cost, not a correctness
  one — consensus ignores what it already has — but a patient attacker can
  amplify by replaying just outside the window.

## Closed by

- **Block sync and the node binary** — both gaps named above are closed by
  [ADR-0024](0024-block-sync-and-the-node-binary.md). Building them found two
  defects in the work recorded here: `MAX_FRAME_LEN` and `MAX_BLOCK_BYTES` were
  equal, so a block at the consensus limit could be proposed and never sent; and
  the transport never fed a node's own votes back into its own vote set, which is
  invisible on four validators and fatal on one.

## Revisit if

- **Block sync arrives** — it has, in
  [ADR-0024](0024-block-sync-and-the-node-binary.md), and it did add the first
  request/response pattern to this protocol
- **A testnet runs on real addresses**, at which point the loopback carve-out
  stops being exercised and ASN bucketing starts mattering
- **Bandwidth becomes the binding constraint**, which is when channel priorities
  and compact block relay earn their complexity
- **A regulator or an operator needs a node behind NAT to be a full participant**.
  Address advertisement is now built — the handshake carries the sender's claimed
  listening address, into the `new` table only, and `advertise` in the config is
  what a node behind NAT sets ([10 §7](../10-network-hardening.md)). Hole
  punching, for a node that cannot be reached at *any* address, is not

## Sources

- [Eclipse Attacks on Bitcoin's Peer-to-Peer Network][heilman], Heilman,
  Kendler, Zohar and Goldberg, USENIX Security 2015 — the attack, and the
  measurement that made address-book design a security question
- [Addrman and eclipse attacks](https://github.com/bitcoin-core/bitcoin-devwiki/wiki/Addrman-and-eclipse-attacks)
  — the tried/new tables, the source-group bucketing, and the numbers behind them
- [Bitcoin Core PR 16702, asmap](https://github.com/bitcoin/bitcoin/pull/16702)
  — ASN bucketing, and the honest note that ASNs can be announced without
  verification, so it raises the cost of Erebus rather than closing it
- [The Erebus attack][erebus] — a network-level adversary that prefix grouping
  does not address
- [Tendermint Secure P2P](https://docs.tendermint.com/v0.33/tendermint-core/secure-p2p.html)
  and [issue 3010](https://github.com/tendermint/tendermint/issues/3010) — the
  Secret Connection, the ephemeral-key malleability bug, and the sorted-transcript
  fix
- [CometBFT MConnection](https://docs.cometbft.com/v0.38/spec/p2p/legacy-docs/connection)
  — channel multiplexing with per-channel priority, which this does not do yet
- [BIP324](https://github.com/bitcoin/bips/blob/master/bip-0324.mediawiki) —
  encrypted peer transport for Bitcoin, and the argument for encrypting a public
  ledger's gossip

[heilman]: https://dl.acm.org/doi/10.5555/2831143.2831152
[erebus]: https://erebus-attack.comp.nus.edu.sg/
