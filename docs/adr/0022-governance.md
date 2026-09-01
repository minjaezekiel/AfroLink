# ADR-0022 — Governance: two tracks, and the line between them

- **Status:** accepted
- **Date:** 2026-09-01
- **Relates to:** [ADR-0002](0002-consensus.md) (the geographic rule this applies
  to governance), [ADR-0010](0010-long-range-attacks.md) (the floor that keeps a
  vote from disarming the light client), [ADR-0020](0020-sovereign-issuance.md)
  and [ADR-0021](0021-licensing-attestors.md) (both named this gap and declined
  to close it in passing), [ADR-0017](0017-key-rotation-and-signer-lists.md)
  (why a lost authority key is an account problem, not a governance problem),
  `crates/gov`, `crates/executor/tests/governance.rs`

## Context

**Every trusted role on this chain was fixed at genesis and could not be
rotated, added or revoked.**

- An issuer authority whose key was lost stayed lost. Nothing could ever mint
  that currency, unpause it, or name a minter again.
- An attestor whose regulator withdrew its licence stayed licensed on-chain.
  `Attestor::active` existed, was documented as governance's to set, and had no
  writer.
- A currency not named in the genesis file could never join the network.
- Every parameter was a `const`. Changing the unbonding period, the rebinding
  delay, or the minimum bond meant a flag day — every node in every corridor
  upgrading at the same moment, or the chain splits. That is the failure
  [ADR-0009](0009-developer-payment-surface.md) §2 already rules out for the
  runtime, and it applies just as much to the numbers the runtime reads.
- `Namespace::Params = 0x07` was declared in `crates/state` and read and written
  by nothing.

Both ADR-0020 and ADR-0021 named this and stopped, on the grounds that inventing
an authority in passing would be worse than naming the gap. This closes it
deliberately.

## Decisions

### 1. Governance is two tracks, and the money is on neither

This is the decision the rest follows from.

| | **Network track** | **Sovereign track** |
|---|---|---|
| Decides | parameters, attestor licences, admitting a new currency, the council's own composition | a currency's minters, cap, freezer, pause, and who holds its authority |
| Who | the council, at two thirds | that currency's authority, alone |
| Delay | a voting period, then a timelock | none — the acceptance is the check |
| Where | `crates/gov` | `crates/bank` |

**The council cannot touch money.** It cannot mint, burn, freeze, spend, slash,
or adjust a balance. It cannot replace the authority of a currency already
admitted — it may only *admit* a denomination the chain has never seen, because
a denomination nobody has registered has no sovereign to ask. Once admitted, the
currency governs itself and the council is done with it.

The reason is not modesty about governance. It is what makes the chain usable by
a central bank at all. On BIS's **mBridge** — a shared ledger operated jointly by
five central banks — *each central bank is the exclusive issuer and redeemer of
its own CBDC*, and only its own domestic banks may request issuance, while the
platform's rules come from a separate steering committee with its own rulebook.
Same split, same reason. A sovereign will not settle on rails where a vote taken
elsewhere can reach its money.

`Action` is exhaustive and six items long, with no `Action::Custom` and no
encoded call. That is a deliberate departure from how on-chain governance is
usually built: Polkadot governance dispatches a runtime `Call`, and Cosmos
executes any message the module holds authority over — in both, the answer to
*"what can governance do?"* is *"anything the chain can do."* Here, adding a
seventh power is a code change that has to be argued for, not a proposal that has
to be noticed.

### 2. A seated council, weighted, with a jurisdiction cap — and an honest reason

The obvious answer is stake-weighted voting. It is the wrong one *here* and
*now*, for two separate reasons.

**Timing.** A token vote at launch, when the founders hold almost everything, is
a vote whose outcome is known in advance. Polkadot ran a Council and a Technical
Committee for years and moved to fully open, stake-weighted OpenGov only once
there was a distribution to vote with. Pretending to skip that stage does not
skip it; it hides it.

**Subject matter.** The governable questions here include *which institution may
attest a national identity* and *which currency joins the network*. Those are
licensing questions, answered in the world by regulators, and settling them by
"whoever bought the most AFRI" would be a worse answer than the one every
jurisdiction already has. Cosmos shows the failure mode plainly: low turnout
makes a coordinated minority decisive, and apathy concentrates power rather than
spreading it.

So: a seated council now, its composition itself governed, and an explicit path
to open it later — written down here rather than left implied.

Two numbers do the work:

- **Threshold ≥ 6667 bps** (two thirds, the consensus quorum). A simple majority
  would let half the weight plus one seat change the rules the other half relies
  on, and this body licenses attestors and admits currencies.
- **No jurisdiction above 3333 bps** of council weight, on mainnet.

Together they give the property worth having: **no single country can block, and
no two countries can decide.** Blocking a two-thirds threshold takes strictly
more than a third; a third is the most any country may hold. Two caps sum to at
most two thirds minus the rounding, which does not reach the threshold.

It is the [ADR-0002](0002-consensus.md) geographic rule applied to the body that
governs the validators. A network whose consensus cannot be captured by one
jurisdiction, but whose governance can, is capturable by one jurisdiction.

The concentration measure **rounds up**, and that is not a detail. Rounded down,
a country holding exactly a third reports 3333 and passes a cap of 3333 — while
in fact holding enough to block. A concentration measure rounded down flatters
the thing it measures.

### 3. A timelock, because a decision needs to be seen before it binds

A proposal that reaches the threshold is not executed. It is *scheduled*, and may
be carried out only after `timelock_blocks`. Execution is then **permissionless**,
exactly like `ApplyRebind` and for the same reason: the vote is taken and the
delay has run, so the outcome is settled, and whoever pays the fee to finish it
changes nothing about it. Requiring a seat would leave a decided question
unexecuted forever if the council moved on, or if the seat that would have sent
it was removed in the meantime.

The timelock is **notice, not deliberation**. By the time it starts the council
has decided; the delay exists so everyone who has to live with the decision — an
exchange, a wallet, an issuer, a regulator — learns about it while it is still
reversible. It is the standard argument for a governance timelock and the reason
OpenZeppelin ships one: it *"allows users to exit the system if they disagree
with a decision before it is executed."*

**A withdrawal is the one thing that skips the timelock.** `Action::Cancel`
clears the same two-thirds bar and then applies at once, because withdrawing a
change is a return to the state everyone already expects and there is nothing to
give notice of. Without that exception a cancellation would have to wait out its
own timelock and would always arrive too late.

It is a vote and not a guardian key, deliberately. A key that can cancel any
queued proposal is a key that can deny governance entirely — which is why
OpenZeppelin warns against granting the canceller role to anyone besides the
governor itself.

### 4. There is no vote against

A seat that does not want a proposal declines to vote, and it lapses at the end
of its voting period. The same shape a savings group's quorum takes in
`crates/types/src/group.rs`: with a threshold to clear and a deadline to clear it
by, silence already means no.

The tally reads the council **as it stands**, not as it stood when the proposal
opened. Any other reading makes removing a compromised seat pointless — its votes
would keep landing on every proposal opened before it left.

### 5. A parameter without a floor is not a parameter

`ChainParams` holds every number governance may change, and `validate` refuses
values that would disarm something the chain depends on. Two floors are
load-bearing:

- **`staking.unbonding_ms` may never fall below `UNBONDING_MS`.** A light client
  derives its trusting period from that constant *at compile time*. Voting the
  chain's unbonding period below it would leave every deployed client trusting
  headers signed by validators whose stake is already withdrawn and unslashable —
  the long-range attack [ADR-0010](0010-long-range-attacks.md) exists to prevent,
  arrived at by vote rather than by force. This was found while writing this ADR,
  and it is the reason the floors exist at all rather than being a tidy idea.
- **`rebind_delay_blocks` may never fall below `MIN_REBIND_DELAY_BLOCKS`.** The
  delay *is* the SIM-swap defence of [ADR-0008](0008-human-readable-addressing.md).
  At zero, a rebind requested by a compromised attestor lands before the owner
  can look at their phone.

The rest keep the chain able to function: an active set below four cannot
tolerate a fault (`n ≥ 3f + 1`), a candidate list shorter than the set it fills
cannot fill it, a voting period below an hour can pass a proposal before seats in
other time zones have seen it exists.

One rule is a **ratchet** rather than a floor: `max_council_country_share_bps`
may be tightened and never loosened. A cap the capped party can widen is not a
cap — it is a promise to everyone who is *not* on the council, and a promise the
promiser can revoke is not a promise. Same rule, same shape, as
`Issuer::tighten_cap`.

And tightening it cannot unseat the council that voted for it: `set_params`
re-checks the sitting body against the new cap. Otherwise the vote that narrows
the cap is the vote that leaves the chain governed by a council its own rules
reject.

### 6. A currency's authority moves in two steps, both signed

`TransferIssuerAuthority` offers the role; `AcceptIssuerAuthority` takes it up.
Nothing changes in between, and `None` withdraws a standing offer.

A one-step transfer to a mistyped address, or to one whose key nobody holds, ends
a currency's governance permanently. The acceptance is the proof that a key
exists on the other end. OpenZeppelin's `Ownable2Step` exists for exactly this
mistake, and clearing the offer works the same way there.

**And the answer to "what if the authority key is lost?" is not governance.** An
authority is an `Address`, and an account already carries a regular key, a
master-key disable, and an M-of-N signer list
([ADR-0017](0017-key-rotation-and-signer-lists.md)). A central bank's authority
should be an M-of-N account. That is why the field is an address and not a public
key, and it is a better answer than a council that could vote a currency into new
hands.

### 7. Parameters that are voted on are parameters that take effect

Every staking path now opens the module with `Staking::with_params(store, …)`
read from state, and a rebinding delay comes from `ChainParams` rather than the
constant. This is not tidiness. **A value written to state and read by nothing is
the same defect as correct code reachable from no transaction** — the pattern
[ADR-0021](0021-licensing-attestors.md) named after meeting it three times. A
governance module whose parameters were stored and ignored would have been the
fourth.

The test for it asserts the *effect*, not the storage: a council votes the
rebinding delay longer, and the next rebinding the chain schedules lands at the
new distance.

### 8. Genesis must seat a council

`Genesis.council` is not optional, and `Council::new` refuses an empty body, so
the type carries the rule. A chain launching without governance has every trusted
role fixed forever, which is the state this ADR exists to end.

`GenesisLimits` checks the council the way it already checks the validator set:
mainnet requires the 3333 cap, devnet allows one seat in one jurisdiction. A
devnet council is seated under `CountryCode::UNSPECIFIED` — `zz`, the ISO 3166
user-assigned code — because the single operator is not standing in for a
jurisdiction, and because a placeholder that is not reserved is a placeholder
that collides with a real country later.

## Consequences

**Good.** Attestors can be licensed and suspended. Currencies can join a running
network. Parameters can be tuned without a flag day. A currency's authority can
be handed on safely. And the properties that matter are enforced rather than
documented: a jurisdiction cannot capture the council, a vote cannot shorten the
unbonding period below what light clients assume, a decision cannot take effect
without notice, and no proposal of any shape can move a shilling.

`Attestor::active` and `Namespace::Params` both finally have writers.
`StakingParams` moved to `crates/gov` — a number the network votes on is a value
shared between modules, not a private detail of the one module that reads it,
which is the same move `CountryCode` made in ADR-0021.

The property suite grew a governance run at governance's own timescale, with its
own coverage guard. At one height per block a voting period never closes and a
timelock never runs, so every governance invariant would hold vacuously — which is
precisely the failure the money-path guard was added to catch. It insists that
`ExecuteGovAction` actually applied.

**Bad, and worth being clear about.**

- **The founding council is whoever writes the genesis file.** This design makes
  that body accountable, bounded and replaceable; it does not make it legitimate.
  Legitimacy comes from who is actually seated, and that is a decision outside
  the code.
- **A two-thirds council can do everything a two-thirds council can do.** The
  timelock gives notice, and a withdrawal needs the same two thirds — so against
  a genuinely captured supermajority, neither helps. What they defend against is
  a mistake, and a body that changes its mind once the reaction arrives, which is
  what a cancellation path is used for in practice.
- **Nothing removes a currency once admitted.** A rogue authority can pause its
  own denomination and freeze its own holders; it can reach nothing else. The
  scoped-freeze design bounds the damage, but delisting is not expressible and is
  deliberately deferred rather than improvised.
- **Voting is not delegated and not private.** Every seat votes for itself, and
  votes are public the moment they land.
- **A scheduled proposal never expires.** Lapsed proposals are swept, but a
  passed one waits indefinitely for someone to execute it. Bounded by
  `MAX_OPEN_PROPOSALS`, and cheap to finish, but it is a queue slot nobody has to
  reclaim.
- **`SetParams` is absolute.** Safe *here* because this codec refuses trailing
  bytes, so a node on an older binary cannot decode a `ChainParams` carrying a
  field it has never heard of — it fails loudly rather than silently reverting
  that field to a default, which is the failure the one-flag-at-a-time argument
  in `SetAccountFlag` is about. A new parameter is a hard fork, and it announces
  itself as one.

## Revisit if

- **There is a real token distribution to vote with.** That is the moment to open
  the network track — Polkadot's arc, deliberately. The shape would be
  stake-weighted referenda over the same `Action` enum, with the council retained
  for licensing questions or retired entirely.
- **A regulator requires a withdrawn licence to take effect within a fixed
  window**, which would make the timelock on `SetAttestorActive` a problem rather
  than a feature and argue for an emergency track.
- **Delisting a currency becomes necessary**, at which point the question is what
  happens to holders of a denomination the network stops accepting — which is a
  harder question than the mechanism.
- **The council reaches the size where per-seat voting is the bottleneck**, which
  is what delegation exists for elsewhere.

## Sources

- [Project mBridge, Bank for International Settlements](https://www.bis.org/project/mbridge)
  — a shared multi-CBDC platform where *each central bank is the exclusive
  issuer/redeemer of its CBDC*, only domestic banks may request issuance, and a
  separate steering committee sets the platform's own rules. The two-track split
  in §1 is this arrangement expressed in message types
- [Polkadot OpenGov](https://docs.polkadot.com/reference/governance/) — replaced
  the Council and Technical Committee once a distribution existed to vote with,
  citing slowness and centralisation; the Fellowship that replaced the Technical
  Committee holds no hard power and *"cannot change parameters or move assets"*
- [Cosmos SDK `x/gov`](https://docs.cosmos.network/sdk/latest/modules/gov/README)
  — quorum, threshold and `NoWithVeto`, and the documented failure mode: low
  turnout makes a coordinated group decisive, and apathy concentrates power
- [OpenZeppelin `Ownable2Step`](https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/access/Ownable2Step.sol)
  — two-step ownership transfer to prevent *"transfers of ownership to incorrect
  accounts, or to contracts that are unable to interact with the permission
  system"*, with the zero address cancelling a pending transfer
- [OpenZeppelin governance guide](https://docs.openzeppelin.com/contracts/5.x/governance)
  — a timelock *"allows users to exit the system if they disagree with a decision
  before it is executed"*, and granting the canceller role beyond the governor is
  a denial-of-service risk against governance itself
