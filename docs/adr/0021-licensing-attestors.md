# ADR-0021 — Licensing attestors, and a country code with one spelling

- **Status:** accepted
- **Date:** 2026-09-01
- **Relates to:** [ADR-0007](0007-distribution-and-sybil-resistance.md) (identity
  attested, never custodial), [ADR-0008](0008-human-readable-addressing.md) (the
  design this makes reachable), [ADR-0020](0020-sovereign-issuance.md) (the same
  defect class, and the same governance gap),
  `crates/alias`, `crates/executor/tests/contacts.rs`

## Context

`crates/alias` had two halves and only one of them worked.

**Usernames worked.** `RegisterName` is a message, anyone can send it, and the
confusable-skeleton index does its job.

**Phone and email did not.** `Message::AttestContact` requires the sender to be a
registered attestor. `Bindings::register_attestor` was called from **tests and
from nothing else** — no genesis field, no message, no governance hook. So on any
real chain no attestor could exist, therefore no contact could ever be bound,
therefore:

- no phone number or email address resolved to anything;
- the 72-hour veto window guarded a binding that could not be created;
- `Message::ApplyRebind` — added in [ADR-0018](0018-savings-group-integrity.md)
  §9 specifically so genuine recovery could complete — completed a recovery of
  nothing.

That is the third instance of one defect class in this codebase: **correct,
tested code reachable from no transaction**. §9 was the first,
[ADR-0020](0020-sovereign-issuance.md) the second and largest. The pattern is
consistent enough to be worth naming: a module gets built with a clean internal
API and a full test suite, and the *last* wire — the one from a signed message to
that API — is the one nobody notices is missing, because every test reaches the
API directly.

## Decisions

### 1. Genesis licenses attestors, exactly as it licenses issuers

```rust
pub struct Genesis {
    …
    pub issuers: Vec<(Denom, Issuer)>,
    pub attestors: Vec<(Address, Attestor)>,
}
```

An attestor is a licensed institution — an MNO, a bank, a national ID authority.
Naming one is precisely the kind of decision the people starting a network make
in the genesis file, and it is where issuers are already named. No new concept,
no invented authority.

Two validation rules, both refusing files a network should not start from:

- **No duplicate attestor addresses.** Two records for one account are two
  answers to *"is this account licensed"*, and which wins would depend on
  iteration order.
- **No attestor registered already suspended.** `Attestor::active` exists so
  governance can withdraw a licence without deleting the record — bindings keep a
  resolvable provenance after a licence lapses. Registering one suspended at
  genesis creates a row **nothing can ever activate**, because activation is
  governance's job and governance does not exist. Better to refuse the file than
  ship a network with a dead registry entry in it.

### 2. `CountryCode` moves to `crates/primitives`

Found while wiring this up. `Attestor.country` was a bare `[u8; 2]`, decoded with
`take_array::<2>()` and **no validation at all** — so `"ke"`, `"KE"`, `"k\0"` and
any two arbitrary bytes were all accepted as spellings of a jurisdiction, in a
record hashed into the state root.

A validated `CountryCode` already existed in `crates/consensus`, decoding
correctly and refusing anything but two lowercase ASCII letters. The attestor
registry simply did not use it, because a jurisdiction label in an addressing
crate had no reason to depend on the consensus crate.

So the type moves to `crates/primitives`, where both users can reach it, and
`crates/consensus` re-exports it so every existing import keeps working. A
country is a primitive value, not a consensus concept; it lived in consensus only
because validators were the first thing to need one.

**One rule in one place.** The alternative — re-deriving "two lowercase ASCII
letters" inside `Attestor::decode` — is how two spellings of a rule drift apart,
and this codebase has already paid for that lesson six times over in
[08](../08-adversarial-testing.md) §1–5.

`Attestor.name` also gained a bound (`1..=64` bytes). It is displayed to a user
deciding whether to trust a binding, so unbounded it is a place to put a
paragraph that every node stores and every wallet renders.

### 3. What is deliberately *not* here

**No `RegisterAttestor` or `SuspendAttestor` message.** Both need an authority
that can act after genesis, and inventing one here would be worse than naming the
gap — the same conclusion [ADR-0020](0020-sovereign-issuance.md) reached about
registering issuers.

The two gaps are now the same gap, and it is the largest one left in the project:
**every trusted role on this chain is fixed at genesis and cannot be rotated,
added, or revoked.** An issuer authority whose key is lost stays lost. An
attestor whose licence is withdrawn by its regulator stays licensed on-chain.
That is a governance decision the project has not yet made.

> **Closed by [ADR-0022](0022-governance.md).** A seated council licenses and
> suspends attestors behind a timelock, and `Attestor::active` finally has a
> writer. The messages named as missing above are `Action::LicenseAttestor` and
> `Action::SetAttestorActive`.

## Consequences

**Good.** The whole of [ADR-0008](0008-human-readable-addressing.md)'s contact
design is now reachable from a genesis file a real network could ship: an MNO
binds a number, the number resolves to an address with a proof, a stolen SIM
produces a *refusable request* rather than a silent redirect, and a user who has
genuinely lost their key gets their number back once the window closes. The tests
in `crates/executor/tests/contacts.rs` drive all of it through ordinary signed
transactions, and `crates/store` now proves resolution against a header a light
client verified, from a chain whose attestor came from genesis rather than from a
test reaching into state.

The privacy property is asserted rather than assumed: the stored record contains
no fragment of the number, and a commitment cannot be recomputed without the
attestor's pepper.

**Bad, and worth being clear about.**

- ~~**Attestors cannot be added, suspended or replaced after genesis.**~~ The
  governance gap above, **closed by [ADR-0022](0022-governance.md)**. What
  remains true is the sentence after it: a network's *founding* attestor set is
  whatever its founders wrote down.
- **A licensed attestor is trusted completely within its scope.** It can bind any
  commitment to any address, and request a rebind of any binding it made. The
  defences against that are the veto window and the fact that an alias never
  authorises — not a limit on the attestor itself. That is the ADR-0007 trust
  model working as designed, and it is still a real trust assumption.
- **The off-chain resolver remains unbuilt**, so nothing yet turns a phone number
  a user types into the commitment the chain stores. That is
  [07](../07-resolver-service.md), and it needs the network layer.
- **No test yet drives a wallet's full path** — type a number, resolve it through
  a rate-limited resolver, confirm an identicon, sign the resolved address. The
  chain-side half is proved; the client-side half is specified.

## Revisit if

- ~~Governance arrives~~ — it has ([ADR-0022](0022-governance.md)), and
  `Attestor::active` now earns its keep
- A regulator requires that a withdrawn licence take effect within a fixed
  window, which would make on-chain suspension urgent rather than merely correct

## Sources

- [ADR-0007](0007-distribution-and-sybil-resistance.md) — attested, never
  custodial: the chain verifies a credential from a licensed party, runs no
  verification itself and holds no documents
- [ADR-0008](0008-human-readable-addressing.md) — the SIM-swap figures (327% rise
  in Kenya in 2025; up to 43% of mobile-money fraud), Celo's ODIS and
  SocialConnect, and the reasoning behind time-locked vetoable rebinding
- [Safaricom's 2026 masking of M-Pesa numbers, with CBK approval](https://www.safaricom.co.ke/)
  — the incumbent regulator moving *away* from exposing numbers, which is the
  direction a public ledger must not move in
