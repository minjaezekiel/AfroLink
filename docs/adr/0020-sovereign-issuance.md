# ADR-0020 — Sovereign issuance: who may create money, and how much

- **Status:** accepted
- **Date:** 2026-09-01
- **Relates to:** [ADR-0005](0005-african-first-design.md) §4.2 (why sovereign
  issuers exist at all), [ADR-0015](0015-committed-outcomes-and-provable-history.md)
  (what makes an issuance event provable), [ADR-0018](0018-savings-group-integrity.md)
  §15 (the fee-denomination whitelist this makes load-bearing),
  `crates/bank`, `crates/executor/tests/issuance.rs`

## Context

**The chain could not create money.** There was no `Mint`, `Burn` or `Freeze`
message — not one of the seventy-odd `Message` variants. `Bank::mint`,
`Bank::burn`, `Bank::freeze` and `Namespace::Frozen` were all written and tested,
and outside `crates/bank` itself the only callers were inside `#[cfg(test)]`.

So after genesis the total supply of every denomination was **frozen forever**. A
central bank registered as a sovereign issuer at genesis could not issue
anything; every shilling that would ever exist had to be listed in the genesis
file. The project's stated purpose — sovereign stablecoins for African payments —
was unreachable, and one test name (`issuers_are_registered_and_can_mint_after_genesis`)
asserted the *library* could mint while nothing on a real chain could.

This is the same defect class as [ADR-0018](0018-savings-group-integrity.md) §9,
where `apply_rebind` was correct, tested and reachable from no transaction. It is
much larger. It also quietly propped up §15's argument that the missing
fee-denomination whitelist "is not currently exploitable **because** issuers exist
only through genesis" — true, and true because issuance did not work.

## The shape of the answer

The obvious fix is one message that lets `Issuer::authority` mint. That would be
wrong, and the reason is the only thing in this ADR worth remembering.

`Issuer` was `{ authority, max_supply, paused }` — **a single address that could
mint, burn, freeze and pause**. Every audit of a production stablecoin flags
exactly that shape: a single all-powerful owner address is a single point of
failure, and *who can call mint* is the highest-severity question in the whole
system. A key that can create money is not a key you can put on a machine that
signs a hundred transactions a day; a key that is offline in a vault cannot sign
a hundred transactions a day. One address cannot be both.

So the roles are split, the way Circle's FiatToken splits them:

| Role | Key lives | May | May not |
|---|---|---|---|
| **Authority** | cold, in a vault | configure minters and the freezer, pause, tighten the cap | mint, burn, freeze |
| **Minter** | hot, one per licensed institution | mint up to its remaining **allowance**, burn its own holdings | configure anything |
| **Freezer** | compliance | freeze and unfreeze holders | mint, burn, configure |

This is also the **two-tier issuance model** every major central bank exploring a
CBDC has converged on, expressed in keys rather than in institutions: the central
bank operates the ledger and holds the authority; licensed intermediaries hold
minter keys and put money into circulation.

### 1. The allowance is the whole point

A minter is authorised for a finite amount, decremented by every mint and
**never restored by a burn**. Take a hot key and you can mint what was left on it
and then nothing — not because somebody noticed, but because the ledger stops
you. Without an allowance the same theft mints until a human intervenes, and the
peg is gone long before that.

The allowance is deducted inside `Bank::mint`, not checked there and written back
later, because the bypass an audit looks for is **batching**: a limit that is
read and not written is a per-transaction cap wearing a total's name, and twenty
small mints in one block defeat it.
`one_block_of_small_mints_cannot_add_up_to_more_than_the_allowance` is that test.

A burn does not refill the allowance. Otherwise a mint-and-burn cycle turns a
ceiling on the damage a stolen key can do into a rate limit on *net* issuance,
which is a much weaker promise wearing the same name.

### 2. `Burn` has no `from`, and its absence is the design

Burning a holder's balance is confiscation with an accounting name on it, and an
issuer able to do it silently makes every balance of that asset conditional.

Redemption does not need it. The holder **signs a transfer to the minter**, and
the minter burns what it then owns — so the holder's consent is on the chain as a
signature, in an ordered, provable transaction. An issuer that genuinely must
immobilise funds without consent has `SetFrozen`, which is visible, reversible
and attributable to a named key.

There is therefore **no spelling of "destroy that account's money"** anywhere in
the message set. That was a choice and it is the one most worth defending.

### 3. A supply cap is a ratchet

`SetSupplyCap` may set a first cap, or lower one already set, and may **never**
raise one or remove it.

A cap is how an issuer binds itself publicly: with one set, a holder can verify
from the chain alone that no more than the stated amount can exist, without
trusting an attestation. A promise the promiser can revoke is not a promise, it
is a preference — so the guarantee is only worth something because the ratchet
exists.

Stellar reaches the same rule from the same reasoning: an issuer may only
*clear* a trustline's clawback flag, never set one, *"to give asset holders
perpetual confidence about the future state of their holdings"*. XRPL refuses to
enable clawback at all once any of an asset has been issued. The general
principle both encode, and the one adopted here: **an issuer's powers over a
holder may only ever shrink, never grow.** A holder should be able to check what
can be done to them once, at the moment they accept the asset, and rely on the
answer.

A cap *below* current supply is allowed and means no more may be minted until
burns bring the total under it — which is how a currency is wound down.

### 4. Pausing and freezing are different tools

`SetIssuerPaused` stops new money **without touching money that already exists**,
so the response to a suspected key compromise is not a payments outage for
everyone holding the currency. `SetFrozen` immobilises one account's holdings of
one denomination, scoped so an issuer can never reach AFRI, another country's
currency, or anything else that account holds.

Minting to a frozen account is refused, so a freeze means one thing rather than
two: an issuer must not be able to inflate a balance it has declared immobile.

## Consequences

**Good.** A sovereign currency can be issued, redeemed and wound down by
transaction. Every issuance event is ordered, signed, attributable to a named
key, committed in `outcome_root` and filed in the recipient's own history
([ADR-0015](0015-committed-outcomes-and-provable-history.md)) — a mint is a
*proof*, not a press release. A stolen hot key costs a bounded amount. A cap is a
commitment rather than a claim.

[ADR-0018](0018-savings-group-integrity.md) §15's fee-denomination whitelist
stops being latent and starts being load-bearing, which was the whole reason it
was built ahead of need.

**Bad, and worth being clear about.**

- **There is no clawback**, and regulated issuers do ask for one — XRPL and
  Stellar both added it. Deferred rather than forgotten: `Freeze` plus a court
  order plus a holder-signed transfer covers the same ground while leaving the
  holder's consent on the chain, and adding clawback later is easy in a way that
  removing it is not. If it is added, the ratchet principle above says it must be
  declared before the asset is issued and be renounceable but not grantable.
- **Freezing the fee denomination immobilises an account entirely.** Paying a fee
  is itself a movement of that asset, so a holder frozen in the currency they use
  for fees cannot act at all unless they hold another fee-payable asset or have a
  sponsor. That is arguably what a freeze should do, but it is the difference
  between "your shillings are held" and "your account is dead", and an issuer
  should know which one they are doing. Asserted rather than left to be
  discovered, in `a_freeze_reaches_one_denomination_and_the_holder_can_see_who_did_it`.
- **No proof of reserve.** The chain can prove how much exists; it cannot prove
  anything backs it. A cap narrows the gap and does not close it. Attestation is
  Phase 4 and stays there.
- **No rate limit per period.** The allowance bounds total damage, not damage per
  day. A daily ceiling is the obvious next control and needs a clock the issuer
  record does not have.
- ~~**Nothing can register an issuer after genesis**, and nothing can change an
  authority key that is lost or compromised.~~ **Closed by
  [ADR-0022](0022-governance.md)**, and closed in two different places on
  purpose: the council may *admit* a denomination the chain has never seen, and
  may never touch one it already has, while the authority of an existing currency
  moves only by a two-step handover signed at both ends. A key that is simply
  *lost*, with nobody to sign the handover, is not a governance problem — an
  authority is an account, and an account already carries an M-of-N signer list
  ([ADR-0017](0017-key-rotation-and-signer-lists.md)). That is why the field is
  an address rather than a public key.
- **The `paused` flag is not a ratchet** and should not be — pausing must be
  reversible or it is a kill switch rather than a circuit breaker.

## Revisit if

- A central bank asks for clawback as a condition of issuing, at which point the
  Stellar shape (declared up front, renounceable, never grantable) is the design
- ~~Governance arrives~~ — it has ([ADR-0022](0022-governance.md)), and the roles
  above are now operable rather than fixed at genesis
- A per-period mint ceiling is wanted, which needs the issuer record to carry a
  window

## Sources

- [Circle, `stablecoin-evm` token design](https://github.com/circlefin/stablecoin-evm/blob/master/doc/tokendesign.md)
  and the [MasterMinter pattern](https://github.com/circlefin/stablecoin-evm) —
  the separation of owner, masterMinter, minters with allowances, pauser and
  blacklister, and the reasoning that allowances exist for offline key management
- [Stellar, *Asset design considerations*](https://developers.stellar.org/docs/tokens/control-asset-access)
  and [CAP-0039](https://github.com/stellar/stellar-protocol/blob/master/core/cap-0039.md)
  — clawback flags that may be cleared but never set, and why
- [XRPL, *Clawing back tokens*](https://xrpl.org/docs/references/protocol/transactions/types/clawback)
  — the flag that cannot be enabled once an asset has been issued
- [Hacken, *Stablecoin security: how design choices create vulnerabilities*](https://hacken.io/discover/stablecoin-security/)
  — mint/burn keys under HSM or multisig, per-period caps as circuit breakers,
  and the batching bypass those caps have to survive
- IMF and BIS work on two-tier CBDC distribution — the central bank operates the
  core ledger and holds monetary control; licensed intermediaries handle
  distribution and end users
