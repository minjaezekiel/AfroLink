# ADR-0008 — Human-readable addressing: usernames, phone numbers, email

- **Status:** accepted
- **Date:** 2026-08-29
- **Implements:** [ADR-0005](0005-african-first-design.md) §D.1, which decided
  this and left it unbuilt
- **Relates to:** [ADR-0007](0007-distribution-and-sybil-resistance.md)
  (attested, never custodial identity)

## Context

The only way to name a recipient today is:

```
afri1qzp8h4cthjxue7g0kk4dmz9nvvqhs6xk3nlq2m
```

Nobody can read that aloud, retype it from a scrap of paper, or notice that four
characters in the middle changed. Adult literacy in sub-Saharan Africa runs
around two thirds, so a very large minority of the people this network is for
cannot read it at all — but the string defeats literate users equally. This is
not an accessibility feature bolted onto the side. **Human-readable addressing is
the primary interface, and raw addresses are the fallback.**

Three things the research settles before any design begins.

### A phone number can never be an authority

SIM-swap fraud rose **327% in Kenya during 2025** — over 123,000 fraudulent SIMs,
around **$3.8M** drained from mobile wallets — and accounts for as much as **43%
of mobile-money fraud** across African markets. The attack is cheap: persuade or
bribe a telco into reissuing a number, and every system treating that number as
proof of identity falls at once.

[ADR-0005](0005-african-first-design.md) §D.1 already called a naive
phone-to-key binding *"the most dangerous thing we could ship"*. It was right.

### Plaintext identifiers can never go on chain

A national phone-number space is around `10^9`. Anyone can hash all of it in
minutes, so `hash(phone_number)` on a public ledger is a complete reverse index
of the country's population, their addresses, and — because our state is public
and provable — their balances. Celo built ODIS, a rate-limited threshold OPRF,
for exactly this reason.

It is also where the incumbent just moved. In 2026 Safaricom began **masking
phone numbers in M-Pesa transactions**, approved by the Central Bank of Kenya,
after two decades of exposing them enabled harvesting and fraud. Publishing
numbers on a public ledger would be walking the other way past the regulator.

### Usernames are the opposite problem

A username is a public handle, so privacy is moot. The attack is visual
spoofing, and ENS demonstrates it at scale: its normalisation is complex enough
that different clients have resolved the same displayed name to different
addresses (ACM Web Conference 2025). The complexity comes from admitting the
whole of Unicode.

## Decision

### 1. An alias resolves. It never authorises.

Keys sign; names point. `crates/alias` contains no operation that spends and no
path from an identifier to a signature. Losing a SIM cannot lose the money, and
stealing one cannot gain it.

This is a genuine improvement on the incumbent rather than parity with it: on
M-Pesa, control of the number is control of the account. Here it is not.

### 2. A transaction commits to the resolved address, never to the alias.

`Message::Transfer` takes an `Address` and always will. A wallet resolves the
name, shows the user who they are about to pay, and signs the address.

Anything else is a live redirect — a rebinding landing between signing and
inclusion would silently send the money elsewhere. A useful consequence: the
alias system touches **no consensus-critical transaction structure**. It is a
registry and a lookup.

### 3. Usernames are ASCII-only, with a confusable-skeleton index.

`[a-z0-9_-]`, 3–32 characters, lowercased, no edge or doubled separators. Any
non-ASCII byte is rejected — Cyrillic `а` cannot be typed into a name at all.

Within ASCII, `0`/`o` and `rn`/`m` still deceive in most fonts, so each name
folds to a *skeleton* (`rn→m`, `vv→w`, `0→o`, `1`/`i→l`, separators dropped) and
a registration is refused when its skeleton is taken. `@arnina_ke` and
`@am1na-ke` cannot exist alongside `@amina_ke`.

We do not attempt to *detect* confusable names. We refuse the conditions that
make them possible.

Names expire and must be renewed, with a grace period during which only the
previous holder may reclaim. This is also the targeted answer to the state-bloat
question [06](../06-adopted-practices.md) left open: charge for the **scarce
public good** — a short name — rather than charging people for existing, which
is why XRPL-style account reserves were rejected.

**The cost, stated plainly:** no Swahili, Amharic, Arabic or Tifinagh script in a
username. For a project whose [ADR-0005](0005-african-first-design.md) rejects
ported Western assumptions, that deserves discomfort rather than a shrug. The
line ADR-0005 draws is that *a market assumption is a design choice about a
context; a mathematical primitive is not.* Homoglyph confusability is a property
of Unicode's code-point space, and the people a lookalike payment name would rob
are precisely the users this chain exists for. Local scripts belong in a wallet's
address book, after the user has confirmed who they are paying — not in the
globally resolvable identifier.

### 4. Phone and email are stored as commitments, attested by licensed issuers.

```text
commitment = H( ContactCommitment, pepper || kind || normalised_identifier )
```

The chain stores the commitment, the bound address, and the attesting issuer.
Never the identifier. There is deliberately **no `StoreKey` constructor that
accepts a phone number** — the type system is the cheapest place to enforce this.

Who attests: the licensed parties [ADR-0007](0007-distribution-and-sybil-resistance.md)
already commits to — MNOs, banks, national ID authorities. An MNO already owns
the phone-to-person mapping; this is no new trust assumption, and it gives MNOs
a role in the network. Governance suspends rather than deletes an attestor, so
existing bindings keep a resolvable provenance after a licence lapses.

### 5. Rebinding is time-locked and vetoable by the current key.

Pointing a contact at a new account takes effect only after
`REBIND_DELAY_BLOCKS` (~72h), and during that window the **currently bound
account** can cancel it with its key. Neither the attestor that requested the
rebind nor the holder of the number can veto — only the key can.

So a SIM swap produces a *visible, refusable request* rather than a silent
redirect. A pending rebind also cannot be replaced, or an attacker would reset
the clock and hide the request the victim was about to refuse.

Genuine recovery still works: someone who lost both phone and key cannot veto,
so after the delay the rebind completes. The mechanism does not distinguish the
honest case from the attack and does not need to — it only needs the honest
owner to be the one holding a key.

### 6. No escrow-to-claim for unregistered recipients.

Sending to a phone number with no account fails cleanly. Holding unclaimed funds
keyed to a phone number would put back exactly the asset a SIM-swap attacker
wants, and the claim path would come down to "controls the SIM".

This is a real cost: it is how M-Pesa onboards people, and it would make a
sender's first transaction do the recruiting. Recorded as **deferred, not
unconsidered**. If it is built later it needs expiry, refund-to-sender, and a
claim path that is not merely possession of the number.

### 7. A username is a pseudonym, not an identity.

The name exists to hide an address, not to reveal a person. Three properties,
each with a test that fails if someone later erodes it:

**Nothing in a name record identifies anyone.** A `NameRecord` is an owner
address and two heights. There is no name field, no document, no country, no
attestor — and `a_name_record_says_nothing_about_who_holds_it` asserts the whole
record structurally, so a "convenient" identity field cannot be added quietly.
Registration asks for a key and a fee. It does not ask who you are.

**The reverse link is opt-in and reversible.** Forward lookup (name → address) is
what a payer needs. Reverse lookup (address → name) is a *disclosure*: it lets
anyone who sees the address in a transaction link that address's entire history
to one handle. So registering publishes no reverse entry, `SetPrimaryAlias` is a
separate deliberate act, and `ClearPrimaryAlias` withdraws it unconditionally —
a disclosure that cannot be withdrawn is not a choice. `ReleaseName` goes
further and removes the registration altogether.

**Compartmentalisation works.** A holder may keep several addresses and name
only one. A trader publishes `@duka-la-amina` for the stall and keeps a separate
unnamed address for everything else; the chain cannot associate them, because
there is nothing to associate them *with*.

**The limits, stated rather than implied.** Clearing a display name stops future
lookups; it cannot unlink what observers recorded while it was published, because
the chain is public and history does not move. And a username used in trade is
inherently linkable by ordinary observation — pay `@duka-la-amina` in person and
you have learned who holds it. This design gives pseudonymity, which is what a
public ledger can honestly offer. It does not give anonymity, and a system that
claimed to would be lying to the people least able to check.

Contact aliases carry this further: phone and email exist on chain only as
commitments (§4), so even the identifier a person is findable by is not
published.

## How Pi Network does this, and where we differ

Pi ships username payments today and calls them **Human-Readable Addresses**: a
Pioneer sends Pi by typing a recipient's Pi username instead of a Stellar-style
address. At 70M+ registrations it is the largest deployment of the idea in our
market, so it is worth being precise about what it gets right and what it costs.

**What Pi got right, and we copied:** a username is the default way to name a
recipient, not an advanced feature; it is the *same* username across the app,
the wallet and the browser, so a merchant verifies a payer without decoding
anything; and the address never appears in normal use.

**Where the designs diverge, and why:**

| | Pi | AfroLink |
|---|---|---|
| Who owns the namespace | Pi Core Team | on-chain registry, first-come |
| What makes a name yours | passing Pi's KYC — one username per verified human | holding a key |
| Lookalike names | not prevented | ASCII-only + skeleton index |
| Resolution is verifiable | no — the directory is the authority | yes — proved against a committed state root |
| Losing the name | possible if KYC is revoked | only by not renewing |
| Phone numbers | KYC input, held by Pi | never stored; commitment only |

The substantive difference is the second row. Pi binds the name to a
*verified identity* held by one company, which is coherent for their goal of one
account per human — and it is the model
[ADR-0007](0007-distribution-and-sybil-resistance.md) rejected, because it makes
a corporate entity the gate on whether your balance exists. We bind the name to a
key. Nobody can revoke it, and losing your identity documents cannot cost you
your payment identity.

The third and fourth rows are where we think Pi is simply exposed. A username
directory that is not committed to state means a wallet has to trust whoever
answers the lookup, and a namespace with no confusable rules means `@arnina`
alongside `@amina` is a live attack against a user base explicitly recruited for
being non-technical.

**The better approach, stated as one sentence:** keep Pi's default — a name, not
an address — and change what the name is anchored to, from an identity a company
certifies to a key the user holds, with the answer arriving under a proof.

## Consequences

**Good.** The interface becomes usable by the people the network is for. The
SIM-swap defence is stronger than the incumbent's rather than equal to it.
Refusing to hold identifiers removes a breach-exposure category across every
jurisdiction we intend to operate in. And because resolution is client-side,
none of this touches consensus.

**Bad.** Non-Latin scripts are excluded from usernames — the sharpest tension
with ADR-0005 in the codebase, and worth revisiting if a safe design appears.
Contact resolution depends on attestors existing, so in a jurisdiction with no
licensed attestor only usernames and raw addresses work. The 72-hour rebind
delay makes honest recovery slow, which will generate support load and will be
the first thing anyone asks to shorten.

**Unresolved.** The pepper in v1 is held by the attestor, so an attestor *can*
enumerate its own subscribers — it already can, being their telco, but the chain
should not require that trust indefinitely. The threshold-OPRF hardening is
specified in [07-resolver-service.md](../07-resolver-service.md) and unbuilt.

## Revisit if

- A safe design for non-Latin usernames appears — script-mixing restrictions
  plus per-script confusable tables is the likely shape
- Attestors prove unobtainable in a target market, making contact aliases dead
  weight there
- Measured support load shows the rebind delay is the wrong number in either
  direction

## Sources

- [Dojah: SIM-swap fraud in Africa — detection and response](https://dojah.io/blog/sim-swap-fraud-africa-2026)
- [TechTrends Africa: SIM-swap fraud and mobile users](https://techtrends.africa/sim-swap-fraud-how-mobile-users-are-losing-money/)
- [African News Agency: most mobile banking fraud in SA linked to SIM swaps](https://africannewsagency.com/most-mobile-banking-fraud-in-sa-linked-to-sim-swaps/)
- [Tech Moni Africa: M-Pesa closes a major scam loophole (number masking)](https://techmoniafrica.com/m-pesa-just-closed-a-major-scam-loophole/)
- [Celo: Oblivious Decentralized Identifier Service (ODIS)](https://docs.celo.org/what-is-celo/about-celo-l1/protocol/identity/odis)
- [Celo: Phone number privacy](https://docs.celo.org/celo-codebase/protocol/odis/use-cases/phone-number-privacy)
- [Celo: SocialConnect](https://github.com/celo-org/social-connect/blob/main/README.md)
- [Celo: Attestation Service — SIM-swap risk](https://docs.celo.org/validator-guide/attestation-service)
- [Beyond Visual Confusion: ENS normalisation and homoglyph attacks (ACM Web Conference 2025)](https://dl.acm.org/doi/10.1145/3696410.3714675)
- [Wikipedia: IDN homograph attack](https://en.wikipedia.org/wiki/IDN_homograph_attack)
- [MetaMask Mobile: warn on ENS homoglyphs](https://github.com/MetaMask/metamask-mobile/issues/2067)
