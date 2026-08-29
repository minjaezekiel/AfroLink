# 07 — The resolver service, and the wallet confirm screen

> **Status: specified, not built.** The chain-side half of
> [ADR-0008](adr/0008-human-readable-addressing.md) is implemented and tested in
> `crates/alias`. This document covers the two halves that live outside the
> chain: the lookup service that turns a phone number into a commitment, and the
> wallet screen that decides whether a person understands who they are paying.
>
> Neither is built. The resolver needs a network layer we do not have yet
> (Phase 2), and the wallet is Phase 4. This is written now so the chain-side
> design is not quietly assuming something the rest cannot deliver.

---

## 1. The problem the resolver exists to solve

The chain stores `H(pepper || kind || identifier)` and never the identifier
([ADR-0008](adr/0008-human-readable-addressing.md) §4). That closes enumeration
but opens a gap: **a sender who legitimately knows Amina's number still has to
turn it into the commitment** before they can look anything up.

The requirement, stated precisely:

> Someone who already knows the identifier must be able to resolve it. Someone
> who does not must not be able to enumerate.

That is the same requirement Celo's ODIS encodes, and the reason a bare hash
does not satisfy it: a national number space of ~10⁹ is exhaustively hashable in
minutes.

## 2. Who runs it

**The licensed attestors already committed to in
[ADR-0007](adr/0007-distribution-and-sybil-resistance.md)** — mobile network
operators, banks, national ID authorities.

This is the design's best property and worth stating plainly: an MNO *already
owns* the phone-to-person mapping. It is their core business, they are already
regulated for it, and they already answer subscriber lookups. Using them adds
**no new trust assumption** — it uses one we already accepted and could not
avoid.

It also gives MNOs a reason to participate in the network rather than to treat it
as a competitor, which matters more than any technical property in this document.

| | Attestor | Chain |
|---|---|---|
| Holds identifiers | yes — already did | **never** |
| Holds the pepper | yes (v1) | no |
| Answers lookups | yes, rate-limited | no |
| Can be enumerated | rate limits + licence | nothing to enumerate |

## 3. The lookup flow

```text
wallet                          attestor                        chain
  │                                 │                              │
  │  blinded(+254712345678) ───────►│                              │
  │                                 │  rate-limit check            │
  │◄─────────── blinded pepper ─────│                              │
  │                                 │                              │
  │  commitment = H(pepper‖kind‖id) │                              │
  │                                 │                              │
  │  Query::ResolveContact ─────────┼─────────────────────────────►│
  │◄──── ProvedValue (record + proof) ───────────────────────────  │
  │                                 │                              │
  │  verify against trusted header  │                              │
```

The last two steps are **already built** — `Query::ResolveContact` and
`ProvedValue::verify` in `crates/rpc`. The resolver never sees the answer and
cannot influence it: it supplies a pepper, and the chain supplies a proof.

That split matters. A compromised resolver can deny service or, at worst,
enumerate its own subscribers. It **cannot** make a wallet resolve a number to
the wrong address, because the binding is proved against a header the wallet
verified from commit signatures.

## 4. Enumeration defence, in two versions

### v1 — per-issuer pepper, rate-limited (ship first)

The attestor holds a high-entropy pepper and serves rate-limited lookups.
Enumeration is bounded operationally, not cryptographically.

**Honest about the weakness:** the attestor *can* enumerate its own subscribers.
It already can — it is their telco — so this adds no exposure. But the chain
should not require that trust permanently.

### v2 — threshold OPRF (the hardening)

ODIS's shape: the pepper is derived by an oblivious pseudorandom function across
`n` operators with threshold `t`, and the identifier is blinded before it leaves
the device, so no operator sees a raw number.

**Its known weakness, recorded rather than glossed:** Celo's own documentation
states that with 7 operators and a threshold of 5, compromising 5 operators lets
an attacker compute the pepper for every phone number. A threshold OPRF moves
the trust from one party to a quorum; it does not remove it.

Because `ContactCommitment::new` takes the pepper as an argument, v2 changes
where the pepper comes from and nothing else. No chain-side change, no
migration for names already bound under v1 — those keep resolving under their
existing pepper.

## 5. The wallet confirm screen

**This is the part that actually determines whether a non-reading user can use
the network safely,** and it deserves as much design attention as the
cryptography above.

The failure mode for an illiterate user is not "cannot type an address". It is
**"sent money to the wrong person and cannot get it back"**. Resolution being
correct is necessary and not sufficient; the user has to *recognise* the answer.

Three elements, in priority order:

1. **A deterministic identicon derived from the address.** A generated pattern of
   shapes and colours. This is the real accessibility answer: a person who cannot
   read `@amina` can absolutely tell that the picture is not the one they have
   paid nine times before. It must derive from the **address**, never the name,
   so a lookalike name cannot inherit a familiar image.
2. **The registered name and the attestor.** "@amina — verified by Safaricom"
   tells the sender who vouched.
3. **The last four digits**, for a contact the sender typed as a number.

The middle element mirrors M-Pesa's confirm-recipient-name step, which is the
single most effective anti-misdirection feature in African mobile money — people
already know to check it, so we inherit a habit rather than teaching one.

### Rules the screen must follow

- **Never render a local-script label for an unknown recipient.** ADR-0008 keeps
  usernames ASCII precisely so the resolvable identifier cannot be spoofed;
  showing arbitrary script for a stranger hands the attack back. A label saved
  in the user's own address book is fine — they already confirmed that person.
- **Show the identicon before the amount.** Who, then how much.
- **A first-time recipient is marked as such.** "You have not paid this person
  before" costs one line and catches most misdirection.
- **A pending rebind is surfaced loudly.** If a contact has a rebinding in
  flight, the sender should see it and the *owner* should be prompted to veto —
  the veto right in `crates/alias` is worthless if nobody is told to exercise it.

The last point is the one most likely to be dropped under deadline, and it is the
one the whole SIM-swap defence rests on.

## 6. What this leaves open

- **Attestor discovery.** How a wallet learns which attestor serves a given
  country, and what happens when a number's operator is not an attestor.
- **Rate-limit parameters.** Too tight breaks a merchant doing bulk payouts; too
  loose is no defence.
- **Identicon algorithm.** Must be deterministic, specified, and identical across
  wallets — two wallets drawing the same address differently would destroy the
  recognition the whole approach depends on. It belongs in a spec, not in each
  wallet.
- **Escrow-to-claim**, deliberately deferred in ADR-0008 §6.

## Sources

- [Celo: ODIS](https://docs.celo.org/what-is-celo/about-celo-l1/protocol/identity/odis)
- [Celo: Phone number privacy](https://docs.celo.org/celo-codebase/protocol/odis/use-cases/phone-number-privacy)
- [Celo: SocialConnect](https://github.com/celo-org/social-connect/blob/main/README.md)
- [Tech Moni Africa: M-Pesa number masking](https://techmoniafrica.com/m-pesa-just-closed-a-major-scam-loophole/)
- [Dojah: SIM-swap fraud in Africa](https://dojah.io/blog/sim-swap-fraud-africa-2026)
