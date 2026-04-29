# What Deadman is for (and what it isn't)

Deadman is built around a narrow promise: *if you stop checking in, the
material you uploaded gets released to the people you nominated, and the
operator of the platform can prove they didn't read it on the way through.*

That promise is genuinely useful for a small set of situations and
genuinely dangerous for several others. Read this before you decide to
arm anything.

---

## Good fits

These are situations where Deadman's design properties — zero-knowledge,
delayed release, threshold key custody, hash-chained audit, optional Tor
hosting — are doing real work that a simpler tool wouldn't.

### 1. Last-wishes dossier for family

You travel a lot. Your spouse doesn't know your password manager master
password, doesn't have access to your business succession docs, doesn't
have the hardware location of your encrypted backup drive. If something
happens to you — a car wreck, a stroke — they need a path to that
information that doesn't depend on remembering you to a lawyer.

A Deadman policy with a 60-day check-in interval, a 7-day grace period,
and a single email destination to your spouse fits this exactly. They
get the dossier if you stop responding for two months. You can pause the
policy when you go off-grid intentionally. The threshold key split means
even an attacker who broke into the server can't read the dossier without
your check-in actually lapsing.

### 2. Source-protection backup for journalists

You've received a sensitive document. Your source asked you to publish
under specific conditions: only if your source themselves goes silent,
only after a defined window, only to specific named outlets. You want
that release to happen even if you're disappeared, killed, or detained.

A Deadman policy with email destinations to two or three trusted
journalists or outlets, behind a cleartext landing page on your onion,
fits this. Combined with `notify-only` mode, you can stage the release
so the destinations get a heads-up first and have to confirm; the
material doesn't auto-publish to the wider internet without human
review. (See "Safe modes" in the admin panel.)

### 3. Estate planning for crypto / hardware-custody material

Hardware wallet seed phrases, key locations, the password vault that
unlocks the password vault. Material that needs to reach an executor
*if and only if* you're not around to give it to them yourself.

A Deadman policy with a long interval (90+ days), a private destination
(email, not public page), and a hold period gives the executor time to
verify before the actual material is released.

### 4. Legal hold "press release" backstop for lawyers

Your client is in a position where their disappearance would be
strategic for a counterparty. You hold a packet of evidence that should
be public if your client stops checking in — court filings, regulator
contacts, named-journalist destinations. Deadman lets the client run the
check-in themselves while you hold the threshold passphrase, eliminating
the "lawyer dies in same plane crash" risk a paper instruction creates.

### 5. Whistleblower personal-safety insurance

You have made a disclosure to authorities. You believe retaliation is
plausible. You upload a complete record of what you reported, who you
reported it to, and what you knew about specific actors. The release
condition is "I stop checking in for two weeks." The destinations are
your lawyer, two press contacts you've already coordinated with, and a
public landing page.

This is a real and well-established use of deadman switches. It is also
the use case most likely to put the operator (you, the self-hoster) on
the radar of whoever the whistleblower's adversary is. **Read
[operator-risks.md](operator-risks.md) before doing this.**

---

## Bad fits — do not use Deadman for these

The threat model assumes you're the legitimate owner of the material and
that the release would be lawful and constructive if it happens. These
uses break that assumption.

### Coercion against another person ("if I die, here's the evidence")

You're using the deadman release as a credible threat against someone
who might harm you. This is *the* canonical use, and Deadman supports it
technically. But:

- The *threat* requires the other party to know you've armed it. That
  means they know you're a customer of a hosted onion. If they have
  resources, they go after the host (you), not you.
- The "release if I'm killed" version of this story has historically
  worked badly. Suppression-then-release is a well-studied attacker
  pattern; people have been killed *and* the deadman has failed for
  unrelated reasons (host dies, key custodian dies, etc).
- If the counterparty has enough motivation to be worth threatening,
  they have enough motivation to be worth not poking with a stick.

If your situation is genuinely in this category, you need a lawyer and
a real plan, not a self-hosted onion service.

### "Auto-leak" for material you do not have authority to release

You possess classified information you obtained outside the channels
authorized to publish it, and you want it auto-released on a deadline.

The platform will technically execute. The legal exposure of running
the platform under those circumstances is severe — see
[operator-risks.md](operator-risks.md). The platform was not designed
to make this kind of release safer or more legitimate; it does not
launder authority.

### Harassment, doxxing, revenge releases, deepfakes, sextortion

Don't.

A platform with auto-release semantics and Tor hosting is structurally
ideal for these and structurally bad at filtering them out, which means
*you* the operator absorb their consequences. Refuse to run a Deadman
instance that any user is using for these. If you find one, suspend the
policy from the admin panel and tell them why.

### "I want this published 5 minutes after I'm executed"

There is a non-configurable 1-hour minimum publication delay (and a
24-hour minimum grace period). This is by design. If you need
5-minute-precision auto-publishing, this is the wrong tool.

### Group secrets ("auto-publish if any of us five disappears")

Deadman's check-in is per-user. There's no quorum or N-of-M check-in
across multiple users. You'd be running 5 separate policies and any one
of them missing would fire — which is probably not what you want.
Trusted-contacts / delegation work was deferred from the lean build for
this reason; building it badly is worse than not building it.

---

## Configuration patterns by scenario

For the four good-fit scenarios above, here are starting policy values.
Tune from there.

### Last-wishes dossier

| Field | Value |
| --- | --- |
| Check-in interval | 60 days |
| Grace period | 168 hours (7 days) |
| Hold period | 24 hours |
| Release mode | `private` |
| Destinations | Email to spouse + sibling |
| Bundle | A single tarball: PDFs, exported password-manager vault, hardware-wallet location |

### Source-protection (notify-only first)

| Field | Value |
| --- | --- |
| Check-in interval | 14 days |
| Grace period | 72 hours |
| Hold period | 48 hours |
| Release mode | `notify-only` (admin panel) |
| Destinations | Email to two named journalists by name |
| Bundle | Source materials + your contemporaneous notes |

### Estate / crypto custody

| Field | Value |
| --- | --- |
| Check-in interval | 90 days |
| Grace period | 168 hours |
| Hold period | 168 hours |
| Release mode | `private` |
| Destinations | Email to executor + secondary executor |
| Bundle | Seed phrases (encrypted), wallet locations, instructions |

### Whistleblower insurance

| Field | Value |
| --- | --- |
| Check-in interval | 14 days |
| Grace period | 96 hours (long enough to survive a brief detention) |
| Hold period | 24 hours |
| Release mode | Public landing page + email to lawyer + 2 press contacts |
| Bundle | Full record: what was disclosed, to whom, when, who else knew |

In all four, **arm in `notify-only` mode for the first cycle.** Confirm
that warnings actually reach you, that check-in works from the device
you'll carry, that the destination addresses still go where you think.
*Then* switch the mode to its real value.

---

## What "release" actually does

Worth being concrete because the word is loaded.

A release event:

1. Decrypts the bundle DEK in the release worker's process memory using
   the unsealed release private key.
2. Decrypts the bundle into a temporary in-memory blob.
3. Builds a release package: tarball, SHA-256, manifest JSON, detached
   signature with the service's Ed25519 audit key.
4. Uploads the package to the configured public landing path (if any).
5. Sends emails to email destinations.
6. POSTs signed bodies to webhook destinations.
7. Records each step in the audit ledger and emits `release.completed`.
8. Wipes the in-memory plaintext.

It does *not*:

- Post to social networks. The platform doesn't speak Twitter, Mastodon,
  Bluesky, or anything else; that was deferred from the lean build.
- Notify recipients with anything other than the bare release URL and a
  signed manifest. The recipient is expected to know what to do with it.
- Mirror to IPFS, Wayback, archive.today, or any anti-takedown service.
  That was deferred too. If you want anti-takedown durability, build it
  into your destinations: aim webhooks at multiple mirrors you control.

---

## Checking your assumptions

Once a quarter, do all of the following:

1. Trigger a *test* policy with non-sensitive content end-to-end.
   Confirm destinations receive it.
2. Verify the audit chain (admin panel → Ledger → Verify chain).
3. Run a backup, then mentally walk through restoring it onto a fresh
   VM. (Once a year, actually do that.)
4. Re-read this document. The world changed; reconsider whether your
   threat model still holds.

If any of those is hard or fails, your real threat model has shifted out
from under your assumptions.
