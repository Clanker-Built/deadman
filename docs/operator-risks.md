# Operator risks: read this before hosting Deadman for anyone but yourself

This document is written for the person who is considering running a
Deadman instance that other people will use. If you are running it for
yourself only — household members, a small known circle — most of this
still applies but at much lower amplitude. If you are thinking about
spinning up a `.onion` and inviting strangers, read this all the way
through, twice, and then sit on the decision for a week.

**This is not legal advice.** It is a writeup of how similar platforms
have actually been treated, written for an engineer trying to gauge
whether they want this in their life. Get an actual lawyer in your
jurisdiction before you publish anything to outside users.

---

## The asymmetry that drives everything

Your zero-knowledge design is real. Without the user's policy triggering
*and* the threshold vault unlocking, the server cannot decrypt their
bundle. You can demonstrate this from the source, the threshold split
of the release key, and the audit ledger.

That is a defense in court. It is not a defense against being
investigated, raided, sued, deplatformed, doxxed, or arrested. The cost
of "I'm innocent and I have the math to prove it" can still be: months
of seized hardware, frozen accounts, public association with whatever
the bad case turns out to be, five-to-six figures in legal fees.

**That cost lands on the operator, not on the user. The user uploads
ciphertext over Tor and walks away anonymous. You don't.**

---

## Risks, sorted by likelihood

### Most likely (will probably happen if your instance gets any uptake)

- **Abuse.** Some users will try to use the platform for things you'd
  refuse to host knowingly: extortion timers, doxxing-on-deadline,
  harassment-in-installments, revenge content, fake-deadman scams. Your
  zero-knowledge design *prevents you from pre-screening this.* The press
  story writes itself: *"Anonymous service auto-publishes [horrible
  thing] when creator misses check-in."*
- **Takedown demands.** DMCA notices, foreign equivalents, court orders.
  Tor hosting reduces this surface but does not eliminate it — your
  hosting provider, your domain registrar (if you point a clearnet alias
  at the onion), your bank, your employer all remain reachable.
- **Account-data subpoenas.** A court orders you to hand over everything
  tied to a specific user. You'd hand over: the ciphertext bundle
  (useless to them), email addresses, audit-log timing metadata, IP
  addresses if you log them, destination addresses at trigger time. The
  audit log is *rich*; "I can't read the payload" doesn't mean "I have
  nothing useful to a prosecutor."

### Plausible (if a high-profile case hits your instance)

- **Compelled key disclosure / compelled assistance.** UK RIPA Part III
  explicitly criminalizes refusing to hand over keys (2-5 years). France
  has similar. Australia's Telecommunications and Other Legislation
  Amendment (Assistance and Access) Act of 2018 ("TOLA") goes further.
  The US is more contested, but `All Writs Act` orders have been
  attempted (Apple v FBI). Your threshold-vault split lets you
  *truthfully* say "no single party has the key" — but a court can
  compel each custodian, and "we designed it that way to defeat court
  orders" is not a friendly-sounding fact when read out in front of a
  judge.
- **Aiding-and-abetting / accessory theories.** If a user releases stolen
  material via your platform and you continued to host them after being
  on notice, prosecutors can argue you facilitated. The intermediary
  protections that help with civil liability (Section 230 in the US,
  e-Commerce Directive in the EU) **do not extend to federal criminal
  law in the US** and have analogous gaps elsewhere.
- **Espionage Act exposure (US).** This is the one that makes the
  "what if it's classified" scenario sharp. 18 USC 793 does not require
  intent to harm the US — *"reason to believe"* the information could
  be used to harm is enough. It has been used against publishers
  (Assange). A platform that *automatically publishes* classified
  material to wide-release destinations is structurally similar to
  Wikileaks. The fact that you didn't read the material isn't the
  defense you want it to be; the fact that you couldn't read it might
  not be either, depending on the prosecutor.
- **BSA / OFAC / FinCEN territory.** If a release contains payment
  instructions, crypto keys, sanctioned-party communications, etc., you
  can land in financial-crimes territory you don't want to be in.

### Less likely but catastrophic

- **Foreign nation-state interest.** If the platform releases classified
  Russian/Chinese/Israeli/etc. material to journalists, the operator
  becomes a target of that state's intelligence services. Tor protects
  against idle observers and casual investigation; it does *not* protect
  against a state actor with patience, infrastructure, and time.
- **Physical risk to the operator.** Sounds dramatic. It's on the table
  for any platform whose explicit purpose is "publish secrets if I die."
  If a user is being actively suppressed and their adversary identifies
  you as the platform operator, you become a target instead of, or in
  addition to, the user.
- **Cascade abuse.** One credible bad case is enough for a press cycle
  that names you. Once that happens, the platform can become a focal
  point for similar use, multiplying every risk above.

---

## What hosting "anonymously" via Tor does and doesn't buy you

It buys you:

- Latency between the cause (your instance is reachable via this
  `.onion`) and the effect (someone who wants to know who you are can
  ask the right person at the right ISP). Not zero, just slower.
- Protection against passive scanning, opportunistic listing, and
  blanket law-enforcement requests of clearnet hosts.
- Some legal-process *friction*: the path to subpoenaing your hosting
  provider goes through more steps when your service is `.onion`-only.

It does NOT buy you:

- Protection against operational mistakes you make: clearnet leaks via
  email setup, payment trails for the VPS, SSH from your home IP,
  uploading the wrong file, or correlating browsing patterns with the
  service's online windows.
- Protection against a state actor that has decided you're worth the
  effort. They will deanonymize you on a long enough timeline.
- Legal protection. If anything, hosting "anonymously" *removes* the
  defenses of having a known legal entity, a lawyer on retainer, and
  formal due process. When something goes wrong on a clearnet host with
  a known operator in a friendly jurisdiction, you have *process* to
  invoke. When something goes wrong on a hidden service, you have only
  the hope of staying hidden.

The intuition that "anonymous hosting = safer" is often wrong above a
certain threshold of seriousness. Anonymous-but-discoverable is the
worst of both worlds.

---

## What changes the calculus

### Toward "host it"

- You're in a jurisdiction with strong intermediary-liability shielding
  *and* strong precedent against compelled disclosure (Iceland,
  Switzerland, parts of Germany, possibly Costa Rica — all of which
  change over time, so verify before you act).
- You're hosting in a legal capacity that limits blowback: an LLC with
  no other assets you care about; a non-profit with explicit press-
  freedom mission; under a foundation that has run platforms like this
  before.
- You have a real lawyer on retainer who has *read this codebase* and
  signed off on your operating model.
- You have written down, in advance, what you'll do when (not if) the
  first abuse case hits and the first subpoena lands.
- You can comfortably absorb the bad case — financially and emotionally
  — not just the median case.

### Toward "don't host it"

- You'd be the sole operator with no legal infrastructure behind you.
- You're in a jurisdiction with key-disclosure laws (UK, France,
  Australia, India, others — list grows).
- The pitch leans into "leak securely" / "release classified info"
  language. That framing is what makes you the sympathetic-target case
  for Espionage-Act-style theories.
- You're not equipped to handle the abuse cases — the harassment-on-
  timer ones, the suicide-note-with-deadline ones, the
  obvious-fraud-with-victims ones.
- You're hoping nobody will actually use it.

If most of the second list applies, **don't host it for anyone but
yourself.** Self-host for personal use, publish the code so others can
do the same, and decline the operator role.

---

## Middle paths

If the answer to "host it for the public?" is no but the answer to
"build it and ship it?" is still yes:

### 1. Build it, don't host it

Publish the code under a strong copyleft license (AGPL is a sane
default) and document self-hosting clearly. Each user runs it on their
own infrastructure; you carry no operator risk. The threat-model writeup,
the runbook, the multi-cloud guide, the setup script *become the
deliverable*. This is what most well-respected privacy projects ended
up doing: Standard Notes, Bitwarden, Mastodon, Vaultwarden, and so on.
The maintainers carry far less personal risk than the hosted-service
operators.

### 2. Host it with a tight content scope

If you must host for others, consider refusing certain destination
kinds entirely. For example, configure the deployment to *disable*
public-page release mode (set `release_mode = private` only — email and
webhook destinations to user-named recipients, no auto-publish). That
removes the auto-Wikileaks failure mode without losing the deadman
utility for last-wishes / source-protection cases. The code supports
this: edit the policy creation handler to refuse `limited_public` /
`full_public` modes.

### 3. Host it openly, not anonymously

Counter-intuitive, but: clearnet hosting under your real identity in a
friendly jurisdiction with a lawyer means you have *legal process* to
invoke when something goes wrong. Tor + anonymous means when something
goes wrong, you have *no defense structures* — only the hope that your
operational security held. Once it doesn't, you have nothing.

### 4. Wait

The platform does not need to ship next month. Watch what happens to
similar projects. Talk to EFF, Freedom of the Press Foundation, the
Tor Project's legal contacts. Read the Wikileaks legal record start to
finish. Read SecureDrop's threat model. Talk to operators who have
shut down platforms like this and ask them what they wished they'd
known.

---

## If you decide to host anyway: minimum baseline

If you've read all of the above and still want to be the operator,
here's the minimum prep you owe yourself:

- **Engage a lawyer**, in your jurisdiction, who has read this code
  and your threat model. Not "I'll find one if something happens" —
  one you can call right now.
- **Form a legal entity** that owns the operation. LLCs are cheap and
  the asset-segregation matters more than people expect.
- **Pick the jurisdiction deliberately.** The host's location, the
  entity's location, your physical location, and the user base's
  location are four different jurisdictions and they all matter.
- **Write an abuse-response policy** before you launch. Not after the
  first incident. A simple decision tree: what kinds of abuse you'll
  suspend a policy for, who decides, what notification looks like,
  what record you keep. The admin panel's `/ui/admin/policies` →
  Suspend action is the technical lever for this; the policy is what
  governs *when you pull it*.
- **Write a subpoena-response policy** before you launch. Who do calls
  go to. What format you respond in. What you preserve and what you
  notify users about.
- **Get a security audit** of the running code, not just the code you
  read. Self-hosting via the setup script means the running code = the
  published code, which is something — but get a third-party audit
  before any high-stakes user puts material into the system.
- **Plan the off-ramp.** Under what conditions do you shut the platform
  down, on what timeline, with what user notice. Write it down. The
  hardest moment to make this decision is when you're already in it.

---

## A short list of things this platform *cannot* do for you

- It cannot make a release lawful that wasn't already lawful.
- It cannot make a recipient willing to receive material they don't want.
- It cannot protect you from a host you don't trust.
- It cannot survive a competent state-level adversary indefinitely.
- It cannot replace legal infrastructure.

It can keep your data confidential against the operator (the math is
sound), execute on a schedule reliably (the engine is real), and produce
verifiable evidence of what it did and didn't do (the audit log is
signed). Those are useful properties. They are not, by themselves, a
license to host anything.

---

## Reading list, if you want to think about this more

- The SecureDrop threat model and operating documentation — they have
  thought about a closely-related problem space for over a decade.
- *The Right to Information* (UK), and the experience of operators
  under it.
- Press-freedom-organization writeups on the Assange case, especially
  the Espionage Act analyses by the Knight First Amendment Institute.
- Tor Project's "Onion Services Operator" docs.
- EFF's "Surveillance Self-Defense" and "Operational Security for
  Activists" materials.

None of these will tell you what to do. They'll all give you better
material to think with than this document can.
