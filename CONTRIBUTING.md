# Contributing

This repository is published **as-is, with no warranty and no
support**, and **does not accept issues or pull requests from outside
contributors.** This is a deliberate choice, not a slight.

The threat model of a deadman's switch platform is unusually
sensitive: code that is reviewed and merged hastily can introduce
covert channels, weaken guarantees the documentation makes, or
silently shift the trust boundary. The maintainers are not staffed to
provide that level of review for unsolicited contributions, and a
half-reviewed PR is worse than no PR.

## What you can do instead

- **Read the source.** AGPL-3.0 — every line is open. The crypto is
  in `control/internal/crypto/`, the state machine in
  `control/internal/state/`, the audit ledger in
  `control/internal/audit/`. Start there.
- **Fork it.** The AGPL gives you the right; we encourage it. If you
  run a fork as a network service, the AGPL requires you to publish
  your modifications under the same license — see [LICENSE](LICENSE).
  This is a feature, not a hurdle: it is what makes the threat-model
  claims about "the running code matches the published code"
  enforceable.
- **Disclose security issues privately.** This is the only category
  of report we actively want. See [SECURITY.md](SECURITY.md).
- **Run a local instance and break it.** Self-hosting is the
  intended deployment posture; finding a way to subvert your own
  instance is exactly the kind of feedback the project benefits
  from, and a security disclosure is the right channel for it.

## What we will not do

- Triage feature requests.
- Help you install or operate an instance.
- Review unsolicited pull requests, even small ones.
- Engage with comments on commits or wiki pages.
- Publish a public roadmap.

## Forks

If you fork this and operate it as a hosted service, you are taking on
the operator risks described in
[docs/operator-risks.md](docs/operator-risks.md). Read that first.
The license requires you to publish your source; the threat model
requires you to be honest about what you've changed.

If your fork makes substantive changes that would alter users' trust
evaluation — different crypto, different audit semantics, removed
safeguards — please rename the project. "Deadman" the name, in the
context of this repository, refers to a specific set of guarantees.
A fork that drops or weakens those guarantees but keeps the name is
misleading.
