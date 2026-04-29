# ios/ — placeholder

No native iOS source is in this repository. The directory is
reserved for the mobile app described in
[../SPECS.md](../SPECS.md), which is **not** in scope for the
v0.1.0 release.

In the meantime, Tor Browser is not available on iOS App Store; on
iPhone, Onion Browser is the closest substitute and supports the
platform's UI flows. Authenticator apps (Raivo, KeePassXC mobile,
1Password, Bitwarden) work fine alongside.

If a native build later lands here, it will:

- Use SwiftUI + BGTaskScheduler.
- Hardware-back the device key in the Secure Enclave.
- Use APNs for escalation reminders.
- Speak the same `/api/v1/*` JSON contract as the existing server.
