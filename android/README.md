# android/ — placeholder

No native Android source is in this repository. The directory is
reserved for the mobile app described in
[../SPECS.md](../SPECS.md), which is **not** in scope for the
v0.1.0 release.

In the meantime, browser access from Tor Browser for Android works
end-to-end: register, set up TOTP with an authenticator app on the
same device, check in, all from the phone.

If a native build later lands here, it will:

- Use Jetpack Compose + WorkManager.
- Hardware-back the device key in StrongBox where available.
- Use FCM high-priority pushes for escalation reminders.
- Speak the same `/api/v1/*` JSON contract as the existing server.
