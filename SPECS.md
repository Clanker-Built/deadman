# Product Specification (Historical)

> **This document is the original full product specification.** It
> describes a multi-team, multi-year product. The actual lean build
> scoped down significantly:
>
> - **Built (M0–M5):** crypto core, threshold vault, state machine,
>   release engine, multi-cloud storage, admin panel, self-host
>   installer for Tor onion. See [`README.md`](README.md),
>   [`CHANGELOG.md`](CHANGELOG.md), and [`docs/`](docs/) for what's
>   actually shipping.
> - **Deferred:** native Android/iOS apps, social-network
>   integrations, trusted-contacts, organization features, HSM,
>   anti-takedown mirroring.
> - **Cut from scope:** SMS auth, hosted-service operations,
>   AI-assisted templates, desktop apps.
>
> Read this document for context on the original ambition, but use
> [`docs/threat-model.md`](docs/threat-model.md) and
> [`docs/crypto-spec.md`](docs/crypto-spec.md) as the authoritative
> reference for what the running code does.

## Project Name

**Deadman**
Secure deadman's switch and controlled-release platform

## 1. Purpose

Aegis Switch is software that allows a user to store protected materials and define a check-in schedule. If the user fails to check in within a user-defined grace period, the system automatically:

1. Releases selected protected materials to one or more destinations.
2. Optionally makes the material publicly accessible.
3. Optionally publishes preapproved announcements to the user’s linked website and social accounts.
4. Produces an immutable audit trail showing what happened, when, and under which policy.

The system must be highly secure, resilient across multiple cloud providers, usable through Android and iPhone apps, and configurable for personal, journalistic, legal, or business continuity use cases.

---

# 2. Core Goals

## 2.1 Functional goals

* Allow a user to define one or more deadman policies.
* Require periodic user check-ins via mobile app.
* Support user-defined check-in intervals measured in days.
* Trigger automated release when no valid check-in occurs before deadline plus grace rules.
* Support confidential storage of arbitrary digital assets.
* Support multiple release targets:

  * public web page
  * downloadable archive
  * email distribution
  * authorized website update
  * authorized social media announcement
* Support multiple cloud providers for storage, compute, keys, and redundancy.
* Support delegated contacts and recovery options.

## 2.2 Security goals

* Ensure only the user can create or modify policies unless delegation is explicitly enabled.
* Prevent cloud provider staff, administrators, or attackers from reading protected content before trigger.
* Minimize trust in any single vendor or operator.
* Preserve integrity and provability of the release process.
* Resist account takeover, device theft, insider abuse, and cloud compromise.
* Make tampering evident.

## 2.3 Reliability goals

* Work despite the failure of one cloud provider or one region.
* Tolerate mobile connectivity issues and brief outages.
* Preserve accurate trigger timing.
* Ensure release is not silently skipped.

## 2.4 Safety goals

* Make irreversible publication difficult to configure accidentally.
* Require explicit user acknowledgement for public release and account posting.
* Support dry-run mode and staged escalation.
* Provide revocation, pause, and policy-lock options where applicable before trigger.

---

# 3. Non-Goals

* No unauthorized access to social media, websites, or third-party systems.
* No covert spyware, hidden surveillance, or device persistence.
* No bypass of MFA or account recovery protections on third-party platforms.
* No unreviewed AI-generated publication of sensitive claims.
* No guarantee that third-party platforms will accept or keep posts live.

---

# 4. High-Level System Overview

The platform has five major planes:

1. **Client plane**

   * Android app
   * iPhone app
   * optional web console
   * optional desktop admin portal

2. **Control plane**

   * policy management
   * scheduling engine
   * check-in verification
   * state machine for arming, grace, hold, trigger, release, complete

3. **Security plane**

   * cryptographic key management
   * end-to-end encryption
   * hardware-backed device identity
   * signing and audit logs
   * secret-sharing and threshold approvals

4. **Release plane**

   * content packaging
   * public publication
   * email distribution
   * website posting
   * social posting via authorized APIs or webhook endpoints

5. **Resilience plane**

   * multi-cloud orchestration
   * replicated metadata
   * object storage redundancy
   * queue failover
   * external watchdogs and independent verifiers

---

# 5. User Roles

## 5.1 Primary user

Owns data, defines policies, performs check-ins, links accounts, and approves release rules.

## 5.2 Delegate / trusted contact

Optional. Can verify user status, receive notices, or participate in threshold-based unsealing.

## 5.3 Organization administrator

Optional enterprise role. Can manage billing, compliance, and deployment settings, but should not be able to decrypt user payloads by default.

## 5.4 Compliance auditor

Read-only access to logs and system health, not to payload plaintext unless separately authorized.

## 5.5 System operator

Operates infrastructure, has minimal privileges, no default plaintext access.

---

# 6. Threat Model

## 6.1 Threats in scope

* Password theft
* Phishing against user credentials
* SIM swap against SMS-based auth
* Cloud credential compromise
* Insider abuse by operators
* Theft of a mobile device
* Malware on one user device
* One-cloud outage or region outage
* Unauthorized policy modifications
* Premature release
* Silent failure to release
* Rollback attacks on policy state
* API token theft for linked destinations
* Time manipulation attempts
* Queue poisoning
* Unauthorized deletion of stored content

## 6.2 Threats partially in scope

* Full compromise of all user devices
* Coercion of user by third parties
* Broad compromise of all clouds and all key shares simultaneously
* Government seizure in all operating regions

## 6.3 Threats out of scope

* User intentionally misconfiguring release content
* User voluntarily giving away their credentials
* Third-party platform censorship or content removal after posting

---

# 7. Security Principles

* **Zero-knowledge by default**: payload plaintext remains client-encrypted.
* **Least privilege**: each service holds only the permissions it needs.
* **Threshold trust**: decrypt/release operations can require multiple shares or conditions.
* **Defense in depth**: mobile auth, cloud IAM, cryptographic signatures, immutable logs.
* **Tamper evidence**: all critical state transitions are signed and logged append-only.
* **Separation of duties**: no single admin can alter policy and trigger release.
* **Explicit consent**: public posting destinations must be preauthorized by the user.
* **Safe defaults**: hold periods and warnings before irreversible publication.

---

# 8. Deployment Models

## 8.1 SaaS multi-tenant

Hosted by vendor, logical tenant isolation, user-managed keys optional.

## 8.2 Single-tenant managed

Dedicated cloud accounts/resources per customer, stronger isolation.

## 8.3 Self-hosted enterprise

Customer deploys control plane in their own cloud(s).

## 8.4 Hybrid

Vendor-managed control plane, customer-managed encrypted object storage and KMS.

---

# 9. Supported Cloud Providers

The design must support at minimum:

* AWS
* Microsoft Azure
* Google Cloud Platform

Optional extensibility:

* Cloudflare R2 / Workers
* Oracle Cloud
* DigitalOcean
* Backblaze B2
* Wasabi
* MinIO / S3-compatible self-hosted
* Kubernetes-based deployment on any provider

## 9.1 Provider abstraction layers

Abstract:

* object storage
* key management
* queues/pubsub
* relational storage
* secrets management
* compute/job runners
* CDN/public distribution
* monitoring/logging

Use interfaces so a tenant can mix:

* primary storage on AWS S3
* backup storage on GCS
* control plane on Azure Kubernetes Service
* key shares split across AWS KMS, Azure Key Vault, and GCP KMS

---

# 10. Core Functional Requirements

## 10.1 Account creation

* Support email + passkey as preferred method.
* Support TOTP app-based MFA.
* SMS only as low-trust fallback with warnings.
* Support recovery codes.
* Optional identity verification for high-risk release profiles.

## 10.2 Device enrollment

* Android and iPhone apps must register a device identity.
* Device keypair generated in secure hardware when available:

  * Android Keystore / StrongBox
  * Apple Secure Enclave / Keychain
* Device attestation should be collected where possible.
* Device nickname, platform, and last-seen metadata visible to user.

## 10.3 Check-in policy

Each deadman policy includes:

* title
* description
* protected content set
* check-in interval in days
* grace period
* escalation schedule
* release destinations
* posting templates
* confirmation requirements
* pause/resume settings
* emergency hold rules
* trusted contacts
* jurisdiction/compliance options

## 10.4 Check-in actions

A valid check-in may occur via:

* mobile app tap
* biometric-confirmed check-in
* challenge-response inside app
* passkey confirmation
* optional location-consistent check-in if enabled
* optional external hardware key confirmation

Check-in should require:

* an authenticated session
* proof-of-presence on enrolled device
* recent biometric or device unlock event where permitted
* signed nonce from server to prevent replay

## 10.5 Deadlines

The user specifies:

* interval in days
* preferred warning cadence
* grace period in hours/days
* maximum offline tolerance
* quiet hours for notifications

The system computes:

* next due date
* soft-miss time
* grace expiration
* trigger time
* release waves

## 10.6 Warning and escalation

Before release, the system can:

* send push notifications
* send email alerts
* send SMS alerts if enabled
* alert trusted contacts
* initiate hold workflow
* require second-factor reconfirmation if a suspicious pattern is detected

## 10.7 Release modes

Support:

* **private release** to named recipients
* **limited public release** through signed URL or public page
* **full public release** with indexable public page and optional mirrors
* **announcement-only mode** that posts links rather than raw content
* **staged release** where some materials are released first, full archive later

## 10.8 Public advertising

Only through authorized, prelinked channels:

* website CMS or static site deployment
* RSS/Atom feed
* Mastodon-compatible APIs
* X/Twitter if platform/API permits and user authorization is valid
* Facebook Page if user authorization is valid
* LinkedIn Page/profile if user authorization is valid
* Bluesky if API/app password integration is valid
* WordPress
* Ghost
* custom webhook
* email newsletter provider webhook
* GitHub Pages / static site repo commit action

All such posting must be:

* preconfigured
* revocable before trigger
* previewable
* logged
* retried safely
* rate-limited
* failure-reported

---

# 11. Protected Content Model

## 11.1 Content types

* documents
* images
* archives
* videos
* audio
* structured notes
* public statements
* contact lists
* external links
* hashes and signatures
* release instructions

## 11.2 Content bundles

A bundle contains:

* encrypted payload objects
* manifest
* metadata
* signatures
* retention policy
* destination mapping
* optional embargo dates
* optional mirror targets

## 11.3 Manifest schema

Must include:

* bundle ID
* version
* owner ID
* creation timestamp
* content hashes
* MIME types
* encryption metadata
* release conditions
* destination list
* public filenames/slugs
* announcement templates
* integrity signatures

---

# 12. Mobile App Requirements

## 12.1 Common mobile requirements

* Native or high-quality cross-platform implementation
* Offline-capable local UI
* local encrypted cache only for minimal metadata
* no local plaintext cache of payloads unless explicitly enabled
* biometric gate for app open
* secure screenshot handling options
* jailbreak/root detection with policy controls
* strong notification support
* account and device management
* time-sensitive notifications
* accessibility compliance

## 12.2 Android-specific

* Use Android Keystore for device keys
* Prefer StrongBox when present
* Support Play Integrity or equivalent attestation
* Handle OEM battery optimization issues for reminder reliability
* Background scheduling with WorkManager
* Push via FCM

## 12.3 iPhone-specific

* Use Secure Enclave-backed keys where available
* APNs push notifications
* Background refresh within OS limits
* critical alerts optional if entitlement/business case permits
* use Face ID / Touch ID for biometric approval

## 12.4 Check-in UX

The app must make it hard to miss:

* home screen shows next due date prominently
* color-coded status: healthy, warning, grace, triggered
* one-tap check-in after auth
* optional “check in for next N days” disabled by default
* travel mode
* temporary pause with re-auth and cooldown
* notification escalation ladder

## 12.5 Anti-replay / anti-fraud

Each check-in:

* fetches server nonce
* signs nonce with device key
* binds to current session and device ID
* includes monotonic client counter if available
* server validates timestamp tolerance and signature

---

# 13. Policy State Machine

States:

1. Draft
2. Armed
3. Healthy
4. Warning
5. Grace
6. Hold
7. Triggered
8. Releasing
9. Released
10. Failed-Partial
11. Suspended
12. Revoked

Transitions must be explicit, signed, and logged.

Examples:

* Healthy -> Warning when due date passes
* Warning -> Grace after configured period
* Grace -> Hold if trusted contact workflow is active
* Grace/Hold -> Triggered when no valid check-in or intervention occurs
* Triggered -> Releasing once unseal criteria are met
* Releasing -> Released when target threshold met
* Releasing -> Failed-Partial when some destinations fail
* Any active state -> Suspended by valid user action before trigger completion

---

# 14. Cryptographic Architecture

## 14.1 Encryption model

Use client-side encryption before upload.

Recommended approach:

* Each content bundle gets a random symmetric data encryption key.
* Data encrypted using modern authenticated encryption.
* Bundle key wrapped by a policy key.
* Policy key protected through threshold or split-key design.

## 14.2 Key hierarchy

* Root user identity key
* Device keys
* Policy key
* Bundle keys
* Destination signing keys where applicable

## 14.3 Key storage

Options:

* user-managed passphrase-derived wrapping key
* hardware-backed mobile key wrapping
* cloud KMS-wrapped shares
* trusted-contact threshold shares
* hardware security module for service-level signing only

## 14.4 Threshold release

For maximum security, support M-of-N unseal strategies:

* 1-of-1 user-only
* 2-of-3 across clouds
* 2-of-3 user + cloud share + escrow share
* 3-of-5 with trusted contacts

This reduces single-vendor risk.

## 14.5 Signatures

* Every policy mutation signed by authenticated user session.
* Every check-in signed by device key.
* Every release manifest signed by service release key and optionally user key.
* Public artifacts should include signatures and checksum files.

## 14.6 Cryptographic agility

Allow algorithm/version migration with rewrapping tools and manifest versioning.

---

# 15. Multi-Cloud Architecture

## 15.1 Storage redundancy

* Primary encrypted objects in one provider
* Secondary replica in another provider
* Optional tertiary cold copy
* Hash consistency checks across providers
* Periodic restore tests

## 15.2 Metadata redundancy

Use strongly consistent relational store or distributed metadata layer with:

* leader/follower or multi-region design
* write-ahead logs
* versioned policy records
* immutable audit ledger

## 15.3 Queueing and scheduling

Avoid single queue dependence:

* primary scheduler
* cross-cloud mirrored trigger queue
* external watchdog that verifies expected trigger executions

## 15.4 Key share distribution

Split key custody:

* share A in AWS KMS/HSM
* share B in Azure Key Vault/HSM
* share C in GCP KMS/HSM
* optional share D in customer-managed HSM
* optional share E held by trusted contact escrow

## 15.5 Failover

The system should continue functioning if:

* one cloud provider fails
* one region fails
* one queue system fails
* one storage backend becomes unavailable
* one KMS backend is temporarily unavailable but threshold still satisfied

---

# 16. Release Engine

## 16.1 Trigger conditions

Trigger only when:

* due date + grace + optional hold period expires
* no valid check-in exists
* no administrator/manual suspension applies
* policy integrity checks pass
* required key shares are available
* release not blocked by legal hold or explicit enterprise rule

## 16.2 Pre-release validation

Before publishing:

* verify policy hash
* verify content hashes
* verify destination tokens still valid if required
* verify signing materials available
* produce release plan
* snapshot immutable audit event
* optionally notify delegates of imminent release if policy says so

## 16.3 Release packaging

Generate:

* public archive
* public landing page
* machine-readable manifest
* checksums
* signatures
* announcement texts
* mirror payloads

## 16.4 Destination execution

Release engine executes actions in ordered phases:

1. unseal content
2. package
3. publish primary landing page
4. verify accessibility
5. send recipient notifications
6. post announcements to linked channels
7. mirror to backup public destinations
8. finalize audit report

## 16.5 Idempotency

Every release action must be idempotent using release transaction IDs.

## 16.6 Partial failure behavior

If some destinations fail:

* keep primary public release live if successful
* retry failed destinations with backoff
* mark state Failed-Partial if threshold of destinations not met
* notify configured recipients/monitors

---

# 17. Website and Social Integrations

## 17.1 General rules

* Only supported via explicit user authorization.
* Store least-privilege tokens.
* Scope tokens narrowly.
* Encrypt tokens with dedicated integration key.
* Regularly verify token validity.
* Show permission inventory to user.

## 17.2 Website publishing methods

Support:

* CMS API publish
* static page upload to object storage + CDN
* Git commit to a website repo
* webhook to user infrastructure
* WordPress/Ghost plugin
* signed deploy hook to Netlify/Vercel/Cloudflare Pages

## 17.3 Social posting methods

Support official or allowed APIs where possible.
For each platform, define:

* auth method
* supported post types
* media constraints
* fallback behavior
* retry policy
* rate limits
* token refresh behavior

## 17.4 Post templates

User can define:

* short announcement
* long announcement
* website post
* platform-specific variants
* localized variants

Template variables:

* user display name
* policy title
* public URL
* release timestamp
* checksum URL
* mirror URLs
* optional legal notice

## 17.5 Safeguards

* preview all posts before arming policy
* require explicit consent checkbox for public posting
* support “publish link only” instead of raw content
* require re-auth when linking new public channels
* require cooling-off delay before enabling irreversible destinations

---

# 18. Notifications

Support:

* mobile push
* email
* SMS optional
* webhook
* delegate alerts
* pager integration for enterprise admins

Notification events:

* policy armed
* due soon
* overdue
* grace started
* hold started
* release imminent
* release triggered
* release completed
* destination failed
* token expired
* suspicious login/check-in
* new device enrolled

---

# 19. Trusted Contacts and Delegation

## 19.1 Trusted contacts

Can be used for:

* emergency hold
* status verification
* threshold key shares
* notification recipients
* release witnesses

## 19.2 Delegated actions

Per policy:

* may request hold
* may confirm user safe
* may not modify content unless explicitly allowed
* may not decrypt payload by default

## 19.3 Anti-abuse

* delegated actions always logged
* optional multiple-contact concurrence
* time-limited holds
* no silent suppression of trigger without audit trail

---

# 20. Admin and Web Console

Must provide:

* dashboard of policies and health
* due dates and recent check-ins
* destination management
* token status
* audit logs
* key custody view
* cloud redundancy health
* release simulation tools
* restore tests
* compliance export

Sensitive operations must require step-up authentication.

---

# 21. Auditability and Evidence

## 21.1 Immutable logging

All critical events appended to tamper-evident ledger:

* login
* device enrollment
* policy creation/update
* check-in
* pause/resume
* hold request
* token change
* trigger
* unseal
* publish
* post to destination
* retry/failure
* admin action

## 21.2 Log properties

* append-only
* signed
* time-stamped
* exportable
* cross-cloud replicated
* searchable
* retention configurable

## 21.3 Public evidence bundle

After release, optionally publish:

* signed manifest
* hashes
* timestamps
* destination success report
* release transaction ID

---

# 22. Privacy and Data Governance

## 22.1 Data minimization

Store minimal PII:

* account identity
* destination tokens
* encrypted metadata
* audit logs

## 22.2 Sensitive data handling

* payload content encrypted client-side
* no plaintext inspection by service unless user opts into server-side processing features
* minimal logging of payload metadata

## 22.3 Retention

User configurable:

* retain encrypted bundles after release
* delete after release
* archive cold copies
* scrub expired tokens
* redact older device telemetry

## 22.4 Compliance support

Design for:

* GDPR
* CCPA/CPRA
* SOC 2
* ISO 27001 alignment
* customer-managed regional residency where possible

---

# 23. Availability and Reliability Targets

## 23.1 Suggested SLOs

* control plane availability: 99.95%
* check-in API availability: 99.95%
* notification delivery initiation: 99.9%
* release initiation after trigger: within configured SLA
* cross-cloud replication RPO: near-zero for metadata, bounded for object replicas

## 23.2 Durability targets

* encrypted object durability aligned with multi-provider replication
* metadata backup with point-in-time restore
* quarterly disaster recovery drills

---

# 24. Observability

Collect:

* API latency and errors
* notification success
* queue lag
* replication lag
* KMS latency
* destination token failures
* release task status
* mobile push delivery metrics
* suspicious auth anomalies

Dashboards:

* policy health
* cloud health
* release readiness
* expiring integrations
* regional outage map

Alerts:

* missed scheduler heartbeat
* replica mismatch
* unseal failure
* token expiration
* audit log append failure
* unexpected policy mutation spikes

---

# 25. Misuse and Safety Guardrails

Because this product can cause irreversible public disclosure, safeguards are mandatory.

## 25.1 Arming safeguards

* confirm destination list
* confirm sample announcement
* confirm public URL preview
* re-authenticate
* acknowledge irreversible effects
* cooldown before first arm

## 25.2 High-risk content warnings

Warn users if they configure:

* full-public release
* very short intervals
* many social destinations
* broad recipient lists
* automatic website overwrite

## 25.3 Safe modes

* private escrow mode
* notify-only mode
* link-only public mode
* staged publication
* legal contact first, public later

## 25.4 Enterprise restrictions

Admins may prohibit:

* social posting
* raw public release
* posting to personal accounts
* use outside approved domains

---

# 26. API Requirements

## 26.1 Public API

For user-authorized operations:

* create/update policy
* enroll device
* initiate check-in
* manage destinations
* fetch status
* request hold
* export audit logs
* configure webhooks

## 26.2 Internal service APIs

* scheduler API
* trigger evaluator
* release executor
* destination connector interface
* key broker
* audit writer

## 26.3 API security

* OAuth 2.1 / OIDC
* mTLS for service-to-service where feasible
* signed requests for critical operations
* idempotency keys
* strict RBAC/ABAC
* rate limiting
* request provenance logging

---

# 27. Data Model

Core entities:

* User
* Device
* Policy
* PolicyState
* ContentBundle
* Manifest
* Destination
* IntegrationToken
* NotificationRule
* TrustedContact
* KeyShareReference
* AuditEvent
* ReleaseTransaction
* HoldRequest
* LegalRestriction

Important attributes:

* immutable version numbers
* created/updated by
* cryptographic hashes
* cloud location metadata
* region
* token scopes
* destination health
* trigger timestamps

---

# 28. Suggested Release Policy Schema

A policy should define:

* policy_id
* owner_id
* interval_days
* grace_period_hours
* warning_schedule
* hold_mode
* check_in_requirements
* content_bundle_ids
* destination_ids
* public_release_enabled
* social_post_enabled
* website_publish_enabled
* staged_release_plan
* key_unseal_policy
* delegate_rules
* notification_rules
* compliance_profile
* suspension_rules
* retention_rules

---

# 29. Failure Scenarios

## 29.1 User misses check-in due to outage

Mitigations:

* grace period
* multi-channel reminders
* travel mode
* offline notice in app
* trusted contact hold option

## 29.2 Lost or replaced phone

Mitigations:

* secondary enrolled devices
* passkey fallback
* recovery codes
* delayed device trust for newly enrolled device
* suspicious-login hold

## 29.3 Cloud provider outage

Mitigations:

* cross-cloud metadata replicas
* mirrored queues
* replicated encrypted objects
* split key shares

## 29.4 Third-party social token expired

Mitigations:

* preflight checks
* token expiry warnings
* fallback to website publication and email
* partial release reporting

## 29.5 Premature trigger from clock issues

Mitigations:

* server-side canonical time
* monotonic event ordering
* multiple evaluators
* no single-client time dependence

## 29.6 Insider tries to alter policy

Mitigations:

* signed policy versions
* immutable audit log
* no plaintext access
* dual control for admin overrides
* user notifications for every critical change

---

# 30. Testing Requirements

## 30.1 Security testing

* mobile app pen tests
* API authz tests
* cloud IAM reviews
* secret scanning
* dependency scanning
* KMS/key share recovery drills
* insider threat scenario testing
* phishing-resistant auth flow testing

## 30.2 Reliability testing

* chaos testing across clouds
* queue outage simulations
* region failover drills
* large bundle release tests
* token expiration tests
* scheduler drift tests

## 30.3 Functional testing

* end-to-end check-in
* grace transitions
* hold workflows
* staged release
* social/website publication
* partial failure retries
* public page verification

## 30.4 Compliance testing

* audit export correctness
* retention enforcement
* deletion workflows
* residency controls

---

# 31. Performance Requirements

* check-in action should complete quickly under normal conditions
* dashboard status updates near real-time
* release packaging scales to large bundles
* concurrent releases isolated per tenant
* destination connector pool rate-aware
* audit writes should not block release execution

---

# 32. UX Requirements

* status must be obvious and understandable
* no ambiguous armed/unarmed state
* all irreversible actions clearly labeled
* public preview before enabling public release
* explain why a check-in failed
* show countdown and deadlines in local time and UTC
* accessibility support for screen readers, large text, contrast, haptics

---

# 33. Legal/Policy Considerations

The product must support configurable terms and controls for:

* user ownership of uploaded content
* authorized publication only
* forbidden use categories
* abuse reporting
* export control where relevant
* lawful response procedures
* court-order hold workflow
* jurisdiction-aware public content hosting

---

# 34. Recommended Security Posture Options

## 34.1 Standard

* passkey + TOTP
* client-side encryption
* single-cloud primary + backup replica
* public release with warning ladder

## 34.2 High security

* passkey only
* two enrolled devices
* threshold key shares across 3 clouds
* trusted contact hold
* staged publication
* signed public evidence bundle

## 34.3 Enterprise hardened

* single-tenant
* customer-managed keys
* private network controls
* HSM-backed service signing
* SIEM integration
* legal hold and admin restrictions

---

# 35. Example Release Sequence

1. User sets interval to 14 days.
2. User misses due date.
3. Push and email warnings sent for 48 hours.
4. Grace begins for 72 hours.
5. Trusted contacts are notified that a hold can be requested.
6. No valid check-in or hold occurs.
7. Trigger event is signed and recorded.
8. Key shares are assembled according to policy.
9. Bundle is decrypted in controlled release worker memory.
10. Public landing page is published to preconfigured website/CDN.
11. Signed archive and checksums are uploaded.
12. Announcement posts are sent to authorized linked channels.
13. Success/failure report is generated and stored.
14. Final state moves to Released or Failed-Partial.

---

# 36. Minimum Viable Product

MVP should include:

* Android + iPhone apps
* account auth with passkey + TOTP
* one policy per user
* encrypted file bundle upload
* interval in days + grace period
* push/email reminders
* public landing page release
* one website integration
* one social integration
* audit logs
* AWS primary with GCP backup

---

# 37. Phase 2

* multiple policies
* trusted contacts
* threshold key shares
* Azure support
* staged release
* richer webhooks
* more social providers
* evidence bundle
* policy templates
* organization admin features

---

# 38. Phase 3

* self-hosted
* customer-managed HSM
* legal hold workflows
* delegated approval models
* advanced risk scoring
* AI-assisted template drafting with user review
* external independent watchdog network

---

# 39. Open Design Decisions

These need product/engineering decisions:

* whether release should ever be fully automatic without pre-release warning wave
* whether user can enable truly immediate public release after grace
* how much platform-specific social support is worth maintaining
* whether trusted contacts can prevent release or only delay it
* whether server-side plaintext processing is ever allowed
* whether public hosting should include anti-takedown mirroring
* whether policy changes require waiting periods before taking effect

---

# 40. Recommended Defaults

* interval: 14 days
* grace: 72 hours
* reminders: 7 days, 3 days, 1 day, due date, every 12 hours in grace
* require biometric + device signature for check-in
* private release first, public release optional
* social posting off by default
* staged release on by default for public mode
* at least 2 recovery methods
* at least 2 cloud replicas
* immutable audit logs enabled
* threshold key shares enabled for public release policies

---

# 41. Acceptance Criteria

The system is acceptable when:

* a user can reliably check in from Android or iPhone
* missing a deadline transitions policy correctly
* release occurs only under documented conditions
* public content is accessible and integrity-verifiable
* linked authorized channels can announce release when configured
* no operator can read payload plaintext by default
* one cloud outage does not prevent continued operation
* all critical actions appear in signed audit logs
* users can preview and understand consequences before arming a policy

---

# 42. Short Engineering Summary

This should be built as a **zero-knowledge, multi-cloud, policy-driven release platform** with:

* hardware-backed mobile identity
* signed check-ins
* threshold-protected keys
* replicated encrypted storage
* deterministic trigger evaluation
* auditable release workflows
* authorized publication integrations only

That combination gives the best balance of **security, reliability, and verifiable execution**.

If you want, I can turn this into a formal **PRD**, a **system architecture spec**, or a **database/API schema pack** next.

