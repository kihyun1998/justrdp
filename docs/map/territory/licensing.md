# Licensing

## What it is

The RDP licensing exchange that runs between NLA and capability exchange: the server
sends a Server License Request (with its certificate and a random), the client
answers with a New License Request carrying an RSA-encrypted premaster secret, may
answer a Platform Challenge, and finally receives either a New License or —
overwhelmingly, in practice — a licensing error PDU that means *"proceed anyway"*.
The crypto is hand-rolled here: MD5/SHA-1 salted hashes, RC4, and a small bignum for
the RSA public-key operation.

## Governing decisions

**None.** No ADR is about licensing.

Adjacent but not governing: [ADR-0002](../../adr/0002-dependency-boundary.md)
decides that security-critical *non-RDP* crypto is delegated — licensing crypto is
RDP-native (`[MS-RDPELE]` 5.1), so it stays in-house by that rule rather than by a
decision of its own. That inference has never been written down as a record.

## Design model

- **A licensing "error" is the normal path.** Per-device CAL grants are the
  exception; the common outcome is `STATUS_VALID_CLIENT`, and treating a licensing
  error as a connect failure would break almost every real server.
- The premaster secret and the derived license keys follow `[MS-RDPELE]` 5.1.x
  verbatim; the entropy is host-supplied (`LicenseEntropy`) so the core stays
  deterministic and testable.
- `BigUint` exists only to do one modular exponentiation — a deliberate refusal to
  pull an RSA crate into the core for a single operation.

## Code

- `justrdp-pdu/src/license.rs` — `LicensePreamble`, `ServerLicenseRequest`,
  `ServerCertificate`, `RsaPublicKey`, `PlatformChallenge`, `NewLicense`,
  `encode_new_license_request`, `encode_platform_challenge_response`, `LicenseError`
- `justrdp/src/license_crypto.rs` — `derive_license_keys`,
  `encrypt_premaster_secret`, `salted_hash`, `mac_data`, `rc4`, `md5`, `sha1`,
  `BigUint`, `LicenseKeys`
- `justrdp/src/connect.rs` — `LicenseConfig`, `LicenseEntropy`
- `justrdp-tokio/src/lib.rs` — `generate_license_entropy`
- Spec sections cited inline: `[MS-RDPELE]` 2.2.2.5.1, 2.2.2.7, 3.2.5, 5.1.2, 5.1.6

## Reference behaviour

**None.** No verified external-fact store.

## Cross-cutting invariants

- [A decoded field with no reader is an unstated decision](../invariant/a-decoded-field-with-no-reader-is-an-unstated-decision.md)
  — `LicensePreamble.flags` (the protocol version in its low nibble) and `msg_size` (a
  declared length never compared to the actual body) have no readers anywhere, tests
  included.
- [Oracle agreement is not independence](../invariant/oracle-agreement-is-not-independence.md)
  — `differential_license_crypto` is this territory's *only* proof, and it compares
  against a codebase sharing this project's lineage. The VM cannot supplement it: it
  has no licensing server.
- [Untrusted decode never panics](../invariant/untrusted-decode-never-panics.md) — every
  message here is server-supplied, and #230 found four of the five parsers driven by neither
  artifact while the module read as covered. Listed only from that issue onward: the omission
  is why it read as covered.

## Blast radius

- [Capability exchange & activation](capability-exchange-activation.md) — licensing
  sits immediately before it; a mis-parse here surfaces there as a missing Demand
  Active.
- [NLA / CredSSP authentication](nla-credssp.md) — supplies the authenticated
  identity the licensing exchange assumes.
- [Verification harness](verification-harness.md) — `differential_license_crypto`
  is the only proof this crypto is right, and it compares against `ironrdp`.

## Known holes / open

- **The grant path is effectively unexercised.** The test VM has no licensing server,
  so only the "error = proceed" branch is proven end-to-end; New License and Platform
  Challenge rest on the differential test alone.
- Per-device CAL storage / reuse is not built, and nothing tracks it.
- The hand-rolled `rc4` / `md5` / `sha1` here are *protocol* primitives, not the
  security boundary — but nothing in the repo says so in a place a reader of this
  file would find, which is why this line exists.
