# Pure-Rust crypto, no external crypto crate

## Decision

All crypto primitives in JustRDP (RC4, AES, DES, RSA, SHA-1/256, MD5, HMAC,
DH, big-int) are implemented *directly* inside `justrdp-core`. We do not
depend on any external crypto crate (`ring`, `aws-lc-rs`, the RustCrypto
family, `openssl`, etc.).

## Why

- **Compatible with the `no_std` core** (ADR-0002). Almost every mainstream
  crypto crate either pulls in `std` or transitively pulls in C.
- **Zero C transitive deps** — important for WASM (`justrdp-web`) and for the
  minimal-FFI-binary path, where `cc`/`cmake`-built dependencies are a
  liability.
- **RDP mandates *deprecated* algorithms** (RC4 + DES inside Standard RDP
  Security). Most modern crypto crates remove them on principle, so depending
  on an external crate would force us to bring in a *second* crate just to
  cover those.

## Considered options

- **`ring`** — `std`, C deps, no RC4/DES.
- **`aws-lc-rs`** — `std`, C deps.
- **RustCrypto family** (`aes`, `rc4`, `des`, `rsa`, `sha2`) — pure Rust, but
  `no_std` support is patchy across crates and feature-gated inconsistently;
  the surfaces we need (especially the byte-exact shapes of `bignum` / `dh`)
  don't map cleanly.
- **`openssl`** — C dependency plus licensing/porting overhead.

## Consequences

- Every crypto change must be validated against NIST/RFC test vectors
  directly (CLAUDE.md rule).
- When a PR proposes "let's just use crate X for crypto", point to this ADR.
