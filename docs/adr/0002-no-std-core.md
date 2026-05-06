# `no_std` core + `extern crate alloc`

## Decision

`justrdp-core`, `justrdp-pdu`, and the protocol-only downstream crates are all
built `#![no_std] + extern crate alloc`. `std` is only depended on in the I/O
and runtime layers (`justrdp-blocking`, `justrdp-tokio`, `justrdp-web`, etc.).

## Why

- **WASM** (`justrdp-web`) — `std::net` / `std::thread` are meaningless in the
  browser.
- **Minimal-FFI binary** (future `justrdp-ffi`) — when a C host pulls in only
  the RDP client core, we want to avoid the `std` runtime overhead.
- **Embedded / unconventional hosts** — not an explicit roadmap target, but
  kept open as an option.

## Consequences

- All PDU code is restricted to `alloc::vec::Vec` / `alloc::string::String`.
- Every file in the affected crates carries the `#![forbid(unsafe_code)]` +
  `#![no_std]` ceremony at the top.
- The `justrdp-derive` proc-macro must be careful that its generated code
  doesn't accidentally depend on `std`.
