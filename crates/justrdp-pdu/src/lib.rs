//! `justrdp-pdu` — RDP wire-format PDUs, encoded and decoded **sans-IO**.
//!
//! TPKT / X.224 / MCS / GCC / capability sets / fast-path / … : bytes in, typed PDUs out (and
//! back). No sockets, no async — this crate is pure (de)serialization so the [`justrdp`] core can
//! drive it from any runtime and tests can feed it captured bytes.
//!
//! See `docs/plan.md` §2 (Layer 0 — wire) and §3 (Layer 1 — connection sequence), and ADR-0001
//! (sans-IO state machine core).
