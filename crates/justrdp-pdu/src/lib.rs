//! `justrdp-pdu` — RDP wire-format PDUs, encoded and decoded **sans-IO**.
//!
//! TPKT / X.224 / MCS / GCC / capability sets / fast-path / … : bytes in, typed PDUs out (and
//! back). No sockets, no async — this crate is pure (de)serialization so the `justrdp` core can
//! drive it from any runtime and tests can feed it captured bytes.
//!
//! See `docs/plan.md` §2 (Layer 0 — wire) and §3 (Layer 1 — connection sequence), and ADR-0001
//! (sans-IO state machine core).

pub mod ber;
pub mod capability;
pub mod client_info;
pub mod cursor;
pub mod displaycontrol;
pub mod dvc;
pub mod egfx;
pub mod errinfo;
pub mod error;
pub mod fastpath;
pub mod finalization;
pub mod gcc;
pub mod input;
pub mod license;
pub mod mcs;
pub mod nego;
pub mod per;
pub mod pointer;
pub mod rfx;
pub mod share;
pub mod svc;
pub mod tpkt;
pub mod update;
pub mod x224;

pub use error::DecodeError;
