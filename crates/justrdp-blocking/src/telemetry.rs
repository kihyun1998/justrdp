//! Thin shim over `tracing` macros so the rest of the crate can call
//! [`info!`], [`debug!`], [`blk_warn!`], [`error!`], and [`trace!`]
//! without sprinkling `#[cfg(feature = "tracing")]` at every call site.
//!
//! When the `tracing` feature is off the macros expand to nothing, so
//! release builds without observability pay zero cost. When the
//! feature is on they delegate to the real `tracing` crate macros.
//!
//! The macros are defined at module scope in this file and re-exported
//! via `pub(crate) use { ... }` so sibling modules pull them in with a
//! normal `use crate::telemetry::{info, debug, blk_warn, ...};` line —
//! this avoids the `#[macro_use]` mechanism, which historically
//! required defining macros with `#[macro_export]` and polluted the
//! crate-root namespace.
//!
//! `warn` is aliased to `blk_warn` because a bare `warn` identifier
//! collides with the built-in `#[warn(...)]` lint attribute when
//! re-exported through `pub(crate) use`; the other four macro names
//! (`info`, `debug`, `error`, `trace`) have no such conflict and are
//! re-exported unchanged.

#![allow(unused_imports, unused_macros)]

// Real-tracing forwarders.

#[cfg(feature = "tracing")]
macro_rules! info {
    ($($tt:tt)*) => { tracing::info!($($tt)*) };
}
#[cfg(feature = "tracing")]
macro_rules! debug {
    ($($tt:tt)*) => { tracing::debug!($($tt)*) };
}
#[cfg(feature = "tracing")]
macro_rules! blk_warn {
    ($($tt:tt)*) => { tracing::warn!($($tt)*) };
}
#[cfg(feature = "tracing")]
macro_rules! error {
    ($($tt:tt)*) => { tracing::error!($($tt)*) };
}
#[cfg(feature = "tracing")]
macro_rules! trace {
    ($($tt:tt)*) => { tracing::trace!($($tt)*) };
}

// Stub macros for the tracing-off path. Each one accepts any token
// tree and expands to nothing.

#[cfg(not(feature = "tracing"))]
macro_rules! info {
    ($($tt:tt)*) => {};
}
#[cfg(not(feature = "tracing"))]
macro_rules! debug {
    ($($tt:tt)*) => {};
}
#[cfg(not(feature = "tracing"))]
macro_rules! blk_warn {
    ($($tt:tt)*) => {};
}
#[cfg(not(feature = "tracing"))]
macro_rules! error {
    ($($tt:tt)*) => {};
}
#[cfg(not(feature = "tracing"))]
macro_rules! trace {
    ($($tt:tt)*) => {};
}

pub(crate) use {blk_warn, debug, error, info, trace};
