//! Thin shim over `tracing` macros so the rest of the crate can call
//! [`info!`], [`debug!`], [`warn!`], [`error!`], and [`trace!`] without
//! sprinkling `#[cfg(feature = "tracing")]` at every call site.
//!
//! When the `tracing` feature is off the macros expand to nothing, so
//! release builds without observability pay zero cost. When the feature
//! is on they delegate to the real `tracing` crate macros.
//!
//! The macros live at crate root via `#[macro_use] mod telemetry;` in
//! `lib.rs`, so sibling modules call them by name (`info!`,
//! `blk_warn!`, etc.) without any `use` line. `warn` is aliased to
//! `blk_warn` because a bare `warn` identifier collides with the
//! built-in `#[warn(...)]` lint attribute when re-exported through
//! `pub(crate) use`.

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
