//! Thin shim over `tracing` macros so the rest of the crate can call
//! [`info!`], [`debug!`], [`async_warn!`], [`error!`], and [`trace!`]
//! without sprinkling `#[cfg(feature = "tracing")]` at every call site.
//!
//! When the `tracing` feature is off the macros expand to nothing, so
//! release builds without observability pay zero cost. When the
//! feature is on they delegate to the real `tracing` crate macros.
//!
//! `warn` is aliased to `async_warn` because a bare `warn` identifier
//! collides with the built-in `#[warn(...)]` lint attribute when
//! re-exported through `pub(crate) use`. The same trick `justrdp-blocking`
//! uses (`blk_warn`) — same rationale.

#![allow(unused_imports, unused_macros)]

#[cfg(feature = "tracing")]
macro_rules! info {
    ($($tt:tt)*) => { tracing::info!($($tt)*) };
}
#[cfg(feature = "tracing")]
macro_rules! debug {
    ($($tt:tt)*) => { tracing::debug!($($tt)*) };
}
#[cfg(feature = "tracing")]
macro_rules! async_warn {
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

#[cfg(not(feature = "tracing"))]
macro_rules! info {
    ($($tt:tt)*) => {};
}
#[cfg(not(feature = "tracing"))]
macro_rules! debug {
    ($($tt:tt)*) => {};
}
#[cfg(not(feature = "tracing"))]
macro_rules! async_warn {
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

pub(crate) use {async_warn, debug, error, info, trace};
