//! IDPS firewalld library.
//!
//! Exposes the firewall daemon modules for testing and integration.

/// Shared daemon state.
pub mod app;
/// Runtime configuration.
pub mod config;
/// Data plane abstraction.
pub mod dataplane;
/// Placeholder event pipeline namespace.
pub mod event;
/// Placeholder identity namespace.
pub mod identity;
/// Placeholder IDPS transport namespace.
pub mod idps;
/// Operational diagnostics namespace.
pub mod ops;
/// Persistence namespace.
pub mod persistence;
/// Reporter namespace.
pub mod reporter;
/// Rule management namespace.
pub mod rule;
/// Lifecycle runtime.
pub mod runtime;
/// Signal handling.
pub mod signal;
/// Traffic aggregation namespace.
pub mod traffic;
