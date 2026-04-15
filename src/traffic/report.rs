//! Traffic report payload helpers.

use crate::traffic::window::{AppTrafficWindow, GlobalTrafficWindow};

/// Outbound traffic report payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrafficReport {
    /// Application flow summary.
    AppSummary(AppTrafficWindow),
    /// Global device summary.
    GlobalSummary(GlobalTrafficWindow),
}
