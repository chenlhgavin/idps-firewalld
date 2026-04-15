//! Traffic window models.

use crate::dataplane::stats::GlobalStats;
use crate::traffic::aggregate::AppTrafficSummary;

/// Closed global traffic window.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GlobalTrafficWindow {
    /// Window start.
    pub window_start: u64,
    /// Window end.
    pub window_end: u64,
    /// Aggregated stats.
    pub stats: GlobalStats,
}

/// Closed app traffic window.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppTrafficWindow {
    /// Window start.
    pub window_start: u64,
    /// Window end.
    pub window_end: u64,
    /// App summaries.
    pub apps: Vec<AppTrafficSummary>,
}
