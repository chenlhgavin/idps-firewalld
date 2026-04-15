//! Runtime lifecycle state for the firewall daemon.

/// Daemon lifecycle phases.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimePhase {
    /// Loading configuration and local state.
    Init,
    /// Establishing the server transport bootstrap.
    Bootstrap,
    /// Registering the component.
    Registering,
    /// Synchronizing firewall and traffic rules.
    RuleSyncing,
    /// Initializing and programming the data plane.
    DataPlaneReady,
    /// Steady-state event, traffic, and report processing.
    Running,
    /// Recoverable connection loss handling.
    Reconnect,
    /// Graceful shutdown.
    Shutdown,
}

impl RuntimePhase {
    /// Return the stable string representation used by health snapshots.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Init => "Init",
            Self::Bootstrap => "Bootstrap",
            Self::Registering => "Registering",
            Self::RuleSyncing => "RuleSyncing",
            Self::DataPlaneReady => "DataPlaneReady",
            Self::Running => "Running",
            Self::Reconnect => "Reconnect",
            Self::Shutdown => "Shutdown",
        }
    }

    /// Parse a persisted runtime phase string.
    #[must_use]
    pub fn from_str(value: &str) -> Option<Self> {
        match value {
            "Init" => Some(Self::Init),
            "Bootstrap" => Some(Self::Bootstrap),
            "Registering" => Some(Self::Registering),
            "RuleSyncing" => Some(Self::RuleSyncing),
            "DataPlaneReady" => Some(Self::DataPlaneReady),
            "Running" => Some(Self::Running),
            "Reconnect" => Some(Self::Reconnect),
            "Shutdown" => Some(Self::Shutdown),
            _ => None,
        }
    }

    /// Return whether a transition is allowed by the stage-1 lifecycle model.
    #[must_use]
    pub const fn can_transition_to(self, next: Self) -> bool {
        matches!(
            (self, next),
            (Self::Init | Self::Reconnect, Self::Bootstrap)
                | (Self::Bootstrap, Self::Registering)
                | (Self::Registering, Self::RuleSyncing)
                | (Self::RuleSyncing, Self::DataPlaneReady)
                | (Self::DataPlaneReady, Self::Running)
                | (
                    Self::Bootstrap
                        | Self::Registering
                        | Self::RuleSyncing
                        | Self::DataPlaneReady
                        | Self::Running,
                    Self::Reconnect,
                )
                | (_, Self::Shutdown)
        )
    }
}

#[cfg(test)]
mod tests {
    use super::RuntimePhase;

    #[test]
    fn lifecycle_allows_nominal_path() {
        assert!(RuntimePhase::Init.can_transition_to(RuntimePhase::Bootstrap));
        assert!(RuntimePhase::Bootstrap.can_transition_to(RuntimePhase::Registering));
        assert!(RuntimePhase::Registering.can_transition_to(RuntimePhase::RuleSyncing));
        assert!(RuntimePhase::RuleSyncing.can_transition_to(RuntimePhase::DataPlaneReady));
        assert!(RuntimePhase::DataPlaneReady.can_transition_to(RuntimePhase::Running));
    }

    #[test]
    fn lifecycle_rejects_skipping_ready_state() {
        assert!(!RuntimePhase::Bootstrap.can_transition_to(RuntimePhase::Running));
    }

    #[test]
    fn lifecycle_allows_shutdown_from_any_state() {
        assert!(RuntimePhase::Init.can_transition_to(RuntimePhase::Shutdown));
        assert!(RuntimePhase::Running.can_transition_to(RuntimePhase::Shutdown));
    }
}
