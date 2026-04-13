//! Firewalld-facing wrappers around `idps-client` event types.

use idps_client::events::{ClientEvent, ClientOperation};

/// Simplified event stream items consumed by the firewall daemon runtime.
#[derive(Debug, Clone)]
pub enum IntegrationEvent {
    /// Registration completed successfully.
    RegistrationSucceeded(i32),
    /// The server acknowledged a report upload.
    ReportAcknowledged,
    /// The transport disconnected.
    Disconnected(String),
    /// A request failed while the client was connected.
    RequestFailed {
        /// Operation that failed.
        operation: ClientOperation,
        /// Human-readable failure summary.
        message: String,
    },
    /// Heartbeat payload surfaced by the client SDK.
    Heartbeat,
}

impl IntegrationEvent {
    /// Convert a raw `idps-client` event into a simplified integration event.
    #[must_use]
    pub fn from_client_event(event: ClientEvent) -> Self {
        match event {
            ClientEvent::RegistrationResult(response) => {
                Self::RegistrationSucceeded(response.state)
            }
            ClientEvent::ReportAck(_) => Self::ReportAcknowledged,
            ClientEvent::Disconnected(event) => Self::Disconnected(event.message),
            ClientEvent::RequestFailure(event) => Self::RequestFailed {
                operation: event.operation,
                message: event.message,
            },
            _ => Self::Heartbeat,
        }
    }
}

#[cfg(test)]
mod tests {
    use idps_client::events::{ClientEvent, DisconnectEvent, RequestFailureEvent};

    use super::IntegrationEvent;

    #[test]
    fn converts_disconnect_event() {
        let event = IntegrationEvent::from_client_event(ClientEvent::Disconnected(
            DisconnectEvent::new("network lost"),
        ));
        match event {
            IntegrationEvent::Disconnected(message) => assert_eq!(message, "network lost"),
            _ => panic!("unexpected event conversion"),
        }
    }

    #[test]
    fn converts_request_failure_event() {
        let event = IntegrationEvent::from_client_event(ClientEvent::RequestFailure(
            RequestFailureEvent::new(idps_client::events::ClientOperation::Rule, "boom"),
        ));
        match event {
            IntegrationEvent::RequestFailed { message, .. } => assert_eq!(message, "boom"),
            _ => panic!("unexpected event conversion"),
        }
    }
}
