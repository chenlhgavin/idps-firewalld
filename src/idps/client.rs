//! Thin `idps-client` wrapper used by the firewall daemon.

use std::time::Duration;

use anyhow::{Result, anyhow};
use async_trait::async_trait;
use idps_client::client::IdpsClient;
use idps_client::error::ClientError;
use idps_client::events::EventSubscription;
use idps_client::register::PreparedRegisterRequest;
use idps_client::report::SecurityEvent;
use idps_client::rule::{RuleLoadResult, RuleSubscription};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::config::FirewallConfig;
use crate::idps::events::IntegrationEvent;

/// Firewall daemon integration surface for the IDPS transport.
#[async_trait]
pub trait FirewalldClient: Send {
    /// Subscribe to inbound client events.
    fn subscribe_events(&self) -> FirewalldEventSubscription;

    /// Register the daemon with the server.
    async fn register(&self) -> Result<PreparedRegisterRequest, ClientError>;

    /// Subscribe to live firewall or traffic rule updates.
    async fn subscribe_rule(
        &self,
        acd: i32,
        fun: i32,
        prot_ver: i32,
        ver: i32,
        poll_interval: Option<Duration>,
    ) -> Result<RuleSubscription, ClientError>;

    /// Load a one-shot rule snapshot.
    async fn load_rule(
        &self,
        acd: i32,
        fun: i32,
        prot_ver: i32,
        ver: i32,
        poll_interval: Option<Duration>,
        timeout: Duration,
    ) -> Result<RuleLoadResult, ClientError>;

    /// Upload a security event.
    async fn report(&self, event: SecurityEvent) -> Result<(), ClientError>;
}

/// Event subscription wrapper that yields simplified integration events.
#[derive(Debug)]
pub struct FirewalldEventSubscription {
    inner: SubscriptionInner,
}

#[derive(Debug)]
enum SubscriptionInner {
    Real(EventSubscription),
    Mock(mpsc::UnboundedReceiver<IntegrationEvent>),
}

impl FirewalldEventSubscription {
    fn new(inner: EventSubscription) -> Self {
        Self {
            inner: SubscriptionInner::Real(inner),
        }
    }

    fn mock() -> Self {
        let (_tx, rx) = mpsc::unbounded_channel();
        Self {
            inner: SubscriptionInner::Mock(rx),
        }
    }

    /// Receive the next mapped integration event.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying event subscription closes or lags.
    pub async fn recv(&mut self) -> Result<IntegrationEvent> {
        match &mut self.inner {
            SubscriptionInner::Real(inner) => {
                let event = inner.recv().await.map_err(|error| anyhow!(error.to_string()))?;
                Ok(IntegrationEvent::from_client_event(event))
            }
            SubscriptionInner::Mock(inner) => inner
                .recv()
                .await
                .ok_or_else(|| anyhow!("mock firewalld event stream closed")),
        }
    }
}

/// Real `idps-client` adapter.
#[derive(Debug)]
pub struct FirewalldSdkClient {
    inner: IdpsClient,
}

impl FirewalldSdkClient {
    /// Connect to the IDPS server and bootstrap the client.
    ///
    /// # Errors
    ///
    /// Returns an error if runtime config loading or transport bootstrap fails.
    pub async fn connect(config: &FirewallConfig, cancellation: CancellationToken) -> Result<Self, ClientError> {
        let client_config = idps_client::runtime_config::load_client_config_from_path(
            config.runtime_config_path.clone(),
        )?;
        let inner = IdpsClient::connect_and_bootstrap_with_retry(
            client_config,
            idps_client::transport::reconnect::ReconnectConfig::default(),
            cancellation,
        )
        .await?;
        Ok(Self { inner })
    }

}

#[async_trait]
impl FirewalldClient for FirewalldSdkClient {
    fn subscribe_events(&self) -> FirewalldEventSubscription {
        FirewalldEventSubscription::new(self.inner.subscribe_events())
    }

    async fn register(&self) -> Result<PreparedRegisterRequest, ClientError> {
        self.inner.register().await
    }

    async fn subscribe_rule(
        &self,
        acd: i32,
        fun: i32,
        prot_ver: i32,
        ver: i32,
        poll_interval: Option<Duration>,
    ) -> Result<RuleSubscription, ClientError> {
        self.inner
            .subscribe_rule(acd, fun, prot_ver, ver, poll_interval)
            .await
    }

    async fn load_rule(
        &self,
        acd: i32,
        fun: i32,
        prot_ver: i32,
        ver: i32,
        poll_interval: Option<Duration>,
        timeout: Duration,
    ) -> Result<RuleLoadResult, ClientError> {
        self.inner
            .load_rule(acd, fun, prot_ver, ver, poll_interval, timeout)
            .await
    }

    async fn report(&self, event: SecurityEvent) -> Result<(), ClientError> {
        self.inner.report(event).await
    }
}

/// Test double for the IDPS integration layer.
#[derive(Debug, Default)]
pub struct MockFirewalldClient {
    /// Recorded registration attempts.
    pub register_calls: std::sync::atomic::AtomicUsize,
}

#[async_trait]
impl FirewalldClient for MockFirewalldClient {
    fn subscribe_events(&self) -> FirewalldEventSubscription {
        FirewalldEventSubscription::mock()
    }

    async fn register(&self) -> Result<PreparedRegisterRequest, ClientError> {
        self.register_calls
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Err(ClientError::InvalidRuntimeConfig(
            "mock register not implemented".to_string(),
        ))
    }

    async fn subscribe_rule(
        &self,
        _acd: i32,
        _fun: i32,
        _prot_ver: i32,
        _ver: i32,
        _poll_interval: Option<Duration>,
    ) -> Result<RuleSubscription, ClientError> {
        Err(ClientError::InvalidRuntimeConfig(
            "mock subscribe_rule not implemented".to_string(),
        ))
    }

    async fn load_rule(
        &self,
        _acd: i32,
        _fun: i32,
        _prot_ver: i32,
        _ver: i32,
        _poll_interval: Option<Duration>,
        _timeout: Duration,
    ) -> Result<RuleLoadResult, ClientError> {
        Err(ClientError::InvalidRuntimeConfig(
            "mock load_rule not implemented".to_string(),
        ))
    }

    async fn report(&self, _event: SecurityEvent) -> Result<(), ClientError> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::Ordering;

    use super::{FirewalldClient, MockFirewalldClient};

    #[tokio::test]
    async fn mock_client_tracks_register_attempts() {
        let client = MockFirewalldClient::default();
        let _ = client.register().await;
        assert_eq!(client.register_calls.load(Ordering::SeqCst), 1);
    }
}
