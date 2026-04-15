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
use idps_core::rule::depot::CachedRule;
use tokio::sync::{mpsc, watch};
use tokio_util::sync::CancellationToken;

use crate::config::FirewallConfig;
use crate::idps::events::IntegrationEvent;

/// Registration context returned by the firewalld client.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FirewalldRegistration {
    /// Active component code.
    pub acd: i32,
}

/// Rule subscription wrapper used by the runtime.
#[derive(Debug)]
pub struct FirewalldRuleSubscription {
    inner: RuleSubscriptionInner,
}

#[derive(Debug)]
enum RuleSubscriptionInner {
    Real(RuleSubscription),
    Mock(watch::Receiver<Option<CachedRule>>),
}

impl FirewalldRuleSubscription {
    fn new(inner: RuleSubscription) -> Self {
        Self {
            inner: RuleSubscriptionInner::Real(inner),
        }
    }

    fn mock(inner: watch::Receiver<Option<CachedRule>>) -> Self {
        Self {
            inner: RuleSubscriptionInner::Mock(inner),
        }
    }

    /// Return the latest currently available cached rule.
    #[must_use]
    pub fn current_rule(&self) -> Option<CachedRule> {
        match &self.inner {
            RuleSubscriptionInner::Real(inner) => inner.current_rule(),
            RuleSubscriptionInner::Mock(inner) => inner.borrow().clone(),
        }
    }

    /// Wait for the next rule update.
    ///
    /// # Errors
    ///
    /// Returns `ClientError::RuleSubscriptionClosed` if the stream is closed.
    pub async fn changed(&mut self) -> Result<(), ClientError> {
        match &mut self.inner {
            RuleSubscriptionInner::Real(inner) => inner.changed().await,
            RuleSubscriptionInner::Mock(inner) => inner
                .changed()
                .await
                .map_err(|_| ClientError::RuleSubscriptionClosed),
        }
    }
}

/// Firewall daemon integration surface for the IDPS transport.
#[async_trait]
pub trait FirewalldClient: Send + Sync {
    /// Subscribe to inbound client events.
    fn subscribe_events(&self) -> FirewalldEventSubscription;

    /// Register the daemon with the server.
    async fn register(&self) -> Result<FirewalldRegistration, ClientError>;

    /// Subscribe to live firewall or traffic rule updates.
    async fn subscribe_rule(
        &self,
        acd: i32,
        fun: i32,
        prot_ver: i32,
        ver: i32,
        poll_interval: Option<Duration>,
    ) -> Result<FirewalldRuleSubscription, ClientError>;

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

    /// Receive the next mapped integration event.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying event subscription closes or lags.
    pub async fn recv(&mut self) -> Result<IntegrationEvent> {
        match &mut self.inner {
            SubscriptionInner::Real(inner) => {
                let event = inner
                    .recv()
                    .await
                    .map_err(|error| anyhow!(error.to_string()))?;
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
    pub async fn connect(
        config: &FirewallConfig,
        cancellation: CancellationToken,
    ) -> Result<Self, ClientError> {
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

    async fn register(&self) -> Result<FirewalldRegistration, ClientError> {
        let prepared: PreparedRegisterRequest = self.inner.register().await?;
        Ok(FirewalldRegistration {
            acd: prepared.request.acd,
        })
    }

    async fn subscribe_rule(
        &self,
        acd: i32,
        fun: i32,
        prot_ver: i32,
        ver: i32,
        poll_interval: Option<Duration>,
    ) -> Result<FirewalldRuleSubscription, ClientError> {
        let subscription = self
            .inner
            .subscribe_rule(acd, fun, prot_ver, ver, poll_interval)
            .await?;
        Ok(FirewalldRuleSubscription::new(subscription))
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
#[derive(Debug)]
pub struct MockFirewalldClient {
    /// Recorded registration attempts.
    pub register_calls: std::sync::atomic::AtomicUsize,
    /// Registration result acd.
    pub registration: Option<FirewalldRegistration>,
    /// Optional registration failure message.
    pub registration_error: Option<String>,
    /// Event sender for runtime tests.
    pub event_tx: mpsc::UnboundedSender<IntegrationEvent>,
    event_rx: std::sync::Mutex<Option<mpsc::UnboundedReceiver<IntegrationEvent>>>,
    firewall_rule_tx: watch::Sender<Option<CachedRule>>,
    firewall_rule_rx: std::sync::Mutex<Option<watch::Receiver<Option<CachedRule>>>>,
    traffic_rule_tx: watch::Sender<Option<CachedRule>>,
    traffic_rule_rx: std::sync::Mutex<Option<watch::Receiver<Option<CachedRule>>>>,
    /// Optional report result override.
    pub report_result: std::sync::Mutex<Result<(), ClientError>>,
}

impl Default for MockFirewalldClient {
    fn default() -> Self {
        let (event_tx, event_rx) = mpsc::unbounded_channel();
        let (firewall_rule_tx, firewall_rx) = watch::channel(None);
        let (traffic_rule_tx, traffic_rx) = watch::channel(None);
        Self {
            register_calls: std::sync::atomic::AtomicUsize::new(0),
            registration: Some(FirewalldRegistration { acd: 1234 }),
            registration_error: None,
            event_tx,
            event_rx: std::sync::Mutex::new(Some(event_rx)),
            firewall_rule_tx,
            firewall_rule_rx: std::sync::Mutex::new(Some(firewall_rx)),
            traffic_rule_tx,
            traffic_rule_rx: std::sync::Mutex::new(Some(traffic_rx)),
            report_result: std::sync::Mutex::new(Ok(())),
        }
    }
}

impl MockFirewalldClient {
    /// Publish a firewall rule snapshot to the mock subscription.
    pub fn set_firewall_rule(&self, rule: CachedRule) {
        let _ = self.firewall_rule_tx.send(Some(rule));
    }

    /// Publish a traffic rule snapshot to the mock subscription.
    pub fn set_traffic_rule(&self, rule: CachedRule) {
        let _ = self.traffic_rule_tx.send(Some(rule));
    }

    /// Emit one integration event into the mock event stream.
    pub fn send_event(&self, event: IntegrationEvent) {
        let _ = self.event_tx.send(event);
    }

    /// Return a clone of the firewall rule sender for async tests.
    #[must_use]
    pub fn firewall_rule_sender(&self) -> watch::Sender<Option<CachedRule>> {
        self.firewall_rule_tx.clone()
    }
}

#[async_trait]
impl FirewalldClient for MockFirewalldClient {
    fn subscribe_events(&self) -> FirewalldEventSubscription {
        let rx = self
            .event_rx
            .lock()
            .expect("event mutex")
            .take()
            .expect("mock event receiver available");
        FirewalldEventSubscription {
            inner: SubscriptionInner::Mock(rx),
        }
    }

    async fn register(&self) -> Result<FirewalldRegistration, ClientError> {
        self.register_calls
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        if let Some(message) = &self.registration_error {
            return Err(ClientError::InvalidRuntimeConfig(message.clone()));
        }
        self.registration.ok_or_else(|| {
            ClientError::InvalidRuntimeConfig("mock register not configured".to_string())
        })
    }

    async fn subscribe_rule(
        &self,
        _acd: i32,
        fun: i32,
        _prot_ver: i32,
        _ver: i32,
        _poll_interval: Option<Duration>,
    ) -> Result<FirewalldRuleSubscription, ClientError> {
        let rx = if fun == 1 {
            self.firewall_rule_rx
                .lock()
                .expect("firewall rule mutex")
                .take()
        } else {
            self.traffic_rule_rx
                .lock()
                .expect("traffic rule mutex")
                .take()
        }
        .expect("mock rule receiver available");
        Ok(FirewalldRuleSubscription::mock(rx))
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
        match &*self.report_result.lock().expect("report mutex") {
            Ok(()) => Ok(()),
            Err(error) => Err(ClientError::InvalidRuntimeConfig(error.to_string())),
        }
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
