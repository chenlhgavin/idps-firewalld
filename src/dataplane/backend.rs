//! Data plane backend abstraction.

use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::Result;

/// Boxed future returned by data plane trait methods.
pub type DataplaneFuture<'a> = Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>>;

/// Data plane lifecycle backend.
pub trait DataplaneBackend: Send + Sync {
    /// Initialize and attach the backend.
    fn initialize(&self) -> DataplaneFuture<'_>;

    /// Shut the backend down and release resources.
    fn shutdown(&self) -> DataplaneFuture<'_>;
}

/// Mock data plane used before privileged eBPF support is available.
#[derive(Debug, Default)]
pub struct MockDataplane {
    initialized: AtomicBool,
}

impl MockDataplane {
    /// Return whether the mock backend has been initialized.
    #[must_use]
    pub fn is_initialized(&self) -> bool {
        self.initialized.load(Ordering::SeqCst)
    }
}

impl DataplaneBackend for MockDataplane {
    fn initialize(&self) -> DataplaneFuture<'_> {
        Box::pin(async move {
            self.initialized.store(true, Ordering::SeqCst);
            Ok(())
        })
    }

    fn shutdown(&self) -> DataplaneFuture<'_> {
        Box::pin(async move {
            self.initialized.store(false, Ordering::SeqCst);
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{DataplaneBackend, MockDataplane};

    #[tokio::test]
    async fn mock_dataplane_tracks_lifecycle() {
        let backend = MockDataplane::default();
        assert!(!backend.is_initialized());
        backend.initialize().await.expect("initialize");
        assert!(backend.is_initialized());
        backend.shutdown().await.expect("shutdown");
        assert!(!backend.is_initialized());
    }
}
