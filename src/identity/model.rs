//! Stable application identity models.

/// Identity type used for app attribution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityType {
    /// Android application package.
    App,
    /// Native or daemon program.
    Program,
    /// UID-only identity when no richer source is available.
    Uid,
    /// Unknown identity source.
    Unknown,
}

impl IdentityType {
    /// Return the stable storage string for this identity type.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::App => "app",
            Self::Program => "program",
            Self::Uid => "uid",
            Self::Unknown => "unknown",
        }
    }

    /// Parse a storage string into an identity type.
    #[must_use]
    pub fn from_storage_str(value: &str) -> Self {
        match value {
            "app" => Self::App,
            "program" => Self::Program,
            "uid" => Self::Uid,
            _ => Self::Unknown,
        }
    }
}

/// Stable app identity used across rules, events, and traffic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppIdentity {
    /// Internal app id.
    pub app_id: String,
    /// Identity type.
    pub identity_type: IdentityType,
    /// Optional package name.
    pub package: Option<String>,
    /// Optional display app name.
    pub app_name: Option<String>,
    /// Optional program name.
    pub program: Option<String>,
    /// Optional local uid.
    pub uid: Option<u32>,
}
