//! Dual identity: Microsoft (verified, feature-gated) and Local profiles.
//!
//! The SDK exposes both complete implementations; a consuming project decides
//! which to enable (A/B/D). The unified [`LaunchIdentity`] keeps the trust
//! attributes type-separated: a Microsoft launch identity can only be produced
//! by the verified Microsoft adapter path, never from JSON labels, and a Local
//! profile never carries official tokens or entitlements.

pub mod local;

#[cfg(feature = "microsoft")]
pub mod microsoft;

use crate::error::SdkErrorSource;
use serde::Serialize;
use std::fmt;

pub use local::{LocalProfile, LocalProfileError, LocalProfileStore};

#[cfg(feature = "microsoft")]
pub use microsoft::{
    LoginHandle, MicrosoftAccount, MicrosoftClientConfig, MicrosoftError, MicrosoftProvider,
};

/// Trust taxonomy of a launch identity. Exactly two kinds; future identity
/// sources still produce one of these two trust classes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "contracts", derive(ts_rs::TS))]
pub enum IdentityKind {
    Microsoft,
    Local,
}

/// Neutral listing entry shown in identity pickers. No tokens, no entitlements.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "contracts", derive(ts_rs::TS))]
pub struct IdentitySummary {
    pub kind: IdentityKind,
    pub id: String,
    pub username: String,
    /// Free-form display label (e.g. "Microsoft · 已验证", "本地档案").
    pub label: String,
}

/// Unified launch identity. See the module docs for the construction rules.
#[derive(Debug, Clone)]
pub enum LaunchIdentity {
    #[cfg(feature = "microsoft")]
    Microsoft(MicrosoftAccountVerified),
    Local(LocalProfile),
}

impl LaunchIdentity {
    pub fn kind(&self) -> IdentityKind {
        match self {
            #[cfg(feature = "microsoft")]
            Self::Microsoft(_) => IdentityKind::Microsoft,
            Self::Local(_) => IdentityKind::Local,
        }
    }

    pub fn summary(&self) -> IdentitySummary {
        match self {
            #[cfg(feature = "microsoft")]
            Self::Microsoft(account) => IdentitySummary {
                kind: IdentityKind::Microsoft,
                id: account.uuid.clone(),
                username: account.username.clone(),
                label: "Microsoft · 已验证".to_string(),
            },
            Self::Local(profile) => IdentitySummary {
                kind: IdentityKind::Local,
                id: profile.id.clone(),
                username: profile.username.clone(),
                label: "本地档案 · 未官方验证".to_string(),
            },
        }
    }

    /// Argument material for the launch executor. Identity placeholders in a
    /// [`crate::launch::LaunchSpec`] are substituted from this; the executor
    /// itself never sees which trust class produced the values.
    pub(crate) fn launch_material(&self) -> LaunchMaterial {
        match self {
            #[cfg(feature = "microsoft")]
            Self::Microsoft(account) => LaunchMaterial {
                username: account.username.clone(),
                uuid: account.uuid.clone(),
                // Placeholder required by the game protocol; a Local profile
                // deliberately produces no official token.
                access_token: account.access_token.expose().to_string(),
                client_id: account.client_id.clone(),
                xuid: account.xuid.clone(),
                user_type: "msa".to_string(),
            },
            Self::Local(profile) => LaunchMaterial {
                username: profile.username.clone(),
                uuid: profile.uuid.clone(),
                access_token: "0".to_string(),
                client_id: String::new(),
                xuid: String::new(),
                user_type: "legacy".to_string(),
            },
        }
    }
}

/// Process-internal launch arguments; never serialized, never logged.
#[derive(Debug, Clone)]
pub(crate) struct LaunchMaterial {
    pub username: String,
    pub uuid: String,
    pub access_token: String,
    pub client_id: String,
    pub xuid: String,
    pub user_type: String,
}

/// Verified Microsoft launch identity. Fields are opaque; the only constructor
/// is the Microsoft adapter after a successful real token/entitlement/profile
/// chain. Not deserializable, so a JSON label can never forge this type.
#[cfg(feature = "microsoft")]
#[derive(Debug, Clone)]
pub struct MicrosoftAccountVerified {
    pub(crate) username: String,
    pub(crate) uuid: String,
    pub(crate) access_token: SecretString,
    pub(crate) client_id: String,
    pub(crate) xuid: String,
}

/// Wraps a secret so it is not accidentally formatted or logged.
#[cfg(feature = "microsoft")]
#[derive(Clone)]
pub(crate) struct SecretString(String);

#[cfg(feature = "microsoft")]
impl SecretString {
    pub(crate) fn new(value: String) -> Self {
        Self(value)
    }

    pub(crate) fn expose(&self) -> &str {
        &self.0
    }
}

#[cfg(feature = "microsoft")]
impl std::fmt::Debug for SecretString {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "[redacted]")
    }
}

/// Contract every identity source implements to feed the unified launch path.
/// Providers declare their kind, list manageable identities and produce a
/// launch identity on demand; kind-specific flows (browser login, refresh)
/// live on the concrete types, not on this trait.
pub trait AccountProvider {
    fn kind(&self) -> IdentityKind;
    fn list_identities(&self) -> Result<Vec<IdentitySummary>, AccountProviderError>;
    fn prepare_launch_identity(&self, id: &str) -> Result<LaunchIdentity, AccountProviderError>;
}

#[derive(Debug)]
pub enum AccountProviderError {
    /// The provider does not manage the requested identity id.
    UnknownIdentity(String),
    /// The identity exists but cannot launch right now (e.g. needs re-login).
    Unavailable {
        id: String,
        reason: String,
    },
    Io {
        action: &'static str,
        source: std::io::Error,
    },
    Other {
        code: &'static str,
        message: String,
    },
}

impl AccountProviderError {
    pub fn other(code: &'static str, message: impl Into<String>) -> Self {
        Self::Other {
            code,
            message: message.into(),
        }
    }
}

impl fmt::Display for AccountProviderError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownIdentity(id) => write!(formatter, "身份源中没有标识为 {id} 的身份"),
            Self::Unavailable { id, reason } => {
                write!(formatter, "身份 {id} 当前无法用于启动：{reason}")
            }
            Self::Io { action, source } => write!(formatter, "无法{action}：{source}"),
            Self::Other { message, .. } => write!(formatter, "{message}"),
        }
    }
}

impl std::error::Error for AccountProviderError {}

impl SdkErrorSource for AccountProviderError {
    fn sdk_code(&self) -> &'static str {
        match self {
            Self::UnknownIdentity(_) => "account/unknown-identity",
            Self::Unavailable { .. } => "account/unavailable",
            Self::Io { .. } => "account/io",
            Self::Other { code, .. } => code,
        }
    }

    fn sdk_details(&self) -> Option<serde_json::Value> {
        match self {
            Self::UnknownIdentity(id) | Self::Unavailable { id, .. } => {
                Some(serde_json::json!({ "identityId": id }))
            }
            _ => None,
        }
    }
}
