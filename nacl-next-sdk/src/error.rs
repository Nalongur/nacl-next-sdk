//! Stable, serializable error shape used at the IPC boundary.
//!
//! Module-internal errors stay typed for granular handling; each implements
//! [`SdkErrorSource`] so hosts and the future Tauri adapter receive one stable
//! code/message/retryable triple instead of per-module enums.

use serde::Serialize;
use std::borrow::Cow;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "contracts", derive(ts_rs::TS))]
pub struct SdkError {
    /// Stable dotted code, e.g. `instance/not-found`. Never repurpose a code.
    pub code: Cow<'static, str>,
    /// Human-readable explanation in the host's UI language.
    pub message: String,
    /// Whether repeating the same call may succeed later.
    pub retryable: bool,
    /// Optional redacted structured context (paths, expected values).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<serde_json::Value>,
}

impl SdkError {
    pub fn new(
        code: impl Into<Cow<'static, str>>,
        message: impl Into<String>,
        retryable: bool,
    ) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
            retryable,
            details: None,
        }
    }

    pub fn with_details(mut self, details: serde_json::Value) -> Self {
        self.details = Some(details);
        self
    }
}

impl std::fmt::Display for SdkError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for SdkError {}

/// Converts a module error into the stable boundary shape.
pub trait SdkErrorSource: std::fmt::Display {
    fn sdk_code(&self) -> &'static str;
    fn sdk_message(&self) -> String {
        self.to_string()
    }
    fn sdk_retryable(&self) -> bool {
        false
    }
    fn sdk_details(&self) -> Option<serde_json::Value> {
        None
    }
}

impl<T: SdkErrorSource> From<T> for SdkError {
    fn from(source: T) -> Self {
        Self {
            code: Cow::Borrowed(source.sdk_code()),
            message: source.sdk_message(),
            retryable: source.sdk_retryable(),
            details: source.sdk_details(),
        }
    }
}
