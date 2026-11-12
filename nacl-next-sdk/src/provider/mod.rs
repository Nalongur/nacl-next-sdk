//! Content providers: turn a content request into a declarative plan.
//!
//! Providers only *describe* — they never write into the install root and
//! never gain permissions by being registered (guide §6.1 role table).

pub mod http;
pub mod local;

pub use http::HttpManifestProvider;
pub use local::LocalFileProvider;

use crate::capability::CapabilityDescriptor;
use crate::error::SdkErrorSource;
use crate::plan::{Artifact, ArtifactSource, DigestSpec, InstallPlan, PlannedFile};
use crate::transfer::TransferControl;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::path::PathBuf;

/// Request for one content set. Providers interpret the id against their
/// own catalog; unknown ids are `provider/unknown-content`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "contracts", derive(ts_rs::TS))]
pub struct ContentRequest {
    pub content_id: String,
}

#[derive(Debug)]
pub enum ProviderError {
    UnknownContent(String),
    InvalidManifest {
        reason: String,
    },
    Network(String),
    Cancelled,
    Io {
        action: &'static str,
        source: std::io::Error,
    },
}

impl fmt::Display for ProviderError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownContent(id) => write!(formatter, "内容源中没有内容集 {id}"),
            Self::InvalidManifest { reason } => write!(formatter, "内容清单无效：{reason}"),
            Self::Network(error) => write!(formatter, "获取内容清单失败：{error}"),
            Self::Cancelled => write!(formatter, "内容解析已取消"),
            Self::Io { action, source } => write!(formatter, "无法{action}：{source}"),
        }
    }
}

impl std::error::Error for ProviderError {}

impl SdkErrorSource for ProviderError {
    fn sdk_code(&self) -> &'static str {
        match self {
            Self::UnknownContent(_) => "provider/unknown-content",
            Self::InvalidManifest { .. } => "provider/invalid-manifest",
            Self::Network(_) => "provider/network",
            Self::Cancelled => "provider/cancelled",
            Self::Io { .. } => "provider/io",
        }
    }
}

/// Shared manifest schema used by the built-in providers. It is a plain,
/// self-owned format — no game metadata anywhere.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "contracts", derive(ts_rs::TS))]
pub struct ContentManifest {
    pub schema_version: u32,
    pub content_id: String,
    pub files: Vec<ManifestFile>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "contracts", derive(ts_rs::TS))]
pub struct ManifestFile {
    pub path: String,
    pub sha256: String,
    pub size: u64,
}

pub(crate) const MANIFEST_SCHEMA_VERSION: u32 = 1;

pub(crate) fn parse_manifest(bytes: &[u8]) -> Result<ContentManifest, ProviderError> {
    let manifest: ContentManifest =
        serde_json::from_slice(bytes).map_err(|error| ProviderError::InvalidManifest {
            reason: error.to_string(),
        })?;
    if manifest.schema_version != MANIFEST_SCHEMA_VERSION || manifest.content_id.is_empty() {
        return Err(ProviderError::InvalidManifest {
            reason: "schema 版本或内容标识无效".to_string(),
        });
    }
    if manifest.files.is_empty() {
        return Err(ProviderError::InvalidManifest {
            reason: "清单不含文件".to_string(),
        });
    }
    for file in &manifest.files {
        if file.path.is_empty()
            || file.sha256.len() != 64
            || !file
                .sha256
                .chars()
                .all(|character| character.is_ascii_hexdigit())
        {
            return Err(ProviderError::InvalidManifest {
                reason: format!("文件条目无效：{}", file.path),
            });
        }
    }
    Ok(manifest)
}

/// Shared manifest→plan conversion for the built-in providers. Only the
/// artifact source differs between local and HTTP; path, digest, size and
/// plan-construction rules stay identical so both providers emit the same
/// contract (guide §11 Provider matrix).
pub(crate) fn plan_from_manifest(
    manifest: ContentManifest,
    requested_id: &str,
    expected_source: String,
    source_for: impl Fn(&str) -> ArtifactSource,
) -> Result<InstallPlan, ProviderError> {
    if manifest.content_id != requested_id {
        return Err(ProviderError::UnknownContent(requested_id.to_string()));
    }
    let content_id = manifest.content_id;
    let files = manifest
        .files
        .into_iter()
        .map(|file| PlannedFile {
            artifact: Artifact {
                id: format!("{}:{}", content_id, file.path),
                source: source_for(&file.path),
                digest: Some(DigestSpec {
                    algorithm: crate::cache::DigestAlgorithm::Sha256,
                    value: file.sha256,
                    expected_source: expected_source.clone(),
                }),
                size: file.size,
            },
            relative_path: PathBuf::from(&file.path),
        })
        .collect();
    Ok(InstallPlan::new(content_id, files))
}

pub trait ContentProvider {
    fn descriptor(&self) -> CapabilityDescriptor;
    /// Resolves a request into a declarative plan. Pure: no writes to the
    /// install root. `control` allows cancellation during (rare) network
    /// manifest fetches.
    fn resolve(
        &self,
        request: &ContentRequest,
        control: &dyn Fn() -> TransferControl,
    ) -> Result<InstallPlan, ProviderError>;
}
