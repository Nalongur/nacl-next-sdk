//! Declarative plan data exchanged with providers, plus the host execution
//! context. Nothing here touches the filesystem except the context helpers
//! that locate executor-owned metadata paths.

use crate::cache::{ContentCache, ContentDigest, DigestAlgorithm};
use crate::transfer::{self, http_client, TransferOptions};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::PathBuf;

use super::errors::InstallExecutionError;
use super::policy::{DigestPolicy, SourcePolicy};

pub const INSTALL_PLAN_SCHEMA_VERSION: u32 = 1;

/// Reserved first path component holding executor metadata (staging,
/// journal, managed registry). Content plans can never enter it.
pub(super) const INTERNAL_NAMESPACE: &str = ".nacl-next-sdk";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "contracts", derive(ts_rs::TS))]
pub enum ArtifactSource {
    Http {
        url: String,
    },
    Local {
        #[cfg_attr(feature = "contracts", ts(type = "string"))]
        path: PathBuf,
    },
    /// Must already exist in the content cache; never touches the network.
    CacheOnly,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "contracts", derive(ts_rs::TS))]
pub struct DigestSpec {
    pub algorithm: DigestAlgorithm,
    /// Lowercase hex.
    pub value: String,
    /// Where the expected value came from (e.g. `local-manifest:demo`),
    /// for audit trails.
    pub expected_source: String,
}

impl DigestSpec {
    pub fn to_content_digest(&self) -> ContentDigest {
        ContentDigest {
            algorithm: self.algorithm,
            value: self.value.clone(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "contracts", derive(ts_rs::TS))]
pub struct Artifact {
    pub id: String,
    pub source: ArtifactSource,
    #[cfg_attr(feature = "contracts", ts(optional))]
    pub digest: Option<DigestSpec>,
    /// Expected size in bytes. The staged file must match exactly.
    pub size: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "contracts", derive(ts_rs::TS))]
pub struct PlannedFile {
    pub artifact: Artifact,
    /// Relative path under the install root. Validated: plain components
    /// only (no `..`, absolute paths, prefixes, reserved names, internal
    /// namespace).
    #[cfg_attr(feature = "contracts", ts(type = "string"))]
    pub relative_path: PathBuf,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "contracts", derive(ts_rs::TS))]
pub enum ConflictPolicy {
    /// Any existing target fails the plan.
    #[default]
    Fail,
    /// Existing *managed* files are replaced (with rollback backups);
    /// unmanaged files still fail the plan.
    OverwriteManaged,
    /// Existing files are left untouched and reported as skipped.
    Skip,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "contracts", derive(ts_rs::TS))]
pub struct ResourceLimits {
    /// Plan-declared ceiling for the sum of artifact sizes; 0 = the plan
    /// declares none (host policy still applies and cannot be relaxed).
    pub max_total_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "contracts", derive(ts_rs::TS))]
pub struct InstallPlan {
    pub schema_version: u32,
    pub plan_id: String,
    pub files: Vec<PlannedFile>,
    #[serde(default)]
    pub conflict_policy: ConflictPolicy,
    #[serde(default)]
    pub limits: ResourceLimits,
}

impl InstallPlan {
    pub fn new(plan_id: impl Into<String>, files: Vec<PlannedFile>) -> Self {
        Self {
            schema_version: INSTALL_PLAN_SCHEMA_VERSION,
            plan_id: plan_id.into(),
            files,
            conflict_policy: ConflictPolicy::default(),
            limits: ResourceLimits::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "contracts", derive(ts_rs::TS))]
pub struct InstallResult {
    pub plan_id: String,
    pub committed: Vec<String>,
    pub skipped: Vec<String>,
    pub cache_hits: usize,
}

/// One entry of the managed registry: who installed the target and with
/// which digest. Never contains credentials.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "contracts", derive(ts_rs::TS))]
pub struct ManagedRecord {
    pub plan_id: String,
    pub digest: Option<String>,
}

pub(super) type ManagedFiles = BTreeMap<String, ManagedRecord>;

/// Host-injected execution context. The client is built from the source
/// policy so a plan can never widen the HTTP host allow-list implicitly.
pub struct InstallContext {
    pub install_root: PathBuf,
    pub cache: ContentCache,
    pub digest_policy: DigestPolicy,
    pub source_policy: SourcePolicy,
    pub transfer_options: TransferOptions,
    client: reqwest::blocking::Client,
}

impl InstallContext {
    pub fn new(
        install_root: impl Into<PathBuf>,
        cache_root: impl Into<PathBuf>,
        digest_policy: DigestPolicy,
        source_policy: SourcePolicy,
    ) -> Result<Self, InstallExecutionError> {
        let client = if source_policy.http_hosts.is_empty() {
            http_client()
        } else {
            transfer::http_client_with_redirect_allowlist(std::sync::Arc::new(
                source_policy.http_hosts.clone(),
            ))
        }
        .map_err(InstallExecutionError::Transfer)?;
        Ok(Self {
            install_root: install_root.into(),
            cache: ContentCache::new(cache_root),
            digest_policy,
            source_policy,
            transfer_options: TransferOptions::default(),
            client,
        })
    }

    pub(super) fn client(&self) -> &reqwest::blocking::Client {
        &self.client
    }

    pub(super) fn staging_root(&self) -> PathBuf {
        self.install_root.join(INTERNAL_NAMESPACE).join("staging")
    }

    pub(super) fn managed_registry_path(&self) -> PathBuf {
        self.install_root
            .join(INTERNAL_NAMESPACE)
            .join("managed.json")
    }
}
