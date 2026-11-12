//! Instance resolution: load and validate an existing instance's version
//! metadata and point at the client jar. Read-only; missing files are errors.

use crate::context::{display_path, SdkContext};
use crate::error::SdkErrorSource;
use crate::instance::{InstallationState, InstanceConfig};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::fs;
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize)]
pub struct ResolvedInstance {
    pub instance_id: String,
    /// Loader profile id when modded (pre-merged metadata), else game version.
    pub metadata_id: String,
    #[serde(skip)]
    pub(crate) metadata: VersionMetadata,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_path: Option<PathBuf>,
    pub required_java_major: u16,
}

pub struct InstanceResolver;

impl InstanceResolver {
    pub fn resolve(
        context: &SdkContext,
        instance: &InstanceConfig,
    ) -> Result<ResolvedInstance, ResolverError> {
        if instance.installation.state != InstallationState::Ready {
            return Err(ResolverError::InstanceNotReady);
        }
        let metadata_id = instance
            .loader
            .profile_id
            .clone()
            .unwrap_or_else(|| instance.game_version.clone());
        let metadata_path = context.versions_root.join(format!("{metadata_id}.json"));
        if !metadata_path.is_file() {
            return Err(ResolverError::MissingVersionMetadata(metadata_path));
        }
        let metadata_contents = fs::read_to_string(&metadata_path)
            .map_err(|source| ResolverError::io("读取版本元数据", &metadata_path, source))?;
        let metadata: VersionMetadata =
            serde_json::from_str(&metadata_contents).map_err(|source| {
                ResolverError::InvalidMetadata {
                    path: metadata_path.clone(),
                    source,
                }
            })?;
        if metadata.main_class.is_empty() {
            return Err(ResolverError::MissingMainClass);
        }

        let profile_client_path = context.versions_root.join(format!("{metadata_id}.jar"));
        let client_path = if profile_client_path.is_file() {
            profile_client_path
        } else {
            context
                .versions_root
                .join(format!("{}.jar", instance.game_version))
        };
        if !client_path.is_file() {
            return Err(ResolverError::MissingClient(client_path));
        }
        let required_java_major = metadata
            .java_version
            .as_ref()
            .map_or(8, |java| java.major_version);
        Ok(ResolvedInstance {
            instance_id: instance.id.clone(),
            metadata_id,
            metadata,
            client_path: Some(client_path),
            required_java_major,
        })
    }
}

#[derive(Debug)]
pub enum ResolverError {
    InstanceNotReady,
    MissingVersionMetadata(PathBuf),
    MissingClient(PathBuf),
    MissingMainClass,
    InvalidMetadata {
        path: PathBuf,
        source: serde_json::Error,
    },
    Io {
        action: &'static str,
        path: PathBuf,
        source: std::io::Error,
    },
}

impl ResolverError {
    fn io(action: &'static str, path: &std::path::Path, source: std::io::Error) -> Self {
        Self::Io {
            action,
            path: path.to_path_buf(),
            source,
        }
    }
}

impl fmt::Display for ResolverError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InstanceNotReady => write!(formatter, "实例尚未安装完整"),
            Self::MissingVersionMetadata(path) => {
                write!(formatter, "找不到版本元数据 {}", path.display())
            }
            Self::MissingClient(path) => write!(formatter, "找不到游戏客户端 {}", path.display()),
            Self::MissingMainClass => write!(formatter, "版本元数据缺少主类"),
            Self::InvalidMetadata { path, source } => {
                write!(formatter, "版本元数据 {} 无效：{source}", path.display())
            }
            Self::Io {
                action,
                path,
                source,
            } => write!(formatter, "无法{action} {}：{source}", path.display()),
        }
    }
}

impl std::error::Error for ResolverError {}

impl SdkErrorSource for ResolverError {
    fn sdk_code(&self) -> &'static str {
        match self {
            Self::InstanceNotReady => "launch/instance-not-ready",
            Self::MissingVersionMetadata(_) => "launch/missing-version-metadata",
            Self::MissingClient(_) => "launch/missing-client",
            Self::MissingMainClass => "launch/missing-main-class",
            Self::InvalidMetadata { .. } => "launch/invalid-metadata",
            Self::Io { .. } => "launch/io",
        }
    }

    fn sdk_details(&self) -> Option<serde_json::Value> {
        match self {
            Self::MissingVersionMetadata(path)
            | Self::MissingClient(path)
            | Self::InvalidMetadata { path, .. }
            | Self::Io { path, .. } => Some(serde_json::json!({ "path": display_path(path) })),
            _ => None,
        }
    }
}

// Version metadata model ported from the original `launch.rs`; loader
// differences arrive pre-merged into these files at install time.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct VersionMetadata {
    #[serde(default)]
    pub main_class: String,
    #[serde(rename = "type", default)]
    pub version_type: String,
    #[serde(default)]
    pub asset_index: AssetIndexReference,
    #[serde(default)]
    pub java_version: Option<JavaVersionMetadata>,
    #[serde(default)]
    pub libraries: Vec<Library>,
    #[serde(default)]
    pub arguments: Option<VersionArguments>,
    #[serde(default)]
    pub minecraft_arguments: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct JavaVersionMetadata {
    pub major_version: u16,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub(crate) struct AssetIndexReference {
    #[serde(default)]
    pub id: String,
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct VersionArguments {
    #[serde(default)]
    pub game: Vec<ArgumentEntry>,
    #[serde(default)]
    pub jvm: Vec<ArgumentEntry>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub(crate) enum ArgumentEntry {
    Plain(String),
    Conditional {
        #[serde(default)]
        rules: Vec<Rule>,
        value: ArgumentValue,
    },
}

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub(crate) enum ArgumentValue {
    One(String),
    Many(Vec<String>),
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct Library {
    pub name: String,
    #[serde(default)]
    pub downloads: LibraryDownloads,
    #[serde(default)]
    pub natives: std::collections::HashMap<String, String>,
    #[serde(default)]
    pub rules: Vec<Rule>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub(crate) struct LibraryDownloads {
    #[serde(default)]
    pub artifact: Option<Artifact>,
    #[serde(default)]
    pub classifiers: std::collections::HashMap<String, Artifact>,
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct Artifact {
    #[serde(default)]
    pub path: String,
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct Rule {
    pub action: String,
    #[serde(default)]
    pub os: Option<RuleOs>,
    #[serde(default)]
    pub features: Option<std::collections::HashMap<String, bool>>,
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct RuleOs {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub arch: Option<String>,
}
