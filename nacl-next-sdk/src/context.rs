//! Host-injected roots for every SDK operation.
//!
//! The SDK never reads environment variables and never embeds a brand
//! directory: the host constructs an [`SdkContext`] (launcher app, generated
//! template, test or example) and passes it explicitly.

use serde::Serialize;
use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "contracts", derive(ts_rs::TS))]
pub struct SdkContext {
    /// Account/profile/config storage (writable).
    pub config_root: PathBuf,
    /// Managed instance roots; each instance lives in `{id}/instance.json`.
    pub instances_root: PathBuf,
    /// Existing version metadata jars `{id}.json` / `{id}.jar`.
    pub versions_root: PathBuf,
    /// Shared asset index storage referenced by version metadata.
    pub assets_root: PathBuf,
    /// Shared library storage (`{group/path}/{artifact}.jar`).
    pub libraries_root: PathBuf,
    /// Launcher and game log output.
    pub logs_root: PathBuf,
    /// SDK-managed Java runtimes (detection marks these as managed).
    pub runtimes_root: PathBuf,
}

impl SdkContext {
    /// Single-root layout: `config/`, `instances/`, `cache/{versions,assets,libraries}/`,
    /// `logs/`, `runtimes/` under one parent. Hosts with roaming/local split use
    /// [`SdkContext::builder`] instead.
    pub fn from_root(root: impl Into<PathBuf>) -> Self {
        let root = root.into();
        let cache = root.join("cache");
        Self {
            config_root: root.join("config"),
            instances_root: root.join("instances"),
            versions_root: cache.join("versions"),
            assets_root: cache.join("assets"),
            libraries_root: cache.join("libraries"),
            logs_root: root.join("logs"),
            runtimes_root: root.join("runtimes"),
        }
    }

    pub fn builder() -> SdkContextBuilder {
        SdkContextBuilder::default()
    }

    /// Creates every managed directory. Idempotent.
    pub fn initialize(&self) -> Result<(), ContextError> {
        for directory in [
            &self.config_root,
            &self.instances_root,
            &self.versions_root,
            &self.assets_root,
            &self.libraries_root,
            &self.logs_root,
            &self.runtimes_root,
        ] {
            fs::create_dir_all(directory).map_err(|source| ContextError::Io {
                action: "创建 SDK 目录",
                path: directory.clone(),
                source,
            })?;
        }
        Ok(())
    }
}

#[derive(Debug, Default)]
pub struct SdkContextBuilder {
    config_root: Option<PathBuf>,
    instances_root: Option<PathBuf>,
    versions_root: Option<PathBuf>,
    assets_root: Option<PathBuf>,
    libraries_root: Option<PathBuf>,
    logs_root: Option<PathBuf>,
    runtimes_root: Option<PathBuf>,
}

impl SdkContextBuilder {
    pub fn config_root(mut self, path: impl Into<PathBuf>) -> Self {
        self.config_root = Some(path.into());
        self
    }

    pub fn instances_root(mut self, path: impl Into<PathBuf>) -> Self {
        self.instances_root = Some(path.into());
        self
    }

    pub fn versions_root(mut self, path: impl Into<PathBuf>) -> Self {
        self.versions_root = Some(path.into());
        self
    }

    pub fn assets_root(mut self, path: impl Into<PathBuf>) -> Self {
        self.assets_root = Some(path.into());
        self
    }

    pub fn libraries_root(mut self, path: impl Into<PathBuf>) -> Self {
        self.libraries_root = Some(path.into());
        self
    }

    pub fn logs_root(mut self, path: impl Into<PathBuf>) -> Self {
        self.logs_root = Some(path.into());
        self
    }

    pub fn runtimes_root(mut self, path: impl Into<PathBuf>) -> Self {
        self.runtimes_root = Some(path.into());
        self
    }

    pub fn build(self) -> SdkContext {
        SdkContext {
            config_root: self.config_root.expect("config_root is required"),
            instances_root: self.instances_root.expect("instances_root is required"),
            versions_root: self.versions_root.expect("versions_root is required"),
            assets_root: self.assets_root.expect("assets_root is required"),
            libraries_root: self.libraries_root.expect("libraries_root is required"),
            logs_root: self.logs_root.expect("logs_root is required"),
            runtimes_root: self.runtimes_root.expect("runtimes_root is required"),
        }
    }
}

#[derive(Debug)]
pub enum ContextError {
    Io {
        action: &'static str,
        path: PathBuf,
        source: io::Error,
    },
}

impl fmt::Display for ContextError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io {
                action,
                path,
                source,
            } => write!(formatter, "无法{action} {}：{source}", path.display()),
        }
    }
}

impl std::error::Error for ContextError {}

impl crate::error::SdkErrorSource for ContextError {
    fn sdk_code(&self) -> &'static str {
        "context/io"
    }
}

/// Display a canonicalized Windows path without the `\\?\` prefix.
pub(crate) fn display_path(path: &Path) -> String {
    let value = path.to_string_lossy();
    if let Some(unc_path) = value.strip_prefix(r"\\?\UNC\") {
        return format!(r"\\{unc_path}");
    }
    value.strip_prefix(r"\\?\").unwrap_or(&value).to_string()
}

#[cfg(test)]
mod tests {
    use super::SdkContext;

    #[test]
    fn single_root_layout_places_cache_under_one_parent() {
        let context = SdkContext::from_root("P:/launcher");
        assert_eq!(
            context.instances_root,
            std::path::Path::new("P:/launcher/instances")
        );
        assert_eq!(
            context.versions_root,
            std::path::Path::new("P:/launcher/cache/versions")
        );
        assert_eq!(
            context.libraries_root,
            std::path::Path::new("P:/launcher/cache/libraries")
        );
        assert_eq!(
            context.runtimes_root,
            std::path::Path::new("P:/launcher/runtimes")
        );
    }
}
