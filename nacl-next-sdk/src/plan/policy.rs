//! Host policy and plan validation.
//!
//! Everything here runs before any staging or mutation. A provider can
//! describe a plan but cannot relax the host's digest, source, size or path
//! rules.

use crate::cache::hash_file;
use std::collections::HashSet;
use std::fs;
use std::path::{Component, Path, PathBuf};

use super::errors::InstallExecutionError;
use super::model::{InstallContext, InstallPlan, INTERNAL_NAMESPACE};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DigestPolicy {
    /// Every artifact must carry a digest and it must match. Default.
    RequiredAndVerify,
    /// Host explicitly allows digest-less artifacts (still size-checked).
    VerifyIfPresent,
}

/// Host-injected source, network and resource policy (guide §6.1: the
/// provider cannot override these). Empty allow-lists mean the host opted
/// into unrestricted sources (tests, private embedders); non-empty lists
/// are enforced and a plan can never widen them.
#[derive(Debug, Clone)]
pub struct SourcePolicy {
    /// Canonicalized roots; `ArtifactSource::Local` paths must live inside.
    pub local_roots: Vec<PathBuf>,
    /// Allowed HTTP hosts (exact, case-insensitive).
    pub http_hosts: Vec<String>,
    /// Host ceiling for one plan's total bytes; `None` = host sets none.
    pub max_total_bytes: Option<u64>,
    /// Host ceiling for a single artifact; `None` = host sets none.
    pub max_file_bytes: Option<u64>,
}

impl SourcePolicy {
    /// Explicit unrestricted opt-in for trusted hosts.
    pub fn allow_all() -> Self {
        Self {
            local_roots: Vec::new(),
            http_hosts: Vec::new(),
            max_total_bytes: None,
            max_file_bytes: None,
        }
    }

    pub fn allow_local_under(root: impl Into<PathBuf>) -> Self {
        Self {
            local_roots: vec![root.into()],
            http_hosts: Vec::new(),
            max_total_bytes: None,
            max_file_bytes: None,
        }
    }

    pub(super) fn local_allowed(&self, path: &Path) -> bool {
        if self.local_roots.is_empty() {
            return true;
        }
        let Ok(candidate) = fs::canonicalize(path) else {
            return false;
        };
        self.local_roots.iter().any(|root| {
            fs::canonicalize(root)
                .map(|root| candidate.starts_with(root))
                .unwrap_or(false)
        })
    }

    pub(super) fn http_allowed(&self, url: &str) -> bool {
        if self.http_hosts.is_empty() {
            return true;
        }
        let host = url::Url::parse(url)
            .ok()
            .and_then(|parsed| parsed.host_str().map(str::to_ascii_lowercase));
        match host {
            Some(host) => self
                .http_hosts
                .iter()
                .any(|allowed| allowed.to_ascii_lowercase() == host),
            None => false,
        }
    }
}

#[cfg(windows)]
const RESERVED_DEVICE_NAMES: [&str; 22] = [
    "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8",
    "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
];

pub(super) fn validate_plan(
    context: &InstallContext,
    plan: &InstallPlan,
) -> Result<(), InstallExecutionError> {
    if plan.schema_version != super::model::INSTALL_PLAN_SCHEMA_VERSION {
        return Err(InstallExecutionError::Validation(
            "plan/schema-version",
            format!("计划 schema 版本 {} 不受支持", plan.schema_version),
        ));
    }
    if plan.plan_id.is_empty() || plan.plan_id.len() > 128 {
        return Err(InstallExecutionError::Validation(
            "plan/invalid-plan-id",
            "计划标识为空或过长".to_string(),
        ));
    }
    if plan.files.is_empty() {
        return Err(InstallExecutionError::Validation(
            "plan/empty",
            "计划不含任何文件".to_string(),
        ));
    }
    if context.digest_policy == DigestPolicy::RequiredAndVerify {
        for file in &plan.files {
            if file.artifact.digest.is_none() {
                return Err(InstallExecutionError::DigestRequired(
                    file.relative_path.to_string_lossy().into_owned(),
                ));
            }
        }
    }

    // Duplicate targets: compare by filesystem-appropriate key so Windows
    // case aliases collide (F8).
    let mut seen = HashSet::new();
    let mut total = 0_u64;
    for file in &plan.files {
        validate_relative_path(&file.relative_path)?;
        let key = path_identity_key(&file.relative_path);
        if !seen.insert(key) {
            return Err(InstallExecutionError::Validation(
                "plan/duplicate-target",
                format!("重复目标路径 {}", file.relative_path.display()),
            ));
        }
        if let Some(max_file) = context.source_policy.max_file_bytes {
            if file.artifact.size > max_file {
                return Err(InstallExecutionError::Validation(
                    "plan/resource-limit",
                    format!(
                        "{} 声明 {} 字节，超出宿主单文件上限 {max_file}",
                        file.relative_path.display(),
                        file.artifact.size
                    ),
                ));
            }
        }
        total = total.saturating_add(file.artifact.size);
    }
    // Effective ceiling: the stricter of host and plan; a plan can never
    // widen the host's limit (F10).
    let effective = match (
        context.source_policy.max_total_bytes,
        (plan.limits.max_total_bytes > 0).then_some(plan.limits.max_total_bytes),
    ) {
        (Some(host), Some(plan_declared)) => Some(host.min(plan_declared)),
        (some, None) => some,
        (None, some) => some,
    };
    if let Some(limit) = effective {
        if total > limit {
            return Err(InstallExecutionError::Validation(
                "plan/resource-limit",
                format!("计划总量 {total} 超出上限 {limit}"),
            ));
        }
    }
    Ok(())
}

/// How a relative path is compared for duplicate detection.
#[cfg(windows)]
fn path_identity_key(path: &Path) -> String {
    path.to_string_lossy().to_ascii_lowercase()
}

#[cfg(not(windows))]
fn path_identity_key(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

/// Stage A: pure string/component checks, before any filesystem access.
pub(super) fn validate_relative_path(path: &Path) -> Result<(), InstallExecutionError> {
    let text = path.to_string_lossy();
    if text.is_empty() || text.len() > 512 {
        return Err(InstallExecutionError::Validation(
            "plan/invalid-path",
            "目标路径为空或过长".to_string(),
        ));
    }
    let mut components = path.components();
    let mut count = 0;
    let mut first = true;
    for component in components.by_ref() {
        count += 1;
        let Component::Normal(value) = component else {
            return Err(InstallExecutionError::Validation(
                "plan/invalid-path",
                format!("目标路径包含不支持的分量：{text}"),
            ));
        };
        let name = value.to_string_lossy();
        // Executor metadata namespace is off-limits to content (F4).
        if first && name.eq_ignore_ascii_case(INTERNAL_NAMESPACE) {
            return Err(InstallExecutionError::Validation(
                "plan/invalid-path",
                format!("目标路径不得进入执行器内部目录 {INTERNAL_NAMESPACE}"),
            ));
        }
        first = false;
        // Windows-unreliable forms (F8): ADS colons, trailing dots/spaces,
        // reserved device names. One consistent rule everywhere; on Unix a
        // colon is legal but rare in content paths.
        if name.contains(':') || name.ends_with('.') || name.ends_with(' ') {
            return Err(InstallExecutionError::Validation(
                "plan/invalid-path",
                format!("目标路径包含不可靠处理的名称分量：{name}"),
            ));
        }
        #[cfg(windows)]
        if RESERVED_DEVICE_NAMES
            .iter()
            .any(|reserved| name.eq_ignore_ascii_case(reserved))
        {
            return Err(InstallExecutionError::Validation(
                "plan/invalid-path",
                format!("目标路径使用了保留设备名：{name}"),
            ));
        }
    }
    if count == 0 {
        return Err(InstallExecutionError::Validation(
            "plan/invalid-path",
            "目标路径为空".to_string(),
        ));
    }
    Ok(())
}

/// Stage C: the canonical parent of the target must stay inside the
/// canonical install root (symlink/junction escapes fail here).
pub(super) fn verify_target_inside_root(
    context: &InstallContext,
    target: &Path,
) -> Result<(), InstallExecutionError> {
    let root =
        fs::canonicalize(&context.install_root).map_err(|source| InstallExecutionError::Io {
            action: "解析安装根目录",
            path: context.install_root.clone(),
            source,
        })?;
    let parent = target.parent().ok_or_else(|| {
        InstallExecutionError::Validation("plan/invalid-path", "目标缺少父目录".to_string())
    })?;
    // Create the parent chain first (it is inside the plan's own tree), then
    // verify the *canonical* location really is under the root.
    fs::create_dir_all(parent).map_err(|source| InstallExecutionError::Io {
        action: "创建目标目录",
        path: parent.to_path_buf(),
        source,
    })?;
    let canonical_parent =
        fs::canonicalize(parent).map_err(|source| InstallExecutionError::Io {
            action: "解析目标目录",
            path: parent.to_path_buf(),
            source,
        })?;
    if !canonical_parent.starts_with(&root) {
        return Err(InstallExecutionError::Validation(
            "plan/path-escape",
            format!("目标目录逃逸出安装根目录：{}", target.display()),
        ));
    }
    if let Ok(metadata) = fs::symlink_metadata(target) {
        if metadata.file_type().is_symlink() {
            return Err(InstallExecutionError::Validation(
                "plan/path-escape",
                format!("目标已是符号链接：{}", target.display()),
            ));
        }
    }
    Ok(())
}

/// Re-hashes a verified staging file; kept here so policy decides which
/// digest algorithm is used for verification.
pub(super) fn verify_digest(
    algorithm: crate::cache::DigestAlgorithm,
    path: &Path,
) -> Result<String, InstallExecutionError> {
    hash_file(algorithm, path).map_err(|error| InstallExecutionError::Io {
        action: "校验暂存文件",
        path: path.to_path_buf(),
        source: std::io::Error::other(error.to_string()),
    })
}
