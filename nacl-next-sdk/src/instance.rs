//! Managed local instances: create/update/duplicate/soft-delete/restore.
//!
//! Ported from the original launcher `instance.rs` (`*_in` variants) with two
//! deliberate changes: every entry point takes an injected [`SdkContext`] and
//! the "currently selected instance" is host-side state, not SDK state.

use crate::context::{display_path, SdkContext};
use crate::error::SdkErrorSource;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use uuid::Uuid;

pub const INSTANCE_SCHEMA_VERSION: u32 = 2;

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "contracts", derive(ts_rs::TS))]
pub struct InstanceConfig {
    pub schema_version: u32,
    pub id: String,
    pub name: String,
    pub game_version: String,
    pub loader: LoaderConfig,
    #[cfg_attr(feature = "contracts", ts(type = "string"))]
    pub game_directory: PathBuf,
    pub java: JavaSelection,
    pub memory: MemorySettings,
    #[serde(default)]
    pub display: DisplaySettings,
    #[serde(default)]
    pub advanced: AdvancedSettings,
    #[serde(default)]
    pub installation: InstallationInfo,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
#[cfg_attr(feature = "contracts", derive(ts_rs::TS))]
pub enum GameLoader {
    Vanilla,
    Fabric,
    Quilt,
    Forge,
    NeoForge,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "contracts", derive(ts_rs::TS))]
pub struct LoaderConfig {
    pub kind: GameLoader,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile_id: Option<String>,
}

impl LoaderConfig {
    pub fn vanilla() -> Self {
        Self {
            kind: GameLoader::Vanilla,
            version: None,
            profile_id: None,
        }
    }

    pub fn modded(kind: GameLoader, version: String, profile_id: String) -> Self {
        Self {
            kind,
            version: Some(version),
            profile_id: Some(profile_id),
        }
    }

    pub fn is_vanilla(&self) -> bool {
        self.kind == GameLoader::Vanilla
    }
}

#[derive(Deserialize)]
#[serde(untagged)]
enum LoaderConfigWire {
    Legacy(GameLoader),
    Current {
        kind: GameLoader,
        version: Option<String>,
        #[serde(rename = "profileId")]
        profile_id: Option<String>,
    },
}

impl<'de> Deserialize<'de> for LoaderConfig {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        match LoaderConfigWire::deserialize(deserializer)? {
            LoaderConfigWire::Legacy(kind) => Ok(Self {
                kind,
                version: None,
                profile_id: None,
            }),
            LoaderConfigWire::Current {
                kind,
                version,
                profile_id,
            } => Ok(Self {
                kind,
                version,
                profile_id,
            }),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(tag = "mode", rename_all = "camelCase")]
#[cfg_attr(feature = "contracts", derive(ts_rs::TS))]
pub enum JavaSelection {
    Auto,
    Custom {
        #[cfg_attr(feature = "contracts", ts(type = "string"))]
        path: PathBuf,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "contracts", derive(ts_rs::TS))]
pub struct MemorySettings {
    pub minimum_mb: u32,
    pub maximum_mb: u32,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
#[cfg_attr(feature = "contracts", derive(ts_rs::TS))]
pub enum WindowMode {
    #[default]
    Windowed,
    Maximized,
    Fullscreen,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "contracts", derive(ts_rs::TS))]
pub struct DisplaySettings {
    pub mode: WindowMode,
    pub width: u32,
    pub height: u32,
}

impl Default for DisplaySettings {
    fn default() -> Self {
        Self {
            mode: WindowMode::Windowed,
            width: 1280,
            height: 720,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "contracts", derive(ts_rs::TS))]
pub struct AdvancedSettings {
    pub jvm_arguments: String,
    pub game_arguments: String,
    pub debug_logging: bool,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
#[cfg_attr(feature = "contracts", derive(ts_rs::TS))]
pub enum InstallationState {
    #[default]
    Incomplete,
    Ready,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "contracts", derive(ts_rs::TS))]
pub struct InstallationInfo {
    pub state: InstallationState,
    #[cfg_attr(feature = "contracts", ts(type = "string | null"))]
    pub installed_epoch_ms: Option<u128>,
}

#[derive(Debug, Clone, Default)]
pub struct InstanceDefaults {
    pub memory_mb: u32,
    pub window_width: u32,
    pub window_height: u32,
}

impl InstanceDefaults {
    fn resolved(&self) -> (u32, u32, u32) {
        (
            if self.memory_mb == 0 {
                4096
            } else {
                self.memory_mb
            },
            if self.window_width == 0 {
                1280
            } else {
                self.window_width
            },
            if self.window_height == 0 {
                720
            } else {
                self.window_height
            },
        )
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateInstanceRequest {
    pub name: String,
    pub game_version: String,
}

#[derive(Debug)]
pub enum InstanceError {
    InvalidName,
    InvalidGameVersion,
    Io {
        action: &'static str,
        path: PathBuf,
        source: io::Error,
    },
    InvalidConfig {
        path: PathBuf,
        source: serde_json::Error,
    },
    InvalidConfigStructure(PathBuf),
    InstanceNotFound(String),
    InvalidInstanceValue(&'static str),
    SerializeConfig(serde_json::Error),
}

impl fmt::Display for InstanceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidName => write!(formatter, "实例名称不能为空、过长或包含控制字符"),
            Self::InvalidGameVersion => {
                write!(formatter, "游戏版本标识为空或包含不支持的字符")
            }
            Self::Io {
                action,
                path,
                source,
            } => write!(formatter, "无法{action} {}：{source}", path.display()),
            Self::InvalidConfig { path, source } => {
                write!(formatter, "实例配置 {} 无效：{source}", path.display())
            }
            Self::InvalidConfigStructure(path) => {
                write!(formatter, "实例配置 {} 的目录结构无效", path.display())
            }
            Self::InstanceNotFound(id) => write!(formatter, "找不到实例 {id}"),
            Self::InvalidInstanceValue(message) => write!(formatter, "实例设置无效：{message}"),
            Self::SerializeConfig(source) => write!(formatter, "无法序列化实例配置：{source}"),
        }
    }
}

impl std::error::Error for InstanceError {}

impl SdkErrorSource for InstanceError {
    fn sdk_code(&self) -> &'static str {
        match self {
            Self::InvalidName => "instance/invalid-name",
            Self::InvalidGameVersion => "instance/invalid-game-version",
            Self::Io { .. } => "instance/io",
            Self::InvalidConfig { .. } | Self::InvalidConfigStructure(_) => {
                "instance/invalid-config"
            }
            Self::InstanceNotFound(_) => "instance/not-found",
            Self::InvalidInstanceValue(_) => "instance/invalid-value",
            Self::SerializeConfig(_) => "instance/serialize-failed",
        }
    }

    fn sdk_details(&self) -> Option<serde_json::Value> {
        match self {
            Self::Io { path, .. } | Self::InvalidConfig { path, .. } => {
                Some(serde_json::json!({ "path": display_path(path) }))
            }
            Self::InvalidConfigStructure(path) => {
                Some(serde_json::json!({ "path": display_path(path) }))
            }
            Self::InstanceNotFound(id) => Some(serde_json::json!({ "instanceId": id })),
            _ => None,
        }
    }
}

pub type InstanceResult<T> = Result<T, InstanceError>;

pub fn find_instance(context: &SdkContext, instance_id: &str) -> InstanceResult<InstanceConfig> {
    list_instances(context)?
        .into_iter()
        .find(|candidate| candidate.id == instance_id)
        .ok_or_else(|| InstanceError::InstanceNotFound(instance_id.to_owned()))
}

pub fn list_instances(context: &SdkContext) -> InstanceResult<Vec<InstanceConfig>> {
    let mut instances = Vec::new();
    let entries = fs::read_dir(&context.instances_root).map_err(|source| InstanceError::Io {
        action: "读取实例目录",
        path: context.instances_root.clone(),
        source,
    })?;

    for entry in entries {
        let entry = entry.map_err(|source| InstanceError::Io {
            action: "读取实例目录项",
            path: context.instances_root.clone(),
            source,
        })?;
        if !entry
            .file_type()
            .map_err(|source| InstanceError::Io {
                action: "读取实例目录项类型",
                path: entry.path(),
                source,
            })?
            .is_dir()
        {
            continue;
        }

        let folder_name = entry.file_name();
        if folder_name.to_string_lossy().starts_with('.') {
            continue;
        }

        let config_path = entry.path().join("instance.json");
        if !config_path.is_file() {
            continue;
        }

        let contents = fs::read_to_string(&config_path).map_err(|source| InstanceError::Io {
            action: "读取实例配置",
            path: config_path.clone(),
            source,
        })?;
        let mut instance: InstanceConfig =
            serde_json::from_str(&contents).map_err(|source| InstanceError::InvalidConfig {
                path: config_path.clone(),
                source,
            })?;
        let needs_migration = instance.schema_version == 1 && instance.loader.is_vanilla();
        if needs_migration {
            instance.schema_version = INSTANCE_SCHEMA_VERSION;
        }
        if instance.schema_version != INSTANCE_SCHEMA_VERSION
            || instance.id != folder_name.to_string_lossy()
            || !valid_loader_config(&instance.loader)
            || instance.game_directory != Path::new("game")
        {
            return Err(InstanceError::InvalidConfigStructure(config_path));
        }
        if needs_migration {
            persist_instance_config(&config_path, &instance)?;
        }
        instances.push(instance);
    }

    instances.sort_by(|left, right| {
        left.name
            .to_lowercase()
            .cmp(&right.name.to_lowercase())
            .then_with(|| left.id.cmp(&right.id))
    });
    Ok(instances)
}

pub fn create_instance(
    context: &SdkContext,
    request: CreateInstanceRequest,
    defaults: &InstanceDefaults,
) -> InstanceResult<InstanceConfig> {
    context.initialize().map_err(|error| match error {
        crate::context::ContextError::Io {
            action,
            path,
            source,
        } => InstanceError::Io {
            action,
            path,
            source,
        },
    })?;

    let name = request.name.trim();
    if name.is_empty() || name.chars().count() > 64 || name.chars().any(char::is_control) {
        return Err(InstanceError::InvalidName);
    }

    let game_version = request.game_version.trim();
    if game_version.is_empty()
        || game_version.len() > 40
        || !game_version
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || ".-_".contains(character))
    {
        return Err(InstanceError::InvalidGameVersion);
    }

    let id = Uuid::new_v4().simple().to_string();
    let staging_dir = context.instances_root.join(format!(".create-{id}"));
    let final_dir = context.instances_root.join(&id);
    let game_dir = staging_dir.join("game");
    let config_path = staging_dir.join("instance.json");

    fs::create_dir(&staging_dir).map_err(|source| InstanceError::Io {
        action: "创建实例暂存目录",
        path: staging_dir.clone(),
        source,
    })?;

    let (default_memory, default_width, default_height) = defaults.resolved();
    let result = (|| {
        fs::create_dir(&game_dir).map_err(|source| InstanceError::Io {
            action: "创建游戏目录",
            path: game_dir.clone(),
            source,
        })?;

        let instance = InstanceConfig {
            schema_version: INSTANCE_SCHEMA_VERSION,
            id: id.clone(),
            name: name.to_owned(),
            game_version: game_version.to_owned(),
            loader: LoaderConfig::vanilla(),
            game_directory: PathBuf::from("game"),
            java: JavaSelection::Auto,
            memory: MemorySettings {
                minimum_mb: 1024,
                maximum_mb: default_memory,
            },
            display: DisplaySettings {
                width: default_width,
                height: default_height,
                ..DisplaySettings::default()
            },
            advanced: AdvancedSettings::default(),
            installation: InstallationInfo::default(),
        };
        let mut contents =
            serde_json::to_vec_pretty(&instance).map_err(InstanceError::SerializeConfig)?;
        contents.push(b'\n');
        fs::write(&config_path, contents).map_err(|source| InstanceError::Io {
            action: "写入实例配置",
            path: config_path.clone(),
            source,
        })?;
        fs::rename(&staging_dir, &final_dir).map_err(|source| InstanceError::Io {
            action: "完成实例创建",
            path: final_dir.clone(),
            source,
        })?;
        Ok(instance)
    })();

    if result.is_err() {
        let rollback_path = if final_dir.is_dir() {
            &final_dir
        } else {
            &staging_dir
        };
        let _ = fs::remove_dir_all(rollback_path);
    }

    result
}

pub fn update_instance(
    context: &SdkContext,
    instance: InstanceConfig,
) -> InstanceResult<InstanceConfig> {
    validate_instance(&instance)?;
    let instance_dir = context.instances_root.join(&instance.id);
    let config_path = instance_dir.join("instance.json");
    if !instance_dir.is_dir() || !config_path.is_file() {
        return Err(InstanceError::InstanceNotFound(instance.id));
    }

    persist_instance_config(&config_path, &instance)?;
    Ok(instance)
}

pub fn duplicate_instance(
    context: &SdkContext,
    instance_id: &str,
) -> InstanceResult<InstanceConfig> {
    let source = find_instance(context, instance_id)?;

    let id = Uuid::new_v4().simple().to_string();
    let staging_dir = context.instances_root.join(format!(".create-{id}"));
    let final_dir = context.instances_root.join(&id);
    let source_dir = context.instances_root.join(instance_id);
    fs::create_dir(&staging_dir).map_err(|source| InstanceError::Io {
        action: "创建实例副本暂存目录",
        path: staging_dir.clone(),
        source,
    })?;

    let result = (|| {
        for entry in walkdir::WalkDir::new(&source_dir).min_depth(1) {
            let entry = entry.map_err(|error| InstanceError::Io {
                action: "读取实例副本来源",
                path: error
                    .path()
                    .map(Path::to_path_buf)
                    .unwrap_or_else(|| source_dir.clone()),
                source: io::Error::other(error.to_string()),
            })?;
            let relative =
                entry
                    .path()
                    .strip_prefix(&source_dir)
                    .map_err(|error| InstanceError::Io {
                        action: "解析实例副本路径",
                        path: entry.path().to_path_buf(),
                        source: io::Error::other(error.to_string()),
                    })?;
            let destination = staging_dir.join(relative);
            if entry.file_type().is_dir() {
                fs::create_dir_all(&destination).map_err(|source| InstanceError::Io {
                    action: "创建实例副本目录",
                    path: destination.clone(),
                    source,
                })?;
            } else if entry.file_name() != "instance.json" {
                fs::copy(entry.path(), &destination).map_err(|source| InstanceError::Io {
                    action: "复制实例文件",
                    path: destination.clone(),
                    source,
                })?;
            }
        }

        let mut duplicate = source;
        duplicate.id.clone_from(&id);
        duplicate.name = unique_copy_name(context, &duplicate.name)?;
        let config_path = staging_dir.join("instance.json");
        let mut contents =
            serde_json::to_vec_pretty(&duplicate).map_err(InstanceError::SerializeConfig)?;
        contents.push(b'\n');
        fs::write(&config_path, contents).map_err(|source| InstanceError::Io {
            action: "写入实例副本配置",
            path: config_path.clone(),
            source,
        })?;
        fs::rename(&staging_dir, &final_dir).map_err(|source| InstanceError::Io {
            action: "完成实例复制",
            path: final_dir.clone(),
            source,
        })?;
        Ok(duplicate)
    })();

    if result.is_err() {
        let rollback_path = if final_dir.is_dir() {
            &final_dir
        } else {
            &staging_dir
        };
        let _ = fs::remove_dir_all(rollback_path);
    }
    result
}

pub fn delete_instance(context: &SdkContext, instance_id: &str) -> InstanceResult<()> {
    let instances = list_instances(context)?;
    if !instances
        .iter()
        .any(|candidate| candidate.id == instance_id)
    {
        return Err(InstanceError::InstanceNotFound(instance_id.to_owned()));
    }

    let instance_dir = context.instances_root.join(instance_id);
    let deleted_dir = deleted_instances_dir(context);
    fs::create_dir_all(&deleted_dir).map_err(|source| InstanceError::Io {
        action: "创建已删除实例目录",
        path: deleted_dir.clone(),
        source,
    })?;
    verify_deleted_instances_dir(context, &deleted_dir)?;
    let deleted_instance_dir = deleted_dir.join(instance_id);
    if deleted_instance_dir.exists() {
        return Err(InstanceError::InvalidInstanceValue(
            "回收区已有相同标识的实例",
        ));
    }
    fs::rename(&instance_dir, &deleted_instance_dir).map_err(|source| InstanceError::Io {
        action: "移动实例到回收区",
        path: instance_dir.clone(),
        source,
    })?;
    Ok(())
}

pub fn list_deleted_instances(context: &SdkContext) -> InstanceResult<Vec<InstanceConfig>> {
    let deleted_dir = deleted_instances_dir(context);
    if !deleted_dir.exists() {
        return Ok(Vec::new());
    }
    verify_deleted_instances_dir(context, &deleted_dir)?;
    let mut deleted_context = context.clone();
    deleted_context.instances_root = deleted_dir;
    list_instances(&deleted_context)
}

pub fn restore_instance(context: &SdkContext, instance_id: &str) -> InstanceResult<InstanceConfig> {
    let instance = list_deleted_instances(context)?
        .into_iter()
        .find(|instance| instance.id == instance_id)
        .ok_or_else(|| InstanceError::InstanceNotFound(instance_id.to_owned()))?;
    let source = deleted_instances_dir(context).join(instance_id);
    let destination = context.instances_root.join(instance_id);
    if destination.exists() {
        return Err(InstanceError::InvalidInstanceValue(
            "实例目录已存在，无法恢复",
        ));
    }
    fs::rename(&source, &destination).map_err(|source_error| InstanceError::Io {
        action: "恢复实例",
        path: source.clone(),
        source: source_error,
    })?;
    Ok(instance)
}

pub fn permanently_delete_instance(context: &SdkContext, instance_id: &str) -> InstanceResult<()> {
    if !list_deleted_instances(context)?
        .iter()
        .any(|instance| instance.id == instance_id)
    {
        return Err(InstanceError::InstanceNotFound(instance_id.to_owned()));
    }
    let source = deleted_instances_dir(context).join(instance_id);
    fs::remove_dir_all(&source).map_err(|source_error| InstanceError::Io {
        action: "彻底删除实例",
        path: source.clone(),
        source: source_error,
    })
}

fn deleted_instances_dir(context: &SdkContext) -> PathBuf {
    context.instances_root.join(".deleted")
}

fn verify_deleted_instances_dir(context: &SdkContext, deleted_dir: &Path) -> InstanceResult<()> {
    let metadata = fs::symlink_metadata(deleted_dir).map_err(|source| InstanceError::Io {
        action: "读取已删除实例目录",
        path: deleted_dir.to_path_buf(),
        source,
    })?;
    if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
        return Err(InstanceError::InvalidInstanceValue("回收区必须是真实目录"));
    }
    let root = fs::canonicalize(&context.instances_root).map_err(|source| InstanceError::Io {
        action: "读取实例目录",
        path: context.instances_root.clone(),
        source,
    })?;
    let deleted = fs::canonicalize(deleted_dir).map_err(|source| InstanceError::Io {
        action: "读取已删除实例目录",
        path: deleted_dir.to_path_buf(),
        source,
    })?;
    if deleted.parent() != Some(root.as_path()) {
        return Err(InstanceError::InvalidInstanceValue(
            "回收区必须位于当前实例目录内",
        ));
    }
    Ok(())
}

fn unique_copy_name(context: &SdkContext, source_name: &str) -> InstanceResult<String> {
    let names = list_instances(context)?
        .into_iter()
        .map(|instance| instance.name)
        .collect::<Vec<_>>();
    let base = format!("{source_name} 副本");
    if !names.iter().any(|name| name == &base) {
        return Ok(base);
    }
    for suffix in 2..=999 {
        let candidate = format!("{base} {suffix}");
        if !names.iter().any(|name| name == &candidate) {
            return Ok(candidate);
        }
    }
    Err(InstanceError::InvalidInstanceValue(
        "无法生成唯一的实例副本名称",
    ))
}

fn validate_instance(instance: &InstanceConfig) -> InstanceResult<()> {
    if instance.schema_version != INSTANCE_SCHEMA_VERSION
        || !valid_loader_config(&instance.loader)
        || instance.game_directory != Path::new("game")
        || instance.id.len() != 32
        || !instance
            .id
            .chars()
            .all(|character| character.is_ascii_hexdigit())
    {
        return Err(InstanceError::InvalidInstanceValue(
            "实例标识或目录结构不正确",
        ));
    }
    let name = instance.name.trim();
    if name.is_empty() || name.chars().count() > 64 || name.chars().any(char::is_control) {
        return Err(InstanceError::InvalidName);
    }
    let version = instance.game_version.trim();
    if version.is_empty()
        || version.len() > 40
        || !version
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || ".-_".contains(character))
    {
        return Err(InstanceError::InvalidGameVersion);
    }
    if instance.memory.minimum_mb < 512
        || instance.memory.maximum_mb > 32768
        || instance.memory.minimum_mb > instance.memory.maximum_mb
    {
        return Err(InstanceError::InvalidInstanceValue(
            "内存范围必须在 512–32768 MB 之间",
        ));
    }
    if !(854..=7680).contains(&instance.display.width)
        || !(480..=4320).contains(&instance.display.height)
    {
        return Err(InstanceError::InvalidInstanceValue(
            "游戏窗口尺寸超出支持范围",
        ));
    }
    if instance.advanced.jvm_arguments.len() > 4096
        || instance.advanced.game_arguments.len() > 4096
        || instance
            .advanced
            .jvm_arguments
            .chars()
            .any(char::is_control)
        || instance
            .advanced
            .game_arguments
            .chars()
            .any(char::is_control)
    {
        return Err(InstanceError::InvalidInstanceValue(
            "高级参数过长或包含控制字符",
        ));
    }
    if let JavaSelection::Custom { path } = &instance.java {
        if path.as_os_str().is_empty() {
            return Err(InstanceError::InvalidInstanceValue(
                "自定义 Java 路径不能为空",
            ));
        }
    }
    Ok(())
}

fn persist_instance_config(config_path: &Path, instance: &InstanceConfig) -> InstanceResult<()> {
    let mut contents =
        serde_json::to_vec_pretty(instance).map_err(InstanceError::SerializeConfig)?;
    contents.push(b'\n');
    crate::fsutil::write_atomic(config_path, &contents).map_err(|source| InstanceError::Io {
        action: "写入实例配置",
        path: config_path.to_path_buf(),
        source,
    })
}

fn valid_loader_config(loader: &LoaderConfig) -> bool {
    match loader.kind {
        GameLoader::Vanilla => loader.version.is_none() && loader.profile_id.is_none(),
        GameLoader::Fabric | GameLoader::Quilt | GameLoader::Forge | GameLoader::NeoForge => {
            loader.version.as_deref().is_some_and(valid_loader_value)
                && loader.profile_id.as_deref().is_some_and(valid_loader_value)
        }
    }
}

fn valid_loader_value(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || ".-_+".contains(character))
}

#[cfg(test)]
mod tests {
    use super::{
        create_instance, delete_instance, duplicate_instance, find_instance,
        list_deleted_instances, list_instances, permanently_delete_instance, restore_instance,
        update_instance, AdvancedSettings, CreateInstanceRequest, DisplaySettings,
        InstallationInfo, InstanceConfig, InstanceDefaults, JavaSelection, LoaderConfig,
        MemorySettings, INSTANCE_SCHEMA_VERSION,
    };

    fn temporary_context() -> (tempfile::TempDir, crate::context::SdkContext) {
        let root = tempfile::tempdir().expect("temporary root");
        let context = crate::context::SdkContext::from_root(root.path());
        (root, context)
    }

    #[test]
    fn vanilla_instance_model_round_trips() {
        let instance = InstanceConfig {
            schema_version: INSTANCE_SCHEMA_VERSION,
            id: "survival".to_string(),
            name: "原版生存".to_string(),
            game_version: "1.21".to_string(),
            loader: LoaderConfig::vanilla(),
            game_directory: std::path::PathBuf::from("game"),
            java: JavaSelection::Auto,
            memory: MemorySettings {
                minimum_mb: 1024,
                maximum_mb: 4096,
            },
            display: DisplaySettings::default(),
            advanced: AdvancedSettings::default(),
            installation: InstallationInfo::default(),
        };

        let json = serde_json::to_string(&instance).expect("instance should serialize");
        let restored: InstanceConfig =
            serde_json::from_str(&json).expect("instance should deserialize");
        assert_eq!(restored, instance);
    }

    #[test]
    fn creates_updates_duplicates_and_soft_deletes() {
        let (root, context) = temporary_context();
        let created = create_instance(
            &context,
            CreateInstanceRequest {
                name: "原版生存".to_string(),
                game_version: "1.21.1".to_string(),
            },
            &InstanceDefaults::default(),
        )
        .expect("instance should be created");
        assert!(context
            .instances_root
            .join(&created.id)
            .join("instance.json")
            .is_file());
        assert_eq!(
            find_instance(&context, &created.id)
                .expect("instance should be found")
                .id,
            created.id
        );

        let mut updated = created.clone();
        updated.memory.maximum_mb = 6144;
        assert_eq!(
            update_instance(&context, updated.clone()).expect("instance should update"),
            updated
        );

        let duplicate =
            duplicate_instance(&context, &created.id).expect("instance should duplicate");
        assert_eq!(duplicate.name, "原版生存 副本");
        delete_instance(&context, &duplicate.id).expect("duplicate should soft delete");
        assert_eq!(list_instances(&context).expect("list").len(), 1);
        assert_eq!(
            list_deleted_instances(&context)
                .expect("deleted list")
                .len(),
            1
        );
        let restored = restore_instance(&context, &duplicate.id).expect("restore");
        assert_eq!(restored, duplicate);
        delete_instance(&context, &duplicate.id).expect("delete again");
        permanently_delete_instance(&context, &duplicate.id).expect("permanent delete");
        assert!(list_deleted_instances(&context)
            .expect("deleted list")
            .is_empty());

        drop(root);
    }

    #[test]
    fn rejects_invalid_request_without_creating_files() {
        let (root, context) = temporary_context();
        context.initialize().expect("initialize");
        let result = create_instance(
            &context,
            CreateInstanceRequest {
                name: " ".to_string(),
                game_version: "../1.21".to_string(),
            },
            &InstanceDefaults::default(),
        );
        assert!(result.is_err());
        assert_eq!(
            std::fs::read_dir(&context.instances_root)
                .expect("instances directory should be readable")
                .count(),
            0
        );
        drop(root);
    }
}
