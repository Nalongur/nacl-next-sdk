//! Launch adapters: turn a resolved instance plus settings into a `LaunchSpec`.
//!
//! S1 ships [`VanillaLaunchAdapter`], which also covers existing modded
//! instances because loader profiles are pre-merged version metadata. Identity
//! placeholders are intentionally left unexpanded (see `spec` docs).

use super::resolver::{ArgumentEntry, ArgumentValue, Library, ResolvedInstance, Rule};
use super::spec::{LaunchSpec, LAUNCH_SPEC_SCHEMA_VERSION};
use crate::context::{display_path, SdkContext};
use crate::error::SdkErrorSource;
use crate::instance::{InstanceConfig, WindowMode};
use crate::java::JavaRuntime;
use std::collections::HashMap;
use std::fmt;
use std::fs::{self, File};
use std::io;
use std::path::{Component, Path, PathBuf};

pub trait LaunchAdapter {
    fn build_spec(
        &self,
        context: &SdkContext,
        instance: &InstanceConfig,
        resolved: &ResolvedInstance,
        java: &JavaRuntime,
    ) -> Result<LaunchSpec, AdapterError>;
}

pub struct VanillaLaunchAdapter;

impl LaunchAdapter for VanillaLaunchAdapter {
    fn build_spec(
        &self,
        context: &SdkContext,
        instance: &InstanceConfig,
        resolved: &ResolvedInstance,
        java: &JavaRuntime,
    ) -> Result<LaunchSpec, AdapterError> {
        let instance_root = context.instances_root.join(&instance.id);
        let game_directory = instance_root.join(&instance.game_directory);
        fs::create_dir_all(&game_directory)
            .map_err(|source| AdapterError::io("创建游戏目录", &game_directory, source))?;
        let natives_directory = instance_root.join(".nacl-next").join("natives");
        prepare_natives(context, &resolved.metadata.libraries, &natives_directory)?;

        let mut classpath = Vec::new();
        for library in &resolved.metadata.libraries {
            if !rules_allow(&library.rules, true)
                || (is_native_artifact(&library.name)
                    && !native_artifact_for_current_arch(&library.name))
            {
                continue;
            }
            if let Some(artifact) = &library.downloads.artifact {
                classpath.push(checked_library_path(context, &artifact.path)?);
            }
        }
        classpath.push(
            resolved
                .client_path
                .clone()
                .ok_or(AdapterError::MissingClient)?,
        );

        let classpath_value = std::env::join_paths(&classpath)
            .map_err(|source| {
                AdapterError::io(
                    "生成 classpath",
                    &context.libraries_root,
                    io::Error::other(source),
                )
            })?
            .to_string_lossy()
            .into_owned();

        // Identity placeholders stay symbolic; the executor expands them from
        // process-internal material at spawn time.
        let replacements = HashMap::<&str, String>::from([
            ("${version_name}", resolved.metadata_id.clone()),
            (
                "${game_directory}",
                game_directory.to_string_lossy().into_owned(),
            ),
            (
                "${assets_root}",
                context.assets_root.to_string_lossy().into_owned(),
            ),
            (
                "${assets_index_name}",
                resolved.metadata.asset_index.id.clone(),
            ),
            ("${user_properties}", "{}".to_string()),
            (
                "${version_type}",
                if resolved.metadata.version_type.is_empty() {
                    "release".to_string()
                } else {
                    resolved.metadata.version_type.clone()
                },
            ),
            (
                "${natives_directory}",
                natives_directory.to_string_lossy().into_owned(),
            ),
            ("${launcher_name}", "NaCL Next".to_string()),
            ("${launcher_version}", env!("CARGO_PKG_VERSION").to_string()),
            ("${classpath}", classpath_value),
            (
                "${classpath_separator}",
                if cfg!(windows) { ";" } else { ":" }.to_string(),
            ),
            (
                "${library_directory}",
                context.libraries_root.to_string_lossy().into_owned(),
            ),
            ("${resolution_width}", instance.display.width.to_string()),
            ("${resolution_height}", instance.display.height.to_string()),
        ]);

        let mut jvm_arguments = vec![
            format!("-Xms{}M", instance.memory.minimum_mb),
            format!("-Xmx{}M", instance.memory.maximum_mb),
            "-Dfile.encoding=UTF-8".to_string(),
        ];
        let mut game_arguments: Vec<String> = Vec::new();
        if let Some(arguments) = &resolved.metadata.arguments {
            jvm_arguments.extend(expand_arguments(&arguments.jvm, &replacements, true));
            game_arguments.extend(expand_arguments(&arguments.game, &replacements, true));
            if let Some(arguments) = &resolved.metadata.minecraft_arguments {
                game_arguments.extend(
                    split_custom_arguments(arguments)?
                        .into_iter()
                        .map(|value| replace_placeholders(&value, &replacements)),
                );
            }
            if !jvm_arguments.iter().any(|argument| {
                argument == "${classpath}" || argument == &replacements["${classpath}"]
            }) {
                jvm_arguments.extend(
                    [
                        "-Djava.library.path=${natives_directory}",
                        "-cp",
                        "${classpath}",
                    ]
                    .map(|value| replace_placeholders(value, &replacements)),
                );
            }
        } else if let Some(arguments) = &resolved.metadata.minecraft_arguments {
            game_arguments.extend(
                split_custom_arguments(arguments)?
                    .into_iter()
                    .map(|value| replace_placeholders(&value, &replacements)),
            );
            jvm_arguments.extend(
                [
                    "-Djava.library.path=${natives_directory}",
                    "-cp",
                    "${classpath}",
                ]
                .map(|value| replace_placeholders(value, &replacements)),
            );
        } else {
            return Err(AdapterError::MissingArguments);
        }
        jvm_arguments.extend(split_custom_arguments(&instance.advanced.jvm_arguments)?);
        game_arguments.extend(split_custom_arguments(&instance.advanced.game_arguments)?);
        if instance.display.mode == WindowMode::Fullscreen {
            game_arguments.push("--fullscreen".to_string());
        }

        Ok(LaunchSpec {
            schema_version: LAUNCH_SPEC_SCHEMA_VERSION,
            instance_id: instance.id.clone(),
            game_version: instance.game_version.clone(),
            java_executable: launch_java_executable(&java.path),
            jvm_arguments,
            main_class: resolved.metadata.main_class.clone(),
            classpath,
            game_arguments,
            working_directory: game_directory,
        })
    }
}

#[derive(Debug)]
pub enum AdapterError {
    MissingClient,
    MissingArguments,
    MissingLibrary(PathBuf),
    InvalidCustomArguments,
    Archive {
        path: PathBuf,
        source: zip::result::ZipError,
    },
    Io {
        action: &'static str,
        path: PathBuf,
        source: io::Error,
    },
}

impl AdapterError {
    fn io(action: &'static str, path: &Path, source: io::Error) -> Self {
        Self::Io {
            action,
            path: path.to_path_buf(),
            source,
        }
    }
}

impl fmt::Display for AdapterError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingClient => write!(formatter, "找不到游戏客户端"),
            Self::MissingArguments => write!(formatter, "版本元数据缺少启动参数"),
            Self::MissingLibrary(path) => write!(formatter, "缺少游戏依赖 {}", path.display()),
            Self::InvalidCustomArguments => {
                write!(formatter, "自定义启动参数包含未闭合的引号")
            }
            Self::Archive { path, source } => {
                write!(formatter, "无法解压原生库 {}：{source}", path.display())
            }
            Self::Io {
                action,
                path,
                source,
            } => write!(formatter, "无法{action} {}：{source}", path.display()),
        }
    }
}

impl std::error::Error for AdapterError {}

impl SdkErrorSource for AdapterError {
    fn sdk_code(&self) -> &'static str {
        match self {
            Self::MissingClient => "launch/missing-client",
            Self::MissingArguments => "launch/missing-arguments",
            Self::MissingLibrary(_) => "launch/missing-library",
            Self::InvalidCustomArguments => "launch/invalid-custom-arguments",
            Self::Archive { .. } => "launch/archive",
            Self::Io { .. } => "launch/io",
        }
    }

    fn sdk_details(&self) -> Option<serde_json::Value> {
        match self {
            Self::MissingLibrary(path) | Self::Archive { path, .. } | Self::Io { path, .. } => {
                Some(serde_json::json!({ "path": display_path(path) }))
            }
            _ => None,
        }
    }
}

fn launch_java_executable(java_path: &str) -> PathBuf {
    let configured = PathBuf::from(java_path);
    #[cfg(target_os = "windows")]
    {
        let javaw = configured.with_file_name("javaw.exe");
        if javaw.is_file() {
            return javaw;
        }
    }
    configured
}

fn checked_library_path(context: &SdkContext, relative: &str) -> Result<PathBuf, AdapterError> {
    let relative = Path::new(relative);
    if relative.as_os_str().is_empty()
        || relative.is_absolute()
        || relative.components().any(|component| {
            matches!(
                component,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        })
    {
        return Err(AdapterError::MissingLibrary(
            context.libraries_root.join(relative),
        ));
    }
    let path = context.libraries_root.join(relative);
    if !path.is_file() {
        return Err(AdapterError::MissingLibrary(path));
    }
    Ok(path)
}

#[derive(Debug, Clone, Copy)]
enum NativeGroup {
    Root,
    Java,
    Lwjgl,
}

fn native_group(library_name: &str) -> NativeGroup {
    if library_name.starts_with("org.lwjgl:") {
        NativeGroup::Lwjgl
    } else {
        NativeGroup::Java
    }
}

fn prepare_natives(
    context: &SdkContext,
    libraries: &[Library],
    destination: &Path,
) -> Result<(), AdapterError> {
    if destination.is_dir() {
        fs::remove_dir_all(destination)
            .map_err(|source| AdapterError::io("清理旧原生库", destination, source))?;
    }
    fs::create_dir_all(destination)
        .map_err(|source| AdapterError::io("创建原生库目录", destination, source))?;

    for library in libraries {
        if !rules_allow(&library.rules, true) {
            continue;
        }
        let mut native_artifacts: Vec<(String, NativeGroup)> = Vec::new();
        if native_artifact_for_current_arch(&library.name) {
            if let Some(artifact) = &library.downloads.artifact {
                native_artifacts.push((artifact.path.clone(), native_group(&library.name)));
            }
        }
        if let Some(classifier) = library.natives.get("windows") {
            let classifier = classifier.replace("${arch}", windows_arch());
            if let Some(artifact) = library.downloads.classifiers.get(&classifier) {
                native_artifacts.push((artifact.path.clone(), NativeGroup::Root));
            }
        }
        for (relative, group) in native_artifacts {
            let archive_path = checked_library_path(context, &relative)?;
            extract_native_archive(&archive_path, destination, group)?;
        }
    }
    for group in ["java", "jna", "lwjgl", "netty"] {
        fs::create_dir_all(destination.join(group)).map_err(|source| {
            AdapterError::io("创建原生库分组目录", &destination.join(group), source)
        })?;
    }
    Ok(())
}

fn extract_native_archive(
    archive_path: &Path,
    destination: &Path,
    group: NativeGroup,
) -> Result<(), AdapterError> {
    let file = File::open(archive_path)
        .map_err(|source| AdapterError::io("读取原生库", archive_path, source))?;
    let mut archive = zip::ZipArchive::new(file).map_err(|source| AdapterError::Archive {
        path: archive_path.to_path_buf(),
        source,
    })?;
    for index in 0..archive.len() {
        let mut entry = archive
            .by_index(index)
            .map_err(|source| AdapterError::Archive {
                path: archive_path.to_path_buf(),
                source,
            })?;
        if entry.is_dir() {
            continue;
        }
        let Some(enclosed) = entry.enclosed_name() else {
            continue;
        };
        let Some(file_name) = enclosed.file_name() else {
            continue;
        };
        let name = file_name.to_string_lossy();
        if !name.to_ascii_lowercase().ends_with(".dll") {
            continue;
        }
        let group_directory = match group {
            NativeGroup::Root => destination.to_path_buf(),
            NativeGroup::Java => destination.join("java"),
            NativeGroup::Lwjgl => destination.join("lwjgl"),
        };
        fs::create_dir_all(&group_directory)
            .map_err(|source| AdapterError::io("创建原生库分组目录", &group_directory, source))?;
        let output = group_directory.join(file_name);
        let mut output_file = File::create(&output)
            .map_err(|source| AdapterError::io("创建原生库文件", &output, source))?;
        io::copy(&mut entry, &mut output_file)
            .map_err(|source| AdapterError::io("解压原生库文件", &output, source))?;
        if !matches!(group, NativeGroup::Root) {
            let root_output = destination.join(file_name);
            fs::copy(&output, &root_output)
                .map_err(|source| AdapterError::io("复制原生库兼容文件", &root_output, source))?;
        }
    }
    Ok(())
}

fn native_artifact_for_current_arch(name: &str) -> bool {
    let Some(classifier) = name.rsplit(':').next() else {
        return false;
    };
    match std::env::consts::ARCH {
        "x86" => classifier == "natives-windows-x86",
        "aarch64" => classifier == "natives-windows-arm64",
        _ => classifier == "natives-windows" || classifier == "natives-windows-x86_64",
    }
}

fn is_native_artifact(name: &str) -> bool {
    name.rsplit(':')
        .next()
        .is_some_and(|classifier| classifier.starts_with("natives-"))
}

pub(crate) fn rules_allow(rules: &[Rule], custom_resolution: bool) -> bool {
    if rules.is_empty() {
        return true;
    }
    let mut allowed = false;
    for rule in rules {
        let os_matches = rule.os.as_ref().is_none_or(|os| {
            os.name.as_deref().is_none_or(|name| name == "windows")
                && os.arch.as_deref().is_none_or(arch_matches)
        });
        let features_match = rule.features.as_ref().is_none_or(|features| {
            features.iter().all(|(name, expected)| {
                let actual = name == "has_custom_resolution" && custom_resolution;
                actual == *expected
            })
        });
        if os_matches && features_match {
            allowed = rule.action == "allow";
        }
    }
    allowed
}

fn arch_matches(value: &str) -> bool {
    match std::env::consts::ARCH {
        "x86_64" => matches!(value, "x86_64" | "amd64" | "64"),
        "aarch64" => matches!(value, "aarch64" | "arm64"),
        "x86" => matches!(value, "x86" | "i386" | "32"),
        other => value == other,
    }
}

fn windows_arch() -> &'static str {
    if cfg!(target_pointer_width = "64") {
        "64"
    } else {
        "32"
    }
}

fn expand_arguments(
    entries: &[ArgumentEntry],
    replacements: &HashMap<&str, String>,
    custom_resolution: bool,
) -> Vec<String> {
    let mut result = Vec::new();
    for entry in entries {
        match entry {
            ArgumentEntry::Plain(value) => {
                result.push(replace_placeholders(value, replacements));
            }
            ArgumentEntry::Conditional { rules, value }
                if rules_allow(rules, custom_resolution) =>
            {
                match value {
                    ArgumentValue::One(value) => {
                        result.push(replace_placeholders(value, replacements))
                    }
                    ArgumentValue::Many(values) => result.extend(
                        values
                            .iter()
                            .map(|value| replace_placeholders(value, replacements)),
                    ),
                }
            }
            ArgumentEntry::Conditional { .. } => {}
        }
    }
    result
}

fn replace_placeholders(value: &str, replacements: &HashMap<&str, String>) -> String {
    replacements
        .iter()
        .fold(value.to_string(), |current, (from, to)| {
            current.replace(from, to)
        })
}

pub(crate) fn split_custom_arguments(value: &str) -> Result<Vec<String>, AdapterError> {
    let mut result = Vec::new();
    let mut current = String::new();
    let mut quote = None;
    let mut escaped = false;
    for character in value.chars() {
        if escaped {
            current.push(character);
            escaped = false;
            continue;
        }
        if character == '\\' && quote == Some('"') {
            escaped = true;
            continue;
        }
        if character == '"' || character == '\'' {
            if quote == Some(character) {
                quote = None;
            } else if quote.is_none() {
                quote = Some(character);
            } else {
                current.push(character);
            }
            continue;
        }
        if character.is_whitespace() && quote.is_none() {
            if !current.is_empty() {
                result.push(std::mem::take(&mut current));
            }
        } else {
            current.push(character);
        }
    }
    if quote.is_some() || escaped {
        return Err(AdapterError::InvalidCustomArguments);
    }
    if !current.is_empty() {
        result.push(current);
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::{native_artifact_for_current_arch, rules_allow, split_custom_arguments};

    #[test]
    fn splits_quoted_custom_arguments() {
        assert_eq!(
            split_custom_arguments(r#"-Dname="Na Craft" --demo"#).unwrap(),
            vec!["-Dname=Na Craft", "--demo"]
        );
        assert!(split_custom_arguments(r#""unfinished"#).is_err());
    }

    #[test]
    fn selects_only_host_native_classifier() {
        if cfg!(target_arch = "x86_64") {
            assert!(native_artifact_for_current_arch(
                "org.lwjgl:lwjgl:3.4.1:natives-windows"
            ));
            assert!(!native_artifact_for_current_arch(
                "org.lwjgl:lwjgl:3.4.1:natives-windows-x86"
            ));
        }
    }

    #[test]
    fn empty_rules_allow_everything() {
        assert!(rules_allow(&[], true));
        assert!(rules_allow(&[], false));
    }
}
