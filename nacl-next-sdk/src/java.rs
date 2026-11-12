//! Java runtime detection and inspection.
//!
//! Ported from the original launcher `java.rs` detection half. Runtime
//! *acquisition* (`install_managed_runtime`) is intentionally not part of S1:
//! the SDK only reports what already exists on the machine.

use crate::context::{display_path, SdkContext};
use crate::error::SdkErrorSource;
use serde::Serialize;
use std::collections::HashSet;
use std::env;
use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;
use walkdir::WalkDir;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "contracts", derive(ts_rs::TS))]
pub struct JavaRuntime {
    #[cfg_attr(feature = "contracts", ts(type = "string"))]
    pub path: String,
    #[cfg_attr(feature = "contracts", ts(type = "string"))]
    pub home: String,
    pub version: Option<String>,
    pub major_version: Option<u16>,
    pub architecture: Option<String>,
    pub vendor: Option<String>,
    pub source: String,
    pub managed: bool,
}

#[derive(Debug)]
pub enum JavaError {
    Io {
        action: &'static str,
        path: PathBuf,
        source: io::Error,
    },
    InvalidExecutable(PathBuf),
}

impl fmt::Display for JavaError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io {
                action,
                path,
                source,
            } => write!(formatter, "无法{action} {}：{source}", path.display()),
            Self::InvalidExecutable(path) => {
                write!(formatter, "{} 不是可用的 Java 运行环境", path.display())
            }
        }
    }
}

impl std::error::Error for JavaError {}

impl SdkErrorSource for JavaError {
    fn sdk_code(&self) -> &'static str {
        match self {
            Self::Io { .. } => "java/io",
            Self::InvalidExecutable(_) => "java/invalid-executable",
        }
    }

    fn sdk_details(&self) -> Option<serde_json::Value> {
        match self {
            Self::Io { path, .. } | Self::InvalidExecutable(path) => {
                Some(serde_json::json!({ "path": display_path(path) }))
            }
        }
    }
}

#[derive(Debug)]
struct JavaCandidate {
    executable: PathBuf,
    source: String,
    managed: bool,
}

/// Finds Java installations reachable from `JAVA_HOME`, `PATH`, well-known
/// installation roots and the context's managed runtimes directory. Managed
/// roots come from the injected context; no brand directory is assumed.
pub fn detect_java_runtimes(context: &SdkContext) -> Vec<JavaRuntime> {
    let mut candidates = Vec::new();

    if let Some(java_home) = env::var_os("JAVA_HOME") {
        candidates.push(JavaCandidate {
            executable: PathBuf::from(java_home)
                .join("bin")
                .join(java_executable_name()),
            source: "JAVA_HOME".to_string(),
            managed: false,
        });
    }

    if let Some(path_value) = env::var_os("PATH") {
        for directory in env::split_paths(&path_value) {
            candidates.push(JavaCandidate {
                executable: directory.join(java_executable_name()),
                source: "PATH".to_string(),
                managed: false,
            });
        }
    }

    for (root, source, max_depth, managed) in known_installation_roots(context) {
        candidates.extend(scan_root(&root, source, max_depth, managed));
    }

    collect_runtimes(candidates, &context.runtimes_root)
}

/// Inspects one explicitly chosen executable. Returns `java/invalid-executable`
/// when the path does not behave like a Java runtime.
pub fn inspect_java_runtime(path: &Path) -> Result<JavaRuntime, JavaError> {
    inspect_candidate(JavaCandidate {
        executable: path.to_path_buf(),
        source: "手动选择".to_string(),
        managed: false,
    })
    .ok_or_else(|| JavaError::InvalidExecutable(path.to_path_buf()))
}

/// Resolves the Java runtime an instance asks for. `preferred` (host state)
/// only reorders auto detection; exact major-version match is still required.
pub fn select_java(
    context: &SdkContext,
    selection: &crate::instance::JavaSelection,
    required_major: u16,
    preferred: Option<&Path>,
) -> Result<JavaRuntime, JavaSelectionError> {
    match selection {
        crate::instance::JavaSelection::Custom { path } => {
            let runtime = inspect_java_runtime(path).map_err(|_| JavaSelectionError::Mismatch {
                expected: required_major,
                actual: None,
            })?;
            if runtime.major_version != Some(required_major) {
                return Err(JavaSelectionError::Mismatch {
                    expected: required_major,
                    actual: runtime.major_version,
                });
            }
            Ok(runtime)
        }
        crate::instance::JavaSelection::Auto => {
            let mut runtimes = detect_java_runtimes(context);
            if let Some(preferred) = preferred {
                runtimes.sort_by_key(|runtime| Path::new(&runtime.path) != preferred);
            }
            runtimes
                .into_iter()
                .find(|runtime| runtime.major_version == Some(required_major))
                .ok_or(JavaSelectionError::Unavailable(required_major))
        }
    }
}

#[derive(Debug)]
pub enum JavaSelectionError {
    Unavailable(u16),
    Mismatch { expected: u16, actual: Option<u16> },
}

impl fmt::Display for JavaSelectionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unavailable(major) => {
                write!(formatter, "未找到兼容的 Java {major} 运行环境")
            }
            Self::Mismatch { expected, actual } => write!(
                formatter,
                "所选 Java 版本不兼容：需要 Java {expected}，当前为 {}",
                actual.map_or_else(|| "未知版本".to_string(), |value| format!("Java {value}"))
            ),
        }
    }
}

impl std::error::Error for JavaSelectionError {}

impl SdkErrorSource for JavaSelectionError {
    fn sdk_code(&self) -> &'static str {
        "java/selection"
    }

    fn sdk_details(&self) -> Option<serde_json::Value> {
        match self {
            Self::Unavailable(major) => Some(serde_json::json!({ "requiredMajor": major })),
            Self::Mismatch { expected, actual } => {
                Some(serde_json::json!({ "expected": expected, "actual": actual }))
            }
        }
    }
}

fn java_executable_name() -> &'static str {
    if cfg!(windows) {
        "java.exe"
    } else {
        "java"
    }
}

fn known_installation_roots(context: &SdkContext) -> Vec<(PathBuf, &'static str, usize, bool)> {
    let mut roots = Vec::new();
    roots.push((context.runtimes_root.clone(), "SDK 托管", 5, true));

    if let Some(program_files) = env::var_os("ProgramFiles") {
        let program_files = PathBuf::from(program_files);
        roots.push((program_files.join("Java"), "Java installation", 3, false));
        roots.push((
            program_files.join("Eclipse Adoptium"),
            "Eclipse Adoptium",
            3,
            false,
        ));
        roots.push((
            program_files.join("Microsoft"),
            "Microsoft OpenJDK",
            3,
            false,
        ));
        roots.push((program_files.join("Zulu"), "Azul Zulu", 3, false));
    }

    if let Some(program_files_x86) = env::var_os("ProgramFiles(x86)") {
        roots.push((
            PathBuf::from(program_files_x86)
                .join("Minecraft Launcher")
                .join("runtime"),
            "Minecraft Launcher",
            7,
            false,
        ));
    }

    if let Some(local_app_data) = env::var_os("LOCALAPPDATA") {
        roots.push((
            PathBuf::from(local_app_data)
                .join("Programs")
                .join("Eclipse Adoptium"),
            "Eclipse Adoptium",
            3,
            false,
        ));
    }

    if let Some(user_profile) = env::var_os("USERPROFILE") {
        let user_profile = PathBuf::from(user_profile);
        roots.push((user_profile.join(".jdks"), "User JDK", 3, false));
        roots.push((
            user_profile
                .join("AppData")
                .join("Roaming")
                .join(".minecraft")
                .join("runtime"),
            "Minecraft runtime",
            7,
            false,
        ));
    }

    roots
}

fn scan_root(root: &Path, source: &str, max_depth: usize, managed: bool) -> Vec<JavaCandidate> {
    if !root.is_dir() {
        return Vec::new();
    }

    WalkDir::new(root)
        .follow_links(false)
        .max_depth(max_depth)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|entry| entry.file_type().is_file())
        .filter(|entry| {
            entry
                .file_name()
                .to_string_lossy()
                .eq_ignore_ascii_case(java_executable_name())
        })
        .filter(|entry| {
            entry
                .path()
                .parent()
                .and_then(Path::file_name)
                .is_some_and(|name| name.to_string_lossy().eq_ignore_ascii_case("bin"))
        })
        .map(|entry| JavaCandidate {
            executable: entry.into_path(),
            source: source.to_string(),
            managed,
        })
        .collect()
}

fn collect_runtimes(candidates: Vec<JavaCandidate>, managed_root: &Path) -> Vec<JavaRuntime> {
    let mut seen = HashSet::new();
    let mut runtimes = Vec::new();

    for candidate in candidates {
        if !candidate.executable.is_file() {
            continue;
        }
        let executable = candidate
            .executable
            .canonicalize()
            .unwrap_or_else(|_| candidate.executable.clone());
        let identity = executable.to_string_lossy().to_lowercase();
        if !seen.insert(identity) {
            continue;
        }
        if let Some(runtime) = inspect_candidate(JavaCandidate {
            managed: is_managed_path(&executable, managed_root),
            executable,
            source: candidate.source,
        }) {
            runtimes.push(runtime);
        }
    }

    runtimes.sort_by(|left, right| {
        right
            .major_version
            .cmp(&left.major_version)
            .then_with(|| left.path.cmp(&right.path))
    });
    runtimes
}

fn inspect_candidate(candidate: JavaCandidate) -> Option<JavaRuntime> {
    if !candidate.executable.is_file() {
        return None;
    }
    let executable = candidate
        .executable
        .canonicalize()
        .unwrap_or(candidate.executable);
    let home = java_home_from_executable(&executable)?;
    let process = read_runtime_properties(&executable)?;
    let release = read_release_metadata(&home);
    let version = process.version.or_else(|| {
        release
            .as_deref()
            .and_then(|contents| release_value(contents, "JAVA_VERSION"))
    });
    let architecture = process.architecture.or_else(|| {
        release
            .as_deref()
            .and_then(|contents| release_value(contents, "OS_ARCH"))
    });
    let vendor = process.vendor.or_else(|| {
        release
            .as_deref()
            .and_then(|contents| release_value(contents, "IMPLEMENTOR"))
    });

    Some(JavaRuntime {
        path: display_path(&executable),
        home: display_path(&home),
        major_version: version.as_deref().and_then(java_major_version),
        version,
        architecture,
        vendor,
        source: candidate.source,
        managed: candidate.managed,
    })
}

#[derive(Default)]
struct RuntimeProperties {
    version: Option<String>,
    architecture: Option<String>,
    vendor: Option<String>,
}

fn read_runtime_properties(executable: &Path) -> Option<RuntimeProperties> {
    let mut command = Command::new(executable);
    command.args(["-XshowSettings:properties", "-version"]);
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        command.creation_flags(CREATE_NO_WINDOW);
    }
    let output = command.output().ok()?;
    if !output.status.success() {
        return None;
    }
    let combined = format!(
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let mut properties = RuntimeProperties {
        version: property_value(&combined, "java.version"),
        architecture: property_value(&combined, "os.arch"),
        vendor: property_value(&combined, "java.vendor"),
    };
    if properties.version.is_none() {
        properties.version = quoted_version(&combined);
    }
    Some(properties)
}

fn property_value(contents: &str, key: &str) -> Option<String> {
    contents.lines().find_map(|line| {
        let (candidate_key, value) = line.trim().split_once('=')?;
        (candidate_key.trim() == key).then(|| value.trim().to_string())
    })
}

fn quoted_version(contents: &str) -> Option<String> {
    contents.lines().find_map(|line| {
        let (_, rest) = line.split_once("version")?;
        let start = rest.find('"')? + 1;
        let tail = &rest[start..];
        let end = tail.find('"')?;
        Some(tail[..end].to_string())
    })
}

pub(crate) fn java_major_version(version: &str) -> Option<u16> {
    let mut parts = version
        .trim_start_matches(|character: char| !character.is_ascii_digit())
        .split(|character: char| !character.is_ascii_digit())
        .filter(|part| !part.is_empty());
    let first = parts.next()?.parse::<u16>().ok()?;
    if first == 1 {
        parts.next()?.parse::<u16>().ok()
    } else {
        Some(first)
    }
}

fn is_managed_path(path: &Path, managed_root: &Path) -> bool {
    path.canonicalize()
        .ok()
        .zip(managed_root.canonicalize().ok())
        .is_some_and(|(candidate, root)| candidate.starts_with(root))
}

fn java_home_from_executable(executable: &Path) -> Option<PathBuf> {
    executable.parent()?.parent().map(Path::to_path_buf)
}

fn read_release_metadata(home: &Path) -> Option<String> {
    fs::read_to_string(home.join("release")).ok()
}

fn release_value(contents: &str, key: &str) -> Option<String> {
    contents.lines().find_map(|line| {
        let (candidate_key, value) = line.split_once('=')?;
        if candidate_key.trim() != key {
            return None;
        }

        Some(value.trim().trim_matches('"').to_string())
    })
}

#[cfg(test)]
mod tests {
    use super::{java_major_version, property_value, release_value};

    #[test]
    fn parses_release_metadata() {
        let release = "JAVA_VERSION=\"21.0.7\"\nOS_ARCH=\"amd64\"\n";
        assert_eq!(
            release_value(release, "JAVA_VERSION"),
            Some("21.0.7".to_string())
        );
        assert_eq!(release_value(release, "OS_ARCH"), Some("amd64".to_string()));
    }

    #[test]
    fn parses_runtime_properties() {
        let output =
            "Property settings:\n    java.vendor = Eclipse Adoptium\n    java.version = 21.0.7\n";
        assert_eq!(
            property_value(output, "java.vendor"),
            Some("Eclipse Adoptium".to_string())
        );
        assert_eq!(
            property_value(output, "java.version"),
            Some("21.0.7".to_string())
        );
    }

    #[test]
    fn parses_legacy_and_modern_major_versions() {
        assert_eq!(java_major_version("1.8.0_452"), Some(8));
        assert_eq!(java_major_version("17.0.15"), Some(17));
        assert_eq!(java_major_version("21"), Some(21));
    }
}
