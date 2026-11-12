//! Controlled process execution: spawn, track, log, report exit.
//!
//! The executor consumes an already-validated [`LaunchSpec`] plus
//! process-internal identity material. It substitutes identity placeholders
//! blindly (no trust-class logic here), writes the game log, records an
//! audit line, and keeps a registry of live processes for status queries.

use super::spec::LaunchSpec;
use crate::account::{LaunchIdentity, LaunchMaterial};
use crate::context::{display_path, SdkContext};
use crate::error::SdkErrorSource;
use serde::Serialize;
use std::collections::HashMap;
use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "contracts", derive(ts_rs::TS))]
pub struct LaunchedProcess {
    pub instance_id: String,
    pub process_id: u32,
    #[cfg_attr(feature = "contracts", ts(type = "string"))]
    pub log_file: PathBuf,
    #[cfg_attr(feature = "contracts", ts(type = "string"))]
    pub started_epoch_ms: u128,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "contracts", derive(ts_rs::TS))]
pub struct ProcessInfo {
    pub instance_id: String,
    pub process_id: u32,
    pub running: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitState {
    Running,
    Exited(i32),
    Terminated,
    Unknown,
}

struct TrackedChild {
    child: Child,
    instance_id: String,
    log_file: PathBuf,
}

pub struct LaunchExecutor {
    processes: Mutex<HashMap<u32, TrackedChild>>,
}

impl Default for LaunchExecutor {
    fn default() -> Self {
        Self::new()
    }
}

impl LaunchExecutor {
    pub fn new() -> Self {
        Self {
            processes: Mutex::new(HashMap::new()),
        }
    }

    /// Spawns the process described by `spec` with the launch material
    /// derived (inside the crate) from the explicit `identity`. Identity
    /// placeholders in `jvm_arguments`/`game_arguments` are substituted
    /// in-memory; nothing secret is written to disk.
    pub fn spawn(
        &self,
        context: &SdkContext,
        spec: LaunchSpec,
        identity: &LaunchIdentity,
    ) -> Result<LaunchedProcess, ExecutorError> {
        let material = identity.launch_material();
        fs::create_dir_all(&context.logs_root)
            .map_err(|source| ExecutorError::io("创建日志目录", &context.logs_root, source))?;
        fs::create_dir_all(&spec.working_directory)
            .map_err(|source| ExecutorError::io("创建游戏目录", &spec.working_directory, source))?;

        let started_epoch_ms = now_epoch_ms();
        let log_file = context
            .logs_root
            .join(format!("game-{}-{started_epoch_ms}.log", spec.instance_id));
        let mut log = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&log_file)
            .map_err(|source| ExecutorError::io("创建游戏日志", &log_file, source))?;
        writeln!(
            log,
            "NaCL Next launch: instance={} version={} user={} java={}",
            spec.instance_id,
            spec.game_version,
            material.username,
            display_path(&spec.java_executable)
        )
        .map_err(|source| ExecutorError::io("写入游戏日志", &log_file, source))?;
        let stderr = log
            .try_clone()
            .map_err(|source| ExecutorError::io("打开游戏错误日志", &log_file, source))?;

        let classpath_value = std::env::join_paths(&spec.classpath)
            .map_err(|source| {
                ExecutorError::io(
                    "生成 classpath",
                    &spec.working_directory,
                    io::Error::other(source),
                )
            })?
            .to_string_lossy()
            .into_owned();

        let mut command = Command::new(&spec.java_executable);
        #[cfg(target_os = "windows")]
        {
            use std::os::windows::process::CommandExt;
            const CREATE_NO_WINDOW: u32 = 0x0800_0000;
            command.creation_flags(CREATE_NO_WINDOW);
        }
        command
            .args(
                spec.jvm_arguments
                    .iter()
                    .map(|argument| expand_identity(argument, &material, &classpath_value)),
            )
            .arg(&spec.main_class)
            .args(
                spec.game_arguments
                    .iter()
                    .map(|argument| expand_identity(argument, &material, &classpath_value)),
            )
            .current_dir(&spec.working_directory)
            .stdin(Stdio::null())
            .stdout(Stdio::from(log))
            .stderr(Stdio::from(stderr));
        let child = command
            .spawn()
            .map_err(|source| ExecutorError::io("启动 Java 进程", &spec.java_executable, source))?;
        let process_id = child.id();

        self.append_audit(
            context,
            &serde_json::json!({
                "event": "launch",
                "epochMs": started_epoch_ms,
                "spec": redacted_spec(&spec, &classpath_value),
                "identityFingerprint": fingerprint_identity(&material),
            }),
        )?;

        let launched = LaunchedProcess {
            instance_id: spec.instance_id.clone(),
            process_id,
            log_file,
            started_epoch_ms,
        };
        self.processes
            .lock()
            .map_err(|_| ExecutorError::RegistryPoisoned)?
            .insert(
                process_id,
                TrackedChild {
                    child,
                    instance_id: spec.instance_id,
                    log_file: launched.log_file.clone(),
                },
            );
        Ok(launched)
    }

    /// Non-blocking status of one tracked process.
    pub fn process_status(&self, process_id: u32) -> ExitState {
        let mut processes = match self.processes.lock() {
            Ok(processes) => processes,
            Err(_) => return ExitState::Unknown,
        };
        match processes.get_mut(&process_id) {
            None => ExitState::Unknown,
            Some(tracked) => match tracked.child.try_wait() {
                Ok(Some(status)) => {
                    let state = if let Some(code) = status.code() {
                        ExitState::Exited(code)
                    } else {
                        ExitState::Terminated
                    };
                    processes.remove(&process_id);
                    state
                }
                Ok(None) => ExitState::Running,
                Err(_) => ExitState::Unknown,
            },
        }
    }

    /// Blocking wait for one tracked process.
    pub fn wait(&self, process_id: u32) -> Result<ExitState, ExecutorError> {
        let mut processes = self
            .processes
            .lock()
            .map_err(|_| ExecutorError::RegistryPoisoned)?;
        let tracked = processes
            .get_mut(&process_id)
            .ok_or(ExecutorError::UnknownProcess(process_id))?;
        let status = tracked
            .child
            .wait()
            .map_err(|source| ExecutorError::io("等待游戏进程", &tracked.log_file, source))?;
        let state = if let Some(code) = status.code() {
            ExitState::Exited(code)
        } else {
            ExitState::Terminated
        };
        drop(processes.remove(&process_id));
        Ok(state)
    }

    /// Snapshot of every tracked process (collected exits are removed).
    pub fn list_processes(&self) -> Vec<ProcessInfo> {
        let mut processes = match self.processes.lock() {
            Ok(processes) => processes,
            Err(_) => return Vec::new(),
        };
        let mut finished = Vec::new();
        let mut infos = Vec::new();
        for (process_id, tracked) in processes.iter_mut() {
            let (running, exit_code) = match tracked.child.try_wait() {
                Ok(Some(status)) => {
                    finished.push(*process_id);
                    (false, status.code())
                }
                Ok(None) => (true, None),
                Err(_) => (false, None),
            };
            infos.push(ProcessInfo {
                instance_id: tracked.instance_id.clone(),
                process_id: *process_id,
                running,
                exit_code,
            });
        }
        for process_id in finished {
            processes.remove(&process_id);
        }
        infos
    }

    fn append_audit(
        &self,
        context: &SdkContext,
        entry: &serde_json::Value,
    ) -> Result<(), ExecutorError> {
        let audit_path = context.logs_root.join("launch-audit.jsonl");
        let mut audit = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&audit_path)
            .map_err(|source| ExecutorError::io("打开启动审计", &audit_path, source))?;
        let mut line = serde_json::to_string(entry).map_err(|source| {
            ExecutorError::io(
                "序列化启动审计",
                &audit_path,
                io::Error::other(source.to_string()),
            )
        })?;
        line.push('\n');
        audit
            .write_all(line.as_bytes())
            .map_err(|source| ExecutorError::io("写入启动审计", &audit_path, source))
    }
}

fn expand_identity(value: &str, material: &LaunchMaterial, classpath_value: &str) -> String {
    value
        .replace("${auth_player_name}", &material.username)
        .replace("${auth_uuid}", &material.uuid)
        .replace("${auth_access_token}", &material.access_token)
        .replace("${clientid}", &material.client_id)
        .replace("${auth_xuid}", &material.xuid)
        .replace("${user_type}", &material.user_type)
        .replace("${classpath}", classpath_value)
}

/// Spec form for the audit log: identity placeholders shown symbolically,
/// classpath collapsed to a count plus the joined value the process received.
fn redacted_spec(spec: &LaunchSpec, classpath_value: &str) -> serde_json::Value {
    serde_json::json!({
        "schemaVersion": spec.schema_version,
        "instanceId": spec.instance_id,
        "gameVersion": spec.game_version,
        "javaExecutable": display_path(&spec.java_executable),
        "jvmArguments": spec.jvm_arguments,
        "mainClass": spec.main_class,
        "classpathCount": spec.classpath.len(),
        "classpath": classpath_value,
        "gameArguments": spec.game_arguments,
        "workingDirectory": display_path(&spec.working_directory),
    })
}

/// Fingerprint of the identity material: first 8 hex chars of the SHA-256 of
/// kind+username+uuid — enough to correlate audit lines, never enough to
/// reconstruct a token (review decision Q6).
fn fingerprint_identity(material: &LaunchMaterial) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(material.user_type.as_bytes());
    hasher.update(material.username.as_bytes());
    hasher.update(material.uuid.as_bytes());
    let digest = hasher.finalize();
    digest[..4]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[derive(Debug)]
pub enum ExecutorError {
    UnknownProcess(u32),
    RegistryPoisoned,
    Io {
        action: &'static str,
        path: PathBuf,
        source: io::Error,
    },
}

impl ExecutorError {
    fn io(action: &'static str, path: &std::path::Path, source: io::Error) -> Self {
        Self::Io {
            action,
            path: path.to_path_buf(),
            source,
        }
    }
}

impl fmt::Display for ExecutorError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownProcess(process_id) => {
                write!(formatter, "没有正在跟踪的进程 {process_id}")
            }
            Self::RegistryPoisoned => write!(formatter, "进程注册表状态异常"),
            Self::Io {
                action,
                path,
                source,
            } => write!(formatter, "无法{action} {}：{source}", path.display()),
        }
    }
}

impl std::error::Error for ExecutorError {}

impl SdkErrorSource for ExecutorError {
    fn sdk_code(&self) -> &'static str {
        match self {
            Self::UnknownProcess(_) => "launch/unknown-process",
            Self::RegistryPoisoned => "launch/registry-poisoned",
            Self::Io { .. } => "launch/io",
        }
    }
}

fn now_epoch_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_millis())
}

#[cfg(test)]
mod tests {
    use super::expand_identity;
    use crate::account::LaunchMaterial;
    fn material() -> LaunchMaterial {
        LaunchMaterial {
            username: "Steve".into(),
            uuid: "uuid-1".into(),
            access_token: "secret-token".into(),
            client_id: "client".into(),
            xuid: "xuid".into(),
            user_type: "msa".into(),
        }
    }

    #[test]
    fn identity_placeholders_expand_from_material() {
        let expanded = expand_identity(
            "--username ${auth_player_name} --accessToken ${auth_access_token}",
            &material(),
            "cp",
        );
        assert_eq!(expanded, "--username Steve --accessToken secret-token");
    }

    #[test]
    fn classpath_placeholder_expands_too() {
        let expanded = expand_identity("-cp ${classpath}", &material(), "a.jar;b.jar");
        assert_eq!(expanded, "-cp a.jar;b.jar");
    }
}
