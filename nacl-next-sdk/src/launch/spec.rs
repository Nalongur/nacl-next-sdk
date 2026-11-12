//! Versioned launch specification.
//!
//! A `LaunchSpec` is the complete, auditable description of one game process.
//! Identity placeholders (`${auth_player_name}`, `${auth_access_token}`, …)
//! stay **unexpanded** here; the executor substitutes them at spawn time from
//! process-internal material, so the spec itself never carries secrets and
//! can be serialized into launch audit records as-is.

use serde::Serialize;
use std::fmt;
use std::path::PathBuf;

pub const LAUNCH_SPEC_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "contracts", derive(ts_rs::TS))]
pub struct LaunchSpec {
    pub schema_version: u32,
    pub instance_id: String,
    pub game_version: String,
    #[cfg_attr(feature = "contracts", ts(type = "string"))]
    pub java_executable: PathBuf,
    pub jvm_arguments: Vec<String>,
    pub main_class: String,
    #[cfg_attr(feature = "contracts", ts(type = "string[]"))]
    pub classpath: Vec<PathBuf>,
    pub game_arguments: Vec<String>,
    #[cfg_attr(feature = "contracts", ts(type = "string"))]
    pub working_directory: PathBuf,
}

impl LaunchSpec {
    /// Audit-safe JSON form. The spec never contains secrets by construction;
    /// this method exists to make that contract explicit and testable.
    pub fn to_audit(&self) -> serde_json::Value {
        serde_json::to_value(self).unwrap_or(serde_json::Value::Null)
    }
}

#[derive(Debug)]
pub enum LaunchSpecError {
    /// Placeholder misuse that should have been impossible to construct.
    Internal(&'static str),
}

impl fmt::Display for LaunchSpecError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Internal(message) => write!(formatter, "启动规格内部错误：{message}"),
        }
    }
}

impl std::error::Error for LaunchSpecError {}

impl crate::error::SdkErrorSource for LaunchSpecError {
    fn sdk_code(&self) -> &'static str {
        "launch/spec-internal"
    }
}

#[cfg(test)]
mod tests {
    use super::LaunchSpec;

    #[test]
    fn audit_serialization_contains_no_identity_values() {
        let spec = LaunchSpec {
            schema_version: super::LAUNCH_SPEC_SCHEMA_VERSION,
            instance_id: "id".into(),
            game_version: "1.21".into(),
            java_executable: "C:/java/bin/javaw.exe".into(),
            jvm_arguments: vec!["-Djava.library.path=${natives_directory}".into()],
            main_class: "net.minecraft.client.main.Main".into(),
            classpath: vec!["libs/a.jar".into()],
            game_arguments: vec![
                "--username".into(),
                "${auth_player_name}".into(),
                "--accessToken".into(),
                "${auth_access_token}".into(),
            ],
            working_directory: "instances/id/game".into(),
        };
        let audit = spec.to_audit().to_string();
        assert!(audit.contains("${auth_access_token}"));
        assert!(!audit.contains("secret"));
    }
}
