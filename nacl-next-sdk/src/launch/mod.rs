//! Unified launch pipeline: resolve → adapt → execute.
//!
//! The orchestrator never selects an identity: callers pass an explicit
//! [`LaunchIdentity`](crate::account::LaunchIdentity). Missing metadata,
//! client jars or libraries are reported, never downloaded.

pub mod adapter;
pub mod executor;
pub mod resolver;
pub mod spec;

pub use adapter::{LaunchAdapter, VanillaLaunchAdapter};
pub use executor::{ExitState, LaunchExecutor, LaunchedProcess, ProcessInfo};
pub use resolver::{InstanceResolver, ResolvedInstance};
pub use spec::{LaunchSpec, LaunchSpecError, LAUNCH_SPEC_SCHEMA_VERSION};

use crate::account::LaunchIdentity;
use crate::context::SdkContext;
use crate::error::SdkErrorSource;
use crate::instance::InstanceConfig;
use serde::Serialize;
use std::fmt;

/// Read-only pre-launch check for UIs: what is missing, which Java would run.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "contracts", derive(ts_rs::TS))]
pub struct LaunchPreview {
    pub instance_id: String,
    pub ready: bool,
    /// `launch/*` or `java/*` stable error code when not ready.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failure_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failure_message: Option<String>,
    /// Resolved metadata id (loader profile id or game version).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub required_java_major: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub selected_java: Option<crate::java::JavaRuntime>,
}

pub enum LaunchError {
    Instance(crate::instance::InstanceError),
    Resolver(resolver::ResolverError),
    JavaSelection(crate::java::JavaSelectionError),
    Adapter(adapter::AdapterError),
    Executor(executor::ExecutorError),
}

impl fmt::Display for LaunchError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Instance(error) => error.fmt(formatter),
            Self::Resolver(error) => error.fmt(formatter),
            Self::JavaSelection(error) => error.fmt(formatter),
            Self::Adapter(error) => error.fmt(formatter),
            Self::Executor(error) => error.fmt(formatter),
        }
    }
}

impl std::fmt::Debug for LaunchError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{self}")
    }
}

impl std::error::Error for LaunchError {}

impl SdkErrorSource for LaunchError {
    fn sdk_code(&self) -> &'static str {
        match self {
            Self::Instance(error) => error.sdk_code(),
            Self::Resolver(error) => error.sdk_code(),
            Self::JavaSelection(error) => error.sdk_code(),
            Self::Adapter(error) => error.sdk_code(),
            Self::Executor(error) => error.sdk_code(),
        }
    }

    fn sdk_message(&self) -> String {
        self.to_string()
    }

    fn sdk_details(&self) -> Option<serde_json::Value> {
        match self {
            Self::Instance(error) => error.sdk_details(),
            Self::Resolver(error) => error.sdk_details(),
            Self::JavaSelection(error) => error.sdk_details(),
            Self::Adapter(error) => error.sdk_details(),
            Self::Executor(error) => error.sdk_details(),
        }
    }
}

/// Dry-run resolution for a UI preview. Never spawns, never downloads.
pub fn preview_launch(
    context: &SdkContext,
    instance_id: &str,
    preferred_java: Option<&std::path::Path>,
) -> LaunchPreview {
    let build_failure = |code: String, message: String| LaunchPreview {
        instance_id: instance_id.to_owned(),
        ready: false,
        failure_code: Some(code),
        failure_message: Some(message),
        metadata_id: None,
        required_java_major: None,
        selected_java: None,
    };
    let instance = match crate::instance::find_instance(context, instance_id) {
        Ok(instance) => instance,
        Err(error) => {
            return build_failure(error.sdk_code().to_string(), error.to_string());
        }
    };
    let resolved = match InstanceResolver::resolve(context, &instance) {
        Ok(resolved) => resolved,
        Err(error) => {
            return build_failure(error.sdk_code().to_string(), error.to_string());
        }
    };
    let required = resolved.required_java_major;
    match crate::java::select_java(context, &instance.java, required, preferred_java) {
        Ok(selected) => LaunchPreview {
            instance_id: instance.id,
            ready: true,
            failure_code: None,
            failure_message: None,
            metadata_id: Some(resolved.metadata_id),
            required_java_major: Some(required),
            selected_java: Some(selected),
        },
        Err(error) => build_failure(error.sdk_code().to_string(), error.to_string()),
    }
}

/// Full launch: resolve the instance, build a [`LaunchSpec`] with the
/// loader-agnostic adapter, then hand it to `executor` with the launch
/// material derived from the explicit identity.
pub fn launch(
    context: &SdkContext,
    executor: &LaunchExecutor,
    instance_id: &str,
    identity: &LaunchIdentity,
    preferred_java: Option<&std::path::Path>,
) -> Result<LaunchedProcess, LaunchError> {
    let instance =
        crate::instance::find_instance(context, instance_id).map_err(LaunchError::Instance)?;
    let resolved = InstanceResolver::resolve(context, &instance).map_err(LaunchError::Resolver)?;
    let selected_java = crate::java::select_java(
        context,
        &instance.java,
        resolved.required_java_major,
        preferred_java,
    )
    .map_err(LaunchError::JavaSelection)?;
    let adapter = adapter_for(&instance);
    let spec = adapter
        .build_spec(context, &instance, &resolved, &selected_java)
        .map_err(LaunchError::Adapter)?;
    executor
        .spawn(context, spec, identity)
        .map_err(LaunchError::Executor)
}

/// S1 ships the vanilla adapter; loader profiles are pre-merged version
/// metadata, so one adapter serves all existing loader kinds. Dedicated
/// per-loader adapters arrive with their own test evidence (review Q8).
pub fn adapter_for(instance: &InstanceConfig) -> &dyn LaunchAdapter {
    let _ = instance;
    &VanillaLaunchAdapter
}
