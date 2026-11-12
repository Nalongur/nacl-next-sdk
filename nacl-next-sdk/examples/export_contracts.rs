//! Exports the IPC-facing DTOs to TypeScript bindings.
//!
//! Run from the SDK workspace root:
//!
//! ```text
//! TS_RS_EXPORT_DIR=../contracts cargo run --example export_contracts --features contracts
//! TS_RS_EXPORT_DIR=../contracts cargo run --example export_contracts --features "contracts microsoft"
//! ```
//!
//! Generated files under `sdk/contracts/` are committed artifacts; the
//! compatibility manifest references them. Rust stays the single source.

fn main() {
    use nacl_next_sdk::account::{IdentityKind, IdentitySummary, LocalProfile};
    use nacl_next_sdk::cache::{ContentDigest, DigestAlgorithm};
    use nacl_next_sdk::capability::CapabilityDescriptor;
    use nacl_next_sdk::context::SdkContext;
    use nacl_next_sdk::error::SdkError;
    use nacl_next_sdk::instance::InstanceConfig;
    use nacl_next_sdk::java::JavaRuntime;
    use nacl_next_sdk::launch::{LaunchPreview, LaunchSpec, LaunchedProcess, ProcessInfo};
    use nacl_next_sdk::plan::{InstallPlan, InstallResult, ManagedRecord};
    use nacl_next_sdk::provider::{ContentManifest, ContentRequest};
    use ts_rs::TS;

    let mut exported: Vec<String> = Vec::new();
    let mut run = |name: &str, result: Result<(), ts_rs::ExportError>| {
        result.unwrap_or_else(|error| panic!("export {name} failed: {error}"));
        exported.push(name.to_string());
    };

    run("SdkError", SdkError::export_all());
    run("SdkContext", SdkContext::export_all());
    run("InstanceConfig", InstanceConfig::export_all());
    run("JavaRuntime", JavaRuntime::export_all());
    run("LocalProfile", LocalProfile::export_all());
    run("IdentityKind", IdentityKind::export_all());
    run("IdentitySummary", IdentitySummary::export_all());
    run("CapabilityDescriptor", CapabilityDescriptor::export_all());
    run("LaunchPreview", LaunchPreview::export_all());
    run("LaunchSpec", LaunchSpec::export_all());
    run("LaunchedProcess", LaunchedProcess::export_all());
    run("ProcessInfo", ProcessInfo::export_all());

    // S2 plan/provider DTOs.
    run("InstallPlan", InstallPlan::export_all());
    run("InstallResult", InstallResult::export_all());
    run("ContentRequest", ContentRequest::export_all());
    run("ContentManifest", ContentManifest::export_all());
    run("ContentDigest", ContentDigest::export_all());
    run("DigestAlgorithm", DigestAlgorithm::export_all());
    run("ManagedRecord", ManagedRecord::export_all());

    #[cfg(feature = "microsoft")]
    {
        use nacl_next_sdk::account::{LoginHandle, MicrosoftAccount};
        run("MicrosoftAccount", MicrosoftAccount::export_all());
        run("LoginHandle", LoginHandle::export_all());
    }

    println!(
        "exported {} DTO groups (microsoft: {})",
        exported.len(),
        cfg!(feature = "microsoft")
    );
}
