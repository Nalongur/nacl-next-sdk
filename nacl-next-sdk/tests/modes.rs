//! Mode isolation smoke tests: B keeps working next to a Microsoft-capable
//! build, and missing Microsoft configuration never blocks the local branch
//! (guide §6.2/§9.2: 正版缺环境不阻塞本地路径).

use nacl_next_sdk::account::{AccountProvider, LocalProfileStore};
use nacl_next_sdk::context::SdkContext;
use nacl_next_sdk::instance::{CreateInstanceRequest, InstanceDefaults};
use nacl_next_sdk::launch::preview_launch;

fn fresh_context(label: &str) -> (tempfile::TempDir, SdkContext) {
    let root = tempfile::tempdir().expect("temporary root");
    let context = SdkContext::from_root(root.path().join(label));
    context.initialize().expect("context should initialize");
    (root, context)
}

#[test]
fn local_branch_operates_without_any_client_id() {
    let (root, context) = fresh_context("b-mode");
    let store = LocalProfileStore::new(&context);
    let profile = store.create("Steve_01").expect("local profile");
    let identity = store
        .prepare_launch_identity(&profile.id)
        .expect("local identity");
    assert_eq!(identity.kind(), nacl_next_sdk::account::IdentityKind::Local);

    let instance = nacl_next_sdk::instance::create_instance(
        &context,
        CreateInstanceRequest {
            name: "本地实例".to_string(),
            game_version: "1.21.1".to_string(),
        },
        &InstanceDefaults::default(),
    )
    .expect("instance");
    let preview = preview_launch(&context, &instance.id, None);
    assert_eq!(
        preview.failure_code.as_deref(),
        Some("launch/instance-not-ready")
    );
    drop(root);
}

#[cfg(feature = "microsoft")]
#[test]
fn d_mode_missing_client_id_does_not_block_local_branch() {
    // A D-project without a configured client id: the Microsoft side reports
    // a stable error, the Local side in the very same process keeps working.
    let (root, context) = fresh_context("d-mode");
    assert!(nacl_next_sdk::MicrosoftClientConfig::new("").is_err());
    assert!(nacl_next_sdk::MicrosoftClientConfig::new("   ").is_err());

    let microsoft = nacl_next_sdk::MicrosoftProvider::new(
        nacl_next_sdk::MicrosoftClientConfig::new("configured-by-developer").unwrap(),
        &context,
    );
    // Not signed in and no stored credentials: Microsoft launch preparation
    // fails with a stable code — no silent fallback, no local contamination.
    let error = microsoft
        .prepare_launch_identity()
        .expect_err("prepare must fail without a login");
    assert_eq!(
        nacl_next_sdk::SdkError::from(error).code,
        "auth/microsoft/io"
    );

    let store = LocalProfileStore::new(&context);
    let profile = store.create("Alex_02").expect("local profile works");
    assert_eq!(store.list_identities().unwrap().len(), 1);
    assert!(microsoft.list_identities().unwrap().is_empty());
    drop(profile);
    drop(root);
}

#[cfg(feature = "microsoft")]
#[test]
fn capability_registry_reports_both_identity_kinds_in_d_builds() {
    let registry = nacl_next_sdk::capability::CapabilityRegistry::builtin();
    assert!(registry.contains("nacl-next", "account.microsoft"));
    assert!(registry.contains("nacl-next", "account.local"));
}
