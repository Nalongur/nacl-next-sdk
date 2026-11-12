//! Independent B-mode consumer of the NaCL Next SDK.
//!
//! No `microsoft` feature, no client id, no network: local profiles and
//! instance management only. Exit code 0 means the demo chain succeeded.

use nacl_next_sdk::account::{AccountProvider, LocalProfileStore};
use nacl_next_sdk::capability::CapabilityRegistry;
use nacl_next_sdk::context::SdkContext;
use nacl_next_sdk::instance::{CreateInstanceRequest, InstanceDefaults};
use nacl_next_sdk::launch::preview_launch;

fn main() {
    let root =
        std::env::temp_dir().join(format!("nacl-next-consumer-local-{}", std::process::id()));
    let context = SdkContext::from_root(&root);
    context.initialize().expect("context should initialize");

    // Discovery reflects compiled capabilities: a B build has no Microsoft.
    let registry = CapabilityRegistry::builtin();
    println!("capabilities: {:?}", registry.list());
    assert!(!registry.contains("nacl-next", "account.microsoft"));
    assert!(registry.contains("nacl-next", "account.local"));

    // Local profile lifecycle.
    let store = LocalProfileStore::new(&context);
    let profile = store.create("Steve_01").expect("profile should create");
    println!("profile: {} ({})", profile.username, profile.id);
    let identities = store.list_identities().expect("identity list");
    println!("identities: {:?}", identities);

    // Instance + dry-run preview: metadata is absent, so the preview must
    // report the stable error code instead of fetching anything.
    let instance = nacl_next_sdk::instance::create_instance(
        &context,
        CreateInstanceRequest {
            name: "演示实例".to_string(),
            game_version: "1.21.1".to_string(),
        },
        &InstanceDefaults::default(),
    )
    .expect("instance should create");
    let preview = preview_launch(&context, &instance.id, None);
    println!(
        "preview: ready={} failure={:?}",
        preview.ready, preview.failure_code
    );
    assert_eq!(
        preview.failure_code.as_deref(),
        Some("launch/instance-not-ready")
    );

    // Mark ready to see the next gap (missing metadata) with its stable code.
    let mut instance = instance;
    instance.installation.state = nacl_next_sdk::instance::InstallationState::Ready;
    nacl_next_sdk::instance::update_instance(&context, instance.clone()).unwrap();
    let preview = preview_launch(&context, &instance.id, None);
    assert_eq!(
        preview.failure_code.as_deref(),
        Some("launch/missing-version-metadata")
    );
    println!(
        "missing metadata reported as: {:?} ({})",
        preview.failure_code,
        preview.failure_message.unwrap_or_default()
    );

    let identity = store
        .prepare_launch_identity(&profile.id)
        .expect("launch identity");
    println!("identity kind: {:?}", identity.kind());

    std::fs::remove_dir_all(&root).ok();
    println!("consumer-local: OK");
}
