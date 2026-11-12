//! S1 B-path integration: full launch chain against a self-owned Java probe.
//!
//! Compiles a tiny Java program with the machine's `javac`, packages it as
//! the instance "client jar", and drives instance → resolver → adapter →
//! executor with a Local identity. Verifies process args substitution,
//! working directory, log file, audit redaction and exit state. The test
//! fails loudly when no JDK is available — a missing Java environment is an
//! environment gap, not a silent pass.

mod common;

use common::{build_probe_fixture, ready_instance};
use nacl_next_sdk::account::{AccountProvider, LaunchIdentity, LocalProfileStore};
use nacl_next_sdk::launch::{preview_launch, ExitState, LaunchExecutor};
use std::path::Path;

#[test]
fn full_local_launch_chain_runs_own_java_probe() {
    let fixture = build_probe_fixture("full-chain");
    let instance = ready_instance(&fixture.context, &fixture.java_executable);

    let preview = preview_launch(&fixture.context, &instance.id, None);
    assert!(
        preview.ready,
        "preview should be ready: {:?}",
        preview.failure_code
    );
    assert_eq!(preview.metadata_id.as_deref(), Some("1.21.1-probe"));

    let store = LocalProfileStore::new(&fixture.context);
    let profile = store.create("Steve_01").expect("local profile");
    let identity = store
        .prepare_launch_identity(&profile.id)
        .expect("launch identity");
    assert_eq!(identity.kind(), nacl_next_sdk::account::IdentityKind::Local);

    let executor = LaunchExecutor::new();
    let launched =
        nacl_next_sdk::launch::launch(&fixture.context, &executor, &instance.id, &identity, None)
            .expect("launch should spawn the probe");
    assert!(launched.log_file.is_file(), "game log should exist");

    let state = executor.wait(launched.process_id).expect("wait");
    assert_eq!(state, ExitState::Exited(0), "probe should exit 0");

    let game_dir = fixture
        .context
        .instances_root
        .join(&instance.id)
        .join("game");
    let arguments = std::fs::read_to_string(game_dir.join("probe-args.txt"))
        .expect("probe should have written its arguments (working directory must be the game dir)");
    assert!(
        arguments.contains("Steve_01"),
        "username placeholder must expand"
    );
    assert!(
        arguments.contains(&profile.uuid),
        "uuid placeholder must expand"
    );
    assert!(
        arguments.contains("legacy"),
        "local identity uses the legacy user type"
    );

    let working_directory =
        std::fs::read_to_string(game_dir.join("probe-cwd.txt")).expect("probe should record cwd");
    assert!(
        same_path(&working_directory, &game_dir),
        "probe cwd {working_directory} should be the game directory {}",
        game_dir.display()
    );

    let audit = std::fs::read_to_string(fixture.context.logs_root.join("launch-audit.jsonl"))
        .expect("launch audit should exist");
    assert!(audit.contains(&instance.id));
    assert!(
        !audit.contains("Steve_01"),
        "audit must stay identity-redacted"
    );

    assert_eq!(
        executor.process_status(launched.process_id),
        ExitState::Unknown
    );
}

#[test]
fn missing_client_is_reported_not_downloaded() {
    let fixture = build_probe_fixture("missing-client");
    // Remove the client jar only; metadata stays.
    std::fs::remove_file(fixture.context.versions_root.join("1.21.1-probe.jar")).unwrap();
    let instance = ready_instance(&fixture.context, &fixture.java_executable);

    let preview = preview_launch(&fixture.context, &instance.id, None);
    assert!(!preview.ready);
    assert_eq!(
        preview.failure_code.as_deref(),
        Some("launch/missing-client")
    );

    let store = LocalProfileStore::new(&fixture.context);
    let profile = store.create("Alex_02").unwrap();
    let executor = LaunchExecutor::new();
    let error = nacl_next_sdk::launch::launch(
        &fixture.context,
        &executor,
        &instance.id,
        &LaunchIdentity::Local(profile),
        None,
    )
    .expect_err("launch must fail on a missing client");
    assert_eq!(
        nacl_next_sdk::error::SdkError::from(error).code,
        "launch/missing-client"
    );
    // Nothing was fetched: the jar is still gone.
    assert!(!fixture
        .context
        .versions_root
        .join("1.21.1-probe.jar")
        .exists());
}

#[test]
fn probe_reports_nonzero_exit_state() {
    let fixture = build_probe_fixture("exit-code");
    let mut instance = ready_instance(&fixture.context, &fixture.java_executable);
    instance.advanced.game_arguments = "--fail".to_string();
    let instance = nacl_next_sdk::instance::update_instance(&fixture.context, instance).unwrap();

    let store = LocalProfileStore::new(&fixture.context);
    let profile = store.create("Notch_03").unwrap();
    let executor = LaunchExecutor::new();
    let launched = nacl_next_sdk::launch::launch(
        &fixture.context,
        &executor,
        &instance.id,
        &LaunchIdentity::Local(profile),
        None,
    )
    .expect("launch should spawn");

    assert_eq!(
        executor.wait(launched.process_id).expect("wait"),
        ExitState::Exited(7),
        "probe should forward its --fail exit code"
    );
}

fn same_path(left: &str, right: &Path) -> bool {
    let left = Path::new(left);
    left == right
        || left
            .canonicalize()
            .ok()
            .zip(right.canonicalize().ok())
            .is_some_and(|(left, right)| left == right)
}
