//! D-mode coexistence at SDK level (requires the `microsoft` feature):
//! the same build hosts both identity sources; the local branch runs the
//! full launch chain while a signed-out Microsoft selection fails with a
//! stable code and no local fallback.

#![cfg(feature = "microsoft")]

mod common;

use common::{build_probe_fixture, ready_instance};
use nacl_next_sdk::account::{AccountProvider, LaunchIdentity, LocalProfileStore};
use nacl_next_sdk::launch::{ExitState, LaunchExecutor};
use nacl_next_sdk::SdkErrorSource;

#[test]
fn d_build_launches_local_identity_full_chain() {
    let fixture = build_probe_fixture("d-full-chain");
    let instance = ready_instance(&fixture.context, &fixture.java_executable);

    let store = LocalProfileStore::new(&fixture.context);
    let profile = store.create("Steve_01").expect("local profile in D build");
    let identity = store
        .prepare_launch_identity(&profile.id)
        .expect("local identity in D build");

    let executor = LaunchExecutor::new();
    let launched =
        nacl_next_sdk::launch::launch(&fixture.context, &executor, &instance.id, &identity, None)
            .expect("D build must launch the local identity");
    assert_eq!(
        executor.wait(launched.process_id).expect("wait"),
        ExitState::Exited(0)
    );

    let game_dir = fixture
        .context
        .instances_root
        .join(&instance.id)
        .join("game");
    let arguments =
        std::fs::read_to_string(game_dir.join("probe-args.txt")).expect("probe arguments");
    assert!(arguments.contains("Steve_01"));
}

#[test]
fn d_build_microsoft_selection_fails_without_local_fallback() {
    let fixture = build_probe_fixture("d-no-fallback");
    let provider = nacl_next_sdk::MicrosoftProvider::new(
        nacl_next_sdk::MicrosoftClientConfig::new("test-client-id-for-d-build").unwrap(),
        &fixture.context,
    );

    // Signed out and no stored credentials: stable error, and the returned
    // identity is never a local one.
    let error = provider
        .prepare_launch_identity()
        .expect_err("signed-out prepare must fail");
    let code = error.sdk_code();
    assert!(
        code.starts_with("auth/microsoft/"),
        "expected an auth/microsoft code, got {code}"
    );

    // The trait-level selection used by the shell reports unavailability
    // before id matching — still no fallback.
    let selection =
        AccountProvider::prepare_launch_identity(&provider, "00000000000000000000000000000000");
    assert!(selection.is_err());
    assert!(provider
        .list_identities()
        .expect("microsoft list")
        .is_empty());

    // And the local branch in the same context keeps working.
    let store = LocalProfileStore::new(&fixture.context);
    let profile = store.create("Alex_02").expect("local branch unaffected");
    assert!(matches!(
        store.prepare_launch_identity(&profile.id),
        Ok(LaunchIdentity::Local(_))
    ));

    // Logging out the empty Microsoft side does not touch local profiles.
    provider.logout().expect("logout on empty state");
    assert_eq!(store.list().expect("local list").len(), 1);
}
