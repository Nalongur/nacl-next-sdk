//! S2 acceptance: transfer engines, cache, plan executor and providers. (r1)
//!
//! All content is self-owned bytes; the HTTP provider tests run against an
//! in-process loopback server (own resources only — no third-party service).

mod common;

use common::http_server::TestServer;
use nacl_next_sdk::cache::DigestAlgorithm;
use nacl_next_sdk::plan::{
    cleanup_stale_staging, execute, Artifact, ArtifactSource, ConflictPolicy, DigestPolicy,
    DigestSpec, ExecutionHooks, InstallContext, InstallPlan, PlannedFile, SourcePolicy,
};
use nacl_next_sdk::provider::{
    ContentProvider, ContentRequest, HttpManifestProvider, LocalFileProvider,
};
use nacl_next_sdk::transfer::{self, TransferControl, TransferOptions};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::Arc;

fn temp_root(label: &str) -> (tempfile::TempDir, PathBuf) {
    let root = tempfile::tempdir().expect("temporary root");
    let dir = root.path().join(label);
    std::fs::create_dir_all(&dir).unwrap();
    (root, dir)
}

fn sha256_of(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(bytes);
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

// ---------- plan-level (local provider; deterministic) ----------

fn write_manifest(dir: &Path, content_id: &str, files: &[(&str, &[u8])]) {
    let manifest = serde_json::json!({
        "schemaVersion": 1,
        "contentId": content_id,
        "files": files.iter().map(|(path, bytes)| {
            serde_json::json!({
                "path": path,
                "sha256": sha256_of(bytes),
                "size": bytes.len(),
            })
        }).collect::<Vec<_>>(),
    });
    std::fs::write(
        dir.join("content-manifest.json"),
        serde_json::to_vec_pretty(&manifest).unwrap(),
    )
    .unwrap();
    for (path, bytes) in files {
        let destination = dir.join(path);
        std::fs::create_dir_all(destination.parent().unwrap()).unwrap();
        std::fs::write(destination, bytes).unwrap();
    }
}

#[test]
fn local_provider_full_install_verifies_and_caches() {
    let (root, source) = temp_root("local-src");
    write_manifest(
        &source,
        "demo-pack",
        &[
            ("docs/readme.txt", b"self owned readme" as &[u8]),
            ("data/blob.bin", &[7_u8; 300 * 1024]),
        ],
    );
    let provider = LocalFileProvider::new(&source);
    let plan = provider
        .resolve(
            &ContentRequest {
                content_id: "demo-pack".into(),
            },
            &|| TransferControl::Running,
        )
        .expect("plan resolves");

    let (install_root, cache_root) = (root.path().join("install"), root.path().join("cache"));
    let context = InstallContext::new(
        &install_root,
        &cache_root,
        DigestPolicy::RequiredAndVerify,
        SourcePolicy::allow_all(),
    )
    .expect("context");
    let hooks = ExecutionHooks::default();
    let result = execute(&context, &plan, &hooks).expect("install succeeds");

    assert_eq!(result.committed.len(), 2);
    assert_eq!(
        std::fs::read_to_string(install_root.join("docs/readme.txt")).unwrap(),
        "self owned readme"
    );
    // Managed registry recorded both files.
    let managed =
        std::fs::read_to_string(install_root.join(".nacl-next-sdk/managed.json")).unwrap();
    assert!(managed.contains("docs/readme.txt"));

    // Second identical install: cache hits, Skip policy leaves files intact.
    let mut plan2 = provider
        .resolve(
            &ContentRequest {
                content_id: "demo-pack".into(),
            },
            &|| TransferControl::Running,
        )
        .unwrap();
    plan2.conflict_policy = ConflictPolicy::Skip;
    let result2 = execute(&context, &plan2, &hooks).expect("second install");
    assert_eq!(result2.skipped.len(), 2);
    assert_eq!(result2.committed.len(), 0);
    drop(root);
}

#[test]
fn digest_mismatch_fails_and_rolls_back() {
    let (root, source) = temp_root("mismatch-src");
    write_manifest(&source, "bad-pack", &[("a.txt", b"original" as &[u8])]);
    // Corrupt the source after the manifest was written.
    std::fs::write(source.join("a.txt"), b"tampered").unwrap();

    let provider = LocalFileProvider::new(&source);
    let plan = provider
        .resolve(
            &ContentRequest {
                content_id: "bad-pack".into(),
            },
            &|| TransferControl::Running,
        )
        .unwrap();
    let context = InstallContext::new(
        root.path().join("install"),
        root.path().join("cache"),
        DigestPolicy::RequiredAndVerify,
        SourcePolicy::allow_all(),
    )
    .unwrap();
    let error = execute(&context, &plan, &ExecutionHooks::default())
        .expect_err("digest mismatch must fail");
    assert_eq!(
        nacl_next_sdk::SdkError::from(error).code,
        "plan/digest-mismatch"
    );
    assert!(!context.install_root.join("a.txt").exists());
    // Cache must not hold the tampered object.
    let digest = plan.files[0].artifact.digest.as_ref().unwrap();
    assert!(!context.cache.contains(&digest.to_content_digest()));
    drop(root);
}

#[test]
fn digest_policy_governs_digestless_artifacts() {
    let (root, _) = temp_root("policy");
    let context = InstallContext::new(
        root.path().join("install"),
        root.path().join("cache"),
        DigestPolicy::RequiredAndVerify,
        SourcePolicy::allow_all(),
    )
    .unwrap();
    let (source_root, source) = temp_root("policy-src");
    std::fs::write(source.join("payload.bin"), b"no digest content").unwrap();
    let plan = InstallPlan::new(
        "no-digest",
        vec![PlannedFile {
            artifact: Artifact {
                id: "a1".into(),
                source: ArtifactSource::Local {
                    path: source.join("payload.bin"),
                },
                digest: None,
                size: 17,
            },
            relative_path: "payload.bin".into(),
        }],
    );
    let error = execute(&context, &plan, &ExecutionHooks::default()).unwrap_err();
    assert_eq!(
        nacl_next_sdk::SdkError::from(error).code,
        "plan/digest-required"
    );

    // Host explicitly relaxes the policy: install succeeds, size-checked.
    let relaxed = InstallContext::new(
        root.path().join("install2"),
        root.path().join("cache2"),
        DigestPolicy::VerifyIfPresent,
        SourcePolicy::allow_all(),
    )
    .unwrap();
    execute(&relaxed, &plan, &ExecutionHooks::default()).expect("relaxed policy installs");
    assert!(relaxed.install_root.join("payload.bin").is_file());
    drop(source_root);
    drop(root);
}

#[test]
fn path_escape_is_rejected_before_any_file_write() {
    let (root, _) = temp_root("escape");
    let context = InstallContext::new(
        root.path().join("install"),
        root.path().join("cache"),
        DigestPolicy::VerifyIfPresent,
        SourcePolicy::allow_all(),
    )
    .unwrap();
    for bad in [
        "../evil.txt",
        "a/../../evil.txt",
        "C:/evil.txt",
        "\\\\server\\share\\e",
    ] {
        let plan = InstallPlan::new(
            "escape",
            vec![PlannedFile {
                artifact: Artifact {
                    id: "x".into(),
                    source: ArtifactSource::CacheOnly,
                    digest: None,
                    size: 1,
                },
                relative_path: bad.into(),
            }],
        );
        let error = execute(&context, &plan, &ExecutionHooks::default()).unwrap_err();
        assert_eq!(
            nacl_next_sdk::SdkError::from(error).code,
            "plan/invalid-path",
            "path {bad:?} must be rejected at validation"
        );
    }
    assert!(std::fs::read_dir(root.path()).unwrap().count() <= 3);
    drop(root);
}

#[test]
fn conflict_policies_protect_unmanaged_files() {
    let (root, source) = temp_root("conflict");
    write_manifest(
        &source,
        "c-pack",
        &[("shared.txt", b"new content" as &[u8])],
    );
    let provider = LocalFileProvider::new(&source);
    let resolve = || {
        provider
            .resolve(
                &ContentRequest {
                    content_id: "c-pack".into(),
                },
                &|| TransferControl::Running,
            )
            .unwrap()
    };

    let install_root = root.path().join("install");
    let context = InstallContext::new(
        &install_root,
        root.path().join("cache"),
        DigestPolicy::RequiredAndVerify,
        SourcePolicy::allow_all(),
    )
    .unwrap();
    std::fs::create_dir_all(&install_root).unwrap();
    std::fs::write(install_root.join("shared.txt"), b"user's own file").unwrap();

    // Fail: the target exists.
    let mut plan = resolve();
    plan.conflict_policy = ConflictPolicy::Fail;
    let error = execute(&context, &plan, &ExecutionHooks::default()).unwrap_err();
    assert_eq!(nacl_next_sdk::SdkError::from(error).code, "plan/conflict");
    assert_eq!(
        std::fs::read_to_string(install_root.join("shared.txt")).unwrap(),
        "user's own file"
    );

    // OverwriteManaged: still fails — the file is not managed.
    let mut plan = resolve();
    plan.conflict_policy = ConflictPolicy::OverwriteManaged;
    let error = execute(&context, &plan, &ExecutionHooks::default()).unwrap_err();
    assert_eq!(nacl_next_sdk::SdkError::from(error).code, "plan/conflict");

    // Once the user removes their file, install succeeds; a re-install with
    // OverwriteManaged then replaces the managed file.
    std::fs::remove_file(install_root.join("shared.txt")).unwrap();
    execute(&context, &resolve(), &ExecutionHooks::default()).expect("fresh install");
    let mut plan = resolve();
    plan.conflict_policy = ConflictPolicy::OverwriteManaged;
    execute(&context, &plan, &ExecutionHooks::default()).expect("managed overwrite");
    assert_eq!(
        std::fs::read_to_string(install_root.join("shared.txt")).unwrap(),
        "new content"
    );
    drop(root);
}

#[test]
fn cancellation_mid_install_rolls_back_everything() {
    let (root, source) = temp_root("cancel");
    write_manifest(
        &source,
        "cancel-pack",
        &[
            ("first.txt", b"one" as &[u8]),
            ("second.txt", b"two" as &[u8]),
            ("third.txt", b"three" as &[u8]),
        ],
    );
    let provider = LocalFileProvider::new(&source);
    let plan = provider
        .resolve(
            &ContentRequest {
                content_id: "cancel-pack".into(),
            },
            &|| TransferControl::Running,
        )
        .unwrap();
    let context = InstallContext::new(
        root.path().join("install"),
        root.path().join("cache"),
        DigestPolicy::RequiredAndVerify,
        SourcePolicy::allow_all(),
    )
    .unwrap();

    let cancel_after_first = AtomicBool::new(false);
    let hooks = ExecutionHooks {
        control: &|| {
            if cancel_after_first.load(Ordering::SeqCst) {
                TransferControl::Cancelled
            } else {
                TransferControl::Running
            }
        },
        on_file_event: &|event| {
            if matches!(event.kind, nacl_next_sdk::plan::FileEventKind::Committed) {
                cancel_after_first.store(true, Ordering::SeqCst);
            }
        },
    };
    let error = execute(&context, &plan, &hooks).unwrap_err();
    assert_eq!(nacl_next_sdk::SdkError::from(error).code, "plan/cancelled");
    assert!(
        !context.install_root.join("first.txt").exists(),
        "rollback removes committed files"
    );
    assert!(!context.install_root.join("third.txt").exists());
    assert!(
        !context.install_root.join(".nacl-next-sdk/staging").exists()
            || std::fs::read_dir(context.install_root.join(".nacl-next-sdk/staging"))
                .unwrap()
                .count()
                == 0,
        "staging is cleared"
    );
    drop(root);
}

#[test]
fn stale_staging_journal_is_recovered_at_startup() {
    let (root, _) = temp_root("stale");
    let context = InstallContext::new(
        root.path().join("install"),
        root.path().join("cache"),
        DigestPolicy::RequiredAndVerify,
        SourcePolicy::allow_all(),
    )
    .unwrap();
    let install_root = &context.install_root;
    let staging = install_root.join(".nacl-next-sdk/staging/interrupted-plan");
    std::fs::create_dir_all(&staging).unwrap();
    // A file the interrupted plan committed…
    std::fs::create_dir_all(install_root).unwrap();
    std::fs::write(install_root.join("half.txt"), b"partial").unwrap();
    // …and its journal.
    std::fs::write(
        staging.join("journal.json"),
        serde_json::json!({
            "schemaVersion": 2,
            "planId": "interrupted-plan",
            "registryBefore": {},
            "files": [{
                "relativePath": "half.txt",
                "backupIntent": false,
                "backupDone": false,
                "committed": true,
            }],
        })
        .to_string(),
    )
    .unwrap();

    let recovered = cleanup_stale_staging(&context).expect("cleanup");
    assert_eq!(recovered, 1);
    assert!(
        !install_root.join("half.txt").exists(),
        "committed file is rolled back"
    );
    assert!(!staging.exists());
    drop(root);
}

#[test]
fn second_plan_on_same_root_is_rejected_while_first_runs() {
    let (root, source) = temp_root("mutex");
    write_manifest(&source, "m-pack", &[("x.txt", b"x" as &[u8])]);
    let provider = LocalFileProvider::new(&source);
    let plan = provider
        .resolve(
            &ContentRequest {
                content_id: "m-pack".into(),
            },
            &|| TransferControl::Running,
        )
        .unwrap();
    let context = InstallContext::new(
        root.path().join("install"),
        root.path().join("cache"),
        DigestPolicy::RequiredAndVerify,
        SourcePolicy::allow_all(),
    )
    .unwrap();

    let release = Arc::new(AtomicBool::new(false));
    let release_for_thread = Arc::clone(&release);
    std::thread::scope(|scope| {
        let handle = scope.spawn(|| {
            let control = || {
                if release_for_thread.load(Ordering::SeqCst) {
                    TransferControl::Running
                } else {
                    TransferControl::Paused
                }
            };
            let paused_hooks = ExecutionHooks {
                control: &control,
                on_file_event: &|_| {},
            };
            execute(&context, &plan, &paused_hooks)
        });
        std::thread::sleep(std::time::Duration::from_millis(300));
        let error = execute(&context, &plan, &ExecutionHooks::default()).unwrap_err();
        assert_eq!(
            nacl_next_sdk::SdkError::from(error).code,
            "plan/install-in-progress"
        );
        release.store(true, Ordering::SeqCst);
        handle
            .join()
            .unwrap()
            .expect("first plan finishes after release");
    });
    drop(root);
}

#[test]
fn cache_only_source_requires_cache_hit() {
    let (root, _) = temp_root("cache-only");
    let context = InstallContext::new(
        root.path().join("install"),
        root.path().join("cache"),
        DigestPolicy::VerifyIfPresent,
        SourcePolicy::allow_all(),
    )
    .unwrap();
    let plan = InstallPlan::new(
        "cache-only",
        vec![PlannedFile {
            artifact: Artifact {
                id: "c1".into(),
                source: ArtifactSource::CacheOnly,
                digest: Some(DigestSpec {
                    algorithm: DigestAlgorithm::Sha256,
                    value: sha256_of(b"never seeded"),
                    expected_source: "test".into(),
                }),
                size: 11,
            },
            relative_path: "missing.bin".into(),
        }],
    );
    let error = execute(&context, &plan, &ExecutionHooks::default()).unwrap_err();
    assert_eq!(nacl_next_sdk::SdkError::from(error).code, "plan/cache-miss");
    drop(root);
}

// ---------- transfer-level (loopback server; resume / ETag / retry) ----------

fn transfer_options_for_local_tests() -> TransferOptions {
    TransferOptions {
        segment_connections: 2,
        segment_threshold_bytes: 128 * 1024,
        retry_count: 2,
        retry_backoff: std::time::Duration::from_millis(20),
        speed_limit_bytes_per_second: None,
    }
}

#[test]
fn segmented_transfer_resumes_and_strong_etag_change_invalidates_state() {
    let server = TestServer::start_default();
    let payload: Vec<u8> = (0..9 * 1024 * 1024_u32)
        .map(|index| (index % 251) as u8)
        .collect::<Vec<_>>();
    server.add_file("blob.bin", payload.clone());
    let total_pieces = 5_u64; // 2 MiB piece size over 9 MiB

    let client = transfer::http_client().unwrap();
    let options = transfer_options_for_local_tests();

    // Pause-confirm-cancel: run until the persisted state shows a completed
    // piece, freeze via Paused, read the stable completed count N, then
    // cancel. This removes the observation race that byte thresholds have.
    fn run_cancelled_after_piece(
        client: &reqwest::blocking::Client,
        server: &TestServer,
        payload: &[u8],
        options: TransferOptions,
        destination: &Path,
    ) -> u64 {
        // Pause-confirm-cancel inside one scoped thread block: run until the
        // persisted state shows a completed piece, freeze via Paused, read
        // the stable completed count, then cancel. Byte thresholds cannot do
        // this without observation races.
        let phase = Arc::new(AtomicU8::new(0)); // 0=running 1=paused 2=cancelled
        let phase_control = Arc::clone(&phase);
        let control = move || match phase_control.load(Ordering::SeqCst) {
            0 => TransferControl::Running,
            1 => TransferControl::Paused,
            _ => TransferControl::Cancelled,
        };
        let state_path = PathBuf::from(format!("{}.nacl-next.json", destination.display()));
        let staged_part = destination.to_path_buf();
        let url = server.url("blob.bin");
        let identity = format!("sha256:{}", sha256_of(payload));

        std::thread::scope(|scope| {
            let handle = scope.spawn(move || {
                transfer::transfer(
                    client,
                    transfer::TransferRequest {
                        url: &url,
                        expected_size: payload.len() as u64,
                        identity: &identity,
                        destination: &staged_part,
                        byte_cap: None,
                    },
                    options,
                    &control,
                    &|_| {},
                )
            });
            let completed_in = || -> u64 {
                std::fs::read_to_string(&state_path)
                    .ok()
                    .and_then(|contents| serde_json::from_str::<serde_json::Value>(&contents).ok())
                    .and_then(|state| {
                        state["completed"].as_array().map(|entries| {
                            entries
                                .iter()
                                .filter(|entry| entry.as_bool() == Some(true))
                                .count() as u64
                        })
                    })
                    .unwrap_or(0)
            };
            loop {
                if completed_in() >= 1 {
                    phase.store(1, Ordering::SeqCst);
                    break;
                }
                assert!(
                    !handle.is_finished(),
                    "transfer finished before a piece could be observed; test environment too fast"
                );
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
            std::thread::sleep(std::time::Duration::from_millis(200));
            phase.store(2, Ordering::SeqCst);
            let result = handle.join().expect("worker should not panic");
            assert!(
                result.is_err(),
                "paused-then-cancelled run must return an error"
            );
            assert!(
                destination.is_file(),
                "cancelled segmented run keeps its .part"
            );
            // The authoritative count is what the state file says *after*
            // the run died — run 2 resumes from exactly this, whatever a
            // piece thread managed to persist during the pause transition.
            let completed = completed_in();
            assert!(
                completed >= 1,
                "at least one piece must be persisted for resume"
            );
            completed
        })
    }

    // Run 1 + resume run 2: only the remaining pieces are fetched.
    let staging = tempfile::tempdir().unwrap();
    let destination = staging.path().join("blob.part");
    let completed = run_cancelled_after_piece(&client, &server, &payload, options, &destination);
    let before = server.range_requests_for("blob.bin");
    transfer::transfer(
        &client,
        transfer::TransferRequest {
            url: &server.url("blob.bin"),
            expected_size: payload.len() as u64,
            identity: &format!("sha256:{}", sha256_of(&payload)),
            destination: &destination,
            byte_cap: None,
        },
        options,
        &|| TransferControl::Running,
        &|_| {},
    )
    .expect("run 2 completes");
    assert_eq!(std::fs::read(&destination).unwrap(), payload);
    let resume_requests = server.range_requests_for("blob.bin") - before;
    let full_after = server.full_requests_for("blob.bin");
    assert_eq!(
        resume_requests,
        1 + (total_pieces - completed),
        "resume must fetch probe + exactly the remaining pieces (range={resume_requests}, full={full_after}, completed={completed})"
    );

    // Run 3: same pause-cancel under the original strong ETag, then change
    // the ETag — resume state is discarded and everything is refetched.
    let fresh = tempfile::tempdir().unwrap();
    let destination3 = fresh.path().join("blob.part");
    run_cancelled_after_piece(&client, &server, &payload, options, &destination3);
    server.set_etag("blob.bin", "\"changed-v2\"");
    let before3 = server.range_requests_for("blob.bin");
    transfer::transfer(
        &client,
        transfer::TransferRequest {
            url: &server.url("blob.bin"),
            expected_size: payload.len() as u64,
            identity: &format!("sha256:{}", sha256_of(&payload)),
            destination: &destination3,
            byte_cap: None,
        },
        options,
        &|| TransferControl::Running,
        &|_| {},
    )
    .expect("etag-changed run completes");
    assert_eq!(std::fs::read(&destination3).unwrap(), payload);
    assert_eq!(
        server.range_requests_for("blob.bin") - before3,
        1 + total_pieces,
        "changed strong ETag must discard resume state and refetch everything"
    );
}

#[test]
fn transfer_retries_transient_failures() {
    let server = TestServer::start_default();
    let payload = vec![9_u8; 64 * 1024];
    server.add_file("flaky.bin", payload.clone());
    server.fail_next_requests("flaky.bin", 2);

    let client = transfer::http_client().unwrap();
    let staging = tempfile::tempdir().unwrap();
    let destination = staging.path().join("flaky.part");
    let outcome = transfer::transfer(
        &client,
        transfer::TransferRequest {
            url: &server.url("flaky.bin"),
            expected_size: payload.len() as u64,
            identity: "sha256:test",
            destination: &destination,
            byte_cap: None,
        },
        transfer_options_for_local_tests(),
        &|| TransferControl::Running,
        &|_| {},
    )
    .expect("retry recovers transient failures");
    assert_eq!(outcome.downloaded_bytes, payload.len() as u64);
}

// ---------- HTTP provider end-to-end ----------

#[test]
fn http_manifest_provider_installs_from_loopback() {
    let server = TestServer::start_default();
    let files: Vec<(&str, Vec<u8>)> = vec![
        (
            "assets/first.bin",
            (0..200_u32).map(|i| (i % 256) as u8).collect(),
        ),
        ("assets/second.bin", vec![3_u8; 700 * 1024]),
    ];
    let manifest = serde_json::json!({
        "schemaVersion": 1,
        "contentId": "http-pack",
        "files": files.iter().map(|(path, bytes)| serde_json::json!({
            "path": path,
            "sha256": sha256_of(bytes),
            "size": bytes.len(),
        })).collect::<Vec<_>>(),
    });
    server.add_file("content-manifest.json", manifest.to_string().into_bytes());
    for (path, bytes) in &files {
        server.add_file(path, bytes.clone());
    }

    let provider = HttpManifestProvider::new(server.base_url()).unwrap();
    let plan = provider
        .resolve(
            &ContentRequest {
                content_id: "http-pack".into(),
            },
            &|| TransferControl::Running,
        )
        .expect("http plan resolves");

    let (root, _) = temp_root("http-install");
    let context = InstallContext::new(
        root.path().join("install"),
        root.path().join("cache"),
        DigestPolicy::RequiredAndVerify,
        SourcePolicy::allow_all(),
    )
    .unwrap();
    let hooks = ExecutionHooks::default();
    let result = execute(&context, &plan, &hooks).expect("http install succeeds");
    assert_eq!(result.committed.len(), 2);
    for (path, bytes) in &files {
        assert_eq!(
            std::fs::read(context.install_root.join(path)).unwrap(),
            *bytes,
            "installed content must match for {path}"
        );
    }

    // Unknown content id is a stable provider error, not a network guess.
    let error = provider
        .resolve(
            &ContentRequest {
                content_id: "no-such-pack".into(),
            },
            &|| TransferControl::Running,
        )
        .unwrap_err();
    assert_eq!(
        nacl_next_sdk::SdkError::from(error).code,
        "provider/unknown-content"
    );
    drop(root);
}

#[test]
fn server_reqwest_probe() {
    let server = TestServer::start_default();
    server.add_file("probe.txt", b"hello".to_vec());
    let client = transfer::http_client().unwrap();
    let response = client.get(server.url("probe.txt")).send();
    match response {
        Ok(response) => println!("status {}", response.status()),
        Err(error) => {
            let mut chain = error.to_string();
            let mut source = std::error::Error::source(&error);
            while let Some(error) = source {
                chain.push_str(" <- ");
                chain.push_str(&error.to_string());
                source = error.source();
            }
            panic!("reqwest error chain: {chain}");
        }
    }
}
