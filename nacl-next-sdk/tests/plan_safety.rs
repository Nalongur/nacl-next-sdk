//! Formal regression tests for the 2026-10-24 review findings F1–F10.
//!
//! These mirror the external reproduction project inside the SDK's own
//! suite so the guarantees stay locked in. All data lives in per-test
//! temporary directories; the "outside" files also stay inside the test's
//! own temporary parent.

use nacl_next_sdk::cache::{hash_file, DigestAlgorithm};
use nacl_next_sdk::plan::{
    cleanup_stale_staging, execute, Artifact, ArtifactSource, ConflictPolicy, DigestPolicy,
    DigestSpec, ExecutionHooks, FileEventKind, InstallContext, InstallPlan, PlannedFile,
    SourcePolicy,
};
use nacl_next_sdk::transfer::TransferControl;
use std::fs;
use std::path::Path;

fn file_entry(source: &Path, relative: &str) -> PlannedFile {
    PlannedFile {
        relative_path: relative.into(),
        artifact: Artifact {
            id: relative.into(),
            source: ArtifactSource::Local {
                path: source.to_path_buf(),
            },
            size: fs::metadata(source).unwrap().len(),
            digest: Some(DigestSpec {
                algorithm: DigestAlgorithm::Sha256,
                value: hash_file(DigestAlgorithm::Sha256, source).unwrap(),
                expected_source: "regression fixture".into(),
            }),
        },
    }
}

fn context(root: &Path) -> InstallContext {
    InstallContext::new(
        root.join("install"),
        root.join("cache"),
        DigestPolicy::RequiredAndVerify,
        SourcePolicy::allow_all(),
    )
    .unwrap()
}

// F1: a failed managed replacement must never lose the original.
#[test]
fn failed_managed_overwrite_restores_original() {
    let tmp = tempfile::tempdir().unwrap();
    let c = context(tmp.path());
    let src = tmp.path().join("source");
    fs::write(&src, b"original").unwrap();
    execute(
        &c,
        &InstallPlan::new("initial", vec![file_entry(&src, "data.txt")]),
        &ExecutionHooks::default(),
    )
    .unwrap();
    fs::write(&src, b"new data").unwrap();
    let mut f = file_entry(&src, "data.txt");
    f.artifact.digest.as_mut().unwrap().value = "0".repeat(64);
    let mut p = InstallPlan::new("update", vec![f]);
    p.conflict_policy = ConflictPolicy::OverwriteManaged;
    let error = execute(&c, &p, &ExecutionHooks::default()).unwrap_err();
    assert_eq!(
        nacl_next_sdk::SdkError::from(error).code,
        "plan/digest-mismatch"
    );
    assert_eq!(
        fs::read(c.install_root.join("data.txt")).ok(),
        Some(b"original".to_vec()),
        "failed replacement lost original file"
    );
}

// F2: commit temps are exclusive and unique; an unmanaged sibling with the
// legacy fixed name survives every policy.
#[test]
fn commit_preserves_unmanaged_sibling_temp_files() {
    let tmp = tempfile::tempdir().unwrap();
    let c = context(tmp.path());
    let src = tmp.path().join("source");
    fs::write(&src, b"payload").unwrap();
    fs::create_dir_all(&c.install_root).unwrap();
    let part = c.install_root.join("data.nacl-next.part");
    fs::write(&part, b"user data").unwrap();
    execute(
        &c,
        &InstallPlan::new("part", vec![file_entry(&src, "data.txt")]),
        &ExecutionHooks::default(),
    )
    .unwrap();
    assert_eq!(
        fs::read(&part).ok(),
        Some(b"user data".to_vec()),
        "unmanaged sibling was overwritten and renamed away"
    );
}

// F3: journal-supplied paths are revalidated; nothing outside the install
// root is ever touched, and untrusted records are kept, not deleted.
#[test]
fn recovery_rejects_journal_paths_outside_install_root() {
    let tmp = tempfile::tempdir().unwrap();
    let c = context(tmp.path());
    let outside = tmp.path().join("outside.txt");
    fs::write(&outside, b"keep").unwrap();
    let stage = c.install_root.join(".nacl-next-sdk/staging/forged");
    fs::create_dir_all(&stage).unwrap();
    fs::write(
        stage.join("journal.json"),
        r#"{"schemaVersion":2,"planId":"forged","registryBefore":{},"files":[{"relativePath":"../outside.txt","backupIntent":false,"backupDone":false,"committed":true}]}"#,
    )
    .unwrap();
    let error = cleanup_stale_staging(&c).unwrap_err();
    assert_eq!(
        nacl_next_sdk::SdkError::from(error).code,
        "plan/recovery-failed"
    );
    assert!(
        outside.exists(),
        "recovery deleted a path outside install root"
    );
    assert!(
        stage.exists(),
        "suspicious record must be preserved for inspection"
    );
}

#[test]
fn recovery_keeps_unrecognized_journal_for_inspection() {
    let tmp = tempfile::tempdir().unwrap();
    let c = context(tmp.path());
    let stage = c.install_root.join(".nacl-next-sdk/staging/garbage");
    fs::create_dir_all(&stage).unwrap();
    fs::write(stage.join("journal.json"), r#"{"planId":"garbage"}"#).unwrap();
    fs::write(stage.join("backup-0"), b"precious").unwrap();
    let error = cleanup_stale_staging(&c).unwrap_err();
    assert_eq!(
        nacl_next_sdk::SdkError::from(error).code,
        "plan/recovery-failed"
    );
    assert!(
        stage.join("backup-0").exists(),
        "unreadable journal's backups were destroyed"
    );
}

// F4: the executor's internal namespace is off-limits to content, in any
// case form; an installed file can therefore never become a recovery
// journal (the forged-journal chain dies here).
#[test]
fn plan_rejects_internal_namespace_targets() {
    let tmp = tempfile::tempdir().unwrap();
    let c = context(tmp.path());
    let src = tmp.path().join("source");
    fs::write(&src, b"payload").unwrap();
    for bad in [
        ".nacl-next-sdk/staging/internal/data.txt",
        ".NACL-NEXT-SDK/managed.json",
        ".nacl-next-sdk/staging/forged/journal.json",
    ] {
        let plan = InstallPlan::new("internal", vec![file_entry(&src, bad)]);
        let error = execute(&c, &plan, &ExecutionHooks::default()).unwrap_err();
        assert_eq!(
            nacl_next_sdk::SdkError::from(error).code,
            "plan/invalid-path",
            "internal namespace target accepted: {bad}"
        );
    }
}

// F5: rollback restores not just the file but its managed record.
#[test]
fn rollback_keeps_restored_files_managed() {
    let tmp = tempfile::tempdir().unwrap();
    let c = context(tmp.path());
    let src = tmp.path().join("source");
    fs::write(&src, b"original").unwrap();
    execute(
        &c,
        &InstallPlan::new("initial", vec![file_entry(&src, "data.txt")]),
        &ExecutionHooks::default(),
    )
    .unwrap();
    fs::write(&src, b"new data").unwrap();
    let good = file_entry(&src, "data.txt");
    let mut bad = file_entry(&src, "other.txt");
    bad.artifact.digest.as_mut().unwrap().value = "0".repeat(64);
    let mut p = InstallPlan::new("update", vec![good, bad]);
    p.conflict_policy = ConflictPolicy::OverwriteManaged;
    assert!(execute(&c, &p, &ExecutionHooks::default()).is_err());
    assert_eq!(
        fs::read(c.install_root.join("data.txt")).unwrap(),
        b"original"
    );
    let registry: serde_json::Value = serde_json::from_slice(
        &fs::read(c.install_root.join(".nacl-next-sdk/managed.json")).unwrap(),
    )
    .unwrap();
    assert!(
        registry["files"].get("data.txt").is_some(),
        "restored file lost managed status"
    );
}

// F6: declared sizes are enforced against actual bytes for every source.
#[test]
fn local_artifact_enforces_declared_size() {
    let tmp = tempfile::tempdir().unwrap();
    let c = context(tmp.path());
    let src = tmp.path().join("source");
    fs::write(&src, b"larger than declared").unwrap();
    let mut f = file_entry(&src, "data.txt");
    f.artifact.digest.as_mut().unwrap().value = hash_file(DigestAlgorithm::Sha256, &src).unwrap(); // digest is correct
    f.artifact.size = 1;
    let mut p = InstallPlan::new("size", vec![f]);
    p.limits.max_total_bytes = 0; // plan declares no extra ceiling
    let error = execute(&c, &p, &ExecutionHooks::default()).unwrap_err();
    assert_eq!(
        nacl_next_sdk::SdkError::from(error).code,
        "plan/size-mismatch"
    );
    assert!(!c.install_root.join("data.txt").exists());
}

#[test]
fn host_total_limit_cannot_be_widened_by_plan() {
    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("source");
    fs::write(&src, b"0123456789").unwrap(); // 10 bytes
    let restricted = InstallContext::new(
        tmp.path().join("install"),
        tmp.path().join("cache"),
        DigestPolicy::RequiredAndVerify,
        SourcePolicy {
            max_total_bytes: Some(4),
            ..SourcePolicy::allow_all()
        },
    )
    .unwrap();
    let mut p = InstallPlan::new("cap", vec![file_entry(&src, "data.txt")]);
    p.limits.max_total_bytes = 0; // plan cannot lift the host ceiling
    let error = execute(&restricted, &p, &ExecutionHooks::default()).unwrap_err();
    assert_eq!(
        nacl_next_sdk::SdkError::from(error).code,
        "plan/resource-limit"
    );
}

// F7: lock identity follows the canonical directory, not the raw string.
#[test]
fn root_alias_cannot_bypass_install_mutex() {
    use std::sync::Mutex;
    let tmp = tempfile::tempdir().unwrap();
    let c = context(tmp.path());
    let src = tmp.path().join("source");
    fs::write(&src, b"payload").unwrap();
    let alias = InstallContext::new(
        c.install_root.join("."),
        tmp.path().join("other-cache"),
        DigestPolicy::RequiredAndVerify,
        SourcePolicy::allow_all(),
    )
    .unwrap();
    let nested = Mutex::new(None);
    let on_event = |event: nacl_next_sdk::plan::FileEvent<'_>| {
        if event.kind == FileEventKind::Started {
            let result = execute(
                &alias,
                &InstallPlan::new("second", vec![file_entry(&src, "second.txt")]),
                &ExecutionHooks::default(),
            );
            *nested.lock().unwrap() = Some(
                result
                    .map(|_| ())
                    .map_err(|error| nacl_next_sdk::SdkError::from(error).code.to_string()),
            );
        }
    };
    let hooks = ExecutionHooks {
        control: &|| TransferControl::Running,
        on_file_event: &on_event,
    };
    execute(
        &c,
        &InstallPlan::new("first", vec![file_entry(&src, "first.txt")]),
        &hooks,
    )
    .unwrap();
    assert_eq!(
        *nested.lock().unwrap(),
        Some(Err("plan/install-in-progress".into())),
        "alias bypassed same-root lock"
    );
}

// F8: case aliases and unreliable Windows path forms are rejected up front.
#[cfg(windows)]
#[test]
fn case_alias_targets_are_rejected_before_install() {
    let tmp = tempfile::tempdir().unwrap();
    let c = context(tmp.path());
    let src = tmp.path().join("source");
    fs::write(&src, b"payload").unwrap();
    let mut p = InstallPlan::new(
        "case",
        vec![file_entry(&src, "A.txt"), file_entry(&src, "a.txt")],
    );
    p.conflict_policy = ConflictPolicy::Skip;
    let error = execute(&c, &p, &ExecutionHooks::default()).unwrap_err();
    assert_eq!(
        nacl_next_sdk::SdkError::from(error).code,
        "plan/duplicate-target"
    );
}

#[test]
fn unreliable_path_forms_are_rejected() {
    let tmp = tempfile::tempdir().unwrap();
    let c = context(tmp.path());
    let src = tmp.path().join("source");
    fs::write(&src, b"payload").unwrap();
    for bad in ["ads:stream.txt", "CON", "trailing. ", "dir./file.txt"] {
        let plan = InstallPlan::new("forms", vec![file_entry(&src, bad)]);
        let error = execute(&c, &plan, &ExecutionHooks::default()).unwrap_err();
        assert_eq!(
            nacl_next_sdk::SdkError::from(error).code,
            "plan/invalid-path",
            "unreliable path accepted: {bad}"
        );
    }
}

// F9: crash between backup and commit recovers the original via the
// write-ahead journal; the worker exits hard inside the Started hook.
#[test]
fn crash_worker_entry() {
    let Some(root) = std::env::var_os("NACL_SDK_SAFETY_CRASH_ROOT") else {
        return;
    };
    let root = Path::new(&root).to_path_buf();
    let c = context(&root);
    let mut p = InstallPlan::new("crash", vec![file_entry(&root.join("source"), "data.txt")]);
    p.conflict_policy = ConflictPolicy::OverwriteManaged;
    let on_event = |event: nacl_next_sdk::plan::FileEvent<'_>| {
        if event.kind == FileEventKind::Started {
            std::process::exit(73);
        }
    };
    let hooks = ExecutionHooks {
        control: &|| TransferControl::Running,
        on_file_event: &on_event,
    };
    execute(&c, &p, &hooks).unwrap();
    panic!("did not reach the crash point");
}

#[test]
fn interrupted_overwrite_recovers_backup() {
    let tmp = tempfile::tempdir().unwrap();
    let c = context(tmp.path());
    let src = tmp.path().join("source");
    fs::write(&src, b"original").unwrap();
    execute(
        &c,
        &InstallPlan::new("initial", vec![file_entry(&src, "data.txt")]),
        &ExecutionHooks::default(),
    )
    .unwrap();
    fs::write(&src, b"new data").unwrap();
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "crash_worker_entry", "--nocapture"])
        .env("NACL_SDK_SAFETY_CRASH_ROOT", tmp.path())
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(73));
    assert!(
        c.install_root
            .join(".nacl-next-sdk/staging/crash/backup-0")
            .is_file(),
        "worker must have moved the original into its backup"
    );
    cleanup_stale_staging(&c).unwrap();
    assert_eq!(
        fs::read(c.install_root.join("data.txt")).ok(),
        Some(b"original".to_vec()),
        "startup recovery destroyed the only backup after process interruption"
    );
}

// F10: host source policy is enforced; plans cannot widen it.
#[test]
fn local_source_outside_allowed_roots_is_denied() {
    let tmp = tempfile::tempdir().unwrap();
    let allowed_root = tmp.path().join("allowed");
    fs::create_dir_all(&allowed_root).unwrap();
    let outside_source = tmp.path().join("outside-source");
    fs::write(&outside_source, b"secret").unwrap();
    let restricted = InstallContext::new(
        tmp.path().join("install"),
        tmp.path().join("cache"),
        DigestPolicy::RequiredAndVerify,
        SourcePolicy::allow_local_under(&allowed_root),
    )
    .unwrap();
    let error = execute(
        &restricted,
        &InstallPlan::new("policy", vec![file_entry(&outside_source, "data.txt")]),
        &ExecutionHooks::default(),
    )
    .unwrap_err();
    assert_eq!(
        nacl_next_sdk::SdkError::from(error).code,
        "plan/source-denied"
    );
    assert!(!restricted.install_root.join("data.txt").exists());
}

#[test]
fn http_source_host_not_on_allow_list_is_denied() {
    let tmp = tempfile::tempdir().unwrap();
    let restricted = InstallContext::new(
        tmp.path().join("install"),
        tmp.path().join("cache"),
        DigestPolicy::RequiredAndVerify,
        SourcePolicy {
            http_hosts: vec!["content.example".to_string()],
            ..SourcePolicy::allow_all()
        },
    )
    .unwrap();
    let plan = InstallPlan::new(
        "http-policy",
        vec![PlannedFile {
            relative_path: "data.bin".into(),
            artifact: Artifact {
                id: "a1".into(),
                source: ArtifactSource::Http {
                    url: "http://127.0.0.1:9/unreachable-and-unallowed.bin".into(),
                },
                digest: Some(DigestSpec {
                    algorithm: DigestAlgorithm::Sha256,
                    value: "0".repeat(64),
                    expected_source: "test".into(),
                }),
                size: 1,
            },
        }],
    );
    let error = execute(&restricted, &plan, &ExecutionHooks::default()).unwrap_err();
    assert_eq!(
        nacl_next_sdk::SdkError::from(error).code,
        "plan/source-denied"
    );
}

// ---------- followup review (FOLLOWUP-c4d38c8) regressions R1-R5 ----------

// R1: retrying a recovery whose registry save failed must not delete the
// already-restored original (Windows: registry held with share_mode(0)).
#[test]
#[cfg(windows)]
fn retrying_failed_recovery_preserves_restored_original() {
    use std::os::windows::fs::OpenOptionsExt;
    let tmp = tempfile::tempdir().unwrap();
    let c = context(tmp.path());
    let stage = c.install_root.join(".nacl-next-sdk/staging/interrupted");
    std::fs::create_dir_all(&stage).unwrap();
    let target = c.install_root.join("data.txt");
    std::fs::write(&target, b"replacement").unwrap();
    std::fs::write(stage.join("backup-0"), b"original").unwrap();
    let registry = c.install_root.join(".nacl-next-sdk/managed.json");
    std::fs::write(&registry, r#"{"files":{}}"#).unwrap();
    std::fs::write(
        stage.join("journal.json"),
        r#"{"schemaVersion":2,"planId":"interrupted","registryBefore":{"data.txt":{"planId":"initial","digest":null}},"files":[{"relativePath":"data.txt","backupIntent":true,"backupDone":true,"committed":true}]}"#,
    )
    .unwrap();
    let locked = std::fs::OpenOptions::new()
        .read(true)
        .share_mode(0)
        .open(&registry)
        .unwrap();
    assert!(
        cleanup_stale_staging(&c).is_err(),
        "first recovery must fail saving the locked registry"
    );
    assert_eq!(std::fs::read(&target).unwrap(), b"original");
    assert!(stage.join("journal.json").is_file());
    drop(locked);
    cleanup_stale_staging(&c).unwrap();
    assert_eq!(
        std::fs::read(&target).ok(),
        Some(b"original".to_vec()),
        "second recovery deleted the already restored original"
    );
}

// R2: a reported-successful install must never be rolled back by startup
// recovery even when staging cleanup failed (journal held open without
// FILE_SHARE_DELETE during the Committed event).
#[test]
#[cfg(windows)]
fn successful_install_not_rolled_back_when_staging_cleanup_fails() {
    use std::os::windows::fs::OpenOptionsExt;
    use std::sync::Mutex;
    let tmp = tempfile::tempdir().unwrap();
    let c = context(tmp.path());
    let src = tmp.path().join("source");
    std::fs::write(&src, b"payload").unwrap();
    let lock = Mutex::new(None);
    let on_event = |event: nacl_next_sdk::plan::FileEvent<'_>| {
        if event.kind == FileEventKind::Committed {
            let path = c
                .install_root
                .join(".nacl-next-sdk/staging/success/journal.json");
            *lock.lock().unwrap() = Some(
                std::fs::OpenOptions::new()
                    .read(true)
                    .share_mode(3)
                    .open(path)
                    .unwrap(),
            );
        }
    };
    let plan = InstallPlan::new("success", vec![file_entry(&src, "data.txt")]);
    let hooks = ExecutionHooks {
        control: &|| TransferControl::Running,
        on_file_event: &on_event,
    };
    let result = execute(&c, &plan, &hooks);
    let reported_success = result.is_ok();
    if reported_success {
        assert_eq!(
            std::fs::read(c.install_root.join("data.txt")).unwrap(),
            b"payload"
        );
    }
    drop(lock.into_inner().unwrap());
    cleanup_stale_staging(&c).unwrap();
    if reported_success {
        assert_eq!(
            std::fs::read(c.install_root.join("data.txt")).ok(),
            Some(b"payload".to_vec()),
            "startup recovery removed a previously successful installation"
        );
    }
}

// R3: the rename-before-journal-update window state (create intent
// persisted, rename landed, committed flag not yet) must roll back the new
// file; a files=[] journal with an untracked target is no longer producible
// by the fixed executor.
#[test]
fn new_file_rename_window_is_recovered() {
    let tmp = tempfile::tempdir().unwrap();
    let c = context(tmp.path());
    let stage = c.install_root.join(".nacl-next-sdk/staging/interrupted");
    std::fs::create_dir_all(&stage).unwrap();
    let target = c.install_root.join("new.txt");
    std::fs::write(&target, b"renamed but not recorded yet").unwrap();
    std::fs::write(
        stage.join("journal.json"),
        r#"{"schemaVersion":2,"planId":"interrupted","registryBefore":{},"files":[{"relativePath":"new.txt","createIntent":true,"replaceExisting":false,"committed":false}]}"#,
    )
    .unwrap();
    cleanup_stale_staging(&c).unwrap();
    assert!(
        !target.exists(),
        "create-intent window state left an untracked file after recovery"
    );
}

// R4: redirects are re-checked against the host allow list on every hop.
#[test]
fn redirect_cannot_escape_http_host_allowlist() {
    use std::io::{Read, Write};
    use std::net::TcpListener;
    let tmp = tempfile::tempdir().unwrap();
    let payload = b"self owned test data";
    let source = tmp.path().join("source");
    std::fs::write(&source, payload).unwrap();
    let allowed = TcpListener::bind("127.0.0.1:0").unwrap();
    let source_port = allowed.local_addr().unwrap().port();
    let denied = TcpListener::bind("127.0.0.1:0").unwrap();
    let denied_port = denied.local_addr().unwrap().port();
    let redirect_thread = std::thread::spawn(move || {
        let (mut stream, _) = allowed.accept().unwrap();
        let mut buffer = [0_u8; 2048];
        let _ = stream.read(&mut buffer).unwrap();
        write!(
            stream,
            "HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:{denied_port}/payload\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        )
        .unwrap();
    });
    let served = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let served_child = std::sync::Arc::clone(&served);
    denied.set_nonblocking(true).unwrap();
    let destination_thread = std::thread::spawn(move || {
        let until = std::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            match denied.accept() {
                Ok((mut stream, _)) => {
                    stream.set_nonblocking(false).unwrap();
                    let mut buffer = [0_u8; 2048];
                    let _ = stream.read(&mut buffer).unwrap();
                    served_child.store(true, std::sync::atomic::Ordering::SeqCst);
                    write!(
                        stream,
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        payload.len()
                    )
                    .unwrap();
                    stream.write_all(payload).unwrap();
                    break;
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    if std::time::Instant::now() > until {
                        break;
                    }
                    std::thread::sleep(std::time::Duration::from_millis(10));
                }
                Err(error) => panic!("{error}"),
            }
        }
    });
    let restricted = InstallContext::new(
        tmp.path().join("install"),
        tmp.path().join("cache"),
        DigestPolicy::RequiredAndVerify,
        SourcePolicy {
            http_hosts: vec!["localhost".to_string()],
            ..SourcePolicy::allow_all()
        },
    )
    .unwrap();
    let plan = InstallPlan::new(
        "redirect",
        vec![PlannedFile {
            relative_path: "data.txt".into(),
            artifact: Artifact {
                id: "owned".into(),
                source: ArtifactSource::Http {
                    url: format!("http://localhost:{source_port}/payload"),
                },
                size: payload.len() as u64,
                digest: Some(DigestSpec {
                    algorithm: DigestAlgorithm::Sha256,
                    value: hash_file(DigestAlgorithm::Sha256, &source).unwrap(),
                    expected_source: "regression fixture".into(),
                }),
            },
        }],
    );
    let result = execute(&restricted, &plan, &ExecutionHooks::default());
    redirect_thread.join().unwrap();
    destination_thread.join().unwrap();
    assert!(
        !served.load(std::sync::atomic::Ordering::SeqCst),
        "request reached a denied host via an allowed-host redirect: {result:?}"
    );
    assert!(result.is_err());
}

// R5: host byte limits apply while reading, not only after the fact; a
// one-byte cap must stop the transfer before more bytes are written.
#[test]
fn host_byte_limit_applies_while_reading_response() {
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::atomic::{AtomicU64, Ordering};
    let tmp = tempfile::tempdir().unwrap();
    let payload = vec![7_u8; 64 * 1024];
    let source = tmp.path().join("source");
    std::fs::write(&source, &payload).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut buffer = [0_u8; 2048];
        let _ = stream.read(&mut buffer).unwrap();
        write!(
            stream,
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            payload.len()
        )
        .unwrap();
        let _ = stream.write_all(&payload);
    });
    let restricted = InstallContext::new(
        tmp.path().join("install"),
        tmp.path().join("cache"),
        DigestPolicy::RequiredAndVerify,
        SourcePolicy {
            max_file_bytes: Some(1),
            max_total_bytes: Some(1),
            ..SourcePolicy::allow_all()
        },
    )
    .unwrap();
    let plan = InstallPlan::new(
        "limit",
        vec![PlannedFile {
            relative_path: "data.txt".into(),
            artifact: Artifact {
                id: "owned".into(),
                source: ArtifactSource::Http {
                    url: format!("http://127.0.0.1:{port}/payload"),
                },
                size: 1,
                digest: Some(DigestSpec {
                    algorithm: DigestAlgorithm::Sha256,
                    value: hash_file(DigestAlgorithm::Sha256, &source).unwrap(),
                    expected_source: "regression fixture".into(),
                }),
            },
        }],
    );
    let observed = AtomicU64::new(0);
    let on_event = |event: nacl_next_sdk::plan::FileEvent<'_>| {
        if event.kind == FileEventKind::Progress {
            observed.fetch_max(event.downloaded_bytes, Ordering::SeqCst);
        }
    };
    let hooks = ExecutionHooks {
        control: &|| TransferControl::Running,
        on_file_event: &on_event,
    };
    assert!(execute(&restricted, &plan, &hooks).is_err());
    server.join().unwrap();
    assert!(
        observed.load(Ordering::SeqCst) <= 1,
        "one-byte host limit allowed {} bytes through before rejecting",
        observed.load(Ordering::SeqCst)
    );
}

// ---------- FOLLOWUP-e74f69d: completion-marker lifecycle ----------

// P1 core: a stale .done marker (orphaned by an interrupted cleanup) must
// never disarm a NEW transaction's rollback under the same plan id.
#[test]
fn orphan_done_marker_cannot_disarm_new_transaction_rollback() {
    let tmp = tempfile::tempdir().unwrap();
    let c = context(tmp.path());
    let src = tmp.path().join("source");
    std::fs::write(&src, b"v1-original").unwrap();

    // First run completes and cleans everything.
    execute(
        &c,
        &InstallPlan::new("cycle", vec![file_entry(&src, "data.txt")]),
        &ExecutionHooks::default(),
    )
    .unwrap();

    // Simulate the interrupted success cleanup: staging dir removed, marker
    // deletion lost — both the legacy name and a fabricated generation.
    let staging_root = c.install_root.join(".nacl-next-sdk/staging");
    std::fs::create_dir_all(&staging_root).unwrap();
    std::fs::write(staging_root.join("cycle.done"), b"").unwrap();
    std::fs::write(staging_root.join("cycle.deadbeef.done"), b"").unwrap();

    // A new transaction with the SAME plan id fails mid-replacement; the
    // stale markers must not turn its rollback into cleanup-only.
    std::fs::write(&src, b"v2-replacement").unwrap();
    let mut entry = file_entry(&src, "data.txt");
    entry.artifact.digest.as_mut().unwrap().value = "0".repeat(64);
    let mut plan = InstallPlan::new("cycle", vec![entry]);
    plan.conflict_policy = ConflictPolicy::OverwriteManaged;
    let error = execute(&c, &plan, &ExecutionHooks::default()).unwrap_err();
    assert_eq!(
        nacl_next_sdk::SdkError::from(error).code,
        "plan/digest-mismatch"
    );
    assert_eq!(
        std::fs::read(c.install_root.join("data.txt")).ok(),
        Some(b"v1-original".to_vec()),
        "stale completion marker disarmed the new transaction's rollback"
    );
    // The failing run also swept the stale markers it inherited.
    let leftovers: Vec<_> = std::fs::read_dir(&staging_root)
        .unwrap()
        .filter_map(Result::ok)
        .filter(|entry| entry.file_name().to_string_lossy().ends_with(".done"))
        .collect();
    assert!(
        leftovers.is_empty(),
        "stale markers survived: {leftovers:?}"
    );
}

// Repeated executions of one plan id (success → success → failure) leave a
// clean staging root and correct content at every step.
#[test]
fn same_plan_id_reexecutes_cleanly() {
    let tmp = tempfile::tempdir().unwrap();
    let c = context(tmp.path());
    let src = tmp.path().join("source");
    let staging_root = c.install_root.join(".nacl-next-sdk/staging");

    std::fs::write(&src, b"one").unwrap();
    execute(
        &c,
        &InstallPlan::new("repeat", vec![file_entry(&src, "data.txt")]),
        &ExecutionHooks::default(),
    )
    .unwrap();
    assert_eq!(
        std::fs::read(c.install_root.join("data.txt")).unwrap(),
        b"one"
    );

    std::fs::write(&src, b"two").unwrap();
    let mut second = InstallPlan::new("repeat", vec![file_entry(&src, "data.txt")]);
    second.conflict_policy = ConflictPolicy::OverwriteManaged;
    execute(&c, &second, &ExecutionHooks::default()).unwrap();
    assert_eq!(
        std::fs::read(c.install_root.join("data.txt")).unwrap(),
        b"two"
    );

    std::fs::write(&src, b"three-broken").unwrap();
    let mut entry = file_entry(&src, "data.txt");
    entry.artifact.digest.as_mut().unwrap().value = "0".repeat(64);
    let mut third = InstallPlan::new("repeat", vec![entry]);
    third.conflict_policy = ConflictPolicy::OverwriteManaged;
    assert!(execute(&c, &third, &ExecutionHooks::default()).is_err());
    assert_eq!(
        std::fs::read(c.install_root.join("data.txt")).ok(),
        Some(b"two".to_vec()),
        "failed rerun must leave the last good version"
    );

    if staging_root.exists() {
        let leftovers: Vec<_> = std::fs::read_dir(&staging_root)
            .unwrap()
            .filter_map(Result::ok)
            .map(|entry| entry.file_name())
            .collect();
        assert!(
            leftovers.is_empty(),
            "staging root not clean after terminal states: {leftovers:?}"
        );
    }
}

// A completed transaction whose staging dir survived (cleanup interrupted
// BEFORE dir removal) is cleanup-only at startup: targets kept, dir and
// generation-bound marker both removed.
#[test]
fn completed_state_cleanup_keeps_targets_and_removes_marker() {
    let tmp = tempfile::tempdir().unwrap();
    let c = context(tmp.path());
    let src = tmp.path().join("source");
    std::fs::write(&src, b"payload").unwrap();
    execute(
        &c,
        &InstallPlan::new("keeper", vec![file_entry(&src, "data.txt")]),
        &ExecutionHooks::default(),
    )
    .unwrap();

    // Reconstruct the "completed but not yet cleaned" state exactly as a
    // hard process exit between marker creation and dir removal leaves it:
    // journal on disk with its generation + the matching marker + the dir.
    let staging_root = c.install_root.join(".nacl-next-sdk/staging");
    let stage = staging_root.join("keeper");
    std::fs::create_dir_all(&stage).unwrap();
    std::fs::write(
        stage.join("journal.json"),
        serde_json::json!({
            "schemaVersion": 2,
            "planId": "keeper",
            "generation": "gen-1",
            "registryBefore": {},
            "files": [{
                "relativePath": "data.txt",
                "createIntent": true,
                "replaceExisting": false,
                "committed": true,
            }],
        })
        .to_string(),
    )
    .unwrap();
    std::fs::write(staging_root.join("keeper.gen-1.done"), b"").unwrap();

    cleanup_stale_staging(&c).unwrap();
    assert_eq!(
        std::fs::read(c.install_root.join("data.txt")).ok(),
        Some(b"payload".to_vec()),
        "completed transaction was rolled back instead of cleaned up"
    );
    assert!(!stage.exists(), "completed staging dir kept");
    assert!(
        !staging_root.join("keeper.gen-1.done").exists(),
        "marker kept"
    );
}

// Standalone orphan markers are swept; unrelated files in the staging root
// are none of the executor's business and stay untouched.
#[test]
fn cleanup_sweeps_orphan_done_files_only() {
    let tmp = tempfile::tempdir().unwrap();
    let c = context(tmp.path());
    let staging_root = c.install_root.join(".nacl-next-sdk/staging");
    std::fs::create_dir_all(&staging_root).unwrap();
    std::fs::write(staging_root.join("cycle.done"), b"").unwrap();
    std::fs::write(staging_root.join("cycle.af00dead.done"), b"").unwrap();
    std::fs::write(staging_root.join("unrelated.txt"), b"keep me").unwrap();

    cleanup_stale_staging(&c).unwrap();
    assert!(!staging_root.join("cycle.done").exists());
    assert!(!staging_root.join("cycle.af00dead.done").exists());
    assert_eq!(
        std::fs::read(staging_root.join("unrelated.txt")).ok(),
        Some(b"keep me".to_vec())
    );
}

// ---------- FOLLOWUP-321dc5e regressions: C1 order independence, C2
// legacy completion records, partial-commit rollback ----------

// Helper: reconstruct a completed transaction state on disk (staging dir +
// journal + generation-bound marker), exactly as a hard process exit
// between marker creation and staging cleanup leaves it.
fn stage_completed_transaction(context: &InstallContext, plan_id: &str, generation: &str) {
    use std::fs;
    let staging_root = context.install_root.join(".nacl-next-sdk/staging");
    let stage = staging_root.join(plan_id);
    fs::create_dir_all(&stage).unwrap();
    let mut journal = serde_json::json!({
        "schemaVersion": 2,
        "planId": plan_id,
        "registryBefore": {},
        "files": [{
            "relativePath": format!("{plan_id}.txt"),
            "createIntent": true,
            "replaceExisting": false,
            "committed": true,
        }],
    });
    if !generation.is_empty() {
        journal["generation"] = serde_json::json!(generation);
    }
    fs::write(stage.join("journal.json"), journal.to_string()).unwrap();
    let marker_name = if generation.is_empty() {
        format!("{plan_id}.done")
    } else {
        format!("{plan_id}.{generation}.done")
    };
    fs::write(staging_root.join(marker_name), b"").unwrap();
}

#[test]
fn completion_evidence_survives_both_enumeration_orders() {
    let tmp = tempfile::tempdir().unwrap();
    let c = context(tmp.path());
    let staging_root = c.install_root.join(".nacl-next-sdk/staging");

    // Two completed transactions (with generations) plus one orphan marker.
    stage_completed_transaction(&c, "alpha", "gen-a1");
    stage_completed_transaction(&c, "beta", "gen-b1");
    std::fs::create_dir_all(&staging_root).unwrap();
    std::fs::write(staging_root.join("gamma.gen-g1.done"), b"").unwrap();
    std::fs::write(c.install_root.join("alpha.txt"), b"alpha done").unwrap();
    std::fs::write(c.install_root.join("beta.txt"), b"beta done").unwrap();

    // Pathological order: the marker sweep runs BEFORE the transaction
    // directories. The sweep must skip markers whose directory still
    // exists, so both completed transactions stay completed.
    nacl_next_sdk::plan::cleanup_stale_staging_ordered(&c, true).unwrap();
    assert_eq!(
        std::fs::read(c.install_root.join("alpha.txt")).ok(),
        Some(b"alpha done".to_vec()),
        "markers-first order rolled back a completed transaction"
    );
    assert_eq!(
        std::fs::read(c.install_root.join("beta.txt")).ok(),
        Some(b"beta done".to_vec()),
        "markers-first order rolled back a completed transaction"
    );
    assert!(!staging_root.join("alpha").exists());
    assert!(!staging_root.join("beta").exists());
    assert!(!staging_root.join("alpha.gen-a1.done").exists());
    assert!(!staging_root.join("beta.gen-b1.done").exists());
    assert!(
        !staging_root.join("gamma.gen-g1.done").exists(),
        "true orphan swept"
    );

    // Shipped order on a fresh copy of the same state: same outcome.
    stage_completed_transaction(&c, "alpha", "gen-a2");
    stage_completed_transaction(&c, "beta", "gen-b2");
    std::fs::write(staging_root.join("gamma.gen-g2.done"), b"").unwrap();
    std::fs::write(c.install_root.join("alpha.txt"), b"alpha done").unwrap();
    std::fs::write(c.install_root.join("beta.txt"), b"beta done").unwrap();
    nacl_next_sdk::plan::cleanup_stale_staging(&c).unwrap();
    assert!(c.install_root.join("alpha.txt").is_file());
    assert!(c.install_root.join("beta.txt").is_file());
    assert!(!staging_root.join("alpha").exists());
    assert!(!staging_root.join("gamma.gen-g2.done").exists());
}

// C2: a pre-generation journal (e74f69d era, no generation field) with the
// old plain `<plan>.done` marker is a COMPLETED transaction — cleanup must
// not roll back its committed targets.
#[test]
fn legacy_completed_marker_is_recognized_not_rolled_back() {
    let tmp = tempfile::tempdir().unwrap();
    let c = context(tmp.path());
    let staging_root = c.install_root.join(".nacl-next-sdk/staging");

    stage_completed_transaction(&c, "oldtimer", "");
    std::fs::write(c.install_root.join("oldtimer.txt"), b"kept from old run").unwrap();
    assert!(
        staging_root.join("oldtimer.done").is_file(),
        "fixture must use the pre-generation marker name"
    );

    nacl_next_sdk::plan::cleanup_stale_staging(&c).unwrap();
    assert_eq!(
        std::fs::read(c.install_root.join("oldtimer.txt")).ok(),
        Some(b"kept from old run".to_vec()),
        "legacy completed transaction was rolled back"
    );
    assert!(!staging_root.join("oldtimer").exists());
    assert!(!staging_root.join("oldtimer.done").exists());
}

// Partial-commit failure (fresh install): file 1 commits, file 2 fails its
// digest check — the committed new file must be rolled back, not left
// behind as an unmanaged leftover.
#[test]
fn partial_commit_failure_rolls_back_committed_new_file() {
    let tmp = tempfile::tempdir().unwrap();
    let c = context(tmp.path());
    let src = tmp.path().join("source");
    std::fs::write(&src, b"payload").unwrap();

    let good = file_entry(&src, "first.txt");
    let mut bad = file_entry(&src, "second.txt");
    bad.artifact.digest.as_mut().unwrap().value = "0".repeat(64);
    let plan = InstallPlan::new("partial", vec![good, bad]);

    let error = execute(&c, &plan, &ExecutionHooks::default()).unwrap_err();
    assert_eq!(
        nacl_next_sdk::SdkError::from(error).code,
        "plan/digest-mismatch"
    );
    assert!(
        !c.install_root.join("first.txt").exists(),
        "first file was committed before the failure but not rolled back"
    );
    assert!(!c.install_root.join("second.txt").exists());
    let staging_root = c.install_root.join(".nacl-next-sdk/staging");
    if staging_root.exists() {
        let leftovers: Vec<_> = std::fs::read_dir(&staging_root)
            .unwrap()
            .filter_map(Result::ok)
            .map(|entry| entry.file_name())
            .collect();
        assert!(leftovers.is_empty(), "staging not clean: {leftovers:?}");
    }
}

// Partial-commit failure (replacement): the first file's managed
// replacement was committed before file 2 failed — the original must be
// restored and stay managed.
#[test]
fn partial_commit_failure_restores_replaced_original() {
    let tmp = tempfile::tempdir().unwrap();
    let c = context(tmp.path());
    let src = tmp.path().join("source");

    std::fs::write(&src, b"v1").unwrap();
    execute(
        &c,
        &InstallPlan::new("base", vec![file_entry(&src, "data.txt")]),
        &ExecutionHooks::default(),
    )
    .unwrap();

    std::fs::write(&src, b"v2-replacement").unwrap();
    let replacement = file_entry(&src, "data.txt");
    let mut bad = file_entry(&src, "other.txt");
    bad.artifact.digest.as_mut().unwrap().value = "0".repeat(64);
    let mut plan = InstallPlan::new("partial-replace", vec![replacement, bad]);
    plan.conflict_policy = ConflictPolicy::OverwriteManaged;

    assert!(execute(&c, &plan, &ExecutionHooks::default()).is_err());
    assert_eq!(
        std::fs::read(c.install_root.join("data.txt")).ok(),
        Some(b"v1".to_vec()),
        "committed replacement was not rolled back to the original"
    );
    assert!(!c.install_root.join("other.txt").exists());
    let registry: serde_json::Value = serde_json::from_slice(
        &std::fs::read(c.install_root.join(".nacl-next-sdk/managed.json")).unwrap(),
    )
    .unwrap();
    assert!(
        registry["files"].get("data.txt").is_some(),
        "restored original lost its managed record"
    );
}
