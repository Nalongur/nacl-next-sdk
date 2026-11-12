//! Write-ahead journal, managed registry, completion markers and startup
//! recovery.
//!
//! All transaction lifecycle rules live here: a journal is persisted before
//! the first mutation, a completion marker is bound to the transaction
//! generation and lives outside the staging directory, and recovery either
//! rolls an interrupted transaction back or treats a marked one as
//! cleanup-only. Callers (the executor) never decide marker semantics.

use crate::fsutil::write_atomic;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

use super::errors::InstallExecutionError;
use super::model::{InstallContext, ManagedFiles};

const JOURNAL_SCHEMA_VERSION: u32 = 2;

// ---------- journal (write-ahead, schema 2) ----------

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct JournalFile {
    pub(super) relative_path: String,
    /// This transaction will (re)create the target; persisted before any
    /// staging or rename so recovery can attribute the file (R3).
    #[serde(default)]
    pub(super) create_intent: bool,
    /// The target already existed when the conflict check ran: this entry
    /// is a replacement, so a missing backup means the untouched original
    /// (or an already-restored one) — recovery must never delete it.
    #[serde(default)]
    pub(super) replace_existing: bool,
    #[serde(default)]
    pub(super) backup_intent: bool,
    #[serde(default)]
    pub(super) backup_done: bool,
    #[serde(default)]
    pub(super) committed: bool,
    /// Recovery progress: this entry's files were already undone (R1).
    #[serde(default)]
    pub(super) rolled_back: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct Journal {
    pub(super) schema_version: u32,
    pub(super) plan_id: String,
    /// Unique id of THIS execution (FOLLOWUP-e74f69d): completion markers
    /// only apply to the generation they were created for.
    #[serde(default)]
    pub(super) generation: String,
    /// Registry snapshot from before the first mutation; restored on any
    /// rollback or recovery (F5/F9).
    pub(super) registry_before: ManagedFiles,
    pub(super) files: Vec<JournalFile>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct ManagedRegistry {
    pub(super) files: ManagedFiles,
}

// ---------- completion markers ----------
//
// Completion marker: `<staging>/<plan>.<generation>.done`, created once the
// whole transaction (files + managed registry) has committed. It lives
// OUTSIDE the plan's staging directory so a partially failed cleanup (which
// may delete arbitrary entries first) can never destroy the evidence; a
// completed transaction must only be cleaned up, never rolled back (R2).
// The name embeds the transaction generation, so a stale marker from an
// earlier run of the same plan id can never mark the CURRENT transaction as
// completed (FOLLOWUP-e74f69d P1).

fn completion_marker(context: &InstallContext, plan_id: &str, generation: &str) -> PathBuf {
    // Empty generation = a journal written before generations existed
    // (e74f69d era): its marker was the plain `<plan>.done` name, so map
    // back to exactly that (C2) — a fabricated suffix would leave old
    // completed transactions looking incomplete and get them rolled back.
    if generation.is_empty() {
        context
            .staging_root()
            .join(format!("{}.done", sanitize_plan_id(plan_id)))
    } else {
        context
            .staging_root()
            .join(format!("{}.{}.done", sanitize_plan_id(plan_id), generation))
    }
}

/// Removes every completion marker belonging to `plan_id` (any generation,
/// including the pre-generation legacy name). Called before a new
/// transaction starts and after terminal handling, so orphan markers from
/// interrupted cleanups can neither accumulate nor leak into later
/// recovery decisions.
pub(super) fn sweep_completion_markers(context: &InstallContext, plan_id: &str) {
    let prefix = format!("{}.", sanitize_plan_id(plan_id));
    let legacy = format!("{}.done", sanitize_plan_id(plan_id));
    let Ok(entries) = fs::read_dir(context.staging_root()) else {
        return;
    };
    for entry in entries.filter_map(Result::ok) {
        let name = entry.file_name().to_string_lossy().into_owned();
        let is_marker = name == legacy || (name.starts_with(&prefix) && name.ends_with(".done"));
        if is_marker
            && entry
                .file_type()
                .map(|kind| kind.is_file())
                .unwrap_or(false)
        {
            let _ = fs::remove_file(entry.path());
        }
    }
}

/// Persists the completion point before cleanup. Failure leaves the journal
/// in place, so the caller reports an error instead of pretending success.
fn persist_completion_marker(
    context: &InstallContext,
    plan_id: &str,
    generation: &str,
) -> Result<(), InstallExecutionError> {
    let marker = completion_marker(context, plan_id, generation);
    let file = fs::File::create(&marker).map_err(|source| InstallExecutionError::Io {
        action: "持久化事务完成标记",
        path: marker.clone(),
        source,
    })?;
    file.sync_all()
        .map_err(|source| InstallExecutionError::Io {
            action: "同步事务完成标记",
            path: marker.clone(),
            source,
        })?;
    Ok(())
}

// ---------- journal IO ----------

pub(super) fn journal_path(context: &InstallContext, plan_id: &str) -> PathBuf {
    context
        .staging_root()
        .join(sanitize_plan_id(plan_id))
        .join("journal.json")
}

pub(super) fn sanitize_plan_id(plan_id: &str) -> String {
    plan_id
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || character == '-' || character == '_' {
                character
            } else {
                '_'
            }
        })
        .collect()
}

fn save_atomic(
    destination: &Path,
    contents: &[u8],
    label: &'static str,
) -> Result<(), InstallExecutionError> {
    write_atomic(destination, contents).map_err(|source| InstallExecutionError::Io {
        action: label,
        path: destination.to_path_buf(),
        source,
    })
}

/// Persists the journal atomically. Called before every filesystem
/// mutation so a crash always leaves a recoverable record (F9).
pub(super) fn save_journal(
    context: &InstallContext,
    journal: &Journal,
) -> Result<(), InstallExecutionError> {
    let contents =
        serde_json::to_vec_pretty(journal).map_err(|error| InstallExecutionError::Io {
            action: "序列化计划日志",
            path: journal_path(context, &journal.plan_id),
            source: std::io::Error::other(error.to_string()),
        })?;
    save_atomic(
        &journal_path(context, &journal.plan_id),
        &contents,
        "保存计划日志",
    )
}

pub(super) fn backup_name(index: usize) -> String {
    format!("backup-{index}")
}

// ---------- managed registry IO ----------

pub(super) fn load_managed(context: &InstallContext) -> ManagedRegistry {
    let path = context.managed_registry_path();
    if !path.is_file() {
        return ManagedRegistry::default();
    }
    fs::read_to_string(&path)
        .ok()
        .and_then(|contents| serde_json::from_str(&contents).ok())
        .unwrap_or_default()
}

pub(super) fn save_managed(
    context: &InstallContext,
    registry: &ManagedRegistry,
) -> Result<(), InstallExecutionError> {
    let contents =
        serde_json::to_vec_pretty(registry).map_err(|error| InstallExecutionError::Io {
            action: "序列化受管记录",
            path: context.managed_registry_path(),
            source: std::io::Error::other(error.to_string()),
        })?;
    save_atomic(&context.managed_registry_path(), &contents, "保存受管记录")
}

// ---------- transaction lifecycle ----------

/// Rolls back an interrupted previous run of `plan_id` (if its journal is
/// still present) before a new execution starts.
pub(super) fn recover_previous_transaction(
    context: &InstallContext,
    plan_id: &str,
) -> Result<(), InstallExecutionError> {
    let journal_file = journal_path(context, plan_id);
    if !journal_file.is_file() {
        return Ok(());
    }
    let contents =
        fs::read_to_string(&journal_file).map_err(|source| InstallExecutionError::Io {
            action: "读取既有计划日志",
            path: journal_file.clone(),
            source,
        })?;
    match serde_json::from_str::<Journal>(&contents) {
        Ok(previous) if previous.schema_version == JOURNAL_SCHEMA_VERSION => {
            if sanitize_plan_id(&previous.plan_id) != sanitize_plan_id(plan_id) {
                return Err(InstallExecutionError::Recovery(
                    "既有恢复日志与当前计划标识不一致".to_string(),
                ));
            }
            rollback_journal(context, &previous).map_err(InstallExecutionError::Recovery)
        }
        _ => Err(InstallExecutionError::Recovery(
            "既有计划日志无法识别，已保留待查".to_string(),
        )),
    }
}

/// Creates and persists the transaction journal with the pre-plan registry
/// snapshot. The journal exists before the first mutation (F9).
pub(super) fn begin_journal(
    context: &InstallContext,
    plan_id: &str,
    generation: &str,
    registry_before: ManagedFiles,
) -> Result<Journal, InstallExecutionError> {
    let journal = Journal {
        schema_version: JOURNAL_SCHEMA_VERSION,
        plan_id: plan_id.to_string(),
        generation: generation.to_string(),
        registry_before,
        files: Vec::new(),
    };
    save_journal(context, &journal)?;
    Ok(journal)
}

/// Marks the transaction committed, then removes executor staging. The
/// marker is written first: if cleanup is interrupted, the next startup
/// must see "completed", never infer a rollback from leftover files (R2).
pub(super) fn complete_transaction(
    context: &InstallContext,
    plan_id: &str,
    generation: &str,
    staging_dir: &Path,
) -> Result<(), InstallExecutionError> {
    persist_completion_marker(context, plan_id, generation)?;
    if fs::remove_dir_all(staging_dir).is_ok() {
        sweep_completion_markers(context, plan_id);
    }
    Ok(())
}

/// Rolls the whole journal back and clears this plan id's markers. Errors
/// are returned as `plan/recovery-failed`; evidence is never deleted by a
/// failed recovery.
pub(super) fn abort_transaction(
    context: &InstallContext,
    journal: &Journal,
) -> Result<(), InstallExecutionError> {
    rollback_journal(context, journal).map_err(InstallExecutionError::Recovery)?;
    sweep_completion_markers(context, &journal.plan_id);
    Ok(())
}

/// Rolls back one journal. Idempotent (R1): per-entry decisions are driven
/// by persisted *intents*, not by backup-file existence — a replacement
/// whose backup is already gone was restored by an earlier (possibly
/// interrupted) recovery attempt and is never deleted again. A staging dir
/// carrying the completion marker is cleaned up only (R2).
fn rollback_journal(context: &InstallContext, journal: &Journal) -> Result<(), String> {
    let staging_dir = context
        .staging_root()
        .join(sanitize_plan_id(&journal.plan_id));
    let marker = completion_marker(context, &journal.plan_id, &journal.generation);
    if marker.is_file() {
        // This exact generation fully committed; leftovers are cleanup-only.
        fs::remove_dir_all(&staging_dir)
            .map_err(|error| format!("清理已完成事务的暂存目录失败：{error}"))?;
        let _ = fs::remove_file(&marker);
        sweep_completion_markers(context, &journal.plan_id);
        return Ok(());
    }
    // The staging directory must stay inside the canonical install root.
    let root = fs::canonicalize(&context.install_root)
        .map_err(|error| format!("无法规范化安装根目录：{error}"))?;
    let canonical_staging =
        fs::canonicalize(&staging_dir).map_err(|error| format!("暂存目录无法解析：{error}"))?;
    if !canonical_staging.starts_with(&root) {
        return Err("暂存目录不在安装根目录内".to_string());
    }
    let mut journal = journal.clone();
    let mut pending = journal.files.len();
    while pending > 0 {
        pending -= 1;
        let index = pending;
        if journal.files[index].rolled_back {
            continue;
        }
        // Journal paths are persistent input: full revalidation (F3).
        let relative = Path::new(&journal.files[index].relative_path);
        if let Err(error) = super::policy::validate_relative_path(relative) {
            return Err(format!(
                "日志目标路径无效 {}：{error}",
                journal.files[index].relative_path
            ));
        }
        let target = context.install_root.join(relative);
        let target_parent = target.parent().ok_or("目标缺少父目录")?;
        if target_parent.exists() {
            let canonical_parent = fs::canonicalize(target_parent)
                .map_err(|error| format!("目标目录无法解析：{error}"))?;
            if !canonical_parent.starts_with(&root) {
                return Err(format!(
                    "日志目标路径逃逸：{}",
                    journal.files[index].relative_path
                ));
            }
            let backup_path = staging_dir.join(backup_name(index));
            if backup_path.is_file() {
                // Original was moved aside: put it back, replacing any
                // committed replacement.
                let _ = fs::remove_file(&target);
                fs::rename(&backup_path, &target)
                    .map_err(|error| format!("恢复备份失败 {}：{error}", backup_path.display()))?;
            } else if journal.files[index].backup_intent
                || journal.files[index].backup_done
                || journal.files[index].replace_existing
            {
                // Replacement whose backup is gone: the original was already
                // restored by an earlier recovery attempt — keep the target.
            } else if (journal.files[index].committed || journal.files[index].create_intent)
                && target.is_file()
            {
                // File created by this transaction (rename may have landed
                // before the committed flag was persisted — R3 window).
                fs::remove_file(&target)
                    .map_err(|error| format!("回滚新建文件失败 {}：{error}", target.display()))?;
            }
        }
        // Persist per-entry recovery progress so a crash mid-recovery never
        // re-decides an already handled entry (R1). Failure is not fatal:
        // the decisions above stay safe on stale flags.
        journal.files[index].rolled_back = true;
        let _ = save_journal(context, &journal);
    }
    // Restore the pre-plan registry snapshot (F5).
    let restored = ManagedRegistry {
        files: journal.registry_before.clone(),
    };
    save_managed(context, &restored).map_err(|error| format!("恢复受管记录失败：{error}"))?;
    let _ = fs::remove_dir_all(&staging_dir);
    sweep_completion_markers(context, &journal.plan_id);
    Ok(())
}

/// Hosts call this at startup: recovers interrupted plans from their
/// journals. Unrecoverable or suspicious records are left in place and
/// reported, never silently deleted (F3/F9). The pass is two-phase and
/// order-independent (C1): every transaction directory is processed first,
/// and orphan markers are only removed afterwards — each removal re-checks
/// that no transaction directory for that marker remains, so completion
/// evidence can never be deleted ahead of the recovery that reads it, no
/// matter what order the filesystem enumerates.
pub fn cleanup_stale_staging(context: &InstallContext) -> Result<usize, InstallExecutionError> {
    cleanup_stale_staging_ordered(context, false)
}

/// Order-injection variant used by regression tests: `true` runs the
/// orphan-marker sweep BEFORE the transaction directories (the pathological
/// order) so tests can prove the completion-evidence invariant holds either
/// way. The shipped entry point always processes directories first.
#[doc(hidden)]
pub fn cleanup_stale_staging_ordered(
    context: &InstallContext,
    orphan_markers_first: bool,
) -> Result<usize, InstallExecutionError> {
    let staging_root = context.staging_root();
    let entries = match fs::read_dir(&staging_root) {
        Ok(entries) => entries,
        Err(_) => return Ok(0),
    };
    let mut transaction_dirs = Vec::new();
    let mut orphan_markers = Vec::new();
    for entry in entries.filter_map(Result::ok) {
        if entry
            .file_type()
            .map(|kind| kind.is_file())
            .unwrap_or(false)
        {
            if entry.file_name().to_string_lossy().ends_with(".done") {
                orphan_markers.push(entry.path());
            }
            // Non-.done files are none of the executor's business.
            continue;
        }
        transaction_dirs.push(entry.path());
    }

    if orphan_markers_first {
        sweep_orphan_markers(context, &orphan_markers);
    }

    let mut recovered = 0;
    for dir in &transaction_dirs {
        let journal_file = dir.join("journal.json");
        let contents = match fs::read_to_string(&journal_file) {
            Ok(contents) => contents,
            Err(_) => {
                // No journal: the plan never mutated anything (the journal
                // is persisted before the first mutation), so only SDK-owned
                // staging temps can be here. Safe to remove.
                let _ = fs::remove_dir_all(dir);
                continue;
            }
        };
        let journal = match serde_json::from_str::<Journal>(&contents) {
            Ok(journal) if journal.schema_version == JOURNAL_SCHEMA_VERSION => journal,
            _ => {
                // Untrusted/unreadable record: keep it AND its completion
                // evidence for inspection (C1: evidence survives failure).
                return Err(InstallExecutionError::Recovery(format!(
                    "暂存目录 {} 的恢复日志无法识别，已保留待查",
                    dir.display()
                )));
            }
        };
        // A journal whose plan_id does not match its directory name is
        // suspect content masquerading as executor metadata (defense in
        // depth for F4; the plan filter already blocks installing here).
        if sanitize_plan_id(&journal.plan_id)
            != dir.file_name().unwrap_or_default().to_string_lossy()
        {
            return Err(InstallExecutionError::Recovery(format!(
                "恢复日志与暂存目录不一致：{}",
                dir.display()
            )));
        }
        rollback_journal(context, &journal).map_err(InstallExecutionError::Recovery)?;
        recovered += 1;
    }

    sweep_orphan_markers(context, &orphan_markers);
    Ok(recovered)
}

/// Removes orphan marker files, but only when no transaction directory for
/// the same plan id still exists (C1): a marker whose directory remains
/// belongs to a transaction this pass (or a later one) must still read.
fn sweep_orphan_markers(context: &InstallContext, markers: &[PathBuf]) {
    for marker in markers {
        let Some(name) = marker
            .file_name()
            .map(|value| value.to_string_lossy().into_owned())
        else {
            continue;
        };
        let Some(stem) = name.strip_suffix(".done") else {
            continue;
        };
        // Sanitized plan ids never contain '.', so the plan part is either
        // the whole stem (pre-generation name, C2) or everything before the
        // last dot (generation suffix).
        let plan_part = match stem.rsplit_once('.') {
            Some((plan, _generation)) => plan,
            None => stem,
        };
        if plan_part.is_empty() {
            continue;
        }
        if context.staging_root().join(plan_part).is_dir() {
            // Its transaction directory still exists: not an orphan.
            continue;
        }
        let _ = fs::remove_file(marker);
    }
}
