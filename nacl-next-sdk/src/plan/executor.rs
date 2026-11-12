//! Execution orchestration: conflict handling, staging, verification,
//! commit and rollback coordination. Transaction state rules live in
//! [`super::store`]; this module only advances one file at a time.

use crate::transfer::{self, TransferControl, TransferUpdate};
use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::path::Path;
use std::sync::{Mutex, OnceLock};
use tempfile::NamedTempFile;

use super::errors::InstallExecutionError;
use super::model::{
    ArtifactSource, ConflictPolicy, InstallContext, InstallPlan, InstallResult, ManagedRecord,
};
use super::policy::{validate_plan, verify_digest, verify_target_inside_root};
use super::store::{self, Journal, JournalFile, ManagedRegistry};

/// Cancellation + progress hooks for one execution.
pub struct ExecutionHooks<'a> {
    pub control: &'a (dyn Fn() -> TransferControl + Sync),
    pub on_file_event: &'a (dyn Fn(FileEvent<'_>) + Sync),
}

impl<'a> Default for ExecutionHooks<'a> {
    fn default() -> Self {
        Self {
            control: &|| TransferControl::Running,
            on_file_event: &|_| {},
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileEventKind {
    Started,
    Progress,
    Committed,
    Skipped,
}

#[derive(Debug)]
pub struct FileEvent<'a> {
    pub kind: FileEventKind,
    pub relative_path: &'a Path,
    pub downloaded_bytes: u64,
    pub total_bytes: u64,
    pub cache_hit: bool,
}

pub fn execute(
    context: &InstallContext,
    plan: &InstallPlan,
    hooks: &ExecutionHooks<'_>,
) -> Result<InstallResult, InstallExecutionError> {
    let _guard = RootGuard::acquire(context)?;

    // Unique id for THIS execution: completion markers are bound to it, so
    // leftovers from an earlier same-id transaction can never apply here.
    let generation = uuid::Uuid::new_v4().simple().to_string();

    // A previous interrupted run for this plan id rolls back first.
    store::recover_previous_transaction(context, &plan.plan_id)?;

    validate_plan(context, plan)?;

    let staging_dir = context
        .staging_root()
        .join(store::sanitize_plan_id(&plan.plan_id));
    fs::create_dir_all(&staging_dir).map_err(|source| InstallExecutionError::Io {
        action: "创建计划暂存目录",
        path: staging_dir.clone(),
        source,
    })?;

    // Old markers from earlier generations of this plan id are meaningless
    // now (their journal is gone or was just rolled back): remove them so
    // they can neither leak into recovery decisions nor accumulate.
    store::sweep_completion_markers(context, &plan.plan_id);

    let registry_before = store::load_managed(context);
    let mut journal = store::begin_journal(
        context,
        &plan.plan_id,
        &generation,
        registry_before.files.clone(),
    )?;

    let mut managed = registry_before;
    let mut result = InstallResult {
        plan_id: plan.plan_id.clone(),
        committed: Vec::new(),
        skipped: Vec::new(),
        cache_hits: 0,
    };

    let outcome = execute_files(
        context,
        plan,
        hooks,
        &staging_dir,
        &mut journal,
        &mut managed,
        &mut result,
    );
    match outcome {
        Ok(()) => {
            store::save_managed(context, &managed)?;
            // The completion marker is persisted before cleanup so a
            // leftover staging dir from a failed cleanup must never regain
            // rollback meaning at the next startup (R2).
            store::complete_transaction(context, &plan.plan_id, &generation, &staging_dir)?;
            Ok(result)
        }
        Err(error) => {
            store::abort_transaction(context, &journal)?;
            Err(error)
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn execute_files(
    context: &InstallContext,
    plan: &InstallPlan,
    hooks: &ExecutionHooks<'_>,
    staging_dir: &Path,
    journal: &mut Journal,
    managed: &mut ManagedRegistry,
    result: &mut InstallResult,
) -> Result<(), InstallExecutionError> {
    for (index, file) in plan.files.iter().enumerate() {
        check_control(hooks.control)?;
        let target = context.install_root.join(&file.relative_path);
        let relative_text = file.relative_path.to_string_lossy().into_owned();

        // Conflict handling happens before any journal entry or transfer.
        let mut replacing_managed = false;
        if let Ok(metadata) = fs::symlink_metadata(&target) {
            if metadata.file_type().is_symlink() {
                return Err(InstallExecutionError::Validation(
                    "plan/path-escape",
                    format!("目标已是符号链接：{relative_text}"),
                ));
            }
            match plan.conflict_policy {
                ConflictPolicy::Fail => {
                    return Err(InstallExecutionError::Conflict {
                        relative_path: relative_text,
                    })
                }
                ConflictPolicy::Skip => {
                    result.skipped.push(relative_text);
                    (hooks.on_file_event)(FileEvent {
                        kind: FileEventKind::Skipped,
                        relative_path: &file.relative_path,
                        downloaded_bytes: file.artifact.size,
                        total_bytes: file.artifact.size,
                        cache_hit: false,
                    });
                    continue;
                }
                ConflictPolicy::OverwriteManaged => {
                    if !managed.files.contains_key(&relative_text) {
                        return Err(InstallExecutionError::Conflict {
                            relative_path: relative_text,
                        });
                    }
                    replacing_managed = true;
                }
            }
        }

        // Persist the creation intent before any staging work: from here on
        // recovery can attribute the target to this transaction even if the
        // process dies between the commit rename and the journal update
        // (R3).
        journal.files.push(JournalFile {
            relative_path: relative_text.clone(),
            create_intent: true,
            replace_existing: replacing_managed,
            backup_intent: false,
            backup_done: false,
            committed: false,
            rolled_back: false,
        });
        let journal_index = journal.files.len() - 1;
        store::save_journal(context, journal)?;

        // Stage the new content and verify it BEFORE touching the original
        // (F1): a digest/size failure here leaves the target untouched.
        // The staging copy is bounded by the declared size (R5).
        let staged = staging_dir.join(format!("stage-{index}.part"));
        let mut cache_hit = false;
        if let Some(digest) = file.artifact.digest.as_ref() {
            let content_digest = digest.to_content_digest();
            if context.cache.contains(&content_digest) {
                cache_hit = true;
                copy_bounded(
                    &context.cache.object_path(&content_digest),
                    &staged,
                    file.artifact.size,
                    "从缓存复用对象",
                )?;
                result.cache_hits += 1;
            }
        }
        if !cache_hit {
            match &file.artifact.source {
                ArtifactSource::CacheOnly => {
                    return Err(InstallExecutionError::Validation(
                        "plan/cache-miss",
                        format!("{relative_text} 仅允许缓存来源，但缓存未命中"),
                    ));
                }
                ArtifactSource::Local { path } => {
                    if !context.source_policy.local_allowed(path) {
                        return Err(InstallExecutionError::SourceDenied {
                            relative_path: relative_text.clone(),
                            reason: "本地来源不在宿主许可的根目录内".to_string(),
                        });
                    }
                    copy_bounded(path, &staged, file.artifact.size, "复制本地资源")?;
                }
                ArtifactSource::Http { url } => {
                    if !context.source_policy.http_allowed(url) {
                        return Err(InstallExecutionError::SourceDenied {
                            relative_path: relative_text.clone(),
                            reason: "HTTP 主机不在宿主许可清单内".to_string(),
                        });
                    }
                    let identity = file
                        .artifact
                        .digest
                        .as_ref()
                        .map(|digest| digest.to_content_digest().identity())
                        .unwrap_or_else(|| format!("artifact:{}", file.artifact.id));
                    let progress = |update: TransferUpdate| {
                        (hooks.on_file_event)(FileEvent {
                            kind: FileEventKind::Progress,
                            relative_path: &file.relative_path,
                            downloaded_bytes: update.downloaded_bytes,
                            total_bytes: file.artifact.size,
                            cache_hit: false,
                        });
                    };
                    transfer::transfer(
                        context.client(),
                        transfer::TransferRequest {
                            url,
                            expected_size: file.artifact.size,
                            identity: &identity,
                            destination: &staged,
                            byte_cap: Some(file.artifact.size),
                        },
                        context.transfer_options,
                        hooks.control,
                        &progress,
                    )?;
                }
            }
        }

        // Actual size check for every source (F6).
        let actual_size = fs::metadata(&staged)
            .map_err(|source| InstallExecutionError::Io {
                action: "读取暂存文件大小",
                path: staged.clone(),
                source,
            })?
            .len();
        if actual_size != file.artifact.size {
            return Err(InstallExecutionError::SizeMismatch {
                relative_path: relative_text.clone(),
                expected: file.artifact.size,
                actual: actual_size,
            });
        }

        // Digest verification (policy-decided; independent of transport).
        if let Some(digest) = file.artifact.digest.as_ref() {
            let actual = verify_digest(digest.algorithm, &staged)?;
            if !actual.eq_ignore_ascii_case(&digest.value) {
                return Err(InstallExecutionError::DigestMismatch {
                    relative_path: relative_text.clone(),
                    expected: digest.value.clone(),
                    actual,
                });
            }
            // Populate the cache from the verified staging file.
            context
                .cache
                .insert_from_file(&staged, &digest.to_content_digest())?;
        }

        // Boundary check before touching the target.
        verify_target_inside_root(context, &target)?;

        if replacing_managed {
            // Write-ahead: record the intent, then move the original aside
            // (F1/F9). backup_intent also marks this entry as a replacement
            // so recovery never treats a restored original as removable
            // (R1).
            journal.files[journal_index].backup_intent = true;
            store::save_journal(context, journal)?;
            let backup = staging_dir.join(store::backup_name(index));
            fs::rename(&target, &backup).map_err(|source| InstallExecutionError::Io {
                action: "备份受管文件",
                path: target.clone(),
                source,
            })?;
            journal.files[journal_index].backup_done = true;
            store::save_journal(context, journal)?;
        }

        (hooks.on_file_event)(FileEvent {
            kind: FileEventKind::Started,
            relative_path: &file.relative_path,
            downloaded_bytes: 0,
            total_bytes: file.artifact.size,
            cache_hit: false,
        });

        // Commit: an exclusive unique temp file in the verified target
        // directory, then an atomic same-directory rename (F2). We only
        // ever operate on files we just created ourselves.
        let mut commit_temp = NamedTempFile::new_in(target.parent().unwrap_or(Path::new(".")))
            .map_err(|source| InstallExecutionError::Io {
                action: "创建提交临时文件",
                path: target.clone(),
                source,
            })?;
        fs::copy(&staged, commit_temp.path()).map_err(|source| InstallExecutionError::Io {
            action: "准备提交文件",
            path: commit_temp.path().to_path_buf(),
            source,
        })?;
        commit_temp
            .as_file_mut()
            .sync_all()
            .map_err(|source| InstallExecutionError::Io {
                action: "同步提交文件",
                path: commit_temp.path().to_path_buf(),
                source,
            })?;
        commit_temp
            .persist(&target)
            .map_err(|error| InstallExecutionError::Io {
                action: "提交受管文件",
                path: target.clone(),
                source: error.error,
            })?;
        journal.files[journal_index].committed = true;
        store::save_journal(context, journal)?;
        managed.files.insert(
            relative_text.clone(),
            ManagedRecord {
                plan_id: plan.plan_id.clone(),
                digest: file
                    .artifact
                    .digest
                    .as_ref()
                    .map(|digest| digest.value.clone()),
            },
        );
        result.committed.push(relative_text.clone());

        (hooks.on_file_event)(FileEvent {
            kind: FileEventKind::Committed,
            relative_path: &file.relative_path,
            downloaded_bytes: file.artifact.size,
            total_bytes: file.artifact.size,
            cache_hit,
        });
    }
    Ok(())
}

// ---------- per-root plan mutex (confirmed Q6) ----------
//
// In-process only. The key is the canonicalized install root so plain
// aliases (`install\.`, separators, case, junctions) map to one lock.

fn root_locks() -> &'static Mutex<HashMap<String, ()>> {
    static LOCKS: OnceLock<Mutex<HashMap<String, ()>>> = OnceLock::new();
    LOCKS.get_or_init(|| Mutex::new(HashMap::new()))
}

struct RootGuard {
    key: String,
}

impl RootGuard {
    fn acquire(context: &InstallContext) -> Result<Self, InstallExecutionError> {
        fs::create_dir_all(&context.install_root).map_err(|source| InstallExecutionError::Io {
            action: "创建安装根目录",
            path: context.install_root.clone(),
            source,
        })?;
        let canonical = fs::canonicalize(&context.install_root).map_err(|source| {
            InstallExecutionError::Io {
                action: "规范化安装根目录",
                path: context.install_root.clone(),
                source,
            }
        })?;
        let key = canonical.to_string_lossy().to_string();
        let mut locks = root_locks()
            .lock()
            .map_err(|_| InstallExecutionError::InstallInProgress)?;
        if locks.contains_key(&key) {
            return Err(InstallExecutionError::InstallInProgress);
        }
        locks.insert(key.clone(), ());
        Ok(Self { key })
    }
}

impl Drop for RootGuard {
    fn drop(&mut self) {
        if let Ok(mut locks) = root_locks().lock() {
            locks.remove(&self.key);
        }
    }
}

/// Copies at most `cap` bytes, failing as soon as the source would exceed
/// the bound — the excess is never written (R5).
fn copy_bounded(
    source: &Path,
    destination: &Path,
    cap: u64,
    label: &'static str,
) -> Result<u64, InstallExecutionError> {
    use std::io::Read;
    let mut reader = fs::File::open(source).map_err(|source_error| InstallExecutionError::Io {
        action: label,
        path: source.to_path_buf(),
        source: source_error,
    })?;
    let mut writer =
        fs::File::create(destination).map_err(|source_error| InstallExecutionError::Io {
            action: label,
            path: destination.to_path_buf(),
            source: source_error,
        })?;
    let mut buffer = [0_u8; 64 * 1024];
    let mut total = 0_u64;
    loop {
        let count = reader
            .read(&mut buffer)
            .map_err(|source_error| InstallExecutionError::Io {
                action: label,
                path: source.to_path_buf(),
                source: source_error,
            })?;
        if count == 0 {
            break;
        }
        if total + count as u64 > cap {
            return Err(InstallExecutionError::SizeMismatch {
                relative_path: destination.to_string_lossy().into_owned(),
                expected: cap,
                actual: total + count as u64,
            });
        }
        writer
            .write_all(&buffer[..count])
            .map_err(|source_error| InstallExecutionError::Io {
                action: label,
                path: destination.to_path_buf(),
                source: source_error,
            })?;
        total += count as u64;
    }
    Ok(total)
}

fn check_control(
    control: &(dyn Fn() -> TransferControl + Sync),
) -> Result<(), InstallExecutionError> {
    match control() {
        TransferControl::Running => Ok(()),
        TransferControl::Cancelled => Err(InstallExecutionError::Cancelled),
        TransferControl::Paused => loop {
            match control() {
                TransferControl::Running => return Ok(()),
                TransferControl::Cancelled => return Err(InstallExecutionError::Cancelled),
                TransferControl::Paused => {
                    std::thread::sleep(std::time::Duration::from_millis(100))
                }
            }
        },
    }
}
