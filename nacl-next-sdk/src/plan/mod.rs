//! Declarative install plans and their executor.
//!
//! Safety model (guide §6.1): the provider only *describes*; the executor
//! validates the plan against host policy, stages, verifies digests and
//! actual sizes, commits with atomic renames behind a write-ahead journal,
//! and can roll back or recover. Credentials never appear in plans, events
//! or the journal.
//!
//! Module split (S3 cleanup): [`model`] holds the plan DTOs and execution
//! context, [`policy`] all host policy and validation, [`store`] the
//! journal / managed registry / completion-marker / recovery rules, and
//! [`executor`] the per-file orchestration. The public `plan::*` paths and
//! the persisted formats are unchanged.

mod errors;
mod executor;
mod model;
mod policy;
mod store;

pub use errors::InstallExecutionError;
pub use executor::{execute, ExecutionHooks, FileEvent, FileEventKind};
pub use model::{
    Artifact, ArtifactSource, ConflictPolicy, DigestSpec, InstallContext, InstallPlan,
    InstallResult, ManagedRecord, PlannedFile, ResourceLimits, INSTALL_PLAN_SCHEMA_VERSION,
};
pub use policy::{DigestPolicy, SourcePolicy};
pub use store::{cleanup_stale_staging, cleanup_stale_staging_ordered};

/// Plan-id helper for provider constructors.
pub fn new_plan_id() -> String {
    uuid::Uuid::new_v4().simple().to_string()
}
