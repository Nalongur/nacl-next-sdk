//! Local file content provider: a directory plus `content-manifest.json`.

use super::{
    parse_manifest, plan_from_manifest, ContentProvider, ContentRequest, ProviderError,
    MANIFEST_SCHEMA_VERSION,
};
use crate::capability::{CapabilityDescriptor, CAPABILITY_NAMESPACE};
use crate::plan::{ArtifactSource, InstallPlan};
use crate::transfer::TransferControl;
use std::path::PathBuf;

pub const MANIFEST_FILE_NAME: &str = "content-manifest.json";

pub struct LocalFileProvider {
    source_root: PathBuf,
}

impl LocalFileProvider {
    pub fn new(source_root: impl Into<PathBuf>) -> Self {
        Self {
            source_root: source_root.into(),
        }
    }
}

impl ContentProvider for LocalFileProvider {
    fn descriptor(&self) -> CapabilityDescriptor {
        CapabilityDescriptor {
            namespace: CAPABILITY_NAMESPACE.to_string(),
            name: "provider.local-files".to_string(),
            contract_version: MANIFEST_SCHEMA_VERSION,
            permissions: vec![],
        }
    }

    fn resolve(
        &self,
        request: &ContentRequest,
        _control: &dyn Fn() -> TransferControl,
    ) -> Result<InstallPlan, ProviderError> {
        if request.content_id.is_empty() {
            return Err(ProviderError::UnknownContent(request.content_id.clone()));
        }
        let manifest_path = self.source_root.join(MANIFEST_FILE_NAME);
        let bytes = std::fs::read(&manifest_path)
            .map_err(|_| ProviderError::UnknownContent(request.content_id.clone()))?;
        let manifest = parse_manifest(&bytes)?;
        let expected_source = format!("local-manifest:{}", request.content_id);
        plan_from_manifest(manifest, &request.content_id, expected_source, |path| {
            ArtifactSource::Local {
                path: self.source_root.join(path),
            }
        })
    }
}
