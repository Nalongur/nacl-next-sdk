//! HTTP manifest content provider: `<base>/content-manifest.json` plus
//! files under the same base. Acceptance vehicle for transfer integration
//! (self-hosted test servers); carries no game-specific knowledge.

use super::{
    parse_manifest, plan_from_manifest, ContentProvider, ContentRequest, ProviderError,
    MANIFEST_SCHEMA_VERSION,
};
use crate::capability::{CapabilityDescriptor, CAPABILITY_NAMESPACE};
use crate::plan::{ArtifactSource, InstallPlan};
use crate::transfer::{self, TransferControl, TransferError};
use std::time::Duration;

pub struct HttpManifestProvider {
    base_url: String,
    client: reqwest::blocking::Client,
}

impl HttpManifestProvider {
    pub fn new(base_url: impl Into<String>) -> Result<Self, ProviderError> {
        Ok(Self {
            base_url: base_url.into().trim_end_matches('/').to_string(),
            client: transfer::http_client().map_err(|error| match error {
                TransferError::Network(message) => ProviderError::Network(message),
                other => ProviderError::Network(other.to_string()),
            })?,
        })
    }

    fn manifest_url(&self) -> String {
        format!("{}/content-manifest.json", self.base_url)
    }
}

impl ContentProvider for HttpManifestProvider {
    fn descriptor(&self) -> CapabilityDescriptor {
        CapabilityDescriptor {
            namespace: CAPABILITY_NAMESPACE.to_string(),
            name: "provider.http-manifest".to_string(),
            contract_version: MANIFEST_SCHEMA_VERSION,
            permissions: vec!["network-content-host".to_string()],
        }
    }

    fn resolve(
        &self,
        request: &ContentRequest,
        control: &dyn Fn() -> TransferControl,
    ) -> Result<InstallPlan, ProviderError> {
        if request.content_id.is_empty() {
            return Err(ProviderError::UnknownContent(request.content_id.clone()));
        }
        if matches!(control(), TransferControl::Cancelled) {
            return Err(ProviderError::Cancelled);
        }
        let response = self
            .client
            .get(self.manifest_url())
            .timeout(Duration::from_secs(30))
            .send()
            .map_err(|error| ProviderError::Network(error.to_string()))?;
        if !response.status().is_success() {
            return Err(ProviderError::UnknownContent(request.content_id.clone()));
        }
        let bytes = response
            .bytes()
            .map_err(|error| ProviderError::Network(error.to_string()))?;
        let manifest = parse_manifest(&bytes)?;
        let expected_source = format!("http-manifest:{}", self.base_url);
        plan_from_manifest(manifest, &request.content_id, expected_source, |path| {
            ArtifactSource::Http {
                url: format!("{}/{}", self.base_url, path),
            }
        })
    }
}
