//! NaCL Next Core SDK (S1 + S2).
//!
//! Local instances, Java detection, dual identity (Microsoft feature-gated,
//! Local always available), a unified launch pipeline with an injected
//! [`SdkContext`], and generic transfer/cache/plan/provider machinery for
//! declarative installs. The SDK never reads environment variables for its
//! roots, never embeds a brand directory, never fetches game content, and
//! never selects an identity on the caller's behalf.

pub mod account;
pub mod cache;
pub mod capability;
pub mod context;
pub mod error;
pub mod instance;
pub mod java;
pub mod launch;
pub mod plan;
pub mod provider;
pub mod transfer;

mod fsutil;

/// SDK crate version, also recorded in generated project compatibility data.
pub const SDK_VERSION: &str = env!("CARGO_PKG_VERSION");

pub use account::{
    AccountProvider, AccountProviderError, IdentityKind, IdentitySummary, LaunchIdentity,
    LocalProfile, LocalProfileError, LocalProfileStore,
};
#[cfg(feature = "microsoft")]
pub use account::{
    LoginHandle, MicrosoftAccount, MicrosoftClientConfig, MicrosoftError, MicrosoftProvider,
};
pub use capability::{CapabilityDescriptor, CapabilityRegistry};
pub use context::SdkContext;
pub use error::{SdkError, SdkErrorSource};
pub use instance::{CreateInstanceRequest, InstanceConfig, InstanceDefaults, InstanceError};
pub use java::{JavaError, JavaRuntime, JavaSelectionError};
pub use launch::{
    preview_launch, LaunchAdapter, LaunchError, LaunchExecutor, LaunchPreview, LaunchSpec,
    LaunchedProcess, VanillaLaunchAdapter,
};

#[cfg(test)]
mod tests {
    use crate::account::{AccountProvider, LaunchIdentity, LocalProfileStore};
    use crate::capability::CapabilityRegistry;

    #[test]
    fn local_identity_is_explicitly_unverified() {
        let root = tempfile::tempdir().unwrap();
        let context = crate::context::SdkContext::from_root(root.path());
        context.initialize().unwrap();
        let store = LocalProfileStore::new(&context);
        let profile = store.create("Steve_01").unwrap();

        let identity = store.prepare_launch_identity(&profile.id).unwrap();
        match &identity {
            LaunchIdentity::Local(profile) => {
                assert_eq!(profile.username, "Steve_01");
            }
            #[cfg(feature = "microsoft")]
            LaunchIdentity::Microsoft(_) => panic!("local store must not produce Microsoft ids"),
        }
        assert_eq!(identity.kind(), crate::account::IdentityKind::Local);
        assert!(identity.summary().label.contains("未官方验证"));
    }

    #[test]
    fn capability_registry_refers_to_real_compiled_features() {
        let registry = CapabilityRegistry::builtin();
        assert!(registry.contains("nacl-next", "instance.manage"));
        assert!(!registry.contains("nacl-next", "transfer.http"));
    }
}
