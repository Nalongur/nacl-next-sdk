//! External identity source: a team-managed fixed profile provider.
//!
//! Implements `AccountProvider` against the SDK's public API only. It can
//! produce Local-class identities (the unverified trust class); it cannot
//! forge a Microsoft identity because that variant is only constructible
//! inside the SDK's verified Microsoft adapter path.

use nacl_next_sdk::account::{
    AccountProvider, AccountProviderError, IdentityKind, IdentitySummary, LaunchIdentity,
    LocalProfile, LocalProfileError,
};
use nacl_next_sdk::context::SdkContext;

struct TeamProfileProvider {
    profile: LocalProfile,
}

impl AccountProvider for TeamProfileProvider {
    fn kind(&self) -> IdentityKind {
        IdentityKind::Local
    }

    fn list_identities(&self) -> Result<Vec<IdentitySummary>, AccountProviderError> {
        Ok(vec![IdentitySummary {
            kind: IdentityKind::Local,
            id: self.profile.id.clone(),
            username: self.profile.username.clone(),
            label: "团队档案 · 外部身份源".to_string(),
        }])
    }

    fn prepare_launch_identity(&self, id: &str) -> Result<LaunchIdentity, AccountProviderError> {
        if id != self.profile.id {
            return Err(AccountProviderError::UnknownIdentity(id.to_owned()));
        }
        Ok(LaunchIdentity::Local(self.profile.clone()))
    }
}

fn main() {
    let root = std::env::temp_dir().join(format!(
        "nacl-next-consumer-custom-identity-{}",
        std::process::id()
    ));
    let context = SdkContext::from_root(&root);
    context.initialize().expect("context should initialize");

    // The team's canonical profile comes from team configuration, not the
    // SDK's own store: construction goes through the public LocalProfile API,
    // which enforces username rules and derives the offline UUID.
    let profile = LocalProfile::new("TeamSteve").expect("team profile should validate");
    let provider = TeamProfileProvider { profile };

    let identities = provider.list_identities().expect("identity list");
    println!("external provider identities: {identities:?}");

    let identity = provider
        .prepare_launch_identity(&identities[0].id)
        .expect("launch identity from external provider");
    assert_eq!(identity.kind(), IdentityKind::Local);
    match &identity {
        LaunchIdentity::Local(profile) => {
            assert_eq!(profile.username, "TeamSteve");
            println!(
                "prepared local identity: {} uuid={}",
                profile.username, profile.uuid
            );
        }
        #[cfg(feature = "microsoft")]
        LaunchIdentity::Microsoft(_) => unreachable!("local provider must not yield Microsoft"),
    }

    // Invalid names stay invalid no matter who constructs the profile.
    assert!(matches!(
        LocalProfile::new("no spaces allowed"),
        Err(LocalProfileError::InvalidUsername)
    ));

    std::fs::remove_dir_all(&root).ok();
    println!("consumer-custom-identity: OK");
}
