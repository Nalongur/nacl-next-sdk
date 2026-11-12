//! Compile-time capability registration: integration and discovery, not trust.
//!
//! Built-in capabilities reflect the feature set this SDK was compiled with
//! (e.g. `account.microsoft` exists only under the `microsoft` feature).
//! Hosts and UIs query the registry to compose their surface; every actual
//! call is still re-checked by the owning module — discovery is not
//! authorization.

use serde::Serialize;
use std::collections::BTreeMap;

pub const CAPABILITY_NAMESPACE: &str = "nacl-next";

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "contracts", derive(ts_rs::TS))]
pub struct CapabilityDescriptor {
    /// Reverse-DNS-style namespace; `nacl-next` for built-ins, host-chosen
    /// for extensions.
    pub namespace: String,
    /// Dotted capability name, e.g. `account.microsoft`.
    pub name: String,
    /// Contract version of the typed interface behind this capability.
    pub contract_version: u32,
    /// Descriptive permission tags (documentation, not enforcement).
    pub permissions: Vec<String>,
}

impl CapabilityDescriptor {
    fn builtin(name: &str, contract_version: u32, permissions: &[&str]) -> Self {
        Self {
            namespace: CAPABILITY_NAMESPACE.to_string(),
            name: name.to_string(),
            contract_version,
            permissions: permissions.iter().map(|value| value.to_string()).collect(),
        }
    }

    pub fn qualified_name(&self) -> String {
        format!("{}.{}", self.namespace, self.name)
    }
}

/// Registry of capabilities available to one host process. Same
/// `namespace.name` may register only one contract version; mismatches are
/// rejected instead of silently merged.
#[derive(Debug, Default)]
pub struct CapabilityRegistry {
    entries: BTreeMap<String, CapabilityDescriptor>,
}

impl CapabilityRegistry {
    /// Built-in capabilities for the compiled feature set.
    pub fn builtin() -> Self {
        let mut registry = Self::default();
        for descriptor in builtin_descriptors() {
            registry
                .register(descriptor)
                .expect("builtin set is consistent");
        }
        registry
    }

    pub fn register(&mut self, descriptor: CapabilityDescriptor) -> Result<(), CapabilityConflict> {
        let key = descriptor.qualified_name();
        if let Some(existing) = self.entries.get(&key) {
            if existing.contract_version != descriptor.contract_version {
                return Err(CapabilityConflict {
                    capability: key,
                    registered: existing.contract_version,
                    attempted: descriptor.contract_version,
                });
            }
            return Ok(());
        }
        self.entries.insert(key, descriptor);
        Ok(())
    }

    pub fn contains(&self, namespace: &str, name: &str) -> bool {
        self.entries.contains_key(&format!("{namespace}.{name}"))
    }

    pub fn list(&self) -> Vec<CapabilityDescriptor> {
        self.entries.values().cloned().collect()
    }
}

#[derive(Debug)]
pub struct CapabilityConflict {
    pub capability: String,
    pub registered: u32,
    pub attempted: u32,
}

impl std::fmt::Display for CapabilityConflict {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "能力 {} 已注册为契约版本 {}，拒绝重复注册版本 {}",
            self.capability, self.registered, self.attempted
        )
    }
}

impl std::error::Error for CapabilityConflict {}

impl crate::error::SdkErrorSource for CapabilityConflict {
    fn sdk_code(&self) -> &'static str {
        "capability/conflict"
    }
}

pub fn builtin_descriptors() -> Vec<CapabilityDescriptor> {
    #[allow(unused_mut)]
    let mut descriptors = vec![
        CapabilityDescriptor::builtin("instance.manage", 1, &["instances-root"]),
        CapabilityDescriptor::builtin("java.detect", 1, &[]),
        CapabilityDescriptor::builtin("account.local", 1, &["config-root"]),
        CapabilityDescriptor::builtin("launch.game", 1, &["spawn-process", "instances-root"]),
        CapabilityDescriptor::builtin("diagnostics.logs", 1, &["logs-root"]),
        CapabilityDescriptor::builtin("transfer.download", 1, &["network-content-host"]),
        CapabilityDescriptor::builtin("install.plan", 1, &["install-root", "cache-root"]),
    ];
    #[cfg(feature = "microsoft")]
    descriptors.push(CapabilityDescriptor::builtin(
        "account.microsoft",
        1,
        &["network-microsoft", "credentials", "config-root"],
    ));
    descriptors
}

#[cfg(test)]
mod tests {
    use super::{
        builtin_descriptors, CapabilityDescriptor, CapabilityRegistry, CAPABILITY_NAMESPACE,
    };

    #[test]
    fn builtin_set_matches_compiled_features() {
        let registry = CapabilityRegistry::builtin();
        assert!(registry.contains(CAPABILITY_NAMESPACE, "account.local"));
        assert_eq!(
            registry.contains(CAPABILITY_NAMESPACE, "account.microsoft"),
            cfg!(feature = "microsoft"),
        );
        assert!(registry.contains(CAPABILITY_NAMESPACE, "launch.game"));
    }

    #[test]
    fn same_version_reregistration_is_idempotent_but_versions_conflict() {
        let mut registry = CapabilityRegistry::builtin();
        let count = registry.list().len();
        registry
            .register(builtin_descriptors().remove(0))
            .expect("same version reregistration is idempotent");
        assert_eq!(registry.list().len(), count);

        let mut conflicting = builtin_descriptors().remove(0);
        conflicting.contract_version = 99;
        assert!(registry.register(conflicting).is_err());
    }

    #[test]
    fn hosts_can_register_their_own_namespaced_extensions() {
        let mut registry = CapabilityRegistry::builtin();
        registry
            .register(CapabilityDescriptor {
                namespace: "example.host".to_string(),
                name: "custom-panel".to_string(),
                contract_version: 1,
                permissions: vec![],
            })
            .unwrap();
        assert!(registry.contains("example.host", "custom-panel"));
    }
}
