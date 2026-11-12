//! Local (offline) profile store: multiple named profiles, no network.
//!
//! Replaces the original single `offline-profile.json` model. The store is
//! pure local file management: no Microsoft requests, no tokens, no
//! entitlements — a Local profile is explicitly *not* a verified identity.
//! Which profile is "selected" is host session state; the SDK only stores,
//! lists, renames and deletes.

use super::{AccountProvider, AccountProviderError, IdentityKind, IdentitySummary, LaunchIdentity};
use crate::context::SdkContext;
use crate::error::SdkErrorSource;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};

pub const LOCAL_PROFILE_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "contracts", derive(ts_rs::TS))]
pub struct LocalProfile {
    pub schema_version: u32,
    pub id: String,
    pub username: String,
    /// Deterministic offline UUID (`OfflinePlayer:{username}`, MD5, Java v3 layout).
    pub uuid: String,
    #[serde(default)]
    pub created_epoch_ms: u128,
}

impl LocalProfile {
    pub fn new(username: impl Into<String>) -> Result<Self, LocalProfileError> {
        let username = username.into().trim().to_string();
        if !valid_username(&username) {
            return Err(LocalProfileError::InvalidUsername);
        }
        Ok(Self {
            schema_version: LOCAL_PROFILE_SCHEMA_VERSION,
            id: uuid::Uuid::new_v4().simple().to_string(),
            uuid: offline_uuid(&username),
            username,
            created_epoch_ms: now_epoch_ms(),
        })
    }
}

#[derive(Debug)]
pub enum LocalProfileError {
    InvalidUsername,
    DuplicateUsername(String),
    ProfileNotFound(String),
    InvalidStore {
        reason: String,
    },
    Io {
        action: &'static str,
        source: std::io::Error,
    },
}

impl fmt::Display for LocalProfileError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidUsername => write!(
                formatter,
                "离线用户名须为 3–16 位，只能包含英文字母、数字和下划线"
            ),
            Self::DuplicateUsername(username) => {
                write!(formatter, "已存在同名离线档案 {username}")
            }
            Self::ProfileNotFound(id) => write!(formatter, "找不到离线档案 {id}"),
            Self::InvalidStore { reason } => write!(formatter, "离线档案存储无效：{reason}"),
            Self::Io { action, source } => write!(formatter, "无法{action}：{source}"),
        }
    }
}

impl std::error::Error for LocalProfileError {}

impl SdkErrorSource for LocalProfileError {
    fn sdk_code(&self) -> &'static str {
        match self {
            Self::InvalidUsername => "account/local/invalid-username",
            Self::DuplicateUsername(_) => "account/local/duplicate-username",
            Self::ProfileNotFound(_) => "account/local/not-found",
            Self::InvalidStore { .. } => "account/local/invalid-store",
            Self::Io { .. } => "account/local/io",
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct LocalProfileStoreFile {
    schema_version: u32,
    #[serde(default)]
    profiles: Vec<LocalProfile>,
}

/// Multiple local profiles persisted atomically in the context config root.
pub struct LocalProfileStore {
    path: std::path::PathBuf,
}

impl LocalProfileStore {
    pub fn new(context: &SdkContext) -> Self {
        Self {
            path: context.config_root.join("local-profiles.json"),
        }
    }

    pub fn list(&self) -> Result<Vec<LocalProfile>, LocalProfileError> {
        Ok(self.load()?.profiles)
    }

    pub fn create(&self, username: impl Into<String>) -> Result<LocalProfile, LocalProfileError> {
        let profile = LocalProfile::new(username)?;
        let mut store = self.load()?;
        if store
            .profiles
            .iter()
            .any(|existing| existing.username == profile.username)
        {
            return Err(LocalProfileError::DuplicateUsername(profile.username));
        }
        store.profiles.push(profile.clone());
        self.save(&store)?;
        Ok(profile)
    }

    pub fn rename(
        &self,
        profile_id: &str,
        username: impl Into<String>,
    ) -> Result<LocalProfile, LocalProfileError> {
        let username = username.into().trim().to_string();
        if !valid_username(&username) {
            return Err(LocalProfileError::InvalidUsername);
        }
        let mut store = self.load()?;
        if store
            .profiles
            .iter()
            .any(|existing| existing.username == username && existing.id != profile_id)
        {
            return Err(LocalProfileError::DuplicateUsername(username));
        }
        let profile = store
            .profiles
            .iter_mut()
            .find(|profile| profile.id == profile_id)
            .ok_or_else(|| LocalProfileError::ProfileNotFound(profile_id.to_owned()))?;
        profile.username = username.clone();
        // Deterministic UUID follows the name so world data stays consistent.
        profile.uuid = offline_uuid(&username);
        let updated = profile.clone();
        self.save(&store)?;
        Ok(updated)
    }

    pub fn delete(&self, profile_id: &str) -> Result<(), LocalProfileError> {
        let mut store = self.load()?;
        let before = store.profiles.len();
        store.profiles.retain(|profile| profile.id != profile_id);
        if store.profiles.len() == before {
            return Err(LocalProfileError::ProfileNotFound(profile_id.to_owned()));
        }
        self.save(&store)
    }

    fn load(&self) -> Result<LocalProfileStoreFile, LocalProfileError> {
        if !self.path.is_file() {
            return Ok(LocalProfileStoreFile {
                schema_version: LOCAL_PROFILE_SCHEMA_VERSION,
                profiles: Vec::new(),
            });
        }
        let contents = fs::read_to_string(&self.path).map_err(|source| LocalProfileError::Io {
            action: "读取离线档案存储",
            source,
        })?;
        let store: LocalProfileStoreFile =
            serde_json::from_str(&contents).map_err(|source| LocalProfileError::InvalidStore {
                reason: source.to_string(),
            })?;
        if store.schema_version != LOCAL_PROFILE_SCHEMA_VERSION
            || store
                .profiles
                .iter()
                .any(|profile| !valid_username(&profile.username))
        {
            return Err(LocalProfileError::InvalidStore {
                reason: "schema 版本或档案条目无效".to_string(),
            });
        }
        Ok(store)
    }

    fn save(&self, store: &LocalProfileStoreFile) -> Result<(), LocalProfileError> {
        let mut contents =
            serde_json::to_vec_pretty(store).map_err(|source| LocalProfileError::InvalidStore {
                reason: source.to_string(),
            })?;
        contents.push(b'\n');
        crate::fsutil::write_atomic(&self.path, &contents).map_err(|source| LocalProfileError::Io {
            action: "写入离线档案存储",
            source,
        })
    }
}

impl AccountProvider for LocalProfileStore {
    fn kind(&self) -> IdentityKind {
        IdentityKind::Local
    }

    fn list_identities(&self) -> Result<Vec<IdentitySummary>, AccountProviderError> {
        self.list()
            .map(|profiles| {
                profiles
                    .into_iter()
                    .map(|profile| IdentitySummary {
                        kind: IdentityKind::Local,
                        id: profile.id,
                        username: profile.username,
                        label: "本地档案 · 未官方验证".to_string(),
                    })
                    .collect()
            })
            .map_err(|error| AccountProviderError::Other {
                code: error.sdk_code(),
                message: error.to_string(),
            })
    }

    fn prepare_launch_identity(&self, id: &str) -> Result<LaunchIdentity, AccountProviderError> {
        let profile = self
            .list()
            .map_err(|error| AccountProviderError::Other {
                code: error.sdk_code(),
                message: error.to_string(),
            })?
            .into_iter()
            .find(|profile| profile.id == id)
            .ok_or_else(|| AccountProviderError::UnknownIdentity(id.to_owned()))?;
        Ok(LaunchIdentity::Local(profile))
    }
}

pub(crate) fn valid_username(value: &str) -> bool {
    (3..=16).contains(&value.len())
        && value
            .bytes()
            .all(|character| character.is_ascii_alphanumeric() || character == b'_')
}

pub(crate) fn offline_uuid(username: &str) -> String {
    let digest = md5::compute(format!("OfflinePlayer:{username}").as_bytes());
    let mut bytes = digest.0;
    bytes[6] = (bytes[6] & 0x0f) | 0x30;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    bytes.iter().map(|value| format!("{value:02x}")).collect()
}

fn now_epoch_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_millis())
}

#[cfg(test)]
mod tests {
    use super::{offline_uuid, valid_username, LocalProfile, LocalProfileStore};

    #[test]
    fn validates_offline_usernames() {
        assert!(valid_username("Steve_01"));
        assert!(!valid_username("ab"));
        assert!(!valid_username("名字"));
        assert!(!valid_username("has space"));
    }

    #[test]
    fn builds_java_compatible_offline_uuid() {
        assert_eq!(offline_uuid("Steve"), "5627dd98e6be3c21b8a8e92344183641");
    }

    #[test]
    fn store_manages_multiple_profiles_atomically() {
        let root = tempfile::tempdir().unwrap();
        let context = crate::context::SdkContext::from_root(root.path());
        let store = LocalProfileStore::new(&context);

        let first = store.create("Steve_01").unwrap();
        let second = store.create("Alex_02").unwrap();
        assert_eq!(store.list().unwrap().len(), 2);

        assert!(store.create("Steve_01").is_err());
        let renamed = store.rename(&second.id, "Notch_03").unwrap();
        assert_eq!(renamed.username, "Notch_03");
        assert_eq!(renamed.uuid, offline_uuid("Notch_03"));

        store.delete(&first.id).unwrap();
        assert_eq!(store.list().unwrap().len(), 1);
        assert!(store.delete(&first.id).is_err());

        drop(root);
    }

    #[test]
    fn profile_construction_rejects_invalid_usernames() {
        assert!(LocalProfile::new("ok_name").is_ok());
        assert!(LocalProfile::new(" no-trim-and-space ").is_err());
    }
}
