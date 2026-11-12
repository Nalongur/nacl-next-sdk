//! Content-addressed cache: one object per `algorithm:value` identity.
//!
//! URLs and file names are never identities (guide §5.1). Objects are
//! verified while being inserted, so a cache hit is only trusted after the
//! executor's own digest check of what it copies out.

use crate::error::SdkErrorSource;
use serde::{Deserialize, Serialize};
use sha1::Sha1;
use sha2::{Digest, Sha256};
use std::fmt;
use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use tempfile::NamedTempFile;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[cfg_attr(feature = "contracts", derive(ts_rs::TS))]
pub enum DigestAlgorithm {
    Sha1,
    Sha256,
}

impl DigestAlgorithm {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Sha1 => "sha1",
            Self::Sha256 => "sha256",
        }
    }
}

fn hex(bytes: impl AsRef<[u8]>) -> String {
    bytes
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "contracts", derive(ts_rs::TS))]
pub struct ContentDigest {
    pub algorithm: DigestAlgorithm,
    /// Lowercase hex value.
    pub value: String,
}

impl ContentDigest {
    pub fn sha256(value: impl Into<String>) -> Self {
        Self {
            algorithm: DigestAlgorithm::Sha256,
            value: value.into(),
        }
    }

    /// Canonical cache identity, e.g. `sha256:ab12…`.
    pub fn identity(&self) -> String {
        format!("{}:{}", self.algorithm.as_str(), self.value)
    }
}

#[derive(Debug)]
pub enum CacheError {
    Io {
        action: &'static str,
        path: PathBuf,
        source: io::Error,
    },
}

impl fmt::Display for CacheError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io {
                action,
                path,
                source,
            } => write!(formatter, "无法{action} {}：{source}", path.display()),
        }
    }
}

impl std::error::Error for CacheError {}

impl SdkErrorSource for CacheError {
    fn sdk_code(&self) -> &'static str {
        "cache/io"
    }
}

/// Object store rooted at `objects/<algorithm>/<value>`.
pub struct ContentCache {
    root: PathBuf,
}

impl ContentCache {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub fn object_path(&self, digest: &ContentDigest) -> PathBuf {
        self.root
            .join(digest.algorithm.as_str())
            .join(&digest.value)
    }

    pub fn contains(&self, digest: &ContentDigest) -> bool {
        self.object_path(digest).is_file()
    }

    /// Copies `source` into the cache after verifying it matches `digest`.
    /// Returns the object path. Existing objects are left untouched (an
    /// object is immutable by construction).
    pub fn insert_from_file(
        &self,
        source: &Path,
        digest: &ContentDigest,
    ) -> Result<PathBuf, CacheInsertError> {
        let actual = hash_file(digest.algorithm, source)?;
        if !actual.eq_ignore_ascii_case(&digest.value) {
            return Err(CacheInsertError::DigestMismatch {
                expected: digest.value.clone(),
                actual,
            });
        }
        let destination = self.object_path(digest);
        if destination.is_file() {
            return Ok(destination);
        }
        if let Some(parent) = destination.parent() {
            fs::create_dir_all(parent).map_err(|source_error| CacheInsertError::Io {
                action: "创建缓存目录",
                path: parent.to_path_buf(),
                source: source_error,
            })?;
        }
        let temporary = NamedTempFile::new_in(destination.parent().unwrap_or(&self.root)).map_err(
            |source_error| CacheInsertError::Io {
                action: "创建缓存临时文件",
                path: destination.clone(),
                source: source_error,
            },
        )?;
        fs::copy(source, temporary.path()).map_err(|source_error| CacheInsertError::Io {
            action: "写入缓存对象",
            path: destination.clone(),
            source: source_error,
        })?;
        temporary
            .persist(&destination)
            .map_err(|error| CacheInsertError::Io {
                action: "提交缓存对象",
                path: destination.clone(),
                source: error.error,
            })?;
        Ok(destination)
    }
}

#[derive(Debug)]
pub enum CacheInsertError {
    DigestMismatch {
        expected: String,
        actual: String,
    },
    Io {
        action: &'static str,
        path: PathBuf,
        source: io::Error,
    },
}

impl fmt::Display for CacheInsertError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DigestMismatch { expected, actual } => write!(
                formatter,
                "缓存对象摘要不符：期望 {expected}，实际 {actual}"
            ),
            Self::Io {
                action,
                path,
                source,
            } => write!(formatter, "无法{action} {}：{source}", path.display()),
        }
    }
}

impl std::error::Error for CacheInsertError {}

impl From<CacheError> for CacheInsertError {
    fn from(error: CacheError) -> Self {
        match error {
            CacheError::Io {
                action,
                path,
                source,
            } => Self::Io {
                action,
                path,
                source,
            },
        }
    }
}

impl SdkErrorSource for CacheInsertError {
    fn sdk_code(&self) -> &'static str {
        match self {
            Self::DigestMismatch { .. } => "cache/digest-mismatch",
            Self::Io { .. } => "cache/io",
        }
    }
}

/// Hashes a file with the given algorithm (lowercase hex).
pub fn hash_file(algorithm: DigestAlgorithm, path: &Path) -> Result<String, CacheError> {
    let mut file = fs::File::open(path).map_err(|source| CacheError::Io {
        action: "打开待校验文件",
        path: path.to_path_buf(),
        source,
    })?;
    let mut sha256 = Sha256::new();
    let mut sha1 = Sha1::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = file.read(&mut buffer).map_err(|source| CacheError::Io {
            action: "读取待校验文件",
            path: path.to_path_buf(),
            source,
        })?;
        if count == 0 {
            break;
        }
        match algorithm {
            DigestAlgorithm::Sha256 => sha256.update(&buffer[..count]),
            DigestAlgorithm::Sha1 => sha1.update(&buffer[..count]),
        }
    }
    Ok(match algorithm {
        DigestAlgorithm::Sha256 => hex(sha256.finalize()),
        DigestAlgorithm::Sha1 => hex(sha1.finalize()),
    })
}
