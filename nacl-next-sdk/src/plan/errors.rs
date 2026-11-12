//! Stable executor error shape. Recovery and IO cases keep enough context
//! for the host to report what was preserved, never to silently retry a
//! destructive step.

use crate::error::SdkErrorSource;
use crate::transfer::TransferError;
use std::fmt;
use std::path::PathBuf;

#[derive(Debug)]
pub enum InstallExecutionError {
    Validation(&'static str, String),
    DigestRequired(String),
    DigestMismatch {
        relative_path: String,
        expected: String,
        actual: String,
    },
    SizeMismatch {
        relative_path: String,
        expected: u64,
        actual: u64,
    },
    SourceDenied {
        relative_path: String,
        reason: String,
    },
    Conflict {
        relative_path: String,
    },
    Cancelled,
    Transfer(TransferError),
    Cache(crate::cache::CacheInsertError),
    InstallInProgress,
    Recovery(String),
    Io {
        action: &'static str,
        path: PathBuf,
        source: std::io::Error,
    },
}

impl fmt::Display for InstallExecutionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Validation(_code, message) => write!(formatter, "计划无效：{message}"),
            Self::DigestRequired(relative_path) => {
                write!(formatter, "宿主要求摘要校验，但 {relative_path} 未提供摘要")
            }
            Self::DigestMismatch {
                relative_path,
                expected,
                actual,
            } => write!(
                formatter,
                "{relative_path} 摘要不符：期望 {expected}，实际 {actual}"
            ),
            Self::SizeMismatch {
                relative_path,
                expected,
                actual,
            } => write!(
                formatter,
                "{relative_path} 大小不符：期望 {expected} 字节，实际 {actual} 字节"
            ),
            Self::SourceDenied {
                relative_path,
                reason,
            } => write!(formatter, "{relative_path} 的来源被宿主策略拒绝：{reason}"),
            Self::Conflict { relative_path } => {
                write!(formatter, "目标 {relative_path} 已存在且策略不允许覆盖")
            }
            Self::Cancelled => write!(formatter, "安装已取消"),
            Self::Transfer(error) => error.fmt(formatter),
            Self::Cache(error) => error.fmt(formatter),
            Self::InstallInProgress => write!(formatter, "已有安装计划正在该目录执行"),
            Self::Recovery(reason) => write!(formatter, "恢复中断计划失败：{reason}"),
            Self::Io {
                action,
                path,
                source,
            } => write!(formatter, "无法{action} {}：{source}", path.display()),
        }
    }
}

impl std::error::Error for InstallExecutionError {}

impl SdkErrorSource for InstallExecutionError {
    fn sdk_code(&self) -> &'static str {
        match self {
            Self::Validation(code, _) => code,
            Self::DigestRequired(_) => "plan/digest-required",
            Self::DigestMismatch { .. } => "plan/digest-mismatch",
            Self::SizeMismatch { .. } => "plan/size-mismatch",
            Self::SourceDenied { .. } => "plan/source-denied",
            Self::Conflict { .. } => "plan/conflict",
            Self::Cancelled => "plan/cancelled",
            Self::Transfer(error) => error.sdk_code(),
            Self::Cache(error) => error.sdk_code(),
            Self::InstallInProgress => "plan/install-in-progress",
            Self::Recovery(_) => "plan/recovery-failed",
            Self::Io { .. } => "plan/io",
        }
    }

    fn sdk_details(&self) -> Option<serde_json::Value> {
        match self {
            Self::Validation(code, message) => {
                Some(serde_json::json!({ "code": code, "message": message }))
            }
            Self::DigestRequired(path)
            | Self::Conflict {
                relative_path: path,
                ..
            }
            | Self::SizeMismatch {
                relative_path: path,
                ..
            }
            | Self::SourceDenied {
                relative_path: path,
                ..
            } => Some(serde_json::json!({ "path": path })),
            Self::DigestMismatch { relative_path, .. } => {
                Some(serde_json::json!({ "path": relative_path }))
            }
            Self::Recovery(reason) => Some(serde_json::json!({ "reason": reason })),
            _ => None,
        }
    }
}

impl From<TransferError> for InstallExecutionError {
    fn from(error: TransferError) -> Self {
        match error {
            TransferError::Cancelled => Self::Cancelled,
            other => Self::Transfer(other),
        }
    }
}

impl From<crate::cache::CacheInsertError> for InstallExecutionError {
    fn from(error: crate::cache::CacheInsertError) -> Self {
        Self::Cache(error)
    }
}
