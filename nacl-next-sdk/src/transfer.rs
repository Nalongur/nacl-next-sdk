//! Generic file transfer: segmented + streaming engines, strong-validator
//! resume, retry with backoff, control-closure cancellation.
//!
//! Ported from the original launcher `downloader.rs` with the S2 contract
//! changes: stable dotted error codes, a retry backoff, and an
//! identity-keyed resume state (`algorithm:value`, never a URL). Transport
//! validators (ETag/Last-Modified) only gate *resuming* — content trust is
//! the plan executor's digest policy, never this module.

use crate::error::SdkErrorSource;
use reqwest::blocking::{Client, Response};
use reqwest::header::{
    HeaderValue, ACCEPT_ENCODING, CONTENT_LENGTH, CONTENT_RANGE, ETAG, IF_RANGE, LAST_MODIFIED,
    RANGE,
};
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};
use tempfile::NamedTempFile;

const MIN_PIECE_SIZE: u64 = 2 * 1024 * 1024;
const MAX_PIECE_SIZE: u64 = 16 * 1024 * 1024;
const IO_BUFFER_SIZE: usize = 64 * 1024;

/// Shared blocking HTTP client with conservative timeouts. Hosts may build
/// their own and pass it to [`transfer`].
pub fn http_client() -> Result<Client, TransferError> {
    Client::builder()
        .connect_timeout(Duration::from_secs(20))
        .timeout(Duration::from_secs(120))
        .user_agent(format!("NaCLNext/{}", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(|error| TransferError::Network(error.to_string()))
}

/// Client whose redirect policy re-checks the host allow list on every
/// hop (empty list = unrestricted host choice, default hop limit). Without
/// this, a whitelisted origin could redirect to any host.
pub fn http_client_with_redirect_allowlist(
    allowed_hosts: std::sync::Arc<Vec<String>>,
) -> Result<Client, TransferError> {
    Client::builder()
        .connect_timeout(Duration::from_secs(20))
        .timeout(Duration::from_secs(120))
        .user_agent(format!("NaCLNext/{}", env!("CARGO_PKG_VERSION")))
        .redirect(reqwest::redirect::Policy::custom(move |attempt| {
            if attempt.previous().len() >= 10 {
                return attempt.stop();
            }
            if allowed_hosts.is_empty() {
                return attempt.follow();
            }
            let hop_host = attempt
                .url()
                .host_str()
                .map(str::to_ascii_lowercase)
                .unwrap_or_default();
            let allowed = allowed_hosts
                .iter()
                .any(|candidate| candidate.to_ascii_lowercase() == hop_host);
            if allowed {
                attempt.follow()
            } else {
                attempt.error(format!(
                    "redirect target host {hop_host:?} is not in the host allow list"
                ))
            }
        }))
        .build()
        .map_err(|error| TransferError::Network(error.to_string()))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferControl {
    Running,
    Paused,
    Cancelled,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum TransferEngine {
    Segmented,
    Streaming,
}

#[derive(Debug, Clone, Copy)]
pub struct TransferUpdate {
    pub downloaded_bytes: u64,
    pub speed_bytes_per_second: u64,
    pub engine: TransferEngine,
    pub active_connections: u8,
}

#[derive(Debug, Clone)]
pub struct TransferRequest<'a> {
    pub url: &'a str,
    /// Expected total size; `0` disables the size precheck (streaming only
    /// then verifies what it actually read).
    pub expected_size: u64,
    /// Content identity key (`algorithm:value`); resume state only applies
    /// when it matches.
    pub identity: &'a str,
    /// Destination path for the staged `.part` file (caller owns naming).
    pub destination: &'a Path,
    /// Hard ceiling on bytes accepted while reading; `None` = uncapped.
    /// Reading aborts (with an error) before writing beyond this bound.
    pub byte_cap: Option<u64>,
}

#[derive(Debug, Clone, Copy)]
pub struct TransferOptions {
    pub segment_connections: u8,
    pub segment_threshold_bytes: u64,
    pub retry_count: u8,
    /// Delay between retries, multiplied by the attempt index.
    pub retry_backoff: Duration,
    pub speed_limit_bytes_per_second: Option<u64>,
}

impl Default for TransferOptions {
    fn default() -> Self {
        Self {
            segment_connections: 4,
            segment_threshold_bytes: 4 * 1024 * 1024,
            retry_count: 2,
            retry_backoff: Duration::from_millis(250),
            speed_limit_bytes_per_second: None,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct TransferOutcome {
    pub downloaded_bytes: u64,
    pub engine: TransferEngine,
}

#[derive(Debug)]
pub enum TransferError {
    Cancelled,
    Network(String),
    HttpStatus {
        url: String,
        status: u16,
    },
    Io {
        action: &'static str,
        path: PathBuf,
        source: io::Error,
    },
    InvalidContentRange(String),
    SizeMismatch {
        expected: u64,
        actual: u64,
    },
    State(String),
    UnsupportedRange(String),
    LimitExceeded {
        cap: u64,
    },
}

impl TransferError {
    fn permits_streaming_fallback(&self) -> bool {
        matches!(
            self,
            Self::Network(_)
                | Self::HttpStatus { .. }
                | Self::InvalidContentRange(_)
                | Self::UnsupportedRange(_)
        )
    }
}

impl fmt::Display for TransferError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cancelled => write!(formatter, "下载已取消"),
            Self::Network(error) => write!(formatter, "网络请求失败：{error}"),
            Self::HttpStatus { url, status } => {
                write!(formatter, "下载 {url} 时返回 HTTP {status}")
            }
            Self::Io {
                action,
                path,
                source,
            } => write!(formatter, "无法{action} {}：{source}", path.display()),
            Self::InvalidContentRange(value) => write!(formatter, "无效的范围响应：{value}"),
            Self::SizeMismatch { expected, actual } => {
                write!(
                    formatter,
                    "大小不符：期望 {expected} 字节，实际 {actual} 字节"
                )
            }
            Self::State(error) => write!(formatter, "断点状态无效：{error}"),
            Self::UnsupportedRange(reason) => write!(formatter, "服务器不支持分段下载：{reason}"),
            Self::LimitExceeded { cap } => {
                write!(formatter, "传输超过字节上限 {cap}，已中止")
            }
        }
    }
}

impl std::error::Error for TransferError {}

impl SdkErrorSource for TransferError {
    fn sdk_code(&self) -> &'static str {
        match self {
            Self::Cancelled => "transfer/cancelled",
            Self::Network(_) => "transfer/network",
            Self::HttpStatus { .. } => "transfer/http-status",
            Self::Io { .. } => "transfer/io",
            Self::InvalidContentRange(_) => "transfer/invalid-content-range",
            Self::SizeMismatch { .. } => "transfer/size-mismatch",
            Self::State(_) => "transfer/state",
            Self::UnsupportedRange(_) => "transfer/unsupported-range",
            Self::LimitExceeded { .. } => "transfer/limit-exceeded",
        }
    }

    fn sdk_retryable(&self) -> bool {
        matches!(
            self,
            Self::Network(_) | Self::HttpStatus { .. } | Self::UnsupportedRange(_)
        )
    }
}

/// Removes a staged transfer and its resume state.
pub fn cleanup_partial_state(temporary: &Path) {
    let _ = fs::remove_file(temporary);
    let _ = fs::remove_file(resume_path(temporary));
}

pub fn transfer(
    client: &Client,
    request: TransferRequest<'_>,
    options: TransferOptions,
    control: &(dyn Fn() -> TransferControl + Sync),
    progress: &(dyn Fn(TransferUpdate) + Sync),
) -> Result<TransferOutcome, TransferError> {
    wait_for_control(control)?;
    let use_segments =
        request.expected_size >= options.segment_threshold_bytes && options.segment_connections > 1;
    if use_segments {
        match segmented_transfer(client, &request, options, control, progress) {
            Ok(bytes) => {
                return Ok(TransferOutcome {
                    downloaded_bytes: bytes,
                    engine: TransferEngine::Segmented,
                });
            }
            Err(error) if error.permits_streaming_fallback() => {
                cleanup_partial_state(request.destination);
                progress(TransferUpdate {
                    downloaded_bytes: 0,
                    speed_bytes_per_second: 0,
                    engine: TransferEngine::Streaming,
                    active_connections: 1,
                });
            }
            Err(error) => return Err(error),
        }
    }

    let bytes = streaming_transfer(client, &request, options, control, progress)?;
    Ok(TransferOutcome {
        downloaded_bytes: bytes,
        engine: TransferEngine::Streaming,
    })
}

fn segmented_transfer(
    client: &Client,
    request: &TransferRequest<'_>,
    options: TransferOptions,
    control: &(dyn Fn() -> TransferControl + Sync),
    progress: &(dyn Fn(TransferUpdate) + Sync),
) -> Result<u64, TransferError> {
    let probe = probe_range_support(client, request.url)?;
    if request.expected_size > 0 && probe.total_size != request.expected_size {
        return Err(TransferError::SizeMismatch {
            expected: request.expected_size,
            actual: probe.total_size,
        });
    }
    if let Some(cap) = request.byte_cap {
        if probe.total_size > cap {
            return Err(TransferError::LimitExceeded { cap });
        }
    }
    let connection_count = options.segment_connections.clamp(2, 16);
    let piece_size = choose_piece_size(probe.total_size, connection_count);
    let pieces = build_pieces(probe.total_size, piece_size);
    let state_path = resume_path(request.destination);
    let mut state = load_compatible_state(&state_path, request, &probe, piece_size, pieces.len())?
        .unwrap_or_else(|| ResumeState {
            schema_version: 1,
            url: request.url.to_string(),
            identity: request.identity.to_string(),
            total_size: probe.total_size,
            piece_size,
            completed: vec![false; pieces.len()],
            etag: probe.etag.clone(),
            last_modified: probe.last_modified.clone(),
        });

    if !request.destination.is_file()
        || fs::metadata(request.destination)
            .map_err(|source| io_error("读取临时文件", request.destination, source))?
            .len()
            != probe.total_size
    {
        state.completed.fill(false);
        let file = File::create(request.destination)
            .map_err(|source| io_error("创建分片临时文件", request.destination, source))?;
        file.set_len(probe.total_size)
            .map_err(|source| io_error("预分配分片临时文件", request.destination, source))?;
        file.sync_all()
            .map_err(|source| io_error("同步分片临时文件", request.destination, source))?;
        save_state(&state_path, &state)?;
    }

    let completed_bytes = pieces
        .iter()
        .filter(|piece| state.completed[piece.index])
        .map(|piece| piece.len())
        .sum::<u64>();
    let queue = pieces
        .iter()
        .filter(|piece| !state.completed[piece.index])
        .copied()
        .collect::<VecDeque<_>>();
    if queue.is_empty() {
        let _ = fs::remove_file(&state_path);
        progress(TransferUpdate {
            downloaded_bytes: probe.total_size,
            speed_bytes_per_second: 0,
            engine: TransferEngine::Segmented,
            active_connections: 0,
        });
        return Ok(probe.total_size);
    }

    let file = Arc::new(
        OpenOptions::new()
            .write(true)
            .open(request.destination)
            .map_err(|source| io_error("打开分片临时文件", request.destination, source))?,
    );
    let queue = Arc::new(Mutex::new(queue));
    let state = Arc::new(Mutex::new(state));
    let first_error = Arc::new(Mutex::new(None::<TransferError>));
    let stop = Arc::new(AtomicBool::new(false));
    let downloaded = Arc::new(AtomicU64::new(completed_bytes));
    let active = Arc::new(AtomicU64::new(0));
    let transfer_rate = Arc::new(Mutex::new(TransferRate::new()));
    let limiter = Arc::new(RateLimiter::new(options.speed_limit_bytes_per_second));
    let validator = probe
        .etag
        .as_deref()
        .filter(|etag| is_strong_entity_tag(etag))
        .or(probe.last_modified.as_deref())
        .map(str::to_owned);

    progress(TransferUpdate {
        downloaded_bytes: completed_bytes,
        speed_bytes_per_second: 0,
        engine: TransferEngine::Segmented,
        active_connections: connection_count,
    });

    let state_path_ref = state_path.as_path();
    thread::scope(|scope| {
        for _ in 0..connection_count {
            let file = Arc::clone(&file);
            let queue = Arc::clone(&queue);
            let state = Arc::clone(&state);
            let first_error = Arc::clone(&first_error);
            let stop = Arc::clone(&stop);
            let downloaded = Arc::clone(&downloaded);
            let active = Arc::clone(&active);
            let transfer_rate = Arc::clone(&transfer_rate);
            let limiter = Arc::clone(&limiter);
            let validator = validator.clone();
            scope.spawn(move || {
                while !stop.load(Ordering::Acquire) {
                    let piece = {
                        let mut queue = queue
                            .lock()
                            .unwrap_or_else(|poisoned| poisoned.into_inner());
                        queue.pop_front()
                    };
                    let Some(piece) = piece else { return };
                    active.fetch_add(1, Ordering::Relaxed);
                    let result = transfer_piece(
                        client,
                        request,
                        piece,
                        validator.as_deref(),
                        options,
                        control,
                        &file,
                        &downloaded,
                        &active,
                        &transfer_rate,
                        &limiter,
                        progress,
                    );
                    active.fetch_sub(1, Ordering::Relaxed);
                    match result {
                        Ok(()) => {
                            let save_result = {
                                let mut state = state
                                    .lock()
                                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                                state.completed[piece.index] = true;
                                save_state(state_path_ref, &state)
                            };
                            if let Err(error) = save_result {
                                record_first_error(&first_error, &stop, error);
                                return;
                            }
                        }
                        Err(error) => {
                            record_first_error(&first_error, &stop, error);
                            return;
                        }
                    }
                }
            });
        }
    });

    if let Some(error) = first_error
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .take()
    {
        return Err(error);
    }
    file.sync_all()
        .map_err(|source| io_error("同步分片临时文件", request.destination, source))?;
    let actual = downloaded.load(Ordering::Relaxed);
    if actual != probe.total_size {
        return Err(TransferError::SizeMismatch {
            expected: probe.total_size,
            actual,
        });
    }
    let _ = fs::remove_file(state_path);
    progress(TransferUpdate {
        downloaded_bytes: actual,
        speed_bytes_per_second: 0,
        engine: TransferEngine::Segmented,
        active_connections: 0,
    });
    Ok(actual)
}

#[allow(clippy::too_many_arguments)]
fn transfer_piece(
    client: &Client,
    request: &TransferRequest<'_>,
    piece: Piece,
    validator: Option<&str>,
    options: TransferOptions,
    control: &(dyn Fn() -> TransferControl + Sync),
    file: &File,
    downloaded: &AtomicU64,
    active: &AtomicU64,
    transfer_rate: &Mutex<TransferRate>,
    limiter: &RateLimiter,
    progress: &(dyn Fn(TransferUpdate) + Sync),
) -> Result<(), TransferError> {
    let mut last_error = None;
    for attempt in 0..=options.retry_count {
        if attempt > 0 {
            thread::sleep(options.retry_backoff.saturating_mul(attempt as u32));
        }
        wait_for_control(control)?;
        let mut request_builder = client
            .get(request.url)
            .header(ACCEPT_ENCODING, "identity")
            .header(RANGE, format!("bytes={}-{}", piece.start, piece.end));
        if let Some(validator) = validator.and_then(|value| HeaderValue::from_str(value).ok()) {
            request_builder = request_builder.header(IF_RANGE, validator);
        }
        let response = match request_builder.send() {
            Ok(response) => response,
            Err(error) => {
                last_error = Some(TransferError::Network(error.to_string()));
                continue;
            }
        };
        let mut response = match validate_piece_response(response, piece) {
            Ok(response) => response,
            Err(error) => {
                last_error = Some(error);
                continue;
            }
        };
        let mut offset = piece.start;
        let mut attempt_bytes = 0_u64;
        let mut buffer = [0_u8; IO_BUFFER_SIZE];
        let result = loop {
            if let Err(error) = wait_for_control(control) {
                break Err(error);
            }
            let count = match response.read(&mut buffer) {
                Ok(count) => count,
                Err(error) => break Err(TransferError::Network(error.to_string())),
            };
            if count == 0 {
                break if attempt_bytes == piece.len() {
                    Ok(())
                } else {
                    Err(TransferError::SizeMismatch {
                        expected: piece.len(),
                        actual: attempt_bytes,
                    })
                };
            }
            if attempt_bytes + count as u64 > piece.len() {
                break Err(TransferError::SizeMismatch {
                    expected: piece.len(),
                    actual: attempt_bytes + count as u64,
                });
            }
            write_all_at(file, &buffer[..count], offset)
                .map_err(|source| io_error("写入分片临时文件", request.destination, source))?;
            offset += count as u64;
            attempt_bytes += count as u64;
            let total = downloaded.fetch_add(count as u64, Ordering::Relaxed) + count as u64;
            limiter.throttle(count as u64);
            let speed = transfer_rate
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .record(count as u64);
            progress(TransferUpdate {
                downloaded_bytes: total,
                speed_bytes_per_second: speed,
                engine: TransferEngine::Segmented,
                active_connections: active.load(Ordering::Relaxed).min(u64::from(u8::MAX)) as u8,
            });
        };
        match result {
            Ok(()) => return Ok(()),
            Err(TransferError::Cancelled) => return Err(TransferError::Cancelled),
            Err(error) => {
                downloaded.fetch_sub(attempt_bytes, Ordering::Relaxed);
                last_error = Some(error);
            }
        }
    }
    Err(last_error.unwrap_or_else(|| TransferError::Network("分片重试次数已耗尽".to_string())))
}

fn streaming_transfer(
    client: &Client,
    request: &TransferRequest<'_>,
    options: TransferOptions,
    control: &(dyn Fn() -> TransferControl + Sync),
    progress: &(dyn Fn(TransferUpdate) + Sync),
) -> Result<u64, TransferError> {
    wait_for_control(control)?;
    let mut last_error = None;
    let mut response = None;
    for attempt in 0..=options.retry_count {
        if attempt > 0 {
            thread::sleep(options.retry_backoff.saturating_mul(attempt as u32));
        }
        match client
            .get(request.url)
            .header(ACCEPT_ENCODING, "identity")
            .send()
        {
            Ok(sent) if sent.status().is_success() => {
                response = Some(sent);
                break;
            }
            Ok(sent) => {
                last_error = Some(TransferError::HttpStatus {
                    url: request.url.to_string(),
                    status: sent.status().as_u16(),
                });
            }
            Err(error) => last_error = Some(TransferError::Network(error.to_string())),
        }
    }
    let mut response = response.ok_or_else(|| {
        last_error.unwrap_or_else(|| TransferError::Network("连接重试次数已耗尽".to_string()))
    })?;
    if let Some(cap) = request.byte_cap {
        let declared_length = response
            .headers()
            .get(reqwest::header::CONTENT_LENGTH)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<u64>().ok());
        if let Some(length) = declared_length {
            if length > cap {
                return Err(TransferError::LimitExceeded { cap });
            }
        }
    }
    let mut file = File::create(request.destination)
        .map_err(|source| io_error("创建流式临时文件", request.destination, source))?;
    let mut total = 0_u64;
    let mut transfer_rate = TransferRate::new();
    let limiter = RateLimiter::new(options.speed_limit_bytes_per_second);
    let mut buffer = [0_u8; IO_BUFFER_SIZE];
    loop {
        wait_for_control(control)?;
        let count = response
            .read(&mut buffer)
            .map_err(|error| TransferError::Network(error.to_string()))?;
        if count == 0 {
            break;
        }
        if let Some(cap) = request.byte_cap {
            if total + count as u64 > cap {
                return Err(TransferError::LimitExceeded { cap });
            }
        }
        file.write_all(&buffer[..count])
            .map_err(|source| io_error("写入流式临时文件", request.destination, source))?;
        total = total.saturating_add(count as u64);
        limiter.throttle(count as u64);
        progress(TransferUpdate {
            downloaded_bytes: total,
            speed_bytes_per_second: transfer_rate.record(count as u64),
            engine: TransferEngine::Streaming,
            active_connections: 1,
        });
    }
    file.sync_all()
        .map_err(|source| io_error("同步流式临时文件", request.destination, source))?;
    if request.expected_size > 0 && total != request.expected_size {
        return Err(TransferError::SizeMismatch {
            expected: request.expected_size,
            actual: total,
        });
    }
    progress(TransferUpdate {
        downloaded_bytes: total,
        speed_bytes_per_second: 0,
        engine: TransferEngine::Streaming,
        active_connections: 0,
    });
    Ok(total)
}

struct ProbeResult {
    total_size: u64,
    etag: Option<String>,
    last_modified: Option<String>,
}

fn probe_range_support(client: &Client, url: &str) -> Result<ProbeResult, TransferError> {
    let response = client
        .get(url)
        .header(ACCEPT_ENCODING, "identity")
        .header(RANGE, "bytes=0-0")
        .send()
        .map_err(|error| TransferError::Network(error.to_string()))?;
    if response.status().as_u16() != 206 {
        return Err(TransferError::UnsupportedRange(format!(
            "探测请求返回 HTTP {}",
            response.status()
        )));
    }
    let content_range = header_string(&response, CONTENT_RANGE)
        .ok_or_else(|| TransferError::InvalidContentRange("缺少响应头".to_string()))?;
    let (start, end, total_size) = parse_content_range(&content_range)?;
    if start != 0 || end != 0 || total_size == 0 {
        return Err(TransferError::InvalidContentRange(content_range));
    }
    Ok(ProbeResult {
        total_size,
        etag: header_string(&response, ETAG),
        last_modified: header_string(&response, LAST_MODIFIED),
    })
}

fn validate_piece_response(response: Response, piece: Piece) -> Result<Response, TransferError> {
    if response.status().as_u16() != 206 {
        return Err(TransferError::UnsupportedRange(format!(
            "分片请求返回 HTTP {}",
            response.status()
        )));
    }
    let content_range = header_string(&response, CONTENT_RANGE)
        .ok_or_else(|| TransferError::InvalidContentRange("缺少响应头".to_string()))?;
    let (start, end, _) = parse_content_range(&content_range)?;
    if start != piece.start || end != piece.end {
        return Err(TransferError::InvalidContentRange(content_range));
    }
    if let Some(length) = response
        .headers()
        .get(CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
    {
        if length != piece.len() {
            return Err(TransferError::SizeMismatch {
                expected: piece.len(),
                actual: length,
            });
        }
    }
    Ok(response)
}

fn parse_content_range(value: &str) -> Result<(u64, u64, u64), TransferError> {
    let value = value.trim();
    let ranges = value
        .strip_prefix("bytes ")
        .ok_or_else(|| TransferError::InvalidContentRange(value.to_string()))?;
    let (range, total) = ranges
        .split_once('/')
        .ok_or_else(|| TransferError::InvalidContentRange(value.to_string()))?;
    let (start, end) = range
        .split_once('-')
        .ok_or_else(|| TransferError::InvalidContentRange(value.to_string()))?;
    let parsed = (
        start.parse::<u64>(),
        end.parse::<u64>(),
        total.parse::<u64>(),
    );
    match parsed {
        (Ok(start), Ok(end), Ok(total)) if start <= end && end < total => Ok((start, end, total)),
        _ => Err(TransferError::InvalidContentRange(value.to_string())),
    }
}

fn is_strong_entity_tag(value: &str) -> bool {
    value.len() >= 2 && value.starts_with('"') && value.ends_with('"') && !value.starts_with("W/")
}

fn choose_piece_size(total_size: u64, connections: u8) -> u64 {
    let desired_pieces = u64::from(connections).saturating_mul(4).max(1);
    let raw = total_size.div_ceil(desired_pieces);
    let aligned = raw.div_ceil(64 * 1024) * 64 * 1024;
    aligned.clamp(MIN_PIECE_SIZE, MAX_PIECE_SIZE)
}

fn build_pieces(total_size: u64, piece_size: u64) -> Vec<Piece> {
    if total_size == 0 {
        return Vec::new();
    }
    (0..total_size.div_ceil(piece_size))
        .map(|index| {
            let start = index * piece_size;
            Piece {
                index: index as usize,
                start,
                end: (start + piece_size - 1).min(total_size - 1),
            }
        })
        .collect()
}

#[derive(Debug, Clone, Copy)]
struct Piece {
    index: usize,
    start: u64,
    end: u64,
}

impl Piece {
    fn len(&self) -> u64 {
        self.end - self.start + 1
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ResumeState {
    schema_version: u32,
    url: String,
    identity: String,
    total_size: u64,
    piece_size: u64,
    completed: Vec<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    etag: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    last_modified: Option<String>,
}

fn load_compatible_state(
    path: &Path,
    request: &TransferRequest<'_>,
    probe: &ProbeResult,
    piece_size: u64,
    piece_count: usize,
) -> Result<Option<ResumeState>, TransferError> {
    if !path.is_file() {
        return Ok(None);
    }
    let contents = match fs::read(path) {
        Ok(contents) => contents,
        Err(_) => return Ok(None),
    };
    let state: ResumeState = match serde_json::from_slice(&contents) {
        Ok(state) => state,
        Err(_) => return Ok(None),
    };
    let validator_matches = state.etag == probe.etag && state.last_modified == probe.last_modified;
    let matches = state.schema_version == 1
        && state.url == request.url
        && state.identity == request.identity
        && state.total_size == probe.total_size
        && state.piece_size == piece_size
        && state.completed.len() == piece_count
        && validator_matches;
    Ok(matches.then_some(state))
}

fn save_state(path: &Path, state: &ResumeState) -> Result<(), TransferError> {
    let parent = path
        .parent()
        .ok_or_else(|| TransferError::State("状态路径缺少父目录".to_string()))?;
    let mut temporary = NamedTempFile::new_in(parent)
        .map_err(|source| io_error("创建断点状态文件", path, source))?;
    serde_json::to_writer(temporary.as_file_mut(), state)
        .map_err(|error| TransferError::State(error.to_string()))?;
    temporary
        .as_file_mut()
        .sync_all()
        .map_err(|source| io_error("同步断点状态文件", path, source))?;
    temporary
        .persist(path)
        .map_err(|error| io_error("保存断点状态文件", path, error.error))?;
    Ok(())
}

fn resume_path(temporary: &Path) -> PathBuf {
    let mut value = temporary.as_os_str().to_os_string();
    value.push(".nacl-next.json");
    PathBuf::from(value)
}

fn header_string(response: &Response, name: reqwest::header::HeaderName) -> Option<String> {
    response
        .headers()
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
}

fn record_first_error(
    first_error: &Mutex<Option<TransferError>>,
    stop: &AtomicBool,
    error: TransferError,
) {
    let mut first = first_error
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if first.is_none() {
        *first = Some(error);
    }
    stop.store(true, Ordering::Release);
}

fn wait_for_control(control: &(dyn Fn() -> TransferControl + Sync)) -> Result<(), TransferError> {
    loop {
        match control() {
            TransferControl::Running => return Ok(()),
            TransferControl::Cancelled => return Err(TransferError::Cancelled),
            TransferControl::Paused => thread::sleep(Duration::from_millis(100)),
        }
    }
}

struct TransferRate {
    window_started: Instant,
    window_bytes: u64,
    last_speed: u64,
}

impl TransferRate {
    fn new() -> Self {
        Self {
            window_started: Instant::now(),
            window_bytes: 0,
            last_speed: 0,
        }
    }

    fn record(&mut self, bytes: u64) -> u64 {
        self.window_bytes = self.window_bytes.saturating_add(bytes);
        let elapsed = self.window_started.elapsed();
        if elapsed >= Duration::from_millis(250) {
            self.last_speed = (self.window_bytes as f64 / elapsed.as_secs_f64()) as u64;
            self.window_started = Instant::now();
            self.window_bytes = 0;
        }
        self.last_speed
    }
}

struct RateLimiter {
    bytes_per_second: u64,
    next_slot: Mutex<Instant>,
}

impl RateLimiter {
    fn new(limit_bytes_per_second: Option<u64>) -> Self {
        Self {
            bytes_per_second: limit_bytes_per_second.unwrap_or(0),
            next_slot: Mutex::new(Instant::now()),
        }
    }

    fn throttle(&self, bytes: u64) {
        if self.bytes_per_second == 0 {
            return;
        }
        let duration = Duration::from_secs_f64(bytes as f64 / self.bytes_per_second as f64);
        let target = {
            let mut next = self
                .next_slot
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let now = Instant::now();
            if *next < now {
                *next = now;
            }
            *next += duration;
            *next
        };
        if let Some(delay) = target.checked_duration_since(Instant::now()) {
            thread::sleep(delay);
        }
    }
}

fn io_error(action: &'static str, path: &Path, source: io::Error) -> TransferError {
    TransferError::Io {
        action,
        path: path.to_path_buf(),
        source,
    }
}

#[cfg(windows)]
fn write_all_at(file: &File, mut buffer: &[u8], mut offset: u64) -> io::Result<()> {
    use std::os::windows::fs::FileExt;
    while !buffer.is_empty() {
        let count = file.seek_write(buffer, offset)?;
        if count == 0 {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "分片写入返回 0 字节",
            ));
        }
        buffer = &buffer[count..];
        offset += count as u64;
    }
    Ok(())
}

#[cfg(unix)]
fn write_all_at(file: &File, mut buffer: &[u8], mut offset: u64) -> io::Result<()> {
    use std::os::unix::fs::FileExt;
    while !buffer.is_empty() {
        let count = file.write_at(buffer, offset)?;
        if count == 0 {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "分片写入返回 0 字节",
            ));
        }
        buffer = &buffer[count..];
        offset += count as u64;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{build_pieces, choose_piece_size, is_strong_entity_tag, parse_content_range};

    #[test]
    fn parses_content_ranges() {
        assert_eq!(parse_content_range("bytes 0-0/1024").unwrap(), (0, 0, 1024));
        assert!(parse_content_range("bytes 5-2/1024").is_err());
        assert!(parse_content_range("items 0-0/10").is_err());
    }

    #[test]
    fn only_strong_entity_tags_are_validators() {
        assert!(is_strong_entity_tag("\"abc\""));
        assert!(!is_strong_entity_tag("W/\"abc\""));
        assert!(!is_strong_entity_tag("abc"));
    }

    #[test]
    fn pieces_cover_the_file_exactly() {
        let pieces = build_pieces(10 * 1024 * 1024, 4 * 1024 * 1024);
        assert_eq!(pieces.len(), 3);
        assert_eq!(pieces[2].end, 10 * 1024 * 1024 - 1);
        assert_eq!(choose_piece_size(0, 4), 2 * 1024 * 1024);
    }
}
