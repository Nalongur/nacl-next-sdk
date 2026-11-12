//! Minimal loopback HTTP server for transfer/provider tests.
//!
//! Own resources only: serves in-memory byte vectors with Range support,
//! per-file strong ETags, and fail-first-N injection. The accept loop is
//! plain blocking — the original project's proven pattern. (An earlier
//! nonblocking-listener version dropped connections at random on Windows:
//! sockets accepted from a nonblocking listener there stay nonblocking, so
//! reads fail with WouldBlock and close mid-handshake.)

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;

#[derive(Default)]
struct ServerState {
    files: HashMap<String, Vec<u8>>,
    etags: HashMap<String, String>,
    remaining_failures: HashMap<String, u32>,
    range_requests: HashMap<String, u64>,
    full_requests: HashMap<String, u64>,
}

pub struct TestServer {
    base: String,
    address: std::net::SocketAddr,
    state: Arc<Mutex<ServerState>>,
    shutdown: Arc<AtomicU64>,
    join: Option<thread::JoinHandle<()>>,
}

impl TestServer {
    pub fn start_default() -> Self {
        Self::start("127.0.0.1:0")
    }

    pub fn start(bind: &str) -> Self {
        let listener = TcpListener::bind(bind).expect("loopback bind");
        let address = listener.local_addr().unwrap();
        let state = Arc::new(Mutex::new(ServerState::default()));
        let shutdown = Arc::new(AtomicU64::new(0));
        let worker_shutdown = Arc::clone(&shutdown);
        let worker_state = Arc::clone(&state);
        let join = thread::spawn(move || {
            let mut handlers = Vec::new();
            loop {
                match listener.accept() {
                    Ok((stream, _)) => {
                        if worker_shutdown.load(Ordering::Acquire) > 0 {
                            break;
                        }
                        let state = Arc::clone(&worker_state);
                        handlers.push(thread::spawn(move || handle(stream, state)));
                    }
                    Err(_) if worker_shutdown.load(Ordering::Acquire) > 0 => break,
                    Err(_) => continue,
                }
            }
            for handler in handlers {
                let _ = handler.join();
            }
        });
        Self {
            base: format!("http://{address}"),
            address,
            state,
            shutdown,
            join: Some(join),
        }
    }

    pub fn base_url(&self) -> String {
        self.base.clone()
    }

    pub fn url(&self, path: &str) -> String {
        format!("{}/{path}", self.base)
    }

    pub fn add_file(&self, path: &str, bytes: Vec<u8>) {
        let etag = format!("\"len-{}\"", bytes.len());
        let mut state = self.state.lock().unwrap();
        state.files.insert(path.to_string(), bytes);
        state.etags.insert(path.to_string(), etag);
    }

    pub fn set_etag(&self, path: &str, etag: &str) {
        self.state
            .lock()
            .unwrap()
            .etags
            .insert(path.to_string(), etag.to_string());
    }

    pub fn fail_next_requests(&self, path: &str, count: u32) {
        self.state
            .lock()
            .unwrap()
            .remaining_failures
            .insert(path.to_string(), count);
    }

    pub fn range_requests_for(&self, path: &str) -> u64 {
        *self
            .state
            .lock()
            .unwrap()
            .range_requests
            .get(path)
            .unwrap_or(&0)
    }

    pub fn full_requests_for(&self, path: &str) -> u64 {
        *self
            .state
            .lock()
            .unwrap()
            .full_requests
            .get(path)
            .unwrap_or(&0)
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        self.shutdown.fetch_add(1, Ordering::SeqCst);
        // Wake the blocking accept loop, then wait for handler threads so no
        // test leaves sockets behind.
        let _ = TcpStream::connect(self.address);
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

const HEADER_TERMINATOR: &[u8] = b"\r\n\r\n";

fn handle(mut stream: TcpStream, state: Arc<Mutex<ServerState>>) {
    let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(5)));
    // Headers may span TCP segments; accumulate until the terminator.
    let mut request = Vec::new();
    let mut buffer = [0_u8; 4096];
    while !request.ends_with(HEADER_TERMINATOR) {
        let Ok(count) = stream.read(&mut buffer) else {
            return;
        };
        if count == 0 {
            return;
        }
        request.extend_from_slice(&buffer[..count]);
        if request.len() > 64 * 1024 {
            return;
        }
    }
    let request = String::from_utf8_lossy(&request).into_owned();
    let Some(path) = request
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .map(|value| value.trim_start_matches('/').to_string())
    else {
        return;
    };
    let range = request.lines().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        name.trim()
            .eq_ignore_ascii_case("range")
            .then(|| value.trim().to_string())
    });

    let mut state = state.lock().unwrap();
    let Some(bytes) = state.files.get(&path).cloned() else {
        write_response(&mut stream, 404, b"not found", None);
        return;
    };
    if let Some(remaining) = state.remaining_failures.get_mut(&path) {
        if *remaining > 0 {
            *remaining -= 1;
            write_response(&mut stream, 503, b"transient", None);
            return;
        }
    }
    let etag = state.etags.get(&path).cloned();

    if let Some((start, end)) = range.and_then(|value| parse_range(&value)) {
        *state.range_requests.entry(path.clone()).or_insert(0) += 1;
        let end = end.min(bytes.len().saturating_sub(1));
        if start > end || end >= bytes.len() {
            write_response(&mut stream, 416, b"range not satisfiable", None);
            return;
        }
        let slice = &bytes[start..=end];
        let mut response = format!(
            "HTTP/1.1 206 Partial Content\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nContent-Range: bytes {start}-{end}/{}\r\nConnection: close\r\n",
            slice.len(),
            bytes.len()
        );
        if let Some(etag) = &etag {
            response.push_str(&format!("ETag: {etag}\r\n"));
        }
        response.push_str("\r\n");
        let _ = stream.write_all(response.as_bytes());
        let _ = stream.write_all(slice);
    } else {
        *state.full_requests.entry(path.clone()).or_insert(0) += 1;
        write_response(&mut stream, 200, &bytes, etag.as_deref());
    }
}

fn write_response(stream: &mut TcpStream, status: u16, body: &[u8], etag: Option<&str>) {
    let reason = match status {
        200 => "OK",
        206 => "Partial Content",
        404 => "Not Found",
        416 => "Range Not Satisfiable",
        503 => "Service Unavailable",
        _ => "Status",
    };
    let mut response = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: close\r\n",
        body.len()
    );
    if let Some(etag) = etag {
        response.push_str(&format!("ETag: {etag}\r\n"));
    }
    response.push_str("\r\n");
    let _ = stream.write_all(response.as_bytes());
    let _ = stream.write_all(body);
}

/// `bytes=start-end` -> `(start, end)`.
fn parse_range(value: &str) -> Option<(usize, usize)> {
    let range = value.strip_prefix("bytes=")?;
    let (start, end) = range.split_once('-')?;
    Some((start.parse().ok()?, end.parse().ok()?))
}
