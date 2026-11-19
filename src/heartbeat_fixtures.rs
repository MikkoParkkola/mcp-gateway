// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Shared fixtures for the heartbeat rows: a recording listener, fixed dates,
//! snapshots, clients and the written-out variable lists. Untagged by part,
//! so the part 3 rows here and the part 4 server-start rows both compile it.
#![allow(dead_code, reason = "each part uses a different subset")]

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use chrono::NaiveDate;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

use super::{Build, Snapshot, base_builder};
use crate::security::posture::SecurityPosture;

/// One request as the listener saw it.
#[derive(Clone, Debug)]
pub(crate) struct Seen {
    pub(crate) method: String,
    pub(crate) path: String,
    pub(crate) query: Option<String>,
    /// Header name (lowercase) to value.
    pub(crate) headers: BTreeMap<String, String>,
    pub(crate) body: String,
}

/// How the listener answers.
#[derive(Clone)]
pub(crate) enum Answer {
    NoContent,
    Error500,
    RedirectTo(String),
    Never,
}

/// A loopback HTTP listener that records every connection and request.
pub(crate) struct Listener {
    base: String,
    connections: Arc<AtomicUsize>,
    seen: Arc<Mutex<Vec<Seen>>>,
}

impl Listener {
    pub(crate) async fn start(answer: Answer) -> Self {
        let socket = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let base = format!("http://{}", socket.local_addr().expect("addr"));
        let connections = Arc::new(AtomicUsize::new(0));
        let seen = Arc::new(Mutex::new(Vec::new()));
        let (count, log) = (Arc::clone(&connections), Arc::clone(&seen));
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = socket.accept().await {
                count.fetch_add(1, Ordering::SeqCst);
                let (log, answer) = (Arc::clone(&log), answer.clone());
                tokio::spawn(async move {
                    let Some(request) = read_request(&mut stream).await else {
                        return;
                    };
                    log.lock().expect("log").push(request);
                    let reply = match answer {
                        Answer::NoContent => "HTTP/1.1 204 No Content\r\n\r\n".to_owned(),
                        Answer::Error500 => {
                            "HTTP/1.1 500 Internal Server Error\r\ncontent-length: 0\r\n\r\n"
                                .to_owned()
                        }
                        Answer::RedirectTo(to) => format!(
                            "HTTP/1.1 302 Found\r\nlocation: {to}\r\ncontent-length: 0\r\n\r\n"
                        ),
                        Answer::Never => {
                            tokio::time::sleep(std::time::Duration::from_secs(60)).await;
                            return;
                        }
                    };
                    let _ = stream.write_all(reply.as_bytes()).await;
                });
            }
        });
        Self {
            base,
            connections,
            seen,
        }
    }

    pub(crate) fn url(&self) -> String {
        format!("{}/v1/heartbeat", self.base)
    }

    pub(crate) fn connections(&self) -> usize {
        self.connections.load(Ordering::SeqCst)
    }

    pub(crate) fn requests(&self) -> Vec<Seen> {
        self.seen.lock().expect("log").clone()
    }
}

/// Read one HTTP/1.1 request: head, then a content-length body.
async fn read_request(stream: &mut tokio::net::TcpStream) -> Option<Seen> {
    let mut buf = Vec::new();
    let mut chunk = [0_u8; 4096];
    let head_end = loop {
        let n = stream.read(&mut chunk).await.ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&chunk[..n]);
        if let Some(at) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break at + 4;
        }
    };
    let head = String::from_utf8_lossy(&buf[..head_end]).into_owned();
    let mut lines = head.split("\r\n");
    let mut first = lines.next()?.split(' ');
    let method = first.next()?.to_owned();
    let target = first.next()?.to_owned();
    let (path, query) = match target.split_once('?') {
        Some((p, q)) => (p.to_owned(), Some(q.to_owned())),
        None => (target, None),
    };
    let mut headers = BTreeMap::new();
    let mut length = 0_usize;
    for line in lines.filter(|l| !l.is_empty()) {
        let (name, value) = line.split_once(':')?;
        let name = name.trim().to_ascii_lowercase();
        if name == "content-length" {
            length = value.trim().parse().ok()?;
        }
        headers.insert(name, value.trim().to_owned());
    }
    while buf.len() < head_end + length {
        let n = stream.read(&mut chunk).await.ok()?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
    }
    let body = String::from_utf8_lossy(&buf[head_end..]).into_owned();
    Some(Seen {
        method,
        path,
        query,
        headers,
        body,
    })
}

fn day(d: u32) -> Option<NaiveDate> {
    NaiveDate::from_ymd_opt(2026, 11, d)
}
pub(crate) fn nov19() -> Option<NaiveDate> {
    day(19)
}
pub(crate) fn nov20() -> Option<NaiveDate> {
    day(20)
}
pub(crate) fn nov18() -> Option<NaiveDate> {
    day(18)
}

/// A release snapshot with nothing set: the one that sends.
pub(crate) fn release() -> Snapshot {
    Snapshot {
        build: Build::Release,
        posture: SecurityPosture::Standard,
        env: BTreeMap::new(),
    }
}

/// `release()` with one variable set.
pub(crate) fn with(name: &str, value: &str) -> Snapshot {
    let mut s = release();
    s.env.insert(name.to_owned(), value.to_owned());
    s
}

pub(crate) fn test_client() -> reqwest::Client {
    base_builder().build().expect("a test client")
}

/// The runtime string for this host, written out (not built from the code's
/// expression).
pub(crate) fn expected_runtime() -> &'static str {
    match (std::env::consts::OS, std::env::consts::ARCH) {
        ("linux", "x86_64") => "linux/x86_64",
        ("linux", "aarch64") => "linux/aarch64",
        ("macos", "aarch64") => "macos/aarch64",
        ("macos", "x86_64") => "macos/x86_64",
        ("windows", "x86_64") => "windows/x86_64",
        ("windows", "aarch64") => "windows/aarch64",
        other => panic!("no expected runtime written for {other:?}"),
    }
}

pub(crate) fn is_install_id(s: &str) -> bool {
    s.len() == 32
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Create `path` owner-only (0700 on Unix), so the wide-dir rule is never
/// what decides a row about something else.
pub(crate) fn owner_only_dir(path: &Path) {
    std::fs::create_dir(path).expect("dir");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).expect("mode");
    }
}

pub(crate) fn read_id(dir: &Path) -> String {
    std::fs::read_to_string(dir.join("heartbeat").join("install-id")).expect("an install id")
}

/// The CI names, written out here rather than taken from `CI` (A7).
pub(crate) const CI_NAMES: [&str; 18] = [
    "CI",
    "CONTINUOUS_INTEGRATION",
    "GITHUB_ACTIONS",
    "GITLAB_CI",
    "CIRCLECI",
    "TRAVIS",
    "BUILDKITE",
    "DRONE",
    "JENKINS_URL",
    "TEAMCITY_VERSION",
    "BITBUCKET_BUILD_NUMBER",
    "APPVEYOR",
    "CODEBUILD_BUILD_ID",
    "TF_BUILD",
    "CIRRUS_CI",
    "SEMAPHORE",
    "BITRISE_IO",
    "BUDDY",
];
/// The proxy names, written out.
pub(crate) const PROXY_NAMES: [&str; 6] = [
    "HTTPS_PROXY",
    "https_proxy",
    "HTTP_PROXY",
    "http_proxy",
    "ALL_PROXY",
    "all_proxy",
];
