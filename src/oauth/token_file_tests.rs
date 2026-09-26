// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! F18 R2: an OAuth token file other users can read is not loaded; the refusal
//! is an ERROR once per path, and a save repairs the file to 0600.

use std::io::Write;
use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;
use std::sync::{Arc, Mutex};

use crate::oauth::{TokenInfo, TokenStorage};

const URL: &str = "https://api.example/mcp";

struct Captured(Arc<Mutex<Vec<u8>>>);

impl Write for Captured {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Runs `op` under a thread-local subscriber at DEBUG and returns its log.
fn logs<T>(op: impl FnOnce() -> T) -> (T, String) {
    let buffer = Arc::new(Mutex::new(Vec::new()));
    let writer = Arc::clone(&buffer);
    let subscriber = tracing_subscriber::fmt()
        .without_time()
        .with_ansi(false)
        .with_max_level(tracing::Level::DEBUG)
        .with_writer(move || Captured(Arc::clone(&writer)))
        .finish();
    let out = tracing::subscriber::with_default(subscriber, op);
    let text = String::from_utf8(buffer.lock().unwrap().clone()).unwrap();
    (out, text)
}

fn token(access: &str) -> TokenInfo {
    TokenInfo::from_response(access.to_string(), None, None, Some(3600), None)
}

fn chmod(path: &Path, mode: u32) {
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}

/// Each test its own backend name, so the process-wide refused set is not shared.
fn storage(backend: &str) -> (tempfile::TempDir, TokenStorage, std::path::PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let store = TokenStorage::new(dir.path().join("oauth")).unwrap();
    store.save(backend, URL, &token("f18-first")).unwrap();
    let path = store.token_path(backend, URL);
    (dir, store, path)
}

fn error_lines(log: &str) -> usize {
    log.lines()
        .filter(|l| l.contains("ERROR") && l.contains("OAuth token file"))
        .count()
}

#[test]
fn oauth_token_world_readable_not_loaded() {
    let (_dir, store, path) = storage("f18-world");
    chmod(&path, 0o644);
    let (loaded, log) = logs(|| store.load("f18-world", URL));
    assert!(loaded.is_none(), "a 0644 token file is not loaded");
    assert!(
        log.lines().any(|l| l.contains("ERROR")
            && l.contains("OAuth token file")
            && l.contains(path.to_str().unwrap())
            && l.contains("mode 0644")),
        "the refusal must be an ERROR naming the file and mode: {log}"
    );
    assert!(
        !log.contains("f18-first"),
        "the token reached the log: {log}"
    );
}

#[test]
fn oauth_token_saved_0600_loads() {
    let (_dir, store, path) = storage("f18-saved");
    assert_eq!(
        std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(
        store.load("f18-saved", URL).unwrap().access_token,
        "f18-first"
    );
}

#[test]
fn oauth_resave_repairs_refused_file() {
    let (_dir, store, path) = storage("f18-repair");
    chmod(&path, 0o644);
    assert!(store.load("f18-repair", URL).is_none());
    store.save("f18-repair", URL, &token("f18-second")).unwrap();
    assert_eq!(
        store.load("f18-repair", URL).unwrap().access_token,
        "f18-second"
    );
    assert_eq!(
        std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
}

#[test]
fn oauth_refusal_logged_error_once_per_path() {
    let (_dir, store, path) = storage("f18-once");
    chmod(&path, 0o644);
    let (_, first) = logs(|| store.load("f18-once", URL));
    let (_, second) = logs(|| store.load("f18-once", URL));
    assert_eq!(error_lines(&first), 1, "{first}");
    assert_eq!(error_lines(&second), 0, "{second}");
    assert!(
        second.contains("DEBUG") && second.contains("OAuth token file"),
        "{second}"
    );

    store.save("f18-once", URL, &token("f18-third")).unwrap();
    chmod(&path, 0o644);
    let (_, again) = logs(|| store.load("f18-once", URL));
    assert_eq!(
        error_lines(&again),
        1,
        "a save resets the once-per-path: {again}"
    );

    // A chmod repair followed by a clean load resets it too.
    chmod(&path, 0o600);
    assert!(store.load("f18-once", URL).is_some());
    chmod(&path, 0o644);
    let (_, relapse) = logs(|| store.load("f18-once", URL));
    assert_eq!(
        error_lines(&relapse),
        1,
        "a clean load resets the once-per-path: {relapse}"
    );
}

#[test]
fn oauth_token_group_readable_owned_not_loaded() {
    let (_dir, store, path) = storage("f18-group");
    chmod(&path, 0o640);
    assert!(
        store.load("f18-group", URL).is_none(),
        "an owned 0640 token is refused"
    );
}
