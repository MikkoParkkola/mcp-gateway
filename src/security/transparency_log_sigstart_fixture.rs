// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Test support for the signing anchor: logs written by the real logger,
//! and the file edits an attacker makes to them. Shared by the writer rows
//! and the reader rows, so every reader is attacked the same way.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde_json::Value;

use super::recompute_entry_hash;
use crate::security::audit_rotation_config::{OnDiskFull, RotationConfig};
use crate::security::transparency_log::{TransparencyLogConfig, TransparencyLogger};

pub(crate) const SECRET: &str = "a-test-secret-that-is-at-least-32-bytes!!";
pub(crate) const KEY_ID: &str = "sigstart";

/// A log under a temp dir, kept alive by the struct.
pub(crate) struct Fixture {
    pub(crate) dir: tempfile::TempDir,
    pub(crate) path: PathBuf,
}

impl Fixture {
    pub(crate) fn new() -> Self {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("audit.jsonl");
        Self { dir, path }
    }

    /// The `.sigstart` sidecar beside the log.
    pub(crate) fn sidecar(&self) -> PathBuf {
        sibling(&self.path, "sigstart")
    }

    /// The `.hwm` sidecar beside the log.
    pub(crate) fn hwm(&self) -> PathBuf {
        sibling(&self.path, "hwm")
    }

    /// Open the real logger, signing when `signed`, rotating at `segment`
    /// bytes (0 = the default, which never rotates in a test).
    pub(crate) fn open(&self, signed: bool, segment: u64) -> TransparencyLogger {
        let mut rotation = RotationConfig::default();
        if segment > 0 {
            rotation = RotationConfig {
                max_segment_bytes: segment,
                max_segment_age_secs: 0,
                retain_segments: 1000,
                on_disk_full: OnDiskFull::ExpireOldest,
            };
        }
        TransparencyLogger::open(Arc::new(TransparencyLogConfig {
            enabled: true,
            path: self.path.to_string_lossy().into_owned(),
            key_id: KEY_ID.into(),
            shared_secret: if signed { SECRET.into() } else { String::new() },
            rotation,
        }))
        .expect("logger opens")
    }

    /// Append `n` invocation records named `tool_<first + i>`.
    pub(crate) fn calls(log: &TransparencyLogger, first: usize, n: usize) {
        for i in first..first + n {
            log.log_invocation("s", "c", "srv", &format!("tool_{i}"), "sha256:aa", "sha256:bb")
                .expect("append");
        }
    }

    /// The active file's records, parsed, with each line's byte offset.
    pub(crate) fn records(&self) -> Vec<(u64, Value)> {
        records_in(&self.path)
    }

    /// Rewrite the record whose `tool` is `tool`: apply `edit`, strip
    /// `sig`/`key_id`, recompute `entry_hash`. The attack every row makes.
    pub(crate) fn strip(&self, tool: &str, edit: impl FnOnce(&mut Value)) {
        rewrite(&self.path, |v| {
            if v.get("tool").and_then(Value::as_str) == Some(tool) {
                edit(v);
                strip_sig(v);
                true
            } else {
                false
            }
        });
    }
}

/// `<path>.<suffix>`, as the log names its sidecars.
pub(crate) fn sibling(path: &Path, suffix: &str) -> PathBuf {
    let mut s = path.as_os_str().to_owned();
    s.push(".");
    s.push(suffix);
    PathBuf::from(s)
}

/// Remove `sig` and `key_id` and recompute `entry_hash` (sig is outside it).
pub(crate) fn strip_sig(v: &mut Value) {
    let obj = v.as_object_mut().expect("a record object");
    obj.remove("sig");
    obj.remove("key_id");
    obj.remove("entry_hash");
    let hash = recompute_entry_hash(v).expect("hash");
    v["entry_hash"] = hash.into();
}

/// Parsed records of `file` with their byte offsets; blank lines skipped.
pub(crate) fn records_in(file: &Path) -> Vec<(u64, Value)> {
    let text = std::fs::read_to_string(file).expect("read log");
    let mut out = Vec::new();
    let mut at = 0u64;
    for line in text.split_inclusive('\n') {
        let body = line.trim_end_matches('\n');
        if !body.is_empty() {
            out.push((at, serde_json::from_str(body).expect("a JSON record")));
        }
        at += line.len() as u64;
    }
    out
}

/// Rewrite every record of `file` for which `edit` returns true; asserts
/// exactly one matched, so a row never edits a record it did not mean to.
pub(crate) fn rewrite(file: &Path, mut edit: impl FnMut(&mut Value) -> bool) {
    let text = std::fs::read_to_string(file).expect("read log");
    let mut hits = 0;
    let mut out = String::new();
    for line in text.lines() {
        if line.is_empty() {
            out.push('\n');
            continue;
        }
        let mut v: Value = serde_json::from_str(line).expect("a JSON record");
        if edit(&mut v) {
            hits += 1;
            out.push_str(&v.to_string());
        } else {
            out.push_str(line);
        }
        out.push('\n');
    }
    assert_eq!(hits, 1, "exactly one record matched the edit in {}", file.display());
    std::fs::write(file, out).expect("write log");
}

/// Records of `file` whose `event` is `event`.
pub(crate) fn events(file: &Path, event: &str) -> usize {
    records_in(file)
        .iter()
        .filter(|(_, v)| v.get("event").and_then(Value::as_str) == Some(event))
        .count()
}
