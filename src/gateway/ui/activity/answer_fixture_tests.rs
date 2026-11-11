// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Test fixture for the delivery-join rows: a log written by the real logger,
//! so hashes, chains and HMACs are the logger's own.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde_json::{Map, Value, json};

use super::{Logs, access::Access};
use crate::security::audit::{AuditEnvelope, AuditWho, InvocationTarget};
use crate::security::audit_rotation_config::{OnDiskFull, RotationConfig};
use crate::security::transparency_log::{CorrelationKey, CorrelationSource};
use crate::security::{TransparencyLogConfig, TransparencyLogger};

pub(super) const SECRET: &str = "a-test-secret-that-is-at-least-32-bytes!!";

/// What a delivery record says (the writer's fields in `delivery_facts.rs`).
#[derive(Clone)]
pub(super) struct Dl {
    pub(super) stage: &'static str,
    pub(super) effect: Option<&'static str>,
    /// `None` omits the field; `Some(Value::Null)` is vouched, not scanned.
    pub(super) findings: Option<Value>,
    pub(super) total: Option<u64>,
}

impl Dl {
    pub(super) fn effect(effect: &'static str) -> Self {
        Self {
            stage: "transport_finalized",
            effect: Some(effect),
            findings: Some(json!([])),
            total: None,
        }
    }

    /// An unvouched answer: neither field is written.
    pub(super) fn omitted() -> Self {
        Self {
            stage: "transport_finalized",
            effect: None,
            findings: None,
            total: None,
        }
    }

    pub(super) fn findings(mut self, findings: Value) -> Self {
        self.findings = Some(findings);
        self
    }

    pub(super) fn stage(mut self, stage: &'static str) -> Self {
        self.stage = stage;
        self
    }
}

pub(super) struct Fixture {
    pub(super) _dir: Arc<tempfile::TempDir>,
    pub(super) path: PathBuf,
    pub(super) logger: TransparencyLogger,
    pub(super) secret: Option<&'static str>,
}

impl Fixture {
    pub(super) fn new(secret: Option<&'static str>) -> Self {
        Self::rotating(secret, RotationConfig::default().max_segment_bytes)
    }

    /// A log that seals its segment at `max_segment_bytes` (0 would seal before
    /// every record).
    pub(super) fn rotating(secret: Option<&'static str>, max_segment_bytes: u64) -> Self {
        let dir = crate::test_dir_keep::kept_tempdir();
        let path = dir.path().join("inv.jsonl");
        let logger = TransparencyLogger::open(Arc::new(TransparencyLogConfig {
            enabled: true,
            path: path.to_string_lossy().into_owned(),
            key_id: "test".into(),
            shared_secret: secret.unwrap_or_default().into(),
            rotation: RotationConfig {
                max_segment_bytes,
                max_segment_age_secs: 0,
                retain_segments: 1000,
                on_disk_full: OnDiskFull::ExpireOldest,
            },
        }))
        .unwrap();
        logger.keep_test_dir(Arc::clone(&dir));
        Self {
            _dir: dir,
            path,
            logger,
            secret,
        }
    }

    pub(super) fn logs(&self) -> Logs {
        Logs {
            invocation: self.path.clone(),
            governance: None,
            secret: self.secret.map(|s| s.as_bytes().to_vec()),
        }
    }

    /// The same log reopened by a gateway that now holds `secret`: what is
    /// already in it stays as written (unsigned), what is appended is signed.
    pub(super) fn reopened_with(&self, secret: &'static str) -> Self {
        let logger = TransparencyLogger::open(Arc::new(TransparencyLogConfig {
            enabled: true,
            path: self.path.to_string_lossy().into_owned(),
            key_id: "test".into(),
            shared_secret: secret.into(),
            rotation: RotationConfig::default(),
        }))
        .unwrap();
        logger.keep_test_dir(Arc::clone(&self._dir));
        Self {
            _dir: Arc::clone(&self._dir),
            path: self.path.clone(),
            logger,
            secret: Some(secret),
        }
    }

    #[expect(
        clippy::unused_self,
        reason = "a fixture reads as `fx.access()`; every row here reads as an admin"
    )]
    pub(super) fn access(&self) -> Access {
        Access::All
    }

    /// A call on `srv` carrying `trace`.
    pub(super) fn call(&self, trace: &str) {
        self.call_on("srv", trace);
    }

    pub(super) fn call_on(&self, server: &str, trace: &str) {
        let envelope = AuditEnvelope {
            trace_id: Some(trace.to_string()),
            ..AuditEnvelope::ok(AuditWho::from_actor_id("c"))
        };
        self.logger
            .log_invocation_correlated(
                CorrelationKey {
                    id: "s",
                    source: CorrelationSource::SessionId,
                },
                &envelope,
                InvocationTarget::meta(server, "tool"),
                "sha256:aa",
                Some("sha256:bb"),
            )
            .unwrap();
    }

    /// A delivery record for `trace`, as the writer shapes it.
    pub(super) fn delivery(&self, trace: &str, d: &Dl) {
        let mut f = Map::new();
        f.insert("event".into(), "response_delivery_attempt".into());
        f.insert("response_stage".into(), d.stage.into());
        f.insert("response_hash".into(), "sha256:bb".into());
        f.insert("server".into(), "srv".into());
        f.insert("tool".into(), "tool".into());
        if let Some(e) = d.effect {
            f.insert("response_effect".into(), e.into());
        }
        if let Some(v) = &d.findings {
            f.insert("response_findings".into(), v.clone());
        }
        if let Some(t) = d.total {
            f.insert("response_findings_total".into(), t.into());
        }
        let envelope = AuditEnvelope {
            trace_id: Some(trace.to_string()),
            ..AuditEnvelope::ok(AuditWho::from_actor_id("c"))
        };
        self.logger.append_event(f, &envelope).unwrap();
    }

    /// The log's lines, parsed.
    pub(super) fn lines(&self) -> Vec<Value> {
        read_lines(&self.path)
    }

    /// Every kept line: the sealed segments oldest first, then the active file.
    pub(super) fn every_line(&self) -> Vec<Value> {
        use crate::security::transparency_log::segments::{list_segments, sealed_path};
        let mut all: Vec<Value> = list_segments(&self.path)
            .unwrap()
            .iter()
            .flat_map(|s| read_lines(&sealed_path(&self.path, s.seq)))
            .collect();
        all.extend(self.lines());
        all
    }

    /// Rewrite line `index` (0-based) through `edit`, leaving the rest.
    pub(super) fn edit(&self, index: usize, edit: impl FnOnce(&mut Value)) {
        let mut lines = self.lines();
        edit(&mut lines[index]);
        write_lines(&self.path, &lines);
    }

    /// The index of the first line whose `trace_id` is `trace` and that is a
    /// delivery record.
    pub(super) fn delivery_index(&self, trace: &str) -> usize {
        self.lines()
            .iter()
            .position(|l| l["trace_id"] == trace && l["event"] == "response_delivery_attempt")
            .unwrap()
    }
}

pub(super) fn read_lines(path: &Path) -> Vec<Value> {
    std::fs::read_to_string(path)
        .unwrap()
        .lines()
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect()
}

pub(super) fn write_lines(path: &Path, lines: &[Value]) {
    let body: String = lines.iter().map(|l| l.to_string() + "\n").collect();
    std::fs::write(path, body).unwrap();
}

/// Set a field and recompute `entry_hash`, as a forger without the key would;
/// `sig` is kept unless `strip_sig`.
pub(super) fn forge(entry: &mut Value, key: &str, value: Value, strip_sig: bool) {
    entry[key] = value;
    let hash = crate::security::transparency_log::recompute_entry_hash(entry).unwrap();
    entry["entry_hash"] = hash.into();
    if strip_sig {
        let o = entry.as_object_mut().unwrap();
        o.remove("sig");
        o.remove("key_id");
    }
}

/// 32 findings, about 3 KiB: a delivery record that fills a small segment.
pub(super) fn fat_findings() -> Value {
    let many: Vec<Value> = (0..32)
        .map(|i| json!({"kind": format!("kind-{i:02}-padding-padding"), "severity": "low", "where": "text"}))
        .collect();
    json!(many)
}

/// The sealed segment files holding `trace`'s delivery record.
pub(super) fn segments_with_delivery(path: &Path, trace: &str) -> Vec<PathBuf> {
    use crate::security::transparency_log::segments::{list_segments, sealed_path};
    let wanted = format!("\"trace_id\":\"{trace}\"");
    list_segments(path)
        .unwrap()
        .iter()
        .map(|s| sealed_path(path, s.seq))
        .filter(|p| {
            std::fs::read_to_string(p).is_ok_and(|t| {
                t.lines()
                    .any(|l| l.contains(&wanted) && l.contains("response_delivery_attempt"))
            })
        })
        .collect()
}
