// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8857.API4.4: the cleartext-override audit record, its order, and the
//! shutdown drain.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use super::OverrideAuditor;
use crate::config::{BackendConfig, TransportConfig};
use crate::security::{TransparencyLogConfig, TransparencyLogger};

fn logger(dir: &tempfile::TempDir) -> (Arc<TransparencyLogger>, PathBuf) {
    let path = dir.path().join("transparency.jsonl");
    let config = Arc::new(TransparencyLogConfig {
        enabled: true,
        path: path.to_string_lossy().into_owned(),
        ..TransparencyLogConfig::default()
    });
    (
        Arc::new(TransparencyLogger::open(config).expect("open log")),
        path,
    )
}

/// `(action, backend)` of every override record in the log, in file order.
fn records(path: &Path) -> Vec<(String, String)> {
    std::fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
        .filter(|v| v.get("surface").and_then(|s| s.as_str()) == Some("config"))
        .map(|v| {
            let field = |k: &str| v.get(k).and_then(|s| s.as_str()).unwrap_or("").to_owned();
            (field("action"), field("backend"))
        })
        .collect()
}

/// A credential-bearing `http://` backend off this machine.
fn exposed(allow: bool) -> BackendConfig {
    let mut backend = BackendConfig {
        transport: TransportConfig::Http {
            http_url: "http://internal-host/mcp".to_owned(),
            streamable_http: Some(false),
            protocol_version: None,
        },
        allow_cleartext_credentials: allow,
        ..Default::default()
    };
    backend
        .headers
        .insert("Authorization".to_owned(), "Bearer x".to_owned());
    backend
}

fn https(allow: bool) -> BackendConfig {
    BackendConfig {
        transport: TransportConfig::Http {
            http_url: "https://internal-host/mcp".to_owned(),
            streamable_http: Some(false),
            protocol_version: None,
        },
        allow_cleartext_credentials: allow,
        ..exposed(allow)
    }
}

fn named(names: &[&str], config: impl Fn() -> BackendConfig) -> Vec<(String, BackendConfig)> {
    names.iter().map(|n| ((*n).to_owned(), config())).collect()
}

fn current_thread() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime")
}

#[test]
fn api4_4_only_an_override_that_lets_a_backend_load_is_recorded() {
    current_thread().block_on(async {
        let dir = tempfile::tempdir().unwrap();
        let (log, path) = logger(&dir);
        let (auditor, drain) = OverrideAuditor::start(Some(log));
        let mut backends = named(&["inventory"], || exposed(true));
        backends.extend(named(&["secure"], || https(true)));
        backends.extend(named(&["plain"], || exposed(false)));
        auditor.sync_config(&backends);
        // Unchanged: nothing new.
        auditor.sync_config(&backends);
        drain
            .drain(
                &crate::backend::BackendRegistry::new(),
                Duration::from_secs(5),
            )
            .await;
        assert_eq!(
            records(&path),
            vec![(
                "cleartext_override_in_effect".to_owned(),
                "inventory".to_owned()
            )]
        );
    });
}

/// The MEDIUM finding (r3): transitions land in the order they were computed.
#[test]
fn api4_4_transitions_land_in_the_order_they_were_queued() {
    current_thread().block_on(async {
        let dir = tempfile::tempdir().unwrap();
        let (log, path) = logger(&dir);
        let (auditor, drain) = OverrideAuditor::start(Some(log));
        let names: Vec<String> = (0..20).map(|i| format!("b{i:02}")).collect();
        let refs: Vec<&str> = names.iter().map(String::as_str).collect();
        auditor.sync_config(&named(&refs, || exposed(true)));
        auditor.sync_config(&[]);
        drain
            .drain(
                &crate::backend::BackendRegistry::new(),
                Duration::from_secs(10),
            )
            .await;

        let mut expected: Vec<(String, String)> = names
            .iter()
            .map(|n| ("cleartext_override_in_effect".to_owned(), n.clone()))
            .collect();
        expected.extend(
            names
                .iter()
                .map(|n| ("cleartext_override_withdrawn".to_owned(), n.clone())),
        );
        assert_eq!(records(&path), expected);
    });
}

/// The HIGH finding (r3): a transition queued just before shutdown is on disk
/// once the drain returns.
#[test]
fn api4_4_a_transition_queued_before_shutdown_is_written_by_the_drain() {
    current_thread().block_on(async {
        let dir = tempfile::tempdir().unwrap();
        let (log, path) = logger(&dir);
        let (auditor, drain) = OverrideAuditor::start(Some(log));
        auditor.sync_config(&named(&["inventory"], || exposed(true)));
        // No yield between the queueing and the shutdown drain.
        drain
            .drain(
                &crate::backend::BackendRegistry::new(),
                Duration::from_secs(5),
            )
            .await;
        assert_eq!(records(&path).len(), 1, "{:?}", records(&path));
    });
}

/// The HIGH finding (r3), deadline half: what the drain could not write is
/// named in the log, one line per record.
#[test]
fn api4_4_a_drain_that_runs_out_names_every_unwritten_record() {
    let dir = tempfile::tempdir().unwrap();
    let (log, _path) = logger(&dir);
    let lines = crate::test_log_capture::records(|| {
        current_thread().block_on(async {
            // The first write hangs until `release` drops: a stalled disk.
            let release = log.stall_next_write_for_test(Duration::from_secs(10));
            let (auditor, drain) = OverrideAuditor::start(Some(Arc::clone(&log)));
            auditor.sync_config(&named(&["alpha", "beta"], || exposed(true)));
            tokio::task::yield_now().await;
            drain
                .drain(
                    &crate::backend::BackendRegistry::new(),
                    Duration::from_millis(100),
                )
                .await;
            drop(release);
        });
    });
    for backend in ["alpha", "beta"] {
        assert!(
            lines.iter().any(|l| {
                l["level"] == "ERROR"
                    && l["fields"]["backend"] == backend
                    && l["fields"]["action"] == "cleartext_override_in_effect"
            }),
            "{backend} not named: {lines:?}"
        );
    }
}

#[test]
fn api4_4_without_a_log_each_transition_is_a_named_warning() {
    let lines = crate::test_log_capture::records(|| {
        current_thread().block_on(async {
            let (auditor, drain) = OverrideAuditor::start(None);
            auditor.sync_config(&named(&["inventory"], || exposed(true)));
            drain
                .drain(
                    &crate::backend::BackendRegistry::new(),
                    Duration::from_secs(5),
                )
                .await;
        });
    });
    assert!(
        lines.iter().any(|l| l["level"] == "WARN"
            && l["fields"]["backend"] == "inventory"
            && l["fields"]["action"] == "cleartext_override_in_effect"),
        "{lines:?}"
    );
}

#[test]
fn api4_4_removing_an_in_effect_backend_withdraws_it() {
    current_thread().block_on(async {
        let dir = tempfile::tempdir().unwrap();
        let (log, path) = logger(&dir);
        let (auditor, drain) = OverrideAuditor::start(Some(log));
        auditor.sync_config(&named(&["inventory"], || exposed(true)));
        auditor.sync_config(&[]);
        drain
            .drain(
                &crate::backend::BackendRegistry::new(),
                Duration::from_secs(5),
            )
            .await;
        let got = records(&path);
        assert_eq!(got.len(), 2);
        assert_eq!(got[1].0, "cleartext_override_withdrawn");
        assert_eq!(got[1].1, "inventory");
    });
}

/// The HIGH finding (r2): the registry is the source, and the guard runs when
/// the reload's scope ends however it ends: here, a future dropped mid-await,
/// as a cancelled reload is.
#[test]
fn api4_4_a_reload_dropped_after_registering_still_records_the_override() {
    current_thread().block_on(async {
        let dir = tempfile::tempdir().unwrap();
        let (log, path) = logger(&dir);
        let (auditor, drain) = OverrideAuditor::start(Some(log));
        let registry = crate::backend::BackendRegistry::new();
        let reload = async {
            let _guard = auditor.guard(&registry);
            assert!(registry.register(Arc::new(crate::backend::Backend::new(
                "inventory",
                exposed(true),
                &crate::config::FailsafeConfig::default(),
                Duration::from_secs(60),
            ))));
            // A stop of another backend the reload awaits forever.
            std::future::pending::<()>().await;
        };
        // Cancelled: the future is dropped while parked at its await.
        assert!(
            tokio::time::timeout(Duration::from_millis(10), reload)
                .await
                .is_err()
        );
        drain
            .drain(
                &crate::backend::BackendRegistry::new(),
                Duration::from_secs(5),
            )
            .await;
        assert_eq!(
            records(&path),
            vec![(
                "cleartext_override_in_effect".to_owned(),
                "inventory".to_owned()
            )]
        );
    });
}

fn registry_with_exposed(name: &str) -> crate::backend::BackendRegistry {
    let registry = crate::backend::BackendRegistry::new();
    assert!(registry.register(Arc::new(crate::backend::Backend::new(
        name,
        exposed(true),
        &crate::config::FailsafeConfig::default(),
        Duration::from_secs(60),
    ))));
    registry
}

/// Code review (HIGH): the drain waits out a reload still in flight, so the
/// transitions that reload queues as it ends are written, not named unwritten.
#[test]
fn api4_4_the_drain_waits_for_a_reload_in_flight() {
    current_thread().block_on(async {
        let dir = tempfile::tempdir().unwrap();
        let (log, path) = logger(&dir);
        let (auditor, drain) = OverrideAuditor::start(Some(log));
        let registry = crate::backend::BackendRegistry::new();
        // Ordered, not timed: the reload holds its lock until the drain has
        // started and is parked on it (current-thread runtime, so one yield
        // after the signal lets the drain reach the lock first).
        let (draining, started) = tokio::sync::oneshot::channel::<()>();
        let reload = async {
            let _in_flight = registry.lock_reload().await;
            started
                .await
                .expect("the shutdown signals before it drains");
            tokio::task::yield_now().await;
            assert!(registry.register(Arc::new(crate::backend::Backend::new(
                "inventory",
                exposed(true),
                &crate::config::FailsafeConfig::default(),
                Duration::from_secs(60),
            ))));
            auditor.sync(&registry);
        };
        let shutdown = async {
            draining.send(()).expect("the reload is waiting");
            drain.drain(&registry, Duration::from_secs(10)).await;
        };
        tokio::join!(reload, shutdown);
        assert_eq!(records(&path).len(), 1, "{:?}", records(&path));
    });
}

/// Code review (HIGH): at start the record is written before serving, and a
/// fail-closed log that cannot take it refuses the start.
#[test]
fn api4_4_a_fail_closed_log_that_cannot_record_at_start_refuses_it() {
    current_thread().block_on(async {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("transparency.jsonl");
        let log = Arc::new(
            TransparencyLogger::open(Arc::new(TransparencyLogConfig {
                enabled: true,
                path: path.to_string_lossy().into_owned(),
                ..TransparencyLogConfig::default()
            }))
            .expect("open log")
            .with_failure_policy(crate::security::audit::AuditFailurePolicy::FailClosed),
        );
        let (auditor, _drain) = OverrideAuditor::start(None);
        log.fail_next_append_of_kind_for_test("admin_action");
        let refused = auditor
            .record_at_start(&registry_with_exposed("inventory"), Some(&log))
            .await;
        assert!(
            matches!(refused, Err(crate::Error::AuditUnavailable)),
            "{refused:?}"
        );
    });
}

#[test]
fn api4_4_the_start_record_is_on_disk_before_serving() {
    current_thread().block_on(async {
        let dir = tempfile::tempdir().unwrap();
        let (log, path) = logger(&dir);
        let (auditor, _drain) = OverrideAuditor::start(None);
        auditor
            .record_at_start(&registry_with_exposed("inventory"), Some(&log))
            .await
            .expect("recorded");
        // No drain: the start record is on disk when the call returns.
        assert_eq!(records(&path).len(), 1, "{:?}", records(&path));
    });
}

/// Lead ruling (round 2): a stuck audit file cannot hang the start. Under
/// `FailClosed` the timed write refuses it; under `BestEffort` the start goes
/// on.
#[test]
fn api4_4_a_stalled_audit_file_does_not_hang_the_start() {
    current_thread().block_on(async {
        for (policy, refuses) in [
            (crate::security::audit::AuditFailurePolicy::FailClosed, true),
            (
                crate::security::audit::AuditFailurePolicy::BestEffort,
                false,
            ),
        ] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("transparency.jsonl");
            let log = Arc::new(
                TransparencyLogger::open(Arc::new(TransparencyLogConfig {
                    enabled: true,
                    path: path.to_string_lossy().into_owned(),
                    ..TransparencyLogConfig::default()
                }))
                .expect("open log")
                .with_failure_policy(policy),
            );
            let release = log.stall_next_write_for_test(Duration::from_millis(100));
            let (auditor, _drain) = OverrideAuditor::start(None);
            let started = tokio::time::timeout(
                Duration::from_secs(10),
                auditor.record_at_start(&registry_with_exposed("inventory"), Some(&log)),
            )
            .await
            .expect("the start must not hang on a stuck audit file");
            assert_eq!(started.is_err(), refuses, "{policy:?}: {started:?}");
            drop(release);
            // The released write still runs on the blocking pool: wait for it,
            // so it never lands while `dir` is being removed (a late `.hwm`
            // would keep the folder).
            let late = Arc::clone(&log);
            assert!(
                tokio::task::spawn_blocking(move || {
                    late.wait_write_cleared_for_test(crate::test_wait::HANG_BOUND)
                })
                .await
                .expect("the wait does not panic"),
                "the released audit write finishes"
            );
        }
    });
}
