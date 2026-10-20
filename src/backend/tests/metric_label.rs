// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8014.PERF.5: the `backend` metric label reaches the recorder as the
//! backend's one shared label, not a fresh copy of its name on every call.

use telemetry_metrics::{Counter, Gauge, Histogram, Key, KeyName, Metadata, SharedString, Unit};

use super::*;

/// One registered label: series name, label key, label value, and the
/// address of the value's bytes.
type SeenLabel = (String, String, String, usize);

/// Records every label of every series registered while it is installed.
#[derive(Default)]
struct BackendLabels(parking_lot::Mutex<Vec<SeenLabel>>);

impl BackendLabels {
    fn note(&self, key: &Key) {
        for label in key.labels() {
            self.0.lock().push((
                key.name().to_string(),
                label.key().to_string(),
                label.value().to_string(),
                label.value().as_ptr() as usize,
            ));
        }
    }
}

impl telemetry_metrics::Recorder for BackendLabels {
    fn describe_counter(&self, _: KeyName, _: Option<Unit>, _: SharedString) {}
    fn describe_gauge(&self, _: KeyName, _: Option<Unit>, _: SharedString) {}
    fn describe_histogram(&self, _: KeyName, _: Option<Unit>, _: SharedString) {}

    fn register_counter(&self, key: &Key, _: &Metadata<'_>) -> Counter {
        self.note(key);
        Counter::noop()
    }

    fn register_gauge(&self, key: &Key, _: &Metadata<'_>) -> Gauge {
        self.note(key);
        Gauge::noop()
    }

    fn register_histogram(&self, key: &Key, _: &Metadata<'_>) -> Histogram {
        self.note(key);
        Histogram::noop()
    }
}

#[test]
fn every_backend_label_is_the_shared_one() {
    let backend = Backend::new(
        "perf5",
        BackendConfig::default(),
        &crate::config::FailsafeConfig::default(),
        Duration::from_secs(60),
    );
    let response = JsonRpcResponse::success_serialized(
        RequestId::Number(1),
        ToolsListResult {
            tools: vec![],
            next_cursor: None,
        },
    );
    let transport: Arc<dyn Transport> =
        Arc::new(MockTransport::new(response, Duration::from_millis(0)));
    backend.set_transport_for_test(transport);

    let recorder = BackendLabels::default();
    telemetry_metrics::with_local_recorder(&recorder, || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        runtime.block_on(async {
            for _ in 0..2 {
                backend.request("tools/list", None).await.expect("listed");
            }
        });
    });

    let seen = recorder.0.into_inner();
    let shared = backend.metric_label.as_ptr() as usize;
    for series in [
        "mcp_backend_requests_total",
        "mcp_backend_request_duration_seconds",
    ] {
        let addresses: Vec<usize> = seen
            .iter()
            .filter(|(name, key, _, _)| name == series && key == "backend")
            .map(|(_, _, _, address)| *address)
            .collect();
        assert!(!addresses.is_empty(), "{series}: registered on a call");
        assert!(
            addresses.iter().all(|address| *address == shared),
            "{series}: the label must be the backend's shared label, not a copy"
        );
    }
}

/// MIK-8014.PERF.5 site 3: the `tools/list` shadow counter now takes literal
/// labels per call. They must spell exactly what its pre-registration spells
/// (`bool::to_string`), or one counter splits into two series at scrape.
/// Every one of the 16 filter combinations runs, so a label that takes another
/// key's value, or inverts its own, differs from the expectation in some case.
#[cfg(feature = "metrics")]
#[test]
fn the_shadow_counter_labels_match_their_registration() {
    use crate::protocol_revision_telemetry::{ListFilters, observe_tools_list};

    for bits in 0u8..16 {
        let filters = ListFilters {
            principal: bits & 1 != 0,
            profile: bits & 2 != 0,
            session: bits & 4 != 0,
            request: bits & 8 != 0,
        };
        let recorder = BackendLabels::default();
        telemetry_metrics::with_local_recorder(&recorder, || {
            let _ = observe_tools_list(filters);
        });

        let seen = recorder.0.into_inner();
        for (key, flag) in [
            ("principal", filters.principal),
            ("profile", filters.profile),
            ("session", filters.session),
            ("request", filters.request),
        ] {
            let values: Vec<&str> = seen
                .iter()
                .filter(|(name, k, _, _)| {
                    name == "mcp_tools_list_cache_scope_shadow_total" && k == key
                })
                .map(|(_, _, value, _)| value.as_str())
                .collect();
            assert_eq!(
                values,
                [flag.to_string()],
                "{key}: label spelled as registered for {filters:?}"
            );
        }
    }
}

/// Transport whose every request and notification fails, so a test can
/// drive the real dispatch paths and watch what they record.
struct FailingTransport;

#[async_trait]
impl Transport for FailingTransport {
    async fn request(&self, _method: &str, _params: Option<Value>) -> Result<JsonRpcResponse> {
        Err(Error::Transport("socket closed".to_string()))
    }

    async fn notify(&self, _method: &str, _params: Option<Value>) -> Result<()> {
        Err(Error::Transport("socket closed".to_string()))
    }

    fn is_connected(&self) -> bool {
        true
    }

    async fn close(&self) -> Result<()> {
        Ok(())
    }
}

fn ok_transport() -> Arc<dyn Transport> {
    let response = JsonRpcResponse::success_serialized(
        RequestId::Number(1),
        ToolsListResult {
            tools: vec![],
            next_cursor: None,
        },
    );
    Arc::new(MockTransport::new(response, Duration::from_millis(0)))
}

fn backend_with(transport: Arc<dyn Transport>) -> Backend {
    let backend = Backend::new(
        "status-pin",
        BackendConfig::default(),
        &crate::config::FailsafeConfig::default(),
        Duration::from_secs(60),
    );
    backend.set_transport_for_test(transport);
    backend
}

/// Dispatch one request (or, with `notify`, one notification) under a
/// local recorder; returns whether it succeeded and every `status` label
/// value registered for `mcp_backend_requests_total`.
fn dispatch_and_statuses(backend: &Backend, notify: bool) -> (bool, Vec<String>) {
    let recorder = BackendLabels::default();
    let succeeded = telemetry_metrics::with_local_recorder(&recorder, || {
        match tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        {
            Ok(runtime) => runtime.block_on(async {
                if notify {
                    backend
                        .notify("notifications/initialized", None)
                        .await
                        .is_ok()
                } else {
                    backend.request("tools/list", None).await.is_ok()
                }
            }),
            Err(_) => false,
        }
    });
    let seen = recorder.0.into_inner();
    let statuses = seen
        .iter()
        .filter(|(name, key, _, _)| name == "mcp_backend_requests_total" && key == "status")
        .map(|(_, _, value, _)| value.clone())
        .collect();
    (succeeded, statuses)
}

#[test]
fn a_successful_request_counts_status_ok() {
    let backend = backend_with(ok_transport());
    let (succeeded, statuses) = dispatch_and_statuses(&backend, false);
    assert!(succeeded, "the request is answered");
    assert!(!statuses.is_empty(), "the counter was registered");
    assert!(statuses.iter().all(|status| status == "ok"), "{statuses:?}");
}

#[test]
fn a_failed_request_counts_status_error() {
    let backend = backend_with(Arc::new(FailingTransport));
    let (succeeded, statuses) = dispatch_and_statuses(&backend, false);
    assert!(!succeeded, "the request fails");
    assert!(!statuses.is_empty(), "the counter was registered");
    assert!(
        statuses.iter().all(|status| status == "error"),
        "{statuses:?}"
    );
}

#[test]
fn a_successful_notification_counts_status_ok() {
    let backend = backend_with(ok_transport());
    let (succeeded, statuses) = dispatch_and_statuses(&backend, true);
    assert!(succeeded, "the notification is sent");
    assert!(!statuses.is_empty(), "the counter was registered");
    assert!(statuses.iter().all(|status| status == "ok"), "{statuses:?}");
}

#[test]
fn a_failed_notification_counts_status_error() {
    let backend = backend_with(Arc::new(FailingTransport));
    let (succeeded, statuses) = dispatch_and_statuses(&backend, true);
    assert!(!succeeded, "the notification fails");
    assert!(!statuses.is_empty(), "the counter was registered");
    assert!(
        statuses.iter().all(|status| status == "error"),
        "{statuses:?}"
    );
}
