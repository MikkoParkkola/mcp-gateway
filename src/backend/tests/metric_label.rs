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
#[cfg(feature = "metrics")]
#[test]
fn the_shadow_counter_labels_match_their_registration() {
    use crate::protocol_revision_telemetry::{ListFilters, observe_tools_list};

    let filters = ListFilters {
        principal: true,
        profile: false,
        session: true,
        request: false,
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
            .filter(|(name, k, _, _)| name == "mcp_tools_list_cache_scope_shadow_total" && k == key)
            .map(|(_, _, value, _)| value.as_str())
            .collect();
        assert_eq!(
            values,
            [flag.to_string()],
            "{key}: label spelled as registered"
        );
    }
}
