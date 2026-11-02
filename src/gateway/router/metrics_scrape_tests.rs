// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The scrape sets the session gauge from the multiplexer, after the token
//! check and before it renders.

use std::sync::Arc;

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode, header};

use super::handlers::{MetricsState, metrics_handler};
use crate::gateway::health_metrics::process::SESSIONS;
use crate::gateway::session_id::SessionOwner;
use crate::gateway::streaming::NotificationMultiplexer;

const TOKEN: &str = "scrape-token";

fn state() -> MetricsState {
    MetricsState {
        token: Some(Arc::from(TOKEN)),
        multiplexer: Arc::new(NotificationMultiplexer::new(
            Arc::new(crate::backend::BackendRegistry::new()),
            crate::config::StreamingConfig::default(),
        )),
    }
}

fn bearer(token: &str) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::AUTHORIZATION,
        format!("Bearer {token}").parse().expect("header value"),
    );
    headers
}

/// Scrape `state` once under `recorder`; the gauge it set, if any.
fn scrape(
    recorder: &metrics_exporter_prometheus::PrometheusRecorder,
    state: &MetricsState,
    headers: HeaderMap,
) -> StatusCode {
    telemetry_metrics::with_local_recorder(recorder, || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("runtime");
        rt.block_on(metrics_handler(State(state.clone()), headers))
            .status()
    })
}

fn gauge(rendered: &str) -> Option<f64> {
    rendered
        .lines()
        .find_map(|l| l.strip_prefix(SESSIONS)?.strip_prefix(' ')?.parse().ok())
}

#[test]
fn the_gauge_follows_the_session_count_at_each_scrape() {
    let recorder = crate::metrics::builder().build_recorder();
    let handle = recorder.handle();
    let state = state();
    let owner = SessionOwner::Anonymous;
    let (first, _a) = state
        .multiplexer
        .get_or_create_session_scoped(Some("a"), &owner, None);
    let (_second, _b) = state
        .multiplexer
        .get_or_create_session_scoped(Some("b"), &owner, None);

    assert_eq!(scrape(&recorder, &state, bearer(TOKEN)), StatusCode::OK);
    assert_eq!(gauge(&handle.render()), Some(2.0));

    state.multiplexer.remove_session(first.as_str());
    assert_eq!(scrape(&recorder, &state, bearer(TOKEN)), StatusCode::OK);
    assert_eq!(gauge(&handle.render()), Some(1.0));
}

#[test]
fn a_refused_scrape_does_not_read_the_count() {
    let recorder = crate::metrics::builder().build_recorder();
    let handle = recorder.handle();
    let state = state();

    assert_eq!(
        scrape(&recorder, &state, bearer("wrong")),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(gauge(&handle.render()), None);
}
