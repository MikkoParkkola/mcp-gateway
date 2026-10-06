// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Every observed request lands in exactly one labelled counter.
//!
//! MIK-7917 item 1 borrows the observation's labels instead of copying them
//! per request. This row holds the counting itself fixed across that change:
//! N requests over several label tuples raise the exported counters by
//! exactly N, each under its own tuple.

use super::*;
use serde_json::json;

/// The value of the first sample of `name` whose line carries every `k="v"`
/// in `labels`; 0 when there is none.
#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
fn sample(rendered: &str, name: &str, labels: &[&str]) -> u64 {
    let prefix = format!("{name}{{");
    rendered
        .lines()
        .filter(|line| line.starts_with(&prefix))
        .find(|line| labels.iter().all(|label| line.contains(label)))
        .and_then(|line| line.rsplit(' ').next()?.parse::<f64>().ok())
        .map_or(0, |value| value as u64)
}

#[test]
#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
fn every_request_counts_once_under_its_tuple() {
    let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
    let handle = recorder.handle();
    let call = json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {} });
    let initialize_params = json!({
        "protocolVersion": "2025-06-18",
        "clientInfo": { "name": "Claude Code" }
    });
    let initialize = json!({
        "jsonrpc": "2.0", "id": 2, "method": "initialize", "params": initialize_params
    });

    telemetry_metrics::with_local_recorder(&recorder, || {
        for _ in 0..4 {
            observe_inbound_request(
                &call,
                None,
                "tools/call",
                Some("2026-07-28"),
                None,
                Transport::Http,
            );
        }
        for _ in 0..3 {
            observe_inbound_request(&call, None, "tools/call", None, None, Transport::Http);
        }
        for _ in 0..2 {
            observe_inbound_request(
                &initialize,
                Some(&initialize_params),
                "initialize",
                None,
                None,
                Transport::Internal,
            );
        }
        // Not a request: never counted.
        observe_inbound_request(
            &call,
            None,
            "notifications/initialized",
            None,
            None,
            Transport::Http,
        );
    });
    let rendered = handle.render();

    let revised = "mcp_protocol_revision_observations_total";
    let unattributed = "mcp_protocol_revision_unattributed_observations_total";
    let header = sample(
        &rendered,
        revised,
        &[
            r#"requested_revision="2026-07-28""#,
            r#"client="unattributed""#,
            r#"transport="http""#,
        ],
    );
    let none = sample(
        &rendered,
        unattributed,
        &[r#"client="unattributed""#, r#"transport="http""#],
    );
    let handshake = sample(
        &rendered,
        revised,
        &[
            r#"requested_revision="2025-06-18""#,
            r#"client="claude""#,
            r#"transport="internal""#,
        ],
    );
    assert_eq!((header, none, handshake), (4, 3, 2), "{rendered}");

    let total: u64 = rendered
        .lines()
        .filter(|line| {
            line.starts_with(&format!("{revised}{{"))
                || line.starts_with(&format!("{unattributed}{{"))
        })
        .filter_map(|line| line.rsplit(' ').next()?.parse::<f64>().ok())
        .map(|value| value as u64)
        .sum();
    assert_eq!(
        total, 9,
        "nine requests, nine counts, the notification none: {rendered}"
    );
}
