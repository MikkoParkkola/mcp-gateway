// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8380: stdio refuses, from the body alone, a modern request that names a
//! revision this build does not serve (-32022) or a method whose client
//! capability was not declared (-32021), in `/mcp`'s order (version, then
//! capability, then removed). A batch item is judged by the process setting;
//! only its `server/discover` listing is the legacy set. Wire strings are
//! written out, never taken from the constants.

use super::era_parity::{legacy_request, modern_request, removed_text, send};
use serde_json::{Value, json};

const UNSERVED: &str = "1999-01-01";

fn unserved_text() -> String {
    format!("unsupported protocol version '{UNSERVED}'")
}

/// BATCH.2: a revision this build does not serve is refused -32022 with the
/// list it could retry on; a served revision with modern serving off is refused
/// with an empty list; a served revision with serving on is served.
/// Red on the 8368 tip: the first two are served.
#[tokio::test]
async fn stdio_refuses_an_unserved_revision() {
    let unserved = send(
        true,
        modern_request(Some(1), "tools/list", UNSERVED, json!({})),
    )
    .await
    .expect("answers");
    assert_eq!(unserved["error"]["code"], -32022, "{unserved}");
    assert_eq!(unserved["error"]["message"], unserved_text());
    assert_eq!(
        unserved["error"]["data"]["supportedVersions"],
        json!(["2026-07-28"])
    );

    let disabled = send(
        false,
        modern_request(Some(2), "tools/list", "2026-07-28", json!({})),
    )
    .await
    .expect("answers");
    assert_eq!(disabled["error"]["code"], -32022, "{disabled}");
    assert_eq!(
        disabled["error"]["message"],
        "unsupported protocol version '2026-07-28'"
    );
    assert_eq!(disabled["error"]["data"]["supportedVersions"], json!([]));

    let served = send(
        true,
        modern_request(Some(3), "tools/list", "2026-07-28", json!({})),
    )
    .await
    .expect("answers");
    assert!(served.get("error").is_none(), "{served}");
}

/// BATCH.2 order: the version is judged before the method. A bad revision on a
/// removed method, and on methods whose capability is undeclared (so two
/// refusals apply at once), all answer -32022.
#[tokio::test]
async fn stdio_judges_the_version_before_the_method() {
    for method in ["ping", "sampling/createMessage", "roots/list"] {
        let answer = send(true, modern_request(Some(1), method, UNSERVED, json!({})))
            .await
            .expect("answers");
        assert_eq!(answer["error"]["code"], -32022, "{method}: {answer}");
        assert_eq!(answer["error"]["message"], unserved_text(), "{method}");
    }
}

/// BATCH.2: a method that needs a client capability the request did not declare
/// is refused -32021 naming it; declared, the request passes the check and falls
/// to stdio's ordinary answer (stdio serves none of these methods); a legacy
/// request of the method keeps that same ordinary answer. Red on the 8368 tip
/// for the first form.
#[tokio::test]
async fn stdio_refuses_an_undeclared_capability() {
    for (method, capability) in [
        ("sampling/createMessage", "sampling"),
        ("elicitation/create", "elicitation"),
        ("roots/list", "roots"),
    ] {
        let refused = send(
            true,
            modern_request(Some(1), method, "2026-07-28", json!({})),
        )
        .await
        .expect("answers");
        assert_eq!(refused["error"]["code"], -32021, "{method}: {refused}");
        assert_eq!(
            refused["error"]["message"],
            format!("client did not declare the '{capability}' capability")
        );
        assert_eq!(
            refused["error"]["data"]["requiredCapabilities"],
            json!([capability])
        );

        let ordinary = format!("Method not found: {method}");
        let declared = send(
            true,
            modern_request(Some(2), method, "2026-07-28", json!({ capability: {} })),
        )
        .await
        .expect("answers");
        assert_eq!(declared["error"]["code"], -32601, "{method}: {declared}");
        assert_eq!(declared["error"]["message"], ordinary);

        let legacy = send(true, legacy_request(Some(3), method))
            .await
            .expect("answers");
        assert_eq!(legacy["error"]["code"], -32601, "{method}: {legacy}");
        assert_eq!(legacy["error"]["message"], ordinary);
    }
}

/// Notifications (the stdio divergence from HTTP, which runs every check before
/// its 202): an id-bearing REMOVED notification gets the version refusal first,
/// then the removed one; every other notification stays silent whatever its
/// revision or serving.
#[tokio::test]
async fn stdio_notifications_judge_the_version_only_when_removed() {
    let removed = "notifications/roots/list_changed";
    let bad = send(true, modern_request(Some(1), removed, UNSERVED, json!({})))
        .await
        .expect("answers");
    assert_eq!(bad["error"]["code"], -32022, "{bad}");
    let served = send(
        true,
        modern_request(Some(2), removed, "2026-07-28", json!({})),
    )
    .await
    .expect("answers");
    assert_eq!(served["error"]["code"], -32601, "{served}");
    assert_eq!(served["error"]["message"], removed_text(removed));
    for request in [
        modern_request(Some(3), "notifications/initialized", UNSERVED, json!({})),
        modern_request(None, "notifications/initialized", UNSERVED, json!({})),
        modern_request(
            Some(4),
            "notifications/initialized",
            "2026-07-28",
            json!({}),
        ),
    ] {
        assert!(send(false, request.clone()).await.is_none(), "{request}");
        assert!(send(true, request.clone()).await.is_none(), "{request}");
    }
}

/// One batch line through the real serve loop (`run_stdio_on`) with
/// `server.modern_protocol` = `modern_protocol`. Returns the answers by id.
async fn served_batch(
    modern_protocol: bool,
    batch: Value,
) -> std::collections::BTreeMap<i64, Value> {
    use std::time::Duration;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    let count = batch.as_array().map_or(0, Vec::len);
    let store = tempfile::tempdir().expect("store root");
    let data = tempfile::tempdir().expect("data dir");
    let mut config = crate::config::Config::default();
    config.tasks.store_dir = store.path().display().to_string();
    config.server.modern_protocol = modern_protocol;
    let gateway = super::super::Gateway::new(config)
        .await
        .expect("gateway boots")
        .with_data_dir(data.path().to_path_buf());
    let (mut stdin, input) = tokio::io::duplex(64 * 1024);
    let (output, reader) = tokio::io::duplex(1 << 20);
    let served = tokio::spawn(async move { gateway.run_stdio_on(input, output, None).await });
    let mut lines = BufReader::new(reader).lines();
    stdin
        .write_all(format!("{batch}\n").as_bytes())
        .await
        .expect("write");
    let mut answers = std::collections::BTreeMap::new();
    while answers.len() < count {
        let line = tokio::time::timeout(Duration::from_secs(20), lines.next_line())
            .await
            .expect("answered in time")
            .expect("read")
            .expect("a line");
        let frame: Value = serde_json::from_str(&line).expect("a JSON frame");
        let items = match frame {
            Value::Array(items) => items,
            single => vec![single],
        };
        for item in items {
            let id = item["id"].as_i64().expect("an integer id");
            assert!(answers.insert(id, item).is_none(), "id {id} answered twice");
        }
    }
    drop(stdin);
    tokio::time::timeout(Duration::from_secs(40), served)
        .await
        .expect("EOF returns")
        .expect("no panic")
        .expect("run_stdio_on returns Ok");
    // One answer per request, and nothing after them: the loop above stops at
    // `count`, so a stray extra frame is only seen by draining to EOF.
    assert_eq!(answers.len(), count, "{answers:?}");
    let extra = tokio::time::timeout(Duration::from_secs(20), lines.next_line())
        .await
        .expect("output closes")
        .expect("read");
    assert!(extra.is_none(), "unexpected extra frame: {extra:?}");
    answers
}

/// BATCH.2 on the batch path, modern serving ON: each item is judged like a
/// single request: an unserved revision -32022, an undeclared capability
/// -32021, a removed method -32601, a supported modern `tools/list` and a
/// legacy `ping` served. Red on the 8368 tip for the first two.
#[tokio::test]
async fn a_served_batch_judges_each_item_like_a_single_request() {
    let batch = json!([
        modern_request(Some(1), "tools/list", "2026-07-28", json!({})),
        modern_request(Some(2), "ping", "2026-07-28", json!({})),
        modern_request(Some(3), "tools/list", UNSERVED, json!({})),
        modern_request(Some(4), "sampling/createMessage", "2026-07-28", json!({})),
        legacy_request(Some(5), "ping"),
    ]);
    let answers = served_batch(true, batch).await;
    assert!(answers[&1].get("error").is_none(), "{}", answers[&1]);
    assert_eq!(answers[&2]["error"]["code"], -32601, "{}", answers[&2]);
    assert_eq!(answers[&2]["error"]["message"], removed_text("ping"));
    assert_eq!(answers[&3]["error"]["code"], -32022, "{}", answers[&3]);
    assert_eq!(answers[&3]["error"]["message"], unserved_text());
    assert_eq!(answers[&4]["error"]["code"], -32021, "{}", answers[&4]);
    assert_eq!(answers[&5]["result"], json!({}), "{}", answers[&5]);
}

/// BATCH.2 on the batch path, modern serving OFF: the same supported modern
/// item is refused -32022 with an empty list, and a legacy item is unchanged.
#[tokio::test]
async fn a_batch_with_modern_serving_off_refuses_modern_items() {
    let batch = json!([
        modern_request(Some(1), "tools/list", "2026-07-28", json!({})),
        legacy_request(Some(2), "ping"),
    ]);
    let answers = served_batch(false, batch).await;
    assert_eq!(answers[&1]["error"]["code"], -32022, "{}", answers[&1]);
    assert_eq!(answers[&1]["error"]["data"]["supportedVersions"], json!([]));
    assert_eq!(answers[&2]["result"], json!({}), "{}", answers[&2]);
}

/// BATCH.3 guard: a batched `server/discover` lists the legacy set only even
/// while modern serving is on, and a single one lists it when serving is on.
#[tokio::test]
async fn a_batched_discover_lists_the_legacy_set_only() {
    let discover = |id: i64| json!({ "jsonrpc": "2.0", "id": id, "method": "server/discover" });
    let versions = |answer: &Value| -> Vec<String> {
        answer["result"]["supportedVersions"]
            .as_array()
            .unwrap_or_else(|| panic!("supportedVersions is a list: {answer}"))
            .iter()
            .map(|version| version.as_str().expect("a string").to_owned())
            .collect()
    };
    let batched = served_batch(true, json!([discover(1)])).await;
    assert!(
        !versions(&batched[&1]).iter().any(|v| v == "2026-07-28"),
        "{}",
        batched[&1]
    );
    let single = send(true, discover(2)).await.expect("answers");
    assert!(
        versions(&single).iter().any(|v| v == "2026-07-28"),
        "{single}"
    );
    let off = send(false, discover(3)).await.expect("answers");
    assert!(!versions(&off).iter().any(|v| v == "2026-07-28"), "{off}");
    // The legacy set exactly: a batched discover loses no revision either.
    assert_eq!(versions(&batched[&1]), versions(&off), "{}", batched[&1]);
}
