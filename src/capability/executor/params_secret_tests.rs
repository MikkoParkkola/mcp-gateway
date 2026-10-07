// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7787: a caller's argument is data, never a secret reference. A value
//! such as `{env.NAME}` in a query argument must reach the provider as that
//! text, not as the gateway's own secret.

use std::sync::Arc;

use serde_json::json;

use super::super::CapabilityExecutor;
use crate::config::{EnvOverlay, LiveEnv, ResolvedEnvFiles};

fn executor_holding(vars: &str) -> (tempfile::TempDir, CapabilityExecutor) {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("keys.env");
    crate::gateway::test_helpers::write_owner_only(&path, vars).expect("write env file");
    let overlay = EnvOverlay::from_paths(&[path]);
    let env = Arc::new(LiveEnv::new(Arc::new(overlay), ResolvedEnvFiles::default()));
    (dir, CapabilityExecutor::new().with_env(env))
}

#[test]
fn a_secret_reference_in_a_caller_value_is_not_expanded() {
    let (_dir, executor) = executor_holding("MIK7787_TEST_SECRET=gateway-owned\n");
    let params = json!({ "q": "{env.MIK7787_TEST_SECRET}" });
    let value = executor.substitute_string("{q}", &params).unwrap();
    assert_eq!(value, "{env.MIK7787_TEST_SECRET}");
    assert!(!value.contains("gateway-owned"));
}

#[test]
fn a_secret_reference_in_the_template_still_resolves() {
    let (_dir, executor) = executor_holding("MIK7787_TEST_SECRET=gateway-owned\n");
    let params = json!({ "q": "cats" });
    let value = executor
        .substitute_string("{q}:{env.MIK7787_TEST_SECRET}", &params)
        .unwrap();
    assert_eq!(value, "cats:gateway-owned");
}

#[test]
fn the_query_path_sends_a_caller_reference_as_text() {
    let (_dir, executor) = executor_holding("MIK7787_TEST_SECRET=gateway-owned\n");
    let params = json!({ "q": "see {env.MIK7787_TEST_SECRET}" });
    let template = std::collections::HashMap::from([("q".to_string(), "{q}".to_string())]);
    let pairs = executor.substitute_params(&template, &params).unwrap();
    assert_eq!(
        pairs,
        [("q".to_string(), "see {env.MIK7787_TEST_SECRET}".to_string())]
    );
}

#[test]
fn the_typed_body_path_sends_a_caller_reference_as_text() {
    let (_dir, executor) = executor_holding("MIK7787_TEST_SECRET=gateway-owned\n");
    let params = json!({ "q": "see {env.MIK7787_TEST_SECRET}" });
    let body = json!({ "query": "{q}", "note": "x {q}" });
    let out = executor
        .substitute_value(&body, &params, super::KeptNulls::None)
        .unwrap();
    assert_eq!(
        out,
        json!({ "query": "see {env.MIK7787_TEST_SECRET}", "note": "x see {env.MIK7787_TEST_SECRET}" })
    );
}

// MIK-7888: one pass over the template. A value that was substituted is data
// and is never scanned for placeholders again.

#[test]
fn a_secret_containing_a_placeholder_reaches_the_provider_byte_for_byte() {
    let (_dir, executor) = executor_holding("MIK7888_TOKEN=abc{q}xyz\n");
    let params = json!({ "q": "caller-text" });
    let value = executor
        .substitute_string("Bearer {env.MIK7888_TOKEN}", &params)
        .unwrap();
    assert_eq!(value, "Bearer abc{q}xyz");
}

#[test]
fn a_caller_value_that_looks_like_another_placeholder_is_not_expanded() {
    let (_dir, executor) = executor_holding("MIK7888_UNUSED=1\n");
    // Whichever key a map visits first, neither value is re-scanned.
    let params = json!({ "a": "{b}", "b": "B-VALUE" });
    let value = executor.substitute_string("{a}|{b}", &params).unwrap();
    assert_eq!(value, "{b}|B-VALUE");
}

#[test]
fn a_secret_containing_another_secret_reference_is_not_chained() {
    let (_dir, executor) = executor_holding("MIK7888_A=x{env.MIK7888_B}y\nMIK7888_B=second\n");
    let value = executor
        .substitute_string("{env.MIK7888_A}-{env.MIK7888_B}", &json!({}))
        .unwrap();
    assert_eq!(value, "x{env.MIK7888_B}y-second");
}

#[test]
fn placeholders_that_name_nothing_stay_as_written() {
    let (_dir, executor) = executor_holding("MIK7888_V=ö-ünï\n");
    let params = json!({ "q": "Q" });
    for (template, want) in [
        ("{}", "{}"),
        ("{env.}", "{env.}"),
        ("{keychain.}", "{keychain.}"),
        ("{nameless}", "{nameless}"),
        ("{{q}}", "{Q}"),
        ("{q", "{q"),
        ("q}", "q}"),
        (r#"{"a": {q}}"#, r#"{"a": Q}"#),
        ("{env.MIK7888_V}", "ö-ünï"),
    ] {
        let got = executor.substitute_string(template, &params).unwrap();
        assert_eq!(got, want, "template {template:?}");
    }
}

// MIK-7857: the query path drops a value because of what it looks like. A
// value is dropped only when the TEMPLATE named a placeholder nothing filled.

fn query_pairs(
    executor: &CapabilityExecutor,
    template: &str,
    params: &serde_json::Value,
) -> Vec<(String, String)> {
    let templates = std::collections::HashMap::from([("q".to_string(), template.to_string())]);
    executor.substitute_params(&templates, params).unwrap()
}

#[test]
fn a_query_value_starting_with_a_brace_reaches_the_provider_verbatim() {
    let (_dir, executor) = executor_holding("MIK7857_UNUSED=1\n");
    let json_text = r#"{"filter": "open"}"#;
    let pairs = query_pairs(&executor, "{q}", &json!({ "q": json_text }));
    assert_eq!(pairs, [("q".to_string(), json_text.to_string())]);
}

#[test]
fn a_caller_value_shaped_like_a_reference_is_sent_as_that_text() {
    let (_dir, executor) = executor_holding("MIK7857_SECRET=gateway-owned\n");
    let pairs = query_pairs(&executor, "{q}", &json!({ "q": "{env.MIK7857_SECRET}" }));
    assert_eq!(
        pairs,
        [("q".to_string(), "{env.MIK7857_SECRET}".to_string())]
    );
}

#[test]
fn a_secret_that_starts_with_a_brace_is_not_dropped_from_the_query() {
    let (_dir, executor) = executor_holding("MIK7857_TOKEN={q}-token\n");
    let pairs = query_pairs(&executor, "{env.MIK7857_TOKEN}", &json!({ "q": "caller" }));
    assert_eq!(pairs, [("q".to_string(), "{q}-token".to_string())]);
}

#[test]
fn a_placeholder_nothing_fills_is_still_left_out_of_the_query() {
    let (_dir, executor) = executor_holding("MIK7857_UNUSED=1\n");
    assert!(query_pairs(&executor, "{absent}", &json!({ "q": "x" })).is_empty());
    assert!(query_pairs(&executor, "{q}", &json!({})).is_empty());
}

/// MIK-7888: a resolved secret is data. One that happens to contain the text
/// `{access_token}` must not make the gateway drop its Authorization header.
#[tokio::test]
async fn a_secret_holding_the_access_token_text_keeps_its_header() {
    let (_dir, executor) = executor_holding("MIK7888_TOKEN=abc{access_token}def\n");
    let config = crate::capability::RestConfig {
        headers: std::collections::HashMap::from([(
            "Authorization".to_string(),
            "Bearer {env.MIK7888_TOKEN}".to_string(),
        )]),
        ..Default::default()
    };
    let headers = executor
        .build_headers(
            &config,
            &crate::capability::AuthConfig::default(),
            &json!({}),
            &crate::capability::CapabilityExecutionContext::default(),
        )
        .await
        .unwrap();
    assert_eq!(
        headers.get("authorization").and_then(|v| v.to_str().ok()),
        Some("Bearer abc{access_token}def")
    );
}

/// An unfilled `{access_token}` in the template still leaves the header to
/// the credential injector.
#[tokio::test]
async fn an_unfilled_access_token_template_is_still_skipped() {
    let executor = CapabilityExecutor::new();
    let config = crate::capability::RestConfig {
        headers: std::collections::HashMap::from([(
            "Authorization".to_string(),
            "Bearer {access_token}".to_string(),
        )]),
        ..Default::default()
    };
    let headers = executor
        .build_headers(
            &config,
            &crate::capability::AuthConfig::default(),
            &json!({}),
            &crate::capability::CapabilityExecutionContext::default(),
        )
        .await
        .unwrap();
    assert!(headers.get("authorization").is_none());
}

/// MIK-7888: a caller value is substituted once; `{b}` inside it is text.
#[test]
fn the_url_builder_substitutes_each_caller_value_once() {
    let executor = CapabilityExecutor::new();
    let config = crate::capability::RestConfig {
        base_url: "https://api.github.com".to_string(),
        path: "/{a}|{b}".to_string(),
        ..Default::default()
    };
    let url = executor
        .build_url(&config, &json!({ "a": "{b}", "b": "B" }))
        .unwrap();
    assert_eq!(url, "https://api.github.com/{b}|B");
}

#[test]
fn the_graphql_builder_substitutes_each_caller_value_once() {
    let config = crate::capability::GraphqlConfig {
        query: Some("{a}|{b}".to_string()),
        ..Default::default()
    };
    let body = super::super::graphql::GraphqlExecutor::build_body(
        &config,
        &json!({ "a": "{b}", "b": "B" }),
    )
    .unwrap();
    assert_eq!(body["query"], "{b}|B");
}

/// A filled `{access_token}` keeps its header even when another placeholder in
/// the same template is left unfilled: the skip is about the token alone.
#[tokio::test]
async fn a_filled_access_token_beside_an_unfilled_placeholder_keeps_its_header() {
    let executor = CapabilityExecutor::new();
    let config = crate::capability::RestConfig {
        headers: std::collections::HashMap::from([(
            "Authorization".to_string(),
            "Bearer {access_token} {scheme}".to_string(),
        )]),
        ..Default::default()
    };
    let headers = executor
        .build_headers(
            &config,
            &crate::capability::AuthConfig::default(),
            &json!({ "access_token": "tok" }),
            &crate::capability::CapabilityExecutionContext::default(),
        )
        .await
        .unwrap();
    assert_eq!(
        headers.get("authorization").and_then(|v| v.to_str().ok()),
        Some("Bearer tok {scheme}")
    );
}

/// MIK-7888B.BODY.1: a body field filled from a caller value or a secret is
/// sent as written, even when the value looks like a placeholder.
#[test]
fn a_filled_body_field_that_looks_like_a_placeholder_is_kept() {
    let (_dir, executor) = executor_holding("MIK7909_TEST_SECRET={abc}\n");
    let template = json!({
        "pure": "{q}",
        "spliced": "{q}{r}",
        "secret": "{env.MIK7909_TEST_SECRET}",
    });
    let params = json!({ "q": "{x}", "r": "}" });
    let body = executor
        .substitute_value(&template, &params, super::KeptNulls::None)
        .unwrap();
    assert_eq!(body["pure"], "{x}", "{body}");
    assert_eq!(body["spliced"], "{x}}", "{body}");
    assert_eq!(body["secret"], "{abc}", "{body}");
}

/// MIK-7888B.BODY.2: a field whose placeholder nothing filled is still left
/// out of the body, beside a filled one.
#[test]
fn a_body_field_nothing_fills_is_still_left_out() {
    let (_dir, executor) = executor_holding("");
    let template = json!({
        "kept": "{q}",
        "missing": "{absent}",
        "defaulted": "{first|50}",
        "indexed": "{filter[id]}",
    });
    let body = executor
        .substitute_value(&template, &json!({ "q": "cats" }), super::KeptNulls::None)
        .unwrap();
    assert_eq!(body, json!({ "kept": "cats" }));
    // The query path omits them the same way.
    for unfilled in ["{absent}", "{first|50}", "{filter[id]}"] {
        let template = std::collections::HashMap::from([("k".to_owned(), unfilled.to_owned())]);
        let pairs = executor.substitute_params(&template, &json!({})).unwrap();
        assert!(pairs.is_empty(), "{unfilled}: {pairs:?}");
    }
}

/// MIK-7888B.BODY.3: a query template whose named placeholders are all filled
/// is sent, even with literal braces such as `{}` in it.
#[test]
fn a_filled_query_template_with_literal_braces_is_sent() {
    let (_dir, executor) = executor_holding("");
    for (template, sent) in [
        (
            r#"{"filter":"{q}","options":{}}"#,
            r#"{"filter":"cats","options":{}}"#,
        ),
        (
            r#"{"filter":"{q}","page":{"size":10}}"#,
            r#"{"filter":"cats","page":{"size":10}}"#,
        ),
    ] {
        let template =
            std::collections::HashMap::from([("filter".to_owned(), template.to_owned())]);
        let pairs = executor
            .substitute_params(&template, &json!({ "q": "cats" }))
            .unwrap();
        assert_eq!(pairs, vec![("filter".to_owned(), sent.to_owned())]);
    }
}

/// MIK-7943 finding 2: a parameter name holding a quote is still a parameter.
/// Only a JSON fragment, which opens with a quoted key, is literal text.
#[test]
fn an_unfilled_parameter_whose_name_holds_a_quote_is_omitted() {
    let (_dir, executor) = executor_holding("");
    let template = std::collections::HashMap::from([("k".to_owned(), "{a\"b}".to_owned())]);
    let pairs = executor.substitute_params(&template, &json!({})).unwrap();
    assert!(pairs.is_empty(), "{pairs:?}");
    let pairs = executor
        .substitute_params(&template, &json!({ "a\"b": "x" }))
        .unwrap();
    assert_eq!(pairs, vec![("k".to_owned(), "x".to_owned())]);
}

/// MIK-7970: a caller's explicit null that fills a pure placeholder reaches
/// the JSON body; an absent value and the template's own null, at any depth,
/// are still left out.
#[test]
fn a_callers_explicit_null_is_sent_in_the_body() {
    let (_dir, executor) = executor_holding("");
    let template = json!({
        "cursor": "{cursor}",
        "missing": "{absent}",
        "fixed": null,
        "outer": { "x": null, "y": "{cursor}" },
    });
    let body = executor
        .substitute_value(
            &template,
            &json!({ "cursor": null }),
            super::KeptNulls::Named(&["cursor".to_owned()]),
        )
        .unwrap();
    assert_eq!(
        body,
        json!({ "cursor": null, "outer": { "y": null } }),
        "{body}"
    );
    // A query string cannot carry a JSON null: it is still left out there.
    let query = std::collections::HashMap::from([("cursor".to_owned(), "{cursor}".to_owned())]);
    let pairs = executor
        .substitute_params(&query, &json!({ "cursor": null }))
        .unwrap();
    assert!(pairs.is_empty(), "{pairs:?}");
}
