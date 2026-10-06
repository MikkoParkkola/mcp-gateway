// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7116.MIN.1: the tenant extractors behind attribution (test plan T4-T6).

use std::collections::BTreeSet;

use serde_json::json;

use super::{TenantGuard, TenantGuardConfig, TenantVerdict};

fn guard(enabled: bool, max: usize) -> TenantGuard {
    TenantGuard::new(TenantGuardConfig {
        enabled,
        max_tenants_per_window: max,
        arg_keys: vec!["customer_id".to_string()],
        ..TenantGuardConfig::default()
    })
}

fn set(ids: &[&str]) -> BTreeSet<String> {
    ids.iter().map(|s| (*s).to_string()).collect()
}

/// T4. Extraction never records: after both extractors saw `cust-2`, a
/// principal limited to one tenant may still reach `cust-1`.
#[test]
fn extraction_does_not_count_against_the_guard() {
    let g = guard(true, 1);
    let names_cust_2 = json!({"filter": {"customer_id": "cust-2"}});
    let _ = g.request_tenants(&names_cust_2);
    let _ = g.response_tenants(&json!({"structuredContent": names_cust_2}));
    assert_eq!(
        g.check(Some("p1"), &json!({"customer_id": "cust-1"})),
        TenantVerdict::Allowed
    );
}

/// The request walk is the guard's walk, at any depth, with the guard off.
#[test]
fn request_tenants_walks_nested_arguments_with_the_guard_off() {
    let g = guard(false, 1);
    let args = json!({"filter": {"customer_id": "cust-1"}, "rows": [{"customer_id": 7}]});
    assert_eq!(g.request_tenants(&args), set(&["cust-1", "7"]));
}

/// T5. Most backends return JSON as text; `structuredContent` is walked too.
#[test]
fn response_tenants_reads_text_json_and_structured_content() {
    let g = guard(false, 1);
    let text = json!({"content": [{
        "type": "text",
        "text": r#"{"rows":[{"customer_id":"cust-9"}]}"#
    }]});
    assert_eq!(g.response_tenants(&text), set(&["cust-9"]));
    let structured = json!({"structuredContent": {"customer_id": 7}});
    assert_eq!(g.response_tenants(&structured), set(&["7"]));
}

/// Plain prose in a text block names no tenant and is not an error.
#[test]
fn response_tenants_ignores_non_json_text() {
    let g = guard(false, 1);
    let prose = json!({"content": [{"type": "text", "text": "customer_id cust-9"}]});
    assert!(g.response_tenants(&prose).is_empty());
}

/// T6 (re-pinned, MIN.1 gap 2). A text block over 1 MiB is not parsed, even
/// when it is valid JSON naming a tenant (the denial-of-service bound holds), and the
/// result says so: its tenants were not read, which is not the same as none.
#[test]
fn response_tenants_skips_text_over_one_mib() {
    let g = guard(false, 1);
    let padding = "x".repeat(1024 * 1024);
    let big = format!(r#"{{"customer_id":"cust-9","pad":"{padding}"}}"#);
    let result = json!({"content": [{"type": "text", "text": big}]});
    assert!(g.response_tenants(&result).is_empty());
    assert!(
        g.response_uninspected(&result),
        "an over-bound block is uninspected"
    );
    let small = json!({"content": [{"type": "text", "text": "{\"customer_id\":\"cust-9\"}"}]});
    assert!(
        !g.response_uninspected(&small),
        "a parsed block is inspected"
    );
    let off = TenantGuard::new(TenantGuardConfig::default());
    assert!(
        !off.response_uninspected(&result),
        "no arg_keys, no attribution"
    );
}

/// A text block holding `inner` as its JSON.
fn text_block(inner: &str) -> serde_json::Value {
    json!({"content": [{"type": "text", "text": inner}]})
}

/// MIN.1 gap 3. Valid JSON under 1 MiB, nested past the parser's depth
/// limit, cannot be read: it is uninspected, never silently empty.
#[test]
fn deep_nested_json_text_is_uninspected() {
    let g = guard(false, 1);
    let deep = format!(
        "{}{{\"customer_id\":\"cust-9\"}}{}",
        "[".repeat(200),
        "]".repeat(200)
    );
    let result = text_block(&deep);
    assert!(
        g.response_uninspected(&result),
        "a too-deep block is uninspected"
    );
    assert!(g.response_tenants(&result).is_empty());
}

/// MIN.1 gap 3. Text shaped as JSON that fails to parse is uninspected.
#[test]
fn malformed_json_text_is_uninspected() {
    let g = guard(false, 1);
    let result = text_block(r#"{"customer_id":"cust-9""#);
    assert!(
        g.response_uninspected(&result),
        "a malformed block is uninspected"
    );
    let field = json!({"structuredContent": {"rows": "[{\"customer_id\":"}});
    assert!(
        g.response_uninspected(&field),
        "a malformed JSON field is uninspected"
    );
    // Fail closed: text that opens like JSON but is not is reported as unread,
    // even when it was prose.
    let prose = json!({"structuredContent": {"note": "[draft] see {notes}"}});
    assert!(g.response_uninspected(&prose));
}

/// MIN.1 gap 3. A double-encoded text block is decoded and read.
#[test]
fn double_encoded_text_is_read() {
    let g = guard(false, 1);
    let once = r#"{"rows":[{"customer_id":"cust-9"}]}"#;
    let twice = serde_json::to_string(once).unwrap();
    let result = text_block(&twice);
    assert_eq!(g.response_tenants(&result), set(&["cust-9"]));
    assert!(
        !g.response_uninspected(&result),
        "a decoded block is inspected"
    );
}

/// MIN.1 gap 3. A JSON document carried in a string field is read, in a text
/// block and in `structuredContent`.
#[test]
fn json_string_field_is_read() {
    let g = guard(false, 1);
    let text = text_block(r#"{"rows":"[{\"customer_id\":\"cust-9\"}]"}"#);
    assert_eq!(g.response_tenants(&text), set(&["cust-9"]));
    assert!(!g.response_uninspected(&text));
    let structured = json!({"structuredContent": {"rows": "{\"customer_id\":7}"}});
    assert_eq!(g.response_tenants(&structured), set(&["7"]));
    assert!(!g.response_uninspected(&structured));
}

/// MIN.1 gap 3. Encoding nested past the decode bound is uninspected.
#[test]
fn encoding_past_the_decode_bound_is_uninspected() {
    let g = guard(false, 1);
    let mut text = r#"{"customer_id":"cust-9"}"#.to_string();
    for _ in 0..6 {
        text = serde_json::to_string(&text).unwrap();
    }
    assert!(g.response_uninspected(&text_block(&text)));
}

/// Prose, quoted prose and plain values are inspected: nothing in them was
/// skipped (green before and after the gap 3 fix, by design).
#[test]
fn prose_and_plain_values_are_inspected() {
    let g = guard(false, 1);
    for text in [
        "customer_id cust-9",
        "\"quoted\" words",
        "\"just a string\"",
        "42",
    ] {
        assert!(!g.response_uninspected(&text_block(text)), "{text}");
    }
}

/// MIK-7881.TENANT.1: a double-encoded document cut short (its outer quote
/// never closes) is unread, as a cut-short document is. Quoted prose that does
/// not open like a document stays inspected (above).
#[test]
fn a_truncated_double_encoded_document_is_uninspected() {
    let g = guard(false, 1);
    let full = serde_json::to_string(r#"{"customer_id":"cust-9","note":"long enough"}"#).unwrap();
    for cut in [&full[..full.len() - 8], &format!(" {}", &full[..20])] {
        assert!(g.response_uninspected(&text_block(cut)), "{cut}");
    }
}

/// Review (gap 3): a byte-order mark before JSON does not hide it.
#[test]
fn bom_led_json_text_is_read() {
    let g = guard(false, 1);
    let result = text_block("\u{feff}{\"customer_id\":\"cust-9\"}");
    assert_eq!(g.response_tenants(&result), set(&["cust-9"]));
    assert!(!g.response_uninspected(&result));
    assert!(g.response_uninspected(&text_block("\u{feff}{\"customer_id\":")));
    let spaced = text_block(" \u{feff} {\"customer_id\":\"cust-9\"}");
    assert_eq!(
        g.response_tenants(&spaced),
        set(&["cust-9"]),
        "whitespace around a mark"
    );
}

/// Review (gap 3): a JSON document under a tenant key is also read, and an
/// unparseable one is unread.
#[test]
fn json_under_a_tenant_key_is_read() {
    let g = guard(false, 1);
    let keyed = json!({"structuredContent": {"customer_id": "{\"customer_id\":\"cust-7\"}"}});
    // The keyed value is the tenant id as given, and the document it carries
    // is read too.
    assert_eq!(
        g.response_tenants(&keyed),
        set(&["{\"customer_id\":\"cust-7\"}", "cust-7"])
    );
    assert!(!g.response_uninspected(&keyed));
    let broken = json!({"structuredContent": {"customer_id": "{"}});
    assert!(g.response_uninspected(&broken));
}

/// Review (gap 3): three encoding layers are read; a fourth is unread.
#[test]
fn three_encoding_layers_are_read_and_four_are_not() {
    let g = guard(false, 1);
    let encode = |layers: usize| {
        let mut text = r#"{"customer_id":"cust-9"}"#.to_string();
        for _ in 0..layers {
            text = serde_json::to_string(&text).unwrap();
        }
        text_block(&text)
    };
    assert_eq!(g.response_tenants(&encode(3)), set(&["cust-9"]));
    assert!(!g.response_uninspected(&encode(3)));
    assert!(g.response_uninspected(&encode(4)));
}

/// Prose over the parse bound holds no keyed tenant and is not marked; the
/// request walk does not decode strings (only the response scan does).
#[test]
fn oversize_prose_is_not_marked_and_requests_are_not_decoded() {
    let g = guard(false, 1);
    let prose = "word ".repeat(300_000);
    assert!(!g.response_uninspected(&text_block(&prose)));
    let args = json!({"rows": "{\"customer_id\":\"cust-9\"}"});
    assert!(g.request_tenants(&args).is_empty());
}
