// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
use serde_json::json;

use crate::capability::validate_output;
use crate::projection::schema::{ActorSpec, ProjectionSpec, SubjectSpec};
use crate::provider::Transform as _;
use crate::provider::transforms::ResponseTransform;
use crate::transform::{RedactRule, TransformConfig};

use super::{apply_capability_projection, enforce_output_schema};

/// Prove the component used by `dispatch_to_backend`: given a non-empty
/// `response_transform` in a capability definition, `ResponseTransform`
/// strips all fields not listed in `project`.
#[tokio::test]
async fn response_transform_project_strips_unlisted_fields() {
    // GIVEN: a response_transform that keeps only "id" and "name"
    let config = TransformConfig {
        project: vec!["id".to_string(), "name".to_string()],
        ..Default::default()
    };
    let transform = ResponseTransform::new(&config);

    // AND: a raw tool response value with extra fields
    let raw = json!({
        "id": "abc",
        "name": "Alice",
        "internal_token": "secret",
        "noise": 42
    });

    // WHEN: applying the transform (as dispatch_to_backend would)
    let result = transform.transform_result("my_tool", raw).await.unwrap();

    // THEN: only projected fields remain
    assert_eq!(result.get("id"), Some(&json!("abc")));
    assert_eq!(result.get("name"), Some(&json!("Alice")));
    assert!(
        result.get("internal_token").is_none() || result["internal_token"].is_null(),
        "internal_token should be stripped"
    );
    assert!(
        result.get("noise").is_none() || result["noise"].is_null(),
        "noise should be stripped"
    );
}

/// Prove that an empty `response_transform` is a no-op: the raw response
/// passes through completely unchanged.
#[tokio::test]
async fn response_transform_noop_when_config_is_empty() {
    // GIVEN: empty (default) transform config
    let config = TransformConfig::default();
    assert!(config.is_empty(), "default config must be empty");
    let transform = ResponseTransform::new(&config);

    // AND: a response with various fields
    let raw = json!({
        "content": [{"type": "text", "text": "hello"}],
        "is_error": false,
        "extra": "field"
    });

    // WHEN: transforming
    let result = transform
        .transform_result("tool", raw.clone())
        .await
        .unwrap();

    // THEN: result is identical to input
    assert_eq!(result, raw);
}

/// Prove redact patterns fire on all string values recursively.
#[tokio::test]
async fn response_transform_redact_replaces_sensitive_patterns() {
    // GIVEN: redact rule for credit card numbers
    let config = TransformConfig {
        redact: vec![RedactRule {
            pattern: r"\b\d{4}-\d{4}-\d{4}-\d{4}\b".to_string(),
            replacement: "[CC_REDACTED]".to_string(),
        }],
        ..Default::default()
    };
    let transform = ResponseTransform::new(&config);

    // AND: a response containing a card number in a nested field
    let raw = json!({
        "user": "Alice",
        "payment": {
            "card": "1234-5678-9012-3456",
            "valid": true
        }
    });

    // WHEN: transforming
    let result = transform
        .transform_result("billing_tool", raw)
        .await
        .unwrap();

    // THEN: the card number is redacted everywhere
    let card_val = result["payment"]["card"].as_str().unwrap();
    assert_eq!(card_val, "[CC_REDACTED]");
    // Non-sensitive fields are untouched
    assert_eq!(result["user"], json!("Alice"));
}

// ------------------------------------------------------------------
// MIK-3534: canonical projection wiring (apply_capability_projection)
// ------------------------------------------------------------------

/// LEAK GUARD: projection runs *after* `response_transform`, so the
/// preserved `_raw` is built from the already-redacted payload. A field
/// redacted by `response_transform` must not reappear anywhere — including
/// under `_raw`. This is the assertion that closes the prior concern about
/// projection re-exposing redacted data.
#[tokio::test]
async fn projection_after_redaction_keeps_raw_redacted() {
    // GIVEN: response_transform redacts a card number...
    let rt = ResponseTransform::new(&TransformConfig {
        redact: vec![RedactRule {
            pattern: r"\b\d{4}-\d{4}-\d{4}-\d{4}\b".to_string(),
            replacement: "[CC_REDACTED]".to_string(),
        }],
        ..Default::default()
    });
    // ...AND the capability also declares a projection spec.
    let spec = ProjectionSpec {
        subject: Some(SubjectSpec {
            title: Some("user".into()),
            ..Default::default()
        }),
        ..Default::default()
    };
    let inner = json!({"user": "Alice", "card": "1234-5678-9012-3456"});

    // WHEN: dispatch applies response_transform FIRST...
    let transformed = rt.transform_result("billing", inner).await.unwrap();
    // ...THEN canonical projection (bare value — no MCP envelope here).
    let out = apply_capability_projection(transformed, &spec, false);

    // THEN: the canonical bucket is built from the redacted payload
    assert_eq!(out["subject"]["title"], json!("Alice"));
    // AND: _raw preserves the payload with the card already redacted
    assert_eq!(out["_raw"]["card"], json!("[CC_REDACTED]"));
    // AND: the sensitive value appears NOWHERE in the output
    let serialized = serde_json::to_string(&out).unwrap();
    assert!(
        !serialized.contains("1234-5678"),
        "redacted value leaked through projection: {serialized}"
    );
}

/// `_full: true` bypasses projection entirely (the same gate that
/// `response_transform` rides), returning the unprojected payload.
#[test]
fn projection_want_full_bypasses() {
    let spec = ProjectionSpec {
        subject: Some(SubjectSpec {
            title: Some("user".into()),
            ..Default::default()
        }),
        ..Default::default()
    };
    let raw = json!({"user": "Alice", "extra": 1});
    let out = apply_capability_projection(raw.clone(), &spec, true);
    assert_eq!(
        out, raw,
        "_full must return the unprojected payload unchanged"
    );
}

/// Fail-fast: a spec that resolves no fields leaves the payload untouched
/// (no `_raw` wrapper), inheriting `engine::project`'s contract.
#[test]
fn projection_fail_fast_passthrough_when_nothing_maps() {
    let spec = ProjectionSpec {
        actor: Some(ActorSpec {
            email: Some("nonexistent.path".into()),
            ..Default::default()
        }),
        ..Default::default()
    };
    let raw = json!({"id": "x", "name": "y"});
    let out = apply_capability_projection(raw.clone(), &spec, false);
    assert_eq!(out, raw);
    assert!(
        out.get("_raw").is_none(),
        "no projection wrapper when nothing maps"
    );
}

/// Projection targets the INNER capability payload inside an MCP envelope
/// (`structuredContent`), not the outer envelope — guards bug #167.
#[test]
fn projection_targets_inner_payload_inside_mcp_envelope() {
    let spec = ProjectionSpec {
        subject: Some(SubjectSpec {
            title: Some("issue.title".into()),
            ..Default::default()
        }),
        ..Default::default()
    };
    let envelope = json!({
        "content": [{"type": "text", "text": "{\"issue\":{\"title\":\"Fix bug\"}}"}],
        "structuredContent": {"issue": {"title": "Fix bug"}},
        "isError": false
    });
    let out = apply_capability_projection(envelope, &spec, false);
    // The projected canonical view lives in structuredContent, not the
    // outer envelope.
    assert_eq!(
        out["structuredContent"]["subject"]["title"],
        json!("Fix bug")
    );
    assert_eq!(
        out["structuredContent"]["_raw"]["issue"]["title"],
        json!("Fix bug")
    );
}

/// Fail-fast on a single-text-content MCP envelope whose text is NOT JSON:
/// projection resolves nothing, so the envelope must pass through unchanged.
/// Re-wrapping would clobber the human-readable text with a JSON dump of the
/// envelope — this is the regression guard for that path.
#[test]
fn projection_fail_fast_leaves_text_envelope_untouched() {
    let spec = ProjectionSpec {
        subject: Some(SubjectSpec {
            id: Some("issue.id".into()),
            ..Default::default()
        }),
        ..Default::default()
    };
    let envelope = json!({
        "content": [{"type": "text", "text": "Issue ISS-1 created"}],
        "isError": false
    });
    let out = apply_capability_projection(envelope.clone(), &spec, false);
    assert_eq!(
        out, envelope,
        "non-matching spec must pass the text envelope through untouched"
    );
}

/// An error envelope is never projected — even when the spec would match the
/// inner payload — so error text stays legible for the recovery classifier.
#[test]
fn projection_skips_error_envelopes() {
    let spec = ProjectionSpec {
        subject: Some(SubjectSpec {
            title: Some("issue.title".into()),
            ..Default::default()
        }),
        ..Default::default()
    };
    let envelope = json!({
        "structuredContent": {"issue": {"title": "boom"}},
        "content": [{"type": "text", "text": "error: boom"}],
        "isError": true
    });
    let out = apply_capability_projection(envelope.clone(), &spec, false);
    assert_eq!(out, envelope, "error envelopes must not be projected");
}

// MIK-7212.MRTR.2a: a backend's own `requestState` must not reach the
// client verbatim. The mint that replaces it (`invoke.rs:1909-1937`)
// rewrites the top-level field only, and it runs *after* the dispatch path
// that calls `enforce_output_schema`. So if schema enforcement republishes
// the whole envelope under `structuredContent`, the backend's string
// survives the mint in a second location.
#[test]
fn mrtr_2a_enforce_output_schema_does_not_republish_backend_request_state() {
    // An interim envelope as a backend sends it: a human-readable prompt in
    // `content` (not JSON, so there is no validation target to extract) and
    // the backend's own opaque `requestState` alongside it.
    let envelope = json!({
        "content": [{"type": "text", "text": "Which account should I use?"}],
        "requestState": "backend-opaque-state-abc123"
    });
    let schema = json!({"type": "object"});

    let result = enforce_output_schema("demo", "ask", envelope, Some(&schema));

    let republished = result
        .get("structuredContent")
        .and_then(|s| s.get("requestState"))
        .and_then(|v| v.as_str());
    assert_eq!(
        republished, None,
        "backend requestState republished under structuredContent: {result:#}"
    );

    // The second channel: `apply_validated_output` also rewrites a single
    // text item with a dump of whatever it validated, so an envelope
    // republished into `content[0].text` leaks the same string in prose.
    let rendered = result.pointer("/content/0/text").and_then(|v| v.as_str());
    assert_eq!(
        rendered,
        Some("Which account should I use?"),
        "backend requestState republished into content[0].text: {result:#}"
    );

    // Returning the envelope UNCHANGED is the contract the guard rests on,
    // not merely the absence of the two leaks above.
    assert_eq!(
        result,
        json!({
            "content": [{"type": "text", "text": "Which account should I use?"}],
            "requestState": "backend-opaque-state-abc123"
        }),
        "an envelope with no extractable payload was not returned unchanged"
    );

    // The other way to have nothing extractable: more than one content
    // item. `extract_output_validation_target` requires exactly one, so a
    // multi-item envelope takes the same arm and must be equally untouched.
    let multi = json!({
        "content": [
            {"type": "text", "text": "Which account should I use?"},
            {"type": "text", "text": "personal or work"}
        ],
        "requestState": "backend-opaque-state-abc123"
    });

    assert_eq!(
        enforce_output_schema("demo", "ask", multi.clone(), Some(&schema)),
        multi,
        "a multi-item envelope was not returned unchanged"
    );
}

// The other half of the predicate: a BARE payload is not an envelope just
// because it carries a field called `content`, and it must still be
// validated against the tool's schema rather than passed through.
#[test]
fn enforce_output_schema_validates_a_bare_payload_with_a_content_field() {
    let payload = json!({"content": "a string, not an array of content items"});
    let schema = json!({
        "type": "object",
        "properties": {"content": {"type": "string"}},
        "required": ["content"]
    });

    let result = enforce_output_schema("demo", "describe", payload.clone(), Some(&schema));

    assert_eq!(
        result, payload,
        "a bare payload is its own validation target and coerces to itself"
    );
}

#[test]
fn enforce_output_schema_accepts_valid_result() {
    let schema = json!({
        "type": "object",
        "properties": {
            "id": { "type": "string" },
            "count": { "type": "integer" }
        },
        "required": ["id", "count"]
    });

    let result = enforce_output_schema(
        "demo",
        "search",
        json!({"id": "abc", "count": 2}),
        Some(&schema),
    );

    assert_eq!(result["id"], json!("abc"));
    assert_eq!(result["count"], json!(2));
}

#[test]
fn enforce_output_schema_passes_through_unexpected_fields_advisory() {
    // Output-schema mismatch is advisory for proxied tools: extra fields
    // from a real upstream API must NOT break the call. The result passes
    // through and structuredContent is still populated (with the extras).
    let schema = json!({
        "type": "object",
        "properties": {
            "data": { "type": "string" }
        },
        "required": ["data"]
    });

    let result = enforce_output_schema(
        "demo",
        "get_data",
        json!({"data": "ok", "extra": "value"}),
        Some(&schema),
    );

    // The raw payload (including the extra field) is preserved.
    assert_eq!(result.get("data").and_then(|v| v.as_str()), Some("ok"));
    assert_eq!(result.get("extra").and_then(|v| v.as_str()), Some("value"));
}

#[test]
fn enforce_output_schema_validates_structured_content_inside_mcp_result() {
    let schema = json!({
        "type": "object",
        "properties": {
            "issue": {
                "type": "object",
                "properties": {
                    "id": { "type": "string" }
                },
                "required": ["id"]
            }
        },
        "required": ["issue"]
    });

    let result = enforce_output_schema(
        "fulcrum",
        "linear_get_issue",
        json!({
            "content": [{
                "type": "text",
                "text": "{\"issue\":{\"id\":\"abc\"}}"
            }],
            "structuredContent": { "issue": { "id": "abc" } },
            "isError": false
        }),
        Some(&schema),
    );

    assert_eq!(result["structuredContent"]["issue"]["id"], json!("abc"));
    assert_eq!(
        result["content"][0]["text"],
        json!("{\n  \"issue\": {\n    \"id\": \"abc\"\n  }\n}")
    );
}

#[test]
fn enforce_output_schema_skips_mcp_error_envelopes() {
    let schema = json!({
        "type": "object",
        "properties": {
            "issue": { "type": "object" }
        }
    });

    let result = enforce_output_schema(
        "fulcrum",
        "linear_get_issue",
        json!({
            "content": [{
                "type": "text",
                "text": "bad input"
            }],
            "isError": true
        }),
        Some(&schema),
    );

    assert_eq!(result["isError"], json!(true));
    assert_eq!(result["content"][0]["text"], json!("bad input"));
}

// Minor 10 (b) — MIK-6865.SCHEMA.1: a scalar or bare-array
// `structuredContent` must survive `enforce_output_schema` unchanged when
// the declared `outputSchema` itself is non-object (`type: string`,
// `type: array`). Every other fixture in this file declares
// `type: object`; this is the clause none of them exercise.
#[test]
fn ac_schema_10b_scalar_structured_content_survives_enforce_output_schema() {
    let schema = json!({ "type": "string" });

    // The discriminating assertion. `enforce_output_schema` is advisory on
    // mismatch (see its else arm) and returns the payload either way, so
    // the survival check below passes whether the scalar validated or was
    // rejected and waved through. Only this one fails if support for a
    // non-object `outputSchema` regresses.
    let validation = validate_output(&json!("hello"), &schema);
    assert!(
        validation.is_valid(),
        "a scalar structuredContent must validate against a type: string outputSchema, not merely survive: {}",
        validation.format_output_error(&schema)
    );

    let result = enforce_output_schema(
        "demo",
        "echo",
        json!({
            "content": [{"type": "text", "text": "hello"}],
            "structuredContent": "hello",
            "isError": false
        }),
        Some(&schema),
    );

    assert_eq!(result["structuredContent"], json!("hello"));
}

#[test]
fn ac_schema_10b_bare_array_structured_content_survives_enforce_output_schema() {
    let schema = json!({ "type": "array", "items": { "type": "string" } });

    let validation = validate_output(&json!(["a", "b"]), &schema);
    assert!(
        validation.is_valid(),
        "a bare-array structuredContent must validate against a type: array outputSchema, not merely survive: {}",
        validation.format_output_error(&schema)
    );

    let result = enforce_output_schema(
        "demo",
        "list_things",
        json!({
            "content": [{"type": "text", "text": "[\"a\",\"b\"]"}],
            "structuredContent": ["a", "b"],
            "isError": false
        }),
        Some(&schema),
    );

    assert_eq!(result["structuredContent"], json!(["a", "b"]));
}

#[tokio::test]
async fn response_transform_runs_before_output_validation() {
    let transform = ResponseTransform::new(&TransformConfig {
        project: vec!["id".to_string()],
        ..Default::default()
    });
    let raw = json!({
        "id": "abc",
        "internal_token": "secret"
    });
    let transformed = transform.transform_result("my_tool", raw).await.unwrap();
    let schema = json!({
        "type": "object",
        "properties": {
            "id": { "type": "string" }
        },
        "required": ["id"]
    });

    let result = enforce_output_schema("demo", "my_tool", transformed, Some(&schema));

    assert_eq!(result, json!({"id": "abc"}));
}

/// Verify `TransformConfig::is_empty` returns expected values.
#[test]
fn transform_config_is_empty_tracks_all_fields() {
    // Default is empty
    assert!(TransformConfig::default().is_empty());

    // project non-empty
    assert!(
        !TransformConfig {
            project: vec!["x".to_string()],
            ..Default::default()
        }
        .is_empty()
    );

    // rename non-empty
    assert!(
        !TransformConfig {
            rename: [("a".to_string(), "b".to_string())].into(),
            ..Default::default()
        }
        .is_empty()
    );

    // redact non-empty
    assert!(
        !TransformConfig {
            redact: vec![RedactRule {
                pattern: "x".to_string(),
                replacement: "y".to_string(),
            }],
            ..Default::default()
        }
        .is_empty()
    );
}

/// `json_is_populated` truth table — the basis of the fail-fast guard.
#[test]
fn json_is_populated_truth_table() {
    use super::json_is_populated;
    assert!(!json_is_populated(&json!(null)));
    assert!(!json_is_populated(&json!({})));
    assert!(!json_is_populated(&json!([])));
    assert!(json_is_populated(&json!({"id": 1})));
    assert!(json_is_populated(&json!([1])));
    assert!(json_is_populated(&json!("x")));
    assert!(json_is_populated(&json!(0)));
    assert!(json_is_populated(&json!(false)));
}

/// Fail-fast trigger: projecting to a field absent from the response
/// empties it. `json_is_populated` returns false, so `dispatch_to_backend`
/// logs a warning (and still applies the projection — it never falls back
/// to the unprojected payload, which could leak dropped fields). Callers
/// pass `_full: true` to bypass projection (MIK-3533).
#[tokio::test]
async fn projection_to_absent_field_empties_payload_and_triggers_failsafe() {
    use super::json_is_populated;
    let config = TransformConfig {
        project: vec!["nonexistent_field".to_string()],
        ..Default::default()
    };
    let transform = ResponseTransform::new(&config);
    let raw = json!({ "id": "abc", "name": "Alice" });

    assert!(json_is_populated(&raw), "raw payload is populated");
    let transformed = transform.transform_result("tool", raw).await.unwrap();
    assert!(
        !json_is_populated(&transformed),
        "projecting to an absent field empties the payload -> warning logged"
    );
}

/// Healthy projection keeps real fields populated, so the fail-fast guard
/// does NOT fire and the projected response is used.
#[tokio::test]
async fn projection_to_present_field_stays_populated() {
    use super::json_is_populated;
    let config = TransformConfig {
        project: vec!["id".to_string()],
        ..Default::default()
    };
    let transform = ResponseTransform::new(&config);
    let raw = json!({ "id": "abc", "name": "Alice", "secret": "x" });

    let transformed = transform.transform_result("tool", raw).await.unwrap();
    assert!(
        json_is_populated(&transformed),
        "a projection that keeps a present field stays populated"
    );
    assert_eq!(transformed.get("id"), Some(&json!("abc")));
}
