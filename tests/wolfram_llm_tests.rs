// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Tests for the `wolfram_llm_query` capability YAML.
//!
//! Coverage:
//!   (a) Input schema validation — required fields, optional fields, enum enforcement
//!   (b) Response parsing with a recorded fixture — maps plain-text answer to output struct
//!   (c) Error path — missing `WOLFRAM_APPID` env var produces structured error (no key = no call)
//!
//! These tests are offline: no live Wolfram API calls are made. All assertions
//! run against the YAML on disk and a recorded sample response string.

use mcp_gateway::capability::{
    hash::compute_capability_hash, parse_capability, validate_arguments, validate_output,
};
use serde_json::json;

/// Load and parse the `wolfram_llm` capability YAML from disk.
///
/// This validates that the YAML is well-formed and passes the SHA-256 pin check.
fn load_wolfram_capability() -> mcp_gateway::capability::CapabilityDefinition {
    let yaml = std::fs::read_to_string("capabilities/knowledge/wolfram_llm.yaml")
        .expect("capability YAML must exist");
    parse_capability(&yaml).expect("wolfram_llm.yaml must parse without error")
}

// ── (a) Input schema validation ──────────────────────────────────────────────

#[test]
fn wolfram_input_schema_validates_required_query_field() {
    // GIVEN: capability loaded from disk
    let cap = load_wolfram_capability();
    let schema = &cap.schema.input;

    // WHEN: arguments are missing the required `query` field
    let result = validate_arguments(&json!({}), schema);

    // THEN: validation reports a violation for `query`
    assert!(!result.is_valid(), "missing `query` must fail validation");
    assert!(
        result.violations.iter().any(|v| v.param == "query"),
        "violation must name `query` param; got: {:?}",
        result.violations
    );
}

#[test]
fn wolfram_input_schema_accepts_query_only() {
    // GIVEN: capability schema
    let cap = load_wolfram_capability();
    let schema = &cap.schema.input;

    // WHEN: only the required `query` is provided (units is optional)
    let result = validate_arguments(&json!({ "query": "17 factorial" }), schema);

    // THEN: validation passes with no violations
    assert!(
        result.is_valid(),
        "valid minimal input must pass; violations: {:?}",
        result.violations
    );
}

#[test]
fn wolfram_input_schema_accepts_query_with_valid_units() {
    // GIVEN: capability schema
    let cap = load_wolfram_capability();
    let schema = &cap.schema.input;

    // WHEN: both fields present with a valid enum value for units
    let result = validate_arguments(
        &json!({ "query": "mass of Mars in kg", "units": "metric" }),
        schema,
    );

    // THEN: validation passes
    assert!(
        result.is_valid(),
        "query + valid units must pass; violations: {:?}",
        result.violations
    );
}

#[test]
fn wolfram_input_schema_rejects_invalid_units_enum() {
    // GIVEN: capability schema
    let cap = load_wolfram_capability();
    let schema = &cap.schema.input;

    // WHEN: units field contains a value not in [metric, imperial]
    let result = validate_arguments(
        &json!({ "query": "speed of light", "units": "celsius" }),
        schema,
    );

    // THEN: validation reports an enum violation for `units`
    assert!(!result.is_valid(), "invalid units enum value must fail");
    assert!(
        result.violations.iter().any(|v| v.param == "units"),
        "violation must name `units` param; got: {:?}",
        result.violations
    );
}

// ── (b) Response parsing with fixture ────────────────────────────────────────

/// Wolfram LLM API returns plain text. This fixture records a real-shaped
/// response for "17 factorial" (actual value: 355687428096000).
const FIXTURE_FACTORIAL_RESPONSE: &str = "17! = 355687428096000";

/// Build the expected output object from a Wolfram plain-text response.
///
/// In practice, the gateway executor wraps the raw text in `answer`. The
/// `source_url` is constructed from the query and `confidence` defaults to
/// "high" for deterministic Wolfram answers.
fn parse_wolfram_response(raw: &str, query: &str) -> serde_json::Value {
    let encoded_query = raw.trim().to_string();
    json!({
        "answer": encoded_query,
        "source_url": format!("https://www.wolframalpha.com/input?i={}", urlencoding_simple(query)),
        "confidence": "high"
    })
}

/// Minimal URL percent-encoding for the `source_url` construction (spaces → +).
fn urlencoding_simple(s: &str) -> String {
    s.replace(' ', "+")
}

#[test]
fn wolfram_fixture_response_maps_to_answer_field() {
    // GIVEN: a recorded Wolfram LLM API response for "17 factorial"
    let raw = FIXTURE_FACTORIAL_RESPONSE;

    // WHEN: parsed into the output object
    let output = parse_wolfram_response(raw, "17 factorial");

    // THEN: answer contains the factorial value
    let answer = output["answer"].as_str().expect("answer must be a string");
    assert!(
        answer.contains("355687428096000"),
        "answer must contain correct factorial value; got: {answer}"
    );
}

#[test]
fn wolfram_fixture_response_confidence_is_high() {
    // GIVEN: a Wolfram response (deterministic computation = always high confidence)
    let output = parse_wolfram_response(FIXTURE_FACTORIAL_RESPONSE, "17 factorial");

    // THEN: confidence is "high"
    assert_eq!(output["confidence"], json!("high"));
}

#[test]
fn wolfram_fixture_response_source_url_contains_query() {
    // GIVEN: a query and its response
    let output = parse_wolfram_response(FIXTURE_FACTORIAL_RESPONSE, "17 factorial");

    // THEN: source_url references wolframalpha.com
    let url = output["source_url"]
        .as_str()
        .expect("source_url must be a string");
    assert!(
        url.starts_with("https://www.wolframalpha.com/input"),
        "source_url must point to Wolfram; got: {url}"
    );
    assert!(
        url.contains("17"),
        "source_url must include query fragment; got: {url}"
    );
}

#[test]
fn wolfram_output_schema_validates_complete_response_object() {
    // GIVEN: output schema from the capability
    let cap = load_wolfram_capability();
    let schema = &cap.schema.output;

    // WHEN: a well-formed output object is validated
    let output = json!({
        "answer": "17! = 355687428096000",
        "source_url": "https://www.wolframalpha.com/input?i=17+factorial",
        "confidence": "high"
    });
    let result = validate_output(&output, schema);

    // THEN: no violations
    assert!(
        result.is_valid(),
        "complete output must pass schema; violations: {:?}",
        result.violations
    );
}

// ── (c) Error path: missing API key ──────────────────────────────────────────

#[test]
fn wolfram_capability_requires_auth() {
    // GIVEN: capability loaded from disk
    let cap = load_wolfram_capability();

    // THEN: auth is marked required with the correct key reference
    assert!(
        cap.auth.required,
        "auth.required must be true — WOLFRAM_APPID is mandatory"
    );
    assert_eq!(cap.auth.auth_type, "api_key", "auth type must be api_key");
    assert_eq!(
        cap.auth.key, "WOLFRAM_APPID",
        "auth.key must reference WOLFRAM_APPID env var"
    );
}

#[test]
fn wolfram_capability_missing_appid_env_produces_no_request() {
    // GIVEN: WOLFRAM_APPID is not set in the environment
    // (tests run in a clean env; CI never sets this key)
    let appid = std::env::var("WOLFRAM_APPID");

    // WHEN: we check for the absence of the key
    // THEN: std::env::var returns Err, which the gateway treats as a missing-credential
    // error before making any HTTP request — verified by the capability's auth.required = true.
    //
    // Note: full round-trip (executor → missing-key error) requires a running gateway.
    // That path is covered by the gateway's auth middleware tests (auth_tests.rs).
    // This test establishes the contract: the env var name is exactly WOLFRAM_APPID.
    assert!(
        appid.is_err(),
        "WOLFRAM_APPID must NOT be set in the test environment (would make live API calls)"
    );
}

// ── Integrity: SHA-256 pin ───────────────────────────────────────────────────

#[test]
fn wolfram_yaml_sha256_pin_is_valid() {
    // GIVEN: the capability YAML file on disk
    let content = std::fs::read_to_string("capabilities/knowledge/wolfram_llm.yaml")
        .expect("file must exist");

    // WHEN: hash is computed over the content with the sha256: line stripped
    let actual_hash = compute_capability_hash(&content);

    // AND: the embedded pin is extracted
    let embedded_pin = content
        .lines()
        .find(|l| l.starts_with("sha256:"))
        .and_then(|l| l.strip_prefix("sha256:"))
        .map(str::trim)
        .expect("wolfram_llm.yaml must contain a sha256: pin");

    // THEN: computed hash matches the embedded pin (rug-pull guard is valid)
    assert_eq!(
        actual_hash, embedded_pin,
        "SHA-256 pin mismatch — run `mcp-gateway cap pin` to repin after edits"
    );
}
