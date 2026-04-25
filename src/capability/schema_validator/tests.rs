use super::*;
use serde_json::json;

// ── Helper ──────────────────────────────────────────────────────────────

#[allow(clippy::needless_pass_by_value)]
fn schema_with_props(props: serde_json::Value, required: &[&str]) -> serde_json::Value {
    json!({
        "type": "object",
        "properties": props,
        "required": required
    })
}

// ── Required parameters ─────────────────────────────────────────────────

#[test]
fn required_param_missing_produces_violation() {
    // GIVEN: schema requiring "query", WHEN: args are empty
    let schema = schema_with_props(json!({ "query": { "type": "string" } }), &["query"]);
    let result = validate_arguments(&json!({}), &schema);

    // THEN: violation for missing required param
    assert!(!result.is_valid());
    assert_eq!(result.violations[0].param, "query");
    assert!(result.violations[0].message.contains("missing"));
}

#[test]
fn required_param_null_produces_violation() {
    // GIVEN: schema requiring "symbol", WHEN: args provide null
    let schema = schema_with_props(json!({ "symbol": { "type": "string" } }), &["symbol"]);
    let result = validate_arguments(&json!({ "symbol": null }), &schema);

    assert!(!result.is_valid());
    assert!(result.violations[0].message.contains("null"));
}

#[test]
fn required_param_present_passes() {
    // GIVEN: schema requiring "query", WHEN: args supply it
    let schema = schema_with_props(json!({ "query": { "type": "string" } }), &["query"]);
    let result = validate_arguments(&json!({ "query": "rust" }), &schema);

    assert!(result.is_valid());
}

#[test]
fn validate_output_reuses_object_schema_rules() {
    let schema = schema_with_props(
        json!({ "status": { "type": "string" }, "count": { "type": "integer" } }),
        &["status", "count"],
    );
    let result = validate_output(&json!({ "status": "ok", "count": "2" }), &schema);

    assert!(result.is_valid(), "violations: {:?}", result.violations);
    assert_eq!(result.coerced["count"], json!(2));
}

#[test]
fn output_error_heading_matches_result_validation() {
    let schema = schema_with_props(json!({ "status": { "type": "string" } }), &["status"]);
    let result = validate_output(&json!({}), &schema);
    let message = result.format_output_error(&schema);

    assert!(message.starts_with("Tool result validation failed:"));
    assert!(message.contains("status"));
}

// ── Unknown parameters ──────────────────────────────────────────────────

#[test]
fn unknown_param_produces_violation() {
    // GIVEN: schema with only "query", WHEN: args include "hallucinated_param"
    let schema = schema_with_props(json!({ "query": { "type": "string" } }), &["query"]);
    let result = validate_arguments(
        &json!({ "query": "rust", "hallucinated_param": "bad" }),
        &schema,
    );

    assert!(!result.is_valid());
    let unknown = result
        .violations
        .iter()
        .find(|v| v.param == "hallucinated_param")
        .expect("violation for hallucinated_param");
    assert!(unknown.message.contains("unknown parameter"));
}

#[test]
fn unknown_param_error_lists_valid_params() {
    // GIVEN: schema with "query" only, WHEN: unknown key sent
    let schema = schema_with_props(json!({ "query": { "type": "string" } }), &[]);
    let result = validate_arguments(&json!({ "bad_key": "v" }), &schema);

    let v = &result.violations[0];
    // The error message must mention the valid param "query"
    assert!(v.message.contains("query"), "message: {}", v.message);
}

// ── Type validation ─────────────────────────────────────────────────────

#[test]
fn string_value_for_integer_field_is_coerced() {
    // GIVEN: "count" declared as integer, WHEN: LLM passes "10" (string)
    let schema = schema_with_props(json!({ "count": { "type": "integer" } }), &[]);
    let result = validate_arguments(&json!({ "count": "10" }), &schema);

    // THEN: coercion succeeds, no violations
    assert!(result.is_valid(), "violations: {:?}", result.violations);
    assert_eq!(result.coerced["count"], json!(10));
}

#[test]
#[allow(clippy::approx_constant)] // 3.14 is the test input string, not π
fn string_value_for_number_field_is_coerced() {
    // GIVEN: "price" declared as number, WHEN: LLM passes "3.14"
    let schema = schema_with_props(json!({ "price": { "type": "number" } }), &[]);
    let result = validate_arguments(&json!({ "price": "3.14" }), &schema);

    assert!(result.is_valid());
    assert_eq!(result.coerced["price"], json!(3.14));
}

#[test]
fn string_true_for_boolean_field_is_coerced() {
    // GIVEN: "spellcheck" declared as boolean, WHEN: LLM passes "true"
    let schema = schema_with_props(json!({ "spellcheck": { "type": "boolean" } }), &[]);
    let result = validate_arguments(&json!({ "spellcheck": "true" }), &schema);

    assert!(result.is_valid());
    assert_eq!(result.coerced["spellcheck"], json!(true));
}

#[test]
fn string_false_for_boolean_field_is_coerced() {
    // GIVEN: "active" declared as boolean, WHEN: LLM passes "false"
    let schema = schema_with_props(json!({ "active": { "type": "boolean" } }), &[]);
    let result = validate_arguments(&json!({ "active": "false" }), &schema);

    assert!(result.is_valid());
    assert_eq!(result.coerced["active"], json!(false));
}

#[test]
fn wrong_type_not_coercible_produces_violation() {
    // GIVEN: "count" declared as integer, WHEN: LLM passes an object
    let schema = schema_with_props(json!({ "count": { "type": "integer" } }), &[]);
    let result = validate_arguments(&json!({ "count": {"nested": true} }), &schema);

    assert!(!result.is_valid());
    assert!(result.violations[0].message.contains("expected integer"));
}

#[test]
fn non_numeric_string_for_integer_field_produces_violation() {
    // GIVEN: "limit" declared as integer, WHEN: LLM passes "hello"
    let schema = schema_with_props(json!({ "limit": { "type": "integer" } }), &[]);
    let result = validate_arguments(&json!({ "limit": "hello" }), &schema);

    assert!(!result.is_valid());
    let msg = &result.violations[0].message;
    assert!(msg.contains("expected integer"), "message: {msg}");
}

#[test]
fn array_field_with_non_array_value_produces_violation() {
    // GIVEN: "tags" declared as array, WHEN: LLM passes a string
    let schema = schema_with_props(json!({ "tags": { "type": "array" } }), &[]);
    let result = validate_arguments(&json!({ "tags": "rust,async" }), &schema);

    assert!(!result.is_valid());
    assert!(result.violations[0].message.contains("expected array"));
}

// ── Enum validation ─────────────────────────────────────────────────────

#[test]
fn enum_value_valid_passes() {
    // GIVEN: "freshness" with enum [pd, pw, pm], WHEN: "pw" provided
    let schema = schema_with_props(
        json!({ "freshness": { "type": "string", "enum": ["pd", "pw", "pm"] } }),
        &[],
    );
    let result = validate_arguments(&json!({ "freshness": "pw" }), &schema);

    assert!(result.is_valid());
}

#[test]
fn enum_value_invalid_produces_violation() {
    // GIVEN: "safesearch" with enum [off, moderate, strict], WHEN: "none" sent
    let schema = schema_with_props(
        json!({ "safesearch": { "type": "string", "enum": ["off", "moderate", "strict"] } }),
        &[],
    );
    let result = validate_arguments(&json!({ "safesearch": "none" }), &schema);

    assert!(!result.is_valid());
    let msg = &result.violations[0].message;
    assert!(msg.contains("must be one of"), "message: {msg}");
    assert!(msg.contains("\"off\""), "message: {msg}");
}

// ── Numeric constraints ─────────────────────────────────────────────────

#[test]
fn value_exceeding_maximum_produces_violation() {
    // GIVEN: "count" with maximum 20, WHEN: 100 provided
    let schema = schema_with_props(
        json!({ "count": { "type": "integer", "maximum": 20 } }),
        &[],
    );
    let result = validate_arguments(&json!({ "count": 100 }), &schema);

    assert!(!result.is_valid());
    assert!(result.violations[0].message.contains("<= 20"));
}

#[test]
fn value_at_maximum_passes() {
    // GIVEN: "count" with maximum 20, WHEN: exactly 20 provided
    let schema = schema_with_props(
        json!({ "count": { "type": "integer", "maximum": 20 } }),
        &[],
    );
    let result = validate_arguments(&json!({ "count": 20 }), &schema);

    assert!(result.is_valid());
}

#[test]
fn value_below_minimum_produces_violation() {
    // GIVEN: "offset" with minimum 0, WHEN: -1 provided
    let schema = schema_with_props(
        json!({ "offset": { "type": "integer", "minimum": 0 } }),
        &[],
    );
    let result = validate_arguments(&json!({ "offset": -1 }), &schema);

    assert!(!result.is_valid());
    assert!(result.violations[0].message.contains(">= 0"));
}

// ── String constraints ──────────────────────────────────────────────────

#[test]
fn string_shorter_than_min_length_produces_violation() {
    // GIVEN: "password" with minLength 8, WHEN: "abc" provided
    let schema = schema_with_props(
        json!({ "password": { "type": "string", "minLength": 8 } }),
        &[],
    );
    let result = validate_arguments(&json!({ "password": "abc" }), &schema);

    assert!(!result.is_valid());
    assert!(
        result.violations[0]
            .message
            .contains("at least 8 characters")
    );
}

#[test]
fn string_longer_than_max_length_produces_violation() {
    // GIVEN: "code" with maxLength 5, WHEN: "toolong" provided
    let schema = schema_with_props(json!({ "code": { "type": "string", "maxLength": 5 } }), &[]);
    let result = validate_arguments(&json!({ "code": "toolong" }), &schema);

    assert!(!result.is_valid());
    assert!(
        result.violations[0]
            .message
            .contains("at most 5 characters")
    );
}

// ── No schema / null schema ─────────────────────────────────────────────

#[test]
fn null_schema_allows_any_arguments() {
    // GIVEN: null schema (no YAML schema defined)
    let result = validate_arguments(
        &json!({ "anything": "goes", "arbitrary": 42 }),
        &Value::Null,
    );
    assert!(result.is_valid());
}

#[test]
fn schema_without_properties_allows_any_arguments() {
    // GIVEN: schema with only "type: object" and no properties
    let schema = json!({ "type": "object" });
    let result = validate_arguments(&json!({ "foo": "bar" }), &schema);

    assert!(result.is_valid());
}

// ── format_error ────────────────────────────────────────────────────────

#[test]
fn format_error_includes_violation_messages() {
    // GIVEN: a schema with "query" required
    let schema = schema_with_props(
        json!({ "query": { "type": "string", "description": "Search query" } }),
        &["query"],
    );
    let result = validate_arguments(&json!({}), &schema);

    let error = result.format_error(&schema);
    assert!(error.contains("Tool call validation failed"));
    assert!(error.contains("query"));
    assert!(error.contains("missing"));
}

#[test]
fn format_error_lists_valid_parameters() {
    // GIVEN: schema with known params, WHEN: unknown param sent
    let schema = schema_with_props(
        json!({
            "query": { "type": "string", "description": "Search" },
            "count": { "type": "integer" }
        }),
        &["query"],
    );
    let result = validate_arguments(&json!({ "unknown": "x" }), &schema);

    let error = result.format_error(&schema);
    assert!(error.contains("Valid parameters"), "error: {error}");
    assert!(error.contains("query"), "error: {error}");
    assert!(error.contains("count"), "error: {error}");
}

// ── Edge cases ──────────────────────────────────────────────────────────

#[test]
fn optional_param_not_provided_is_accepted() {
    // GIVEN: schema with required "query" and optional "count"
    let schema = schema_with_props(
        json!({
            "query": { "type": "string" },
            "count": { "type": "integer" }
        }),
        &["query"],
    );
    let result = validate_arguments(&json!({ "query": "rust" }), &schema);

    assert!(result.is_valid());
}

#[test]
fn null_arguments_treated_as_empty_object() {
    // GIVEN: schema with no required params, WHEN: null arguments
    let schema = schema_with_props(json!({ "query": { "type": "string" } }), &[]);
    let result = validate_arguments(&Value::Null, &schema);

    assert!(result.is_valid());
}

#[test]
fn arguments_not_an_object_produces_violation() {
    // GIVEN: schema, WHEN: arguments is a plain array (invalid)
    let schema = schema_with_props(json!({ "q": { "type": "string" } }), &[]);
    let result = validate_arguments(&json!(["wrong", "type"]), &schema);

    assert!(!result.is_valid());
    assert!(result.violations[0].message.contains("JSON object"));
}

#[test]
fn float_with_zero_fraction_coerced_to_integer() {
    // GIVEN: "count" declared integer, WHEN: 10.0 provided (float with no fractional part)
    let schema = schema_with_props(json!({ "count": { "type": "integer" } }), &[]);
    let result = validate_arguments(&json!({ "count": 10.0 }), &schema);

    assert!(result.is_valid());
    assert_eq!(result.coerced["count"], json!(10));
}

#[test]
fn brave_search_realistic_valid_call() {
    // GIVEN: real brave_search schema, WHEN: valid LLM call
    let schema = json!({
        "type": "object",
        "properties": {
            "query": { "type": "string" },
            "count": { "type": "integer", "maximum": 20 },
            "safesearch": { "type": "string", "enum": ["off", "moderate", "strict"] },
            "freshness": { "type": "string", "enum": ["pd", "pw", "pm", "py"] },
            "spellcheck": { "type": "boolean" }
        },
        "required": ["query"]
    });
    let result = validate_arguments(
        &json!({ "query": "rust async", "count": 5, "safesearch": "moderate" }),
        &schema,
    );
    assert!(result.is_valid());
}

#[test]
fn brave_search_hallucinated_param_rejected() {
    // GIVEN: real brave_search schema, WHEN: LLM adds "language" (not in schema)
    let schema = json!({
        "type": "object",
        "properties": {
            "query": { "type": "string" },
            "count": { "type": "integer" }
        },
        "required": ["query"]
    });
    let result = validate_arguments(
        &json!({ "query": "rust", "language": "en", "format": "json" }),
        &schema,
    );
    assert!(!result.is_valid());
    // Both hallucinated params should appear
    let params: Vec<&str> = result.violations.iter().map(|v| v.param.as_str()).collect();
    assert!(params.contains(&"language"), "params: {params:?}");
    assert!(params.contains(&"format"), "params: {params:?}");
}

#[test]
fn stock_quote_missing_required_symbol() {
    // GIVEN: stock_quote schema requiring "symbol"
    let schema = json!({
        "type": "object",
        "properties": {
            "symbol": { "type": "string" }
        },
        "required": ["symbol"]
    });
    let result = validate_arguments(&json!({}), &schema);

    assert!(!result.is_valid());
    assert_eq!(result.violations[0].param, "symbol");
}

#[test]
fn coerced_args_used_in_valid_result() {
    // GIVEN: integer field with string value that can be coerced
    let schema = schema_with_props(
        json!({
            "query": { "type": "string" },
            "count": { "type": "integer" }
        }),
        &["query"],
    );
    let result = validate_arguments(&json!({ "query": "test", "count": "5" }), &schema);

    assert!(result.is_valid());
    // Coerced result must have integer 5, not string "5"
    assert_eq!(result.coerced["query"], json!("test"));
    assert_eq!(result.coerced["count"], json!(5));
}
