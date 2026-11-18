// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Map tools' loader rows (LD): `rate_limit`, `attribution` and strict keys, judged where
//! the loader, the editor's writer and the validate route all parse a file
//! (`parse_capability_text`).

use std::path::Path;

use crate::capability::parser::parse_capability_text;

const FILE: &str = "maps/t.yaml";

/// A valid paced, attributed REST capability. Each row changes one thing.
const BASE: &str = r#"fulcrum: "1.0"
name: t
description: d
attribution: "© OpenStreetMap contributors"
schema:
  input:
    type: object
    properties:
      q:
        type: string
  output:
    type: object
    properties:
      attribution:
        type: string
providers:
  primary:
    service: rest
    rate_limit:
      interval_ms: 1000
    config:
      endpoint: https://example.org/search
      method: GET
"#;

fn parse(text: &str) -> crate::Result<crate::capability::CapabilityDefinition> {
    parse_capability_text(text, Path::new(FILE))
}

fn with(old: &str, new: &str) -> String {
    assert_eq!(
        BASE.matches(old).count(),
        1,
        "fixture edit must hit once: {old}"
    );
    BASE.replacen(old, new, 1)
}

fn refusal(text: &str) -> String {
    match parse(text) {
        Ok(_) => panic!("expected a refusal, the file loaded"),
        Err(e) => e.to_string(),
    }
}

fn interval(text: &str) -> u64 {
    let cap = parse(text).expect("loads");
    cap.providers
        .get("primary")
        .expect("primary")
        .rate_limit
        .expect("rate_limit")
        .interval_ms
}

#[test]
fn ld0_the_base_fixture_loads_with_its_interval_and_attribution() {
    let cap = parse(BASE).expect("loads");
    assert_eq!(
        cap.attribution.as_deref(),
        Some("© OpenStreetMap contributors")
    );
    assert_eq!(interval(BASE), 1000);
}

// ── LD1: interval bounds, both sides ─────────────────────────────────

#[test]
fn ld1_interval_bounds_are_accepted() {
    assert_eq!(interval(&with("interval_ms: 1000", "interval_ms: 1")), 1);
    assert_eq!(
        interval(&with("interval_ms: 1000", "interval_ms: 600000")),
        600_000
    );
}

#[test]
fn ld1_interval_outside_its_bounds_is_refused() {
    for bad in ["0", "600001"] {
        let text = with("interval_ms: 1000", &format!("interval_ms: {bad}"));
        assert_eq!(
            refusal(&text),
            format!(
                "Configuration error: {FILE}: providers.primary.rate_limit.interval_ms is {bad}; \
                 it must be a whole number of milliseconds from 1 to 600000"
            ),
        );
    }
}

#[test]
fn ld1_a_non_integer_or_missing_interval_is_refused() {
    assert!(parse(&with("interval_ms: 1000", "interval_ms: 1.5")).is_err());
    assert!(parse(&with("interval_ms: 1000", "{}")).is_err());
}

#[test]
fn ld1_an_interval_past_the_duration_bound_is_refused_as_it_parses() {
    // 100 years is 3155760000000 ms: one more passes no duration bound.
    let refused = refusal(&with("interval_ms: 1000", "interval_ms: 3155760000001"));
    assert!(
        refused.contains("this duration is longer than 100 years, the most any duration may be"),
        "the shared duration bound refuses it before the load rule: {refused}"
    );
}

// ── LD2: strict keys name the nearest key ────────────────────────────

#[test]
fn ld2_a_misspelt_provider_key_names_the_nearest() {
    assert_eq!(
        refusal(&with("    rate_limit:\n", "    rate_lmit:\n")),
        format!(
            "Configuration error: {FILE}: key `rate_lmit` is not a capability provider field. \
             Did you mean: rate_limit?"
        ),
    );
}

#[test]
fn ld2_a_misspelt_top_level_key_names_the_nearest() {
    assert_eq!(
        refusal(&with("attribution: \"©", "attributon: \"©")),
        format!(
            "Configuration error: {FILE}: key `attributon` is not a capability field. \
             Did you mean: attribution?"
        ),
    );
}

#[test]
fn ld2_a_misspelt_rate_limit_key_names_the_nearest() {
    assert_eq!(
        refusal(&with("interval_ms: 1000", "intervl_ms: 1000")),
        format!(
            "Configuration error: {FILE}: key `intervl_ms` is not a rate_limit field. \
             Did you mean: interval_ms?"
        ),
    );
}

#[test]
fn ld2_a_key_with_no_near_match_lists_the_accepted_keys() {
    assert_eq!(
        refusal(&with("    rate_limit:\n", "    zzzzzzzzzz:\n")),
        format!(
            "Configuration error: {FILE}: key `zzzzzzzzzz` is not a capability provider field. \
             Accepted keys: config, cost_per_call, rate_limit, service, timeout."
        ),
    );
}

#[test]
fn ld2_annotation_keys_still_load() {
    // `_` and `x-` keys are the author's notes (providers.rs, `Tracked`).
    let text = with("description: d\n", "description: d\n_note: n\nx-owner: o\n");
    assert!(parse(&text).is_ok());
    let text = with(
        "    service: rest\n",
        "    service: rest\n    _note: n\n    x-owner: o\n",
    );
    assert!(parse(&text).is_ok());
}

#[test]
fn ld2_metadata_stays_lenient() {
    let text = with(
        "description: d\n",
        "description: d\nmetadata:\n  rate_limit: \"1 req/sec\"\n",
    );
    assert!(parse(&text).is_ok());
}

// ── LD3: where a rate_limit may stand ────────────────────────────────

#[test]
fn ld3_rate_limit_on_graphql_or_jsonrpc_is_refused() {
    for service in ["graphql", "jsonrpc"] {
        let text = with("service: rest", &format!("service: {service}"));
        assert_eq!(
            refusal(&text),
            format!(
                "Configuration error: {FILE}: providers.primary.rate_limit is for REST providers; \
                 this provider's service is {service}"
            ),
        );
    }
}

#[test]
fn ld3_a_paced_provider_with_a_templated_host_is_refused() {
    let text = with(
        "endpoint: https://example.org/search",
        "endpoint: https://{region}.example.org/search",
    );
    let text = text.replacen(
        "      q:\n",
        "      region:\n        type: string\n      q:\n",
        1,
    );
    assert_eq!(
        refusal(&text),
        format!(
            "Configuration error: {FILE}: providers.primary.rate_limit needs a fixed host; \
             the endpoint's host is templated"
        ),
    );
}

// ── LD4: attribution and the output schema ───────────────────────────

#[test]
fn ld4_an_empty_or_blank_attribution_is_refused() {
    for blank in ["\"\"", "\"   \""] {
        let text = with(
            "attribution: \"© OpenStreetMap contributors\"",
            &format!("attribution: {blank}"),
        );
        assert_eq!(
            refusal(&text),
            format!("Configuration error: {FILE}: attribution is empty"),
        );
    }
}

#[test]
fn ld4_attribution_needs_its_output_schema_property() {
    let text = with(
        "    properties:\n      attribution:\n        type: string\n",
        "    properties:\n      name:\n        type: string\n",
    );
    assert_eq!(
        refusal(&text),
        format!(
            "Configuration error: {FILE}: attribution is declared, so schema.output must declare \
             an `attribution` string property"
        ),
    );
}

#[test]
fn ld4b_attribution_on_a_non_object_output_root_is_refused() {
    let text = with(
        "  output:\n    type: object\n    properties:\n      attribution:\n        type: string\n",
        "  output:\n    type: array\n    items:\n      type: object\n",
    );
    assert_eq!(
        refusal(&text),
        format!(
            "Configuration error: {FILE}: attribution is declared, so schema.output must be an \
             object; this one is array"
        ),
    );
}

#[test]
fn ld4b_control_an_object_root_with_results_loads() {
    let text = with(
        "      attribution:\n        type: string\n",
        "      attribution:\n        type: string\n      results:\n        type: array\n",
    );
    assert!(parse(&text).is_ok());
}

#[test]
fn ld4c_an_attribution_property_of_another_type_is_refused() {
    let text = with(
        "      attribution:\n        type: string\n",
        "      attribution:\n        type: integer\n",
    );
    assert_eq!(
        refusal(&text),
        format!(
            "Configuration error: {FILE}: attribution is declared, so schema.output must declare \
             an `attribution` string property"
        ),
    );
}

#[test]
fn ld3b_a_paced_provider_with_no_host_is_refused() {
    let text = with("endpoint: https://", "endpoint: not-a-url-");
    assert_eq!(
        refusal(&text),
        format!(
            "Configuration error: {FILE}: providers.primary.rate_limit needs a fixed host; \
             its URL has none"
        ),
    );
}

#[test]
fn ld4d_attribution_on_a_type_list_root_is_refused() {
    let text = with(
        "  output:\n    type: object\n",
        "  output:\n    type: [array, \"null\"]\n",
    );
    assert_eq!(
        refusal(&text),
        format!(
            "Configuration error: {FILE}: attribution is declared, so schema.output must be an \
             object; this one is [\"array\",\"null\"]"
        ),
    );
}
