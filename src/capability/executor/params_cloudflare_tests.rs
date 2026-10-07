// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7818: the shipped Cloudflare capabilities refuse the calls they cannot
//! serve and serve the calls their schema allows.

use serde_json::{Value, json};

use super::super::CapabilityExecutor;
use crate::capability::{CapabilityDefinition, parse_capability, validate_arguments};

fn shipped(name: &str) -> CapabilityDefinition {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join(format!("capabilities/infrastructure/{name}.yaml"));
    let yaml = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{name}: {e}"));
    parse_capability(&yaml).unwrap_or_else(|e| panic!("{name}: {e}"))
}

fn valid(cap: &CapabilityDefinition, args: &Value) -> bool {
    validate_arguments(args, &cap.schema.input).is_valid()
}

/// MIK-7818.WAF.1
#[test]
fn get_waf_rules_without_a_phase_validates_and_uses_the_default_phase() {
    let cap = shipped("cloudflare_get_waf_rules");
    let args = json!({ "zone_id": "z1" });
    assert!(valid(&cap, &args), "a call without ruleset_phase is valid");

    let provider = cap.primary_provider().expect("a primary provider");
    let effective = super::with_path_defaults(&provider.config, &cap.schema.input, &args);
    let url = CapabilityExecutor::new()
        .build_url(&provider.config, effective.as_ref())
        .unwrap();
    assert_eq!(
        url,
        "https://api.cloudflare.com/client/v4/zones/z1/rulesets/phases/\
         http_request_firewall_custom/entrypoint"
    );

    // A phase the caller names still wins.
    let named = json!({ "zone_id": "z1", "ruleset_phase": "http_ratelimit" });
    let effective = super::with_path_defaults(&provider.config, &cap.schema.input, &named);
    let url = CapabilityExecutor::new()
        .build_url(&provider.config, effective.as_ref())
        .unwrap();
    assert!(url.contains("/phases/http_ratelimit/"), "{url}");
}

/// MIK-7818.PURGE.2
#[test]
fn purge_cache_needs_exactly_one_selector() {
    let cap = shipped("cloudflare_purge_cache");
    assert!(!valid(&cap, &json!({ "zone_id": "z" })), "neither");
    assert!(
        !valid(
            &cap,
            &json!({ "zone_id": "z", "purge_everything": true, "files": ["https://a/x"] })
        ),
        "both"
    );
    // `false` selects nothing; beside `files` it would reach Cloudflare as a
    // mixed request, so it is refused rather than forwarded.
    assert!(
        !valid(
            &cap,
            &json!({ "zone_id": "z", "purge_everything": false, "files": ["https://a/x"] })
        ),
        "false beside files"
    );
    assert!(
        !valid(&cap, &json!({ "zone_id": "z", "purge_everything": false })),
        "false alone"
    );
    assert!(valid(
        &cap,
        &json!({ "zone_id": "z", "purge_everything": true })
    ));
    assert!(valid(
        &cap,
        &json!({ "zone_id": "z", "files": ["https://a/x"] })
    ));
}

/// MIK-7818.DNS.3
#[test]
fn update_dns_record_needs_a_field_to_change() {
    let cap = shipped("cloudflare_update_dns_record");
    let base = json!({ "zone_id": "z", "dns_record_id": "r" });
    assert!(
        !valid(&cap, &base),
        "an update that changes nothing sends {{}}"
    );
    for field in [
        json!({ "type": "A" }),
        json!({ "name": "www" }),
        json!({ "content": "192.0.2.1" }),
        json!({ "ttl": 300 }),
        json!({ "proxied": false }),
        json!({ "comment": "c" }),
    ] {
        let mut args = base.clone();
        args.as_object_mut()
            .unwrap()
            .extend(field.as_object().unwrap().clone());
        assert!(valid(&cap, &args), "{args}");
    }
}

/// Only a parameter the path names gets its default: a default for a query or
/// body field stays the upstream's own to apply.
#[test]
fn only_path_parameters_get_their_schema_default() {
    let cap = shipped("cloudflare_get_waf_rules");
    let config = &cap.primary_provider().expect("a primary provider").config;
    let schema = json!({
        "properties": {
            "ruleset_phase": { "default": "http_request_firewall_custom" },
            "page": { "default": 1 }
        }
    });
    let args = json!({ "zone_id": "z" });
    let effective = super::with_path_defaults(config, &schema, &args);
    assert_eq!(effective["ruleset_phase"], "http_request_firewall_custom");
    assert!(effective.get("page").is_none(), "{effective}");
    // A null counts as not given.
    let nulled = json!({ "zone_id": "z", "ruleset_phase": null });
    let effective = super::with_path_defaults(config, &schema, &nulled);
    assert_eq!(effective["ruleset_phase"], "http_request_firewall_custom");
}

/// What the gateway lists for the Cloudflare capabilities carries no root
/// `oneOf`/`anyOf` (some clients reject the whole request over one), yet the
/// call is still refused, and the description names the rule.
#[test]
fn the_listed_cloudflare_schemas_hide_the_combinators_and_the_description_names_the_rule() {
    let purge = shipped("cloudflare_purge_cache");
    let tool = purge.to_mcp_tool();
    assert!(
        tool.input_schema.get("oneOf").is_none(),
        "{}",
        tool.input_schema
    );
    assert!(
        tool.description
            .as_deref()
            .unwrap_or_default()
            .contains("exactly one of"),
        "{:?}",
        tool.description
    );
    assert!(!valid(&purge, &json!({ "zone_id": "z" })));

    let update = shipped("cloudflare_update_dns_record");
    let tool = update.to_mcp_tool();
    assert!(
        tool.input_schema.get("anyOf").is_none(),
        "{}",
        tool.input_schema
    );
    assert!(
        tool.description
            .as_deref()
            .unwrap_or_default()
            .contains("at least one field"),
        "{:?}",
        tool.description
    );
    assert!(!valid(
        &update,
        &json!({ "zone_id": "z", "dns_record_id": "r" })
    ));
}

/// A required-only alternative declares no key, so the input root closes the
/// schema itself: declaring alternatives must not admit an undeclared key.
#[test]
fn the_cloudflare_alternatives_still_refuse_an_undeclared_key() {
    let purge = shipped("cloudflare_purge_cache");
    let files = json!({ "zone_id": "z", "files": ["https://a/x"] });
    assert!(valid(&purge, &files), "the files selector alone");
    let smuggled = json!({ "zone_id": "z", "files": ["https://a/x"], "smuggled": 1 });
    assert!(
        !valid(&purge, &smuggled),
        "purge admitted an undeclared key"
    );

    let dns = shipped("cloudflare_update_dns_record");
    let comment = json!({ "zone_id": "z", "dns_record_id": "r", "comment": "c" });
    assert!(valid(&dns, &comment), "a comment change alone");
    let smuggled = json!({ "zone_id": "z", "dns_record_id": "r", "comment": "c", "smuggled": 1 });
    assert!(
        !valid(&dns, &smuggled),
        "dns update admitted an undeclared key"
    );
}

/// MIK-7909 on the shipped DNS update: a comment that looks like a placeholder
/// is the caller's value, so it reaches the PATCH body and the anyOf guard's
/// "one field to change" is a real change, not an empty request.
#[test]
fn update_dns_record_sends_a_brace_wrapped_comment() {
    let cap = shipped("cloudflare_update_dns_record");
    let args = json!({ "zone_id": "z", "dns_record_id": "r", "comment": "{literal}" });
    assert!(valid(&cap, &args), "{args}");
    let provider = cap.primary_provider().expect("a primary provider");
    let template = provider.config.body.as_ref().expect("a body template");
    let body = CapabilityExecutor::new()
        .substitute_value(template, &args, super::KeptNulls::None)
        .unwrap();
    assert_eq!(body, json!({ "comment": "{literal}" }), "{body}");
}

/// MIK-7943 finding 4: a default reaches every URL template `build_url` can
/// use, not only `path`: the endpoint, the base URL and a selector's paths.
#[test]
fn every_url_template_gets_its_parameter_defaults() {
    let schema = json!({ "properties": { "region": { "default": "eu" } } });
    for config in [
        json!({ "endpoint": "https://api.invalid/{region}/items" }),
        json!({ "base_url": "https://{region}.api.invalid", "path": "/items" }),
        json!({
            "base_url": "https://api.invalid",
            "path_selector": {
                "parameter": "kind",
                "default": "a",
                "paths": { "a": "/{region}/a" }
            }
        }),
    ] {
        let rest: crate::capability::RestConfig =
            serde_json::from_value(config.clone()).expect("a REST config");
        let args = json!({});
        let effective = super::with_path_defaults(&rest, &schema, &args);
        assert_eq!(effective["region"], "eu", "{config}");
    }
}

/// A selector path the call does not pick names nothing it sends, so its
/// placeholders get no default.
#[test]
fn an_unpicked_selector_path_gets_no_default() {
    let schema = json!({ "properties": { "region": { "default": "eu" } } });
    let rest: crate::capability::RestConfig = serde_json::from_value(json!({
        "base_url": "https://api.invalid",
        "path_selector": {
            "parameter": "kind",
            "default": "a",
            "paths": { "a": "/items", "b": "/{region}/b" }
        }
    }))
    .expect("a REST config");
    let args = json!({});
    let effective = super::with_path_defaults(&rest, &schema, &args);
    assert!(effective.get("region").is_none(), "{effective}");
    let args = json!({ "kind": "b" });
    let effective = super::with_path_defaults(&rest, &schema, &args);
    assert_eq!(effective["region"], "eu");
}

/// With a selector, `path` is only a compatibility copy of the default route:
/// a call that picks another route gets no default from it.
#[test]
fn the_compatibility_path_gives_no_default_to_another_route() {
    let schema = json!({ "properties": { "region": { "default": "eu" } } });
    let rest: crate::capability::RestConfig = serde_json::from_value(json!({
        "base_url": "https://api.invalid",
        "path": "/{region}/a",
        "path_selector": {
            "parameter": "kind",
            "default": "a",
            "paths": { "a": "/{region}/a", "b": "/items" }
        }
    }))
    .expect("a REST config");
    let args = json!({ "kind": "b" });
    let effective = super::with_path_defaults(&rest, &schema, &args);
    assert!(effective.get("region").is_none(), "{effective}");
    let args = json!({});
    let effective = super::with_path_defaults(&rest, &schema, &args);
    assert_eq!(effective["region"], "eu", "the default route still gets it");
}
