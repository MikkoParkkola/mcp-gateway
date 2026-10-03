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
