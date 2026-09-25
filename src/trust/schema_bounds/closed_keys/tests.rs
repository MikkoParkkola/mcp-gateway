// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! R2 key walker cells (MIK-7570.SCHEMA.1). Row names follow the design:
//! R2-T<n> for the numbered rows, N1-N3 for the non-regressions.

use serde_json::{Value, json};

use super::{KeyFault, undeclared_keys};
use crate::config::InputSchemaEnforcement::{Closed, Off, Standard};

fn refused(schema: &Value, args: &Value) -> bool {
    !undeclared_keys(args, schema, Closed).is_empty()
}

fn closed(props: &Value) -> Value {
    json!({"type": "object", "properties": props, "additionalProperties": false})
}

/// R2-T8: a schema-valued `additionalProperties` checks the extra's value.
#[test]
fn additional_properties_schema_validates_extra_values() {
    let schema = json!({"type": "object", "properties": {
        "counts": {"type": "object", "additionalProperties": {"type": "integer"}}
    }});
    assert!(refused(&schema, &json!({"counts": {"x": "abc"}})));
    assert!(!refused(&schema, &json!({"counts": {"x": 3}})));
}

/// R2-T9: `anyOf` property sets and a `$ref` into `$defs` are walked.
#[test]
fn combinator_and_ref_levels_are_walked() {
    let any = json!({"anyOf": [
        {"properties": {"a": {}}, "additionalProperties": false},
        {"properties": {"b": {}}, "additionalProperties": false}
    ]});
    assert!(!refused(&any, &json!({"b": 1})));
    assert!(refused(&any, &json!({"c": 1})));
    let by_ref = json!({
        "$defs": {"Edit": {"type": "object", "properties": {"x": {}}}},
        "type": "object",
        "properties": {"e": {"$ref": "#/$defs/Edit"}}
    });
    assert!(!refused(&by_ref, &json!({"e": {"x": 1}})));
    assert!(refused(&by_ref, &json!({"e": {"y": 1}})));
}

/// R2-T11 (walker half): `standard` opens absent-closed levels only.
#[test]
fn standard_mode_closes_only_on_an_explicit_false() {
    let absent = json!({"type": "object", "properties": {"a": {}}});
    assert!(undeclared_keys(&json!({"b": 1}), &absent, Standard).is_empty());
    let explicit = closed(&json!({"a": {}}));
    assert!(!undeclared_keys(&json!({"b": 1}), &explicit, Standard).is_empty());
    assert!(undeclared_keys(&json!({"b": 1}), &explicit, Off).is_empty());
}

/// R2-T12: a self-referential tree with deep args and a pure `$ref` cycle
/// both end, refused, without overflowing the stack.
#[test]
fn schema_walk_budget_bounds_ref_cycles() {
    let tree = json!({
        "$defs": {"node": {"type": "object", "properties": {"child": {"$ref": "#/$defs/node"}}}},
        "$ref": "#/$defs/node"
    });
    let mut deep = json!({});
    for _ in 0..64 {
        deep = json!({"child": deep});
    }
    assert_eq!(
        undeclared_keys(&deep, &tree, Closed),
        vec![KeyFault::TooDeep]
    );
    let cycle = json!({"$defs": {"a": {"$ref": "#/$defs/b"}, "b": {"$ref": "#/$defs/a"}},
        "$ref": "#/$defs/a"});
    let faults = undeclared_keys(&json!({"k": 1}), &cycle, Closed);
    assert_eq!(faults, vec![KeyFault::TooDeep]);
}

/// R2-T18 / R2-T19: a `string` arm neither opens nor closes; `{}` opens.
#[test]
fn any_of_ignores_a_string_arm_and_opens_on_an_empty_arm() {
    let two_closed = json!({"anyOf": [closed(&json!({"a": {}})), closed(&json!({"b": {}})),
        {"type": "string"}]});
    assert!(refused(&two_closed, &json!({"z": 1})));
    let with_open = json!({"anyOf": [closed(&json!({"a": {}})), {}]});
    assert!(!refused(&with_open, &json!({"z": 1})));
}

/// R2-T20: `patternProperties` without `additionalProperties` is closed.
#[test]
fn pattern_properties_declare_the_shape() {
    let schema = json!({"type": "object", "patternProperties": {"^x_": {}}});
    assert!(!refused(&schema, &json!({"x_1": 1})));
    assert!(refused(&schema, &json!({"y": 1})));
}

/// R2-T21: 16 nested `anyOf` levels of fan-out 4, built as a `$ref` cycle,
/// finish within the budget or refuse; they never hang.
#[test]
fn fan_out_any_of_is_bounded() {
    let schema = json!({
        "$defs": {"n": {"type": "object", "properties": {"c": {"anyOf": [
            {"$ref": "#/$defs/n"}, {"$ref": "#/$defs/n"},
            {"$ref": "#/$defs/n"}, {"$ref": "#/$defs/n"}
        ]}}}},
        "$ref": "#/$defs/n"
    });
    let mut args = json!({"zz": 1});
    for _ in 0..16 {
        args = json!({"c": args});
    }
    assert!(refused(&schema, &args));
}

/// R2-T22: the nullable idiom does not open the object branch.
#[test]
fn nullable_idiom_refuses_an_undeclared_key() {
    let schema = json!({"anyOf": [closed(&json!({"a": {}})), {"enum": [null]}]});
    assert!(refused(&schema, &json!({"b": 1})));
}

/// R2-T23: `allOf: [closed, {}]` stays closed.
#[test]
fn all_of_with_an_empty_branch_stays_closed() {
    let schema = json!({"allOf": [closed(&json!({"a": {}})), {}]});
    assert!(refused(&schema, &json!({"b": 1})));
    assert!(!refused(&schema, &json!({"a": 1})));
}

/// R2-T24: an unresolvable `$ref` refuses under `closed` and is a free map
/// under `standard`.
#[test]
fn unresolvable_ref_refuses_closed_and_opens_standard() {
    let schema = json!({"$ref": "https://example.invalid/schema.json"});
    assert!(refused(&schema, &json!({"a": 1})));
    assert!(undeclared_keys(&json!({"a": 1}), &schema, Standard).is_empty());
    let any = json!({"anyOf": [{"$ref": "#/$defs/missing"}]});
    assert!(refused(&any, &json!({"a": 1})));
}

/// R2-T25: one `$ref` target under two combinators with different siblings
/// gets its own verdict at each.
#[test]
fn one_ref_under_two_combinators_gets_two_verdicts() {
    let schema = json!({
        "$defs": {"base": {"properties": {"a": {}}}},
        "type": "object",
        "properties": {
            "open": {"allOf": [{"$ref": "#/$defs/base"}], "properties": {"b": {}}},
            "shut": {"allOf": [{"$ref": "#/$defs/base"}], "additionalProperties": false}
        }
    });
    assert!(!refused(&schema, &json!({"open": {"b": 1}})));
    assert!(refused(&schema, &json!({"shut": {"b": 1}})));
}

/// R2-T26: an `allOf` base+extension mixin declares both halves.
#[test]
fn all_of_mixin_declares_both_halves() {
    let schema = json!({"allOf": [{"properties": {"a": {}}}, {"properties": {"b": {}}}]});
    assert!(!refused(&schema, &json!({"a": 1, "b": 2})));
    assert!(refused(&schema, &json!({"c": 3})));
}

/// R2-T27: a branch-declared key is accepted at a level with its own `properties`.
#[test]
fn branch_declared_key_accepted_beside_own_properties() {
    let schema = json!({"properties": {"a": {}}, "anyOf": [{"properties": {"b": {}}}]});
    assert!(!refused(&schema, &json!({"a": 1, "b": 2})));
    assert!(refused(&schema, &json!({"c": 3})));
}

/// R2-T28: an object-valued `enum` branch is closed to its literals' keys.
#[test]
fn object_enum_branch_declares_its_keys() {
    let schema = json!({"anyOf": [{"enum": [{"mode": "a"}, {"level": 1}]}]});
    assert!(!refused(&schema, &json!({"mode": "a"})));
    assert!(refused(&schema, &json!({"other": 1})));
}

/// R2-T29: a `not`-only branch does not open the union.
#[test]
fn not_only_branch_does_not_open_the_union() {
    let schema = json!({"anyOf": [closed(&json!({"a": {}})), {"not": {"required": ["x"]}}]});
    assert!(refused(&schema, &json!({"b": 1})));
}

/// R2-T30: a nested `anyOf` inside `allOf` still refuses.
#[test]
fn nested_any_of_inside_all_of_refuses() {
    let schema = json!({"allOf": [{"anyOf": [closed(&json!({"a": {}}))]}]});
    assert!(refused(&schema, &json!({"b": 1})));
}

/// R2-T31: a match-nothing `allOf` branch refuses even a declared key.
#[test]
fn match_nothing_all_of_branch_refuses() {
    let schema = json!({"allOf": [{"properties": {"a": {}}}, false]});
    assert!(refused(&schema, &json!({"a": 1})));
}

/// R2-T32: a branch accepting any object accepts every key.
#[test]
fn any_object_branch_accepts_every_key() {
    let schema = json!({"anyOf": [{"type": "object"}, closed(&json!({"a": {}}))]});
    assert!(!refused(&schema, &json!({"b": 1})));
}

/// R2-T33: an `allOf` branch `$ref`ing a subschema declares its keys.
#[test]
fn all_of_ref_branch_declares_its_keys() {
    let schema = json!({"$defs": {"B": {"properties": {"b": {}}}},
        "allOf": [{"$ref": "#/$defs/B"}]});
    assert!(!refused(&schema, &json!({"b": 1})));
    assert!(refused(&schema, &json!({"c": 1})));
}

/// R2-T34 / R2-T35: `items` and `prefixItems` positions check their own schema.
#[test]
fn array_items_and_prefix_items_are_checked() {
    let items = json!({"type": "object", "properties": {"e": {"type": "array",
        "items": {"type": "object", "properties": {"x": {}}}}}});
    assert!(refused(&items, &json!({"e": [{"x": 1}, {"y": 2}]})));
    let prefix = json!({"type": "object", "properties": {"e": {"type": "array",
        "prefixItems": [{"type": "object", "properties": {"p": {}}}],
        "items": {"type": "object", "properties": {"q": {}}}}}});
    assert!(!refused(&prefix, &json!({"e": [{"p": 1}, {"q": 2}]})));
    assert!(refused(&prefix, &json!({"e": [{"q": 1}]})));
}

/// R2-T36: a catastrophic-backtracking pattern completes (linear-time regex).
#[test]
fn catastrophic_pattern_completes() {
    let schema = json!({"type": "object", "patternProperties": {"(a+)+$": {}}});
    let key = format!("{}!", "a".repeat(10_000));
    let started = std::time::Instant::now();
    let _ = refused(&schema, &json!({ key: 1 }));
    assert!(started.elapsed() < std::time::Duration::from_secs(2));
    // A pattern the engine cannot express compiles to nothing: fail closed.
    let lookaround = json!({"type": "object", "patternProperties": {"^(?=a)": {}}});
    assert!(refused(&lookaround, &json!({"abc": 1})));
}

/// R2-T37: an `allOf` branch's closed `items` refuses an undeclared element key.
#[test]
fn all_of_branch_items_close_elements() {
    let schema = json!({"type": "object", "properties": {"e": {"allOf": [
        {"type": "array"},
        {"items": closed(&json!({"x": {}}))}
    ]}}});
    assert!(refused(&schema, &json!({"e": [{"y": 1}]})));
}

/// R2-T38: an `anyOf` whose second branch's items declare the key accepts it.
#[test]
fn any_of_second_branch_items_accept() {
    let schema = json!({"type": "object", "properties": {"e": {"anyOf": [
        {"items": closed(&json!({"x": {}}))},
        {"items": closed(&json!({"y": {}}))}
    ]}}});
    assert!(!refused(&schema, &json!({"e": [{"y": 1}]})));
}

/// N1 (walker half): permissive shapes still accept extras.
#[test]
fn permissive_schemas_accept_extras() {
    for schema in [
        json!({"type": "object"}),
        json!({"type": "object", "properties": {}}),
        json!({"type": "object", "properties": {"n": {"type": "object",
            "properties": {"a": {}}, "additionalProperties": true}}}),
        json!({"type": "object", "patternProperties": {"^x": {}}}),
    ] {
        let args = json!({"n": {"a": 1, "extra": 2}});
        let args = if schema.get("patternProperties").is_some() {
            json!({"x1": 3})
        } else if schema["properties"].get("n").is_some() {
            args
        } else {
            json!({"anything": 1})
        };
        assert!(
            undeclared_keys(&args, &schema, Closed).is_empty(),
            "{schema}"
        );
    }
}

/// Grok MEDIUM on #890: `required` names keys; it does not close a level. A
/// schema listing only `required` is a free map that accepts the required key.
#[test]
fn required_without_properties_is_a_free_map() {
    let schema = json!({"type": "object", "required": ["a"]});
    assert!(!refused(&schema, &json!({"a": 1})));
    // F14b: a free map accepts extras too, not only the named key.
    assert!(!refused(&schema, &json!({"a": 1, "b": 2})));
}

/// F14d: `additionalItems` governs the elements past a tuple `items`, so an
/// invented key in one of them is refused like one inside the tuple.
#[test]
fn additional_items_are_descended() {
    let schema = json!({
        "type": "object",
        "properties": {"xs": {
            "type": "array",
            "items": [{"type": "string"}],
            "additionalItems": closed(&json!({"a": {}}))
        }}
    });
    assert!(refused(&schema, &json!({"xs": ["s", {"b": 1}]})));
    assert!(!refused(&schema, &json!({"xs": ["s", {"a": 1}]})));
}

/// F14e: a `$ref` to a free map is a free map, as the same schema inlined is.
/// A close on the level holding the `$ref` still refuses.
#[test]
fn a_ref_to_a_free_map_is_a_free_map() {
    let schema = json!({
        "$defs": {"free": {"type": "object"}},
        "type": "object",
        "properties": {
            "open": {"$ref": "#/$defs/free"},
            "shut": {"$ref": "#/$defs/free", "additionalProperties": false}
        }
    });
    assert!(!refused(&schema, &json!({"open": {"anything": 1}})));
    assert!(refused(&schema, &json!({"shut": {"anything": 1}})));
}
