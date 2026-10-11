// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8340 row 9 (ORACLE.4) on `/mcp`: every listing surface omits a
//! withheld tool for the denied caller exactly as it omits the tool where it
//! is gone from its backend's catalogue (`Absence::NotInCatalogue`), and
//! still shows the healthy sibling. RED for schema; GREEN for policy and
//! descriptor (listings already filter `may_invoke` and blocked names).

use serde_json::{Value, json};

use super::withheld_twin_tests::{Absence, Reason, SIBLING, Side, Spec, twin};

/// One listing surface: a label, the JSON-RPC method and its params, and
/// whether its records name tools (a count-only answer does not).
struct Surface {
    label: &'static str,
    method: &'static str,
    params: Value,
    names_tools: bool,
}

/// The listing surfaces the default fixture serves. Spec preview is added
/// under its feature.
fn surfaces() -> Vec<Surface> {
    let call = |name: &str, arguments: Value| json!({"name": name, "arguments": arguments});
    let mut surfaces = vec![
        Surface {
            label: "tools/list",
            method: "tools/list",
            params: json!({}),
            names_tools: true,
        },
        Surface {
            label: "gateway_search_tools",
            method: "tools/call",
            params: call("gateway_search_tools", json!({"query": "record"})),
            names_tools: true,
        },
        Surface {
            label: "gateway_list_tools (all)",
            method: "tools/call",
            params: call("gateway_list_tools", json!({})),
            names_tools: true,
        },
        Surface {
            label: "gateway_list_tools (alpha)",
            method: "tools/call",
            params: call("gateway_list_tools", json!({"server": "alpha"})),
            names_tools: true,
        },
        Surface {
            label: "gateway_search (code mode)",
            method: "tools/call",
            params: call("gateway_search", json!({"query": "record"})),
            names_tools: true,
        },
        Surface {
            label: "miss-hint pool (gateway_invoke alpha reed)",
            method: "tools/call",
            params: call(
                "gateway_invoke",
                json!({"server": "alpha", "tool": "reed", "arguments": {}}),
            ),
            names_tools: false,
        },
        Surface {
            label: "gateway_list_servers counts",
            method: "tools/call",
            params: call("gateway_list_servers", json!({})),
            names_tools: false,
        },
    ];
    if cfg!(feature = "spec-preview") {
        surfaces.push(Surface {
            label: "spec preview tools/list query",
            method: "tools/list",
            params: json!({"query": "record"}),
            names_tools: true,
        });
        surfaces.push(Surface {
            label: "spec preview tools/resolve",
            method: "tools/resolve",
            params: json!({"name": "read"}),
            names_tools: false,
        });
    }
    surfaces
}

/// Whether `value` holds a record naming `tool` (a `name` or `tool` member).
/// Text answers are parsed too: meta tools answer JSON inside a text block.
fn names(value: &Value, tool: &str) -> bool {
    match value {
        Value::Object(map) => {
            ["name", "tool"].iter().any(|key| {
                map.get(*key).and_then(Value::as_str).is_some_and(|name| {
                    // Code mode names a tool `server:tool`.
                    name == tool || name.rsplit_once(':').is_some_and(|(_, t)| t == tool)
                })
            }) || map.values().any(|v| names(v, tool))
        }
        Value::Array(items) => items.iter().any(|v| names(v, tool)),
        Value::String(text) => serde_json::from_str::<Value>(text)
            .is_ok_and(|inner| inner.is_object() && names(&inner, tool)),
        _ => false,
    }
}

/// `value` with every JSON text expanded and every array sorted. Two fixtures
/// list `alpha` and `alpha-pt` in registry order, which is not stable across
/// builds; order is not the property under test, membership and content are.
fn canonical(value: &Value) -> Value {
    match value {
        Value::Object(map) => Value::Object(
            map.iter()
                .map(|(key, v)| (key.clone(), canonical(v)))
                .collect(),
        ),
        Value::Array(items) => {
            let mut items: Vec<Value> = items.iter().map(canonical).collect();
            items.sort_by_cached_key(Value::to_string);
            Value::Array(items)
        }
        Value::String(text) => match serde_json::from_str::<Value>(text) {
            Ok(inner) if inner.is_object() || inner.is_array() => canonical(&inner),
            _ => value.clone(),
        },
        _ => value.clone(),
    }
}

/// Row 9: for each reason and surface, the withheld fixture's answer has no
/// record of the tool, keeps the sibling, and equals the `NotInCatalogue`
/// twin's whole answer.
#[tokio::test]
async fn row9_listings_omit_a_withheld_tool_as_an_absent_one() {
    let mut failures = Vec::new();
    for reason in [Reason::Policy, Reason::Schema, Reason::Descriptor] {
        let spec = Spec::of(reason, Side::Withheld);
        for surface in surfaces() {
            // Fresh twins per surface: a listing can promote or remember.
            let withheld = twin(spec).await;
            let absent = twin(spec.with_side(Side::Absent(Absence::NotInCatalogue))).await;
            let w = withheld
                .request(surface.method, surface.params.clone())
                .await;
            let a = absent.request(surface.method, surface.params.clone()).await;
            let cell = format!("{reason:?} x {}", surface.label);
            if surface.names_tools {
                assert!(
                    names(&a.body, SIBLING),
                    "premise ({cell}): the sibling is not listed: {}",
                    a.body
                );
                if names(&w.body, spec.tool) {
                    failures.push(format!("{cell}: lists `{}`: {}", spec.tool, w.body));
                    continue;
                }
            }
            if (w.status, canonical(&w.body)) != (a.status, canonical(&a.body)) {
                failures.push(format!("{cell}: withheld {} vs absent {}", w.body, a.body));
            }
        }
    }
    assert!(failures.is_empty(), "row 9:\n{}", failures.join("\n"));
}
