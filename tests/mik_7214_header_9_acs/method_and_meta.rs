// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The method and name headers and the _meta envelope on both outbound paths, and header precedence.

use super::*;

/// MIK-7214.HEADER.9a — a modern call names its own method.
#[tokio::test]
async fn a_modern_call_carries_its_method_on_both_paths() {
    for (path, label) in BOTH_PATHS {
        let run = Run::of(Peer::Modern, *path, "tools/list", None, &[], &[]).await;
        assert_eq!(
            header(run.under_test("tools/list"), "Mcp-Method"),
            "tools/list",
            "the {label} path must name the method it is carrying"
        );
    }
}

/// MIK-7214.HEADER.9a — `Mcp-Name` mirrors the body field the method selects.
#[tokio::test]
async fn a_modern_named_call_mirrors_the_body_field_its_method_selects() {
    for (method, field, sentinel) in NAMED_METHODS {
        for (path, label) in BOTH_PATHS {
            let params = Some(json!({ *field: sentinel }));
            let run = Run::of(Peer::Modern, *path, method, params, &[], &[]).await;
            let wire = run.under_test(method);
            assert_eq!(
                header(wire, "Mcp-Name"),
                *sentinel,
                "on the {label} path {method} must mirror `params.{field}`, not \
                 whichever field happens to be present"
            );
        }
    }
}

/// MIK-7214.HEADER.9a — a method with no name source carries no `Mcp-Name`.
///
/// The negative half of the table. Without it, an implementation that emits
/// `Mcp-Name` unconditionally — reading any string it can find — passes every
/// row above.
#[tokio::test]
async fn a_modern_call_to_an_unnamed_method_carries_no_name_header() {
    for (path, label) in BOTH_PATHS {
        let params = Some(json!({ "name": "a decoy the method does not address" }));
        let run = Run::of(Peer::Modern, *path, "tools/list", params, &[], &[]).await;
        assert!(
            run.under_test("tools/list")
                .headers
                .get("Mcp-Name")
                .is_none(),
            "`tools/list` addresses no tool, prompt or resource, so the {label} \
             path must send no name — not the decoy beside it"
        );
    }
}

/// MIK-7214.HEADER.9a — a named method whose name source is missing or not a
/// string fails locally, before anything is sent.
#[tokio::test]
async fn a_modern_named_call_with_no_usable_name_source_fails_before_sending() {
    for (method, field, _) in NAMED_METHODS {
        // Built from the field the METHOD selects, not a hardcoded `name`: a
        // `resources/read` carrying a wrong-typed `name` is missing its `uri`
        // for the boring reason, and would pass without the check existing.
        let bad: &[Value] = &[
            json!({}),
            json!({ *field: 7 }),
            json!({ *field: null }),
            // Empty is rejected here rather than encoded: an empty header value
            // cannot round-trip back through `decode_header_value`.
            json!({ *field: "" }),
        ];
        for params in bad {
            for (path, _) in BOTH_PATHS {
                let run =
                    Run::of(Peer::Modern, *path, method, Some(params.clone()), &[], &[]).await;
                run.failed_before_sending(method);
            }
        }
    }
}

/// Read `params._meta` off a captured call, or say what the body held instead.
fn meta_of(wire: &Wire) -> &Value {
    wire.body
        .get("params")
        .and_then(|params| params.get("_meta"))
        .unwrap_or_else(|| panic!("no `params._meta` in {}", wire.body))
}

/// MIK-7214.HEADER.9a — a modern call with no params still declares.
///
/// A builder that skips declaration when there is nothing to merge into sends
/// no `params` at all, and this fails on the object's absence.
#[tokio::test]
async fn a_modern_call_without_params_still_declares_the_envelope() {
    for (path, label) in BOTH_PATHS {
        let run = Run::of(Peer::Modern, *path, "tools/list", None, &[], &[]).await;
        let meta = meta_of(run.under_test("tools/list"));
        let keys: Vec<&str> = meta
            .as_object()
            .unwrap_or_else(|| panic!("`_meta` must be an object on the {label} path"))
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(
            keys,
            vec![KEY_CLIENT_CAPABILITIES, KEY_PROTOCOL_VERSION],
            "the {label} path must declare exactly the two required keys, and \
             `clientInfo` is not one of them"
        );
    }
}

/// MIK-7214.HEADER.9a — the caller's own params survive the merge.
#[tokio::test]
async fn a_modern_call_keeps_the_callers_params_beside_the_envelope() {
    for (path, label) in BOTH_PATHS {
        let params = Some(json!({ "cursor": "caller-cursor-delta", "limit": 17 }));
        let run = Run::of(Peer::Modern, *path, "tools/list", params, &[], &[]).await;
        let body = &run.under_test("tools/list").body;
        let sent = body
            .get("params")
            .unwrap_or_else(|| panic!("no params in {body}"));
        assert_eq!(
            sent.get("cursor").and_then(Value::as_str),
            Some("caller-cursor-delta"),
            "the {label} path must merge into the caller's params, not replace them"
        );
        assert_eq!(sent.get("limit").and_then(Value::as_i64), Some(17));
    }
}

/// MIK-7214.HEADER.9a — a caller's own `_meta` keys survive; this design's own
/// two are overwritten.
///
/// The fixture pre-sets both a foreign key and one of the two design keys to a
/// wrong value: a wholesale replace loses the first, a merge that skips keys
/// already present keeps the second.
#[tokio::test]
async fn a_modern_call_merges_into_an_existing_meta_without_losing_foreign_keys() {
    for (path, label) in BOTH_PATHS {
        let params = Some(json!({
            "_meta": {
                "io.example/trace": "foreign-trace-epsilon",
                KEY_CLIENT_INFO: { "name": "a caller's own, neither inserted nor stripped" },
                KEY_PROTOCOL_VERSION: "1999-01-01",
            }
        }));
        let run = Run::of(Peer::Modern, *path, "tools/list", params, &[], &[]).await;
        let meta = meta_of(run.under_test("tools/list"));
        assert_eq!(
            meta.get("io.example/trace").and_then(Value::as_str),
            Some("foreign-trace-epsilon"),
            "the {label} path must not drop a caller's foreign `_meta` key"
        );
        assert!(
            meta.get(KEY_CLIENT_INFO).is_some(),
            "a caller's own clientInfo is neither inserted nor stripped by this design"
        );
        assert_eq!(
            meta.get(KEY_PROTOCOL_VERSION).and_then(Value::as_str),
            Some(MODERN_VERSIONS[0]),
            "this design owns the protocol-version key and must overwrite a \
             caller's stale value on the {label} path"
        );
    }
}

/// MIK-7214.HEADER.9a — a non-object `params` fails locally, before any send.
#[tokio::test]
async fn a_modern_call_with_non_object_params_fails_before_sending() {
    let bad: &[Value] = &[json!(null), json!("a string"), json!(7), json!([1, 2])];
    for params in bad {
        for (path, _) in BOTH_PATHS {
            let run = Run::of(
                Peer::Modern,
                *path,
                "tools/list",
                Some(params.clone()),
                &[],
                &[],
            )
            .await;
            run.failed_before_sending("tools/list");
        }
    }
}

/// MIK-7214.HEADER.9a — a `_meta` that is not an object fails locally.
///
/// An implementation that overwrites destroys caller data and passes a happy
/// path; one that forwards unchanged emits no `clientCapabilities` and is
/// rejected `-32602` by a real modern peer, which no local assertion catches.
#[tokio::test]
async fn a_modern_call_with_a_non_object_meta_fails_before_sending() {
    let bad: &[Value] = &[json!(null), json!("a string"), json!(7), json!([1, 2])];
    for meta in bad {
        for (path, _) in BOTH_PATHS {
            let params = Some(json!({ "_meta": meta.clone() }));
            let run = Run::of(Peer::Modern, *path, "tools/list", params, &[], &[]).await;
            run.failed_before_sending("tools/list");
        }
    }
}

/// The three headers this design owns, and a custom value for each that the
/// builder could never produce.
///
/// Values chosen so a pin that leaks reads as an operator's, not as a plausible
/// gateway output: `1999-01-01` is not a revision, and neither name is a method.
const PINNED: &[(&str, &str)] = &[
    ("MCP-Protocol-Version", "1999-01-01"),
    ("Mcp-Method", "operator/override"),
    ("Mcp-Name", "operator-supplied-name"),
];

/// MIK-7214.HEADER.9b — this design's values survive operator configuration,
/// at both merge sites and on both paths.
///
/// On `Request` finalisation must run after the per-request `extra_headers`
/// merge (`mod.rs:846-854`), so an implementation inside `build_mcp_headers`
/// passes the static half and fails the per-request half. On `Notify` there is
/// no per-request merge at all (`mod.rs:1051-1053`), so an implementation that
/// finalises only in `send_request_with_headers` sends the operator's values
/// and fails every notify assertion.
#[tokio::test]
async fn this_designs_headers_outrank_operator_configuration_at_both_merge_sites() {
    let expected: &[(&str, &str)] = &[
        ("MCP-Protocol-Version", MODERN_VERSIONS[0]),
        ("Mcp-Method", "tools/call"),
        ("Mcp-Name", "sentinel-tool-alpha"),
    ];
    for (path, label) in BOTH_PATHS {
        // Static configuration on both paths; the per-request merge exists on
        // `Request` only, so the notify row drives statics alone.
        let extra: &[(&str, &str)] = match path {
            Path::Request => PINNED,
            Path::Notify => &[],
        };
        let params = Some(json!({ "name": "sentinel-tool-alpha" }));
        let run = Run::of(Peer::Modern, *path, "tools/call", params, PINNED, extra).await;
        let wire = run.under_test("tools/call");
        for (name, value) in expected {
            assert_eq!(
                header(wire, name),
                *value,
                "on the {label} path {name} must come from this design, not from \
                 the operator's configuration"
            );
        }
    }
}

/// MIK-7215.STATELESS.3a — a modern call sends no session header, neither the
/// minted one nor an operator's.
///
/// The prohibition is on emission, not on minting: a fixture with an empty
/// session map passes an absence assertion without the removal existing, which
/// is why a priming ordinary response mints one and `under_test` proves that
/// response preceded the call under test. The custom static value is the second half — an
/// implementation that only skips the mint still forwards the operator's.
#[tokio::test]
async fn a_modern_call_sends_neither_the_minted_nor_the_configured_session() {
    let configured: &[(&str, &str)] = &[("MCP-Session-Id", "operator-session-zeta")];
    for (path, label) in BOTH_PATHS {
        let run = Run::of(Peer::Modern, *path, "tools/list", None, configured, &[]).await;
        assert!(
            run.under_test("tools/list")
                .headers
                .get("Mcp-Session-Id")
                .is_none(),
            "the {label} path must carry no session header on a modern peer; saw {:?} across {}",
            run.under_test("tools/list").headers,
            run.methods()
        );
    }
}

/// MIK-7215.STATELESS.3a — the legacy rows still carry the minted session.
///
/// The counterweight. Without it, an implementation that strips the session
/// header unconditionally passes the case above and silently breaks every
/// legacy backend.
#[tokio::test]
async fn a_legacy_call_still_carries_the_minted_session() {
    for (path, label) in BOTH_PATHS {
        let run = Run::of(Peer::Legacy, *path, "tools/list", None, &[], &[]).await;
        assert_eq!(
            header(run.under_test("tools/list"), "Mcp-Session-Id"),
            "s1",
            "a legacy peer's {label} path is byte-for-byte what it was, session \
             header included"
        );
    }
}
