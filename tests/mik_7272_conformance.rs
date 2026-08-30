// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The conformance matrix (NFR.COMPAT.4, U6).
//!
//! One row per normative statement in the 2026-07-28 changelog, crossed with
//! the role the gateway plays for it and the transport it plays it on.
//!
//! The matrix exists because per-increment tests inherit each increment's
//! shape: they check what was built, in the role it was built for. A statement
//! verified server-side only is verified at half, and nothing in a green suite
//! says which half.
//!
//! **An empty evidence cell is the finding.** This file therefore asserts
//! coverage of the matrix itself, not only the behaviours: `matrix_has_no_empty
//! _cells` fails if a statement is listed with no test naming it.

/// Which side of the connection the gateway is on for a statement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// The gateway answering a client.
    Server,
    /// The gateway calling a backend.
    Client,
    /// Both, and the statement is only satisfied when both hold.
    Both,
}

/// Where a statement applies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    /// Streamable HTTP.
    Http,
    /// stdio.
    Stdio,
    /// Not transport-specific.
    Any,
}

/// One normative statement and the evidence for it.
pub struct Row {
    /// The changelog item, quoted closely enough to be found again.
    pub statement: &'static str,
    /// The requirement identifier that owns it.
    pub requirement: &'static str,
    pub role: Role,
    pub transport: Transport,
    /// Test functions that verify it. **Empty is the finding.**
    pub evidence: &'static [&'static str],
}

/// The nine major changes of the 2026-07-28 changelog, in its own order.
const MAJOR: &[Row] = &[
    Row {
        statement: "1. Remove protocol-level sessions and the Mcp-Session-Id header; \
                    list endpoints no longer vary per-connection",
        requirement: "MIK-7215.STATELESS.3, MIK-7272.ORDER.2",
        role: Role::Server,
        transport: Transport::Http,
        evidence: &[
            "mik_7215_acs::http::ac_stateless_3_a_modern_response_carries_no_session_header",
            "mik_7215_acs::http::ac_stateless_3_a_legacy_response_still_carries_the_session_header",
        ],
    },
    Row {
        statement: "2. Make MCP stateless: remove the initialize handshake; every request \
                    carries its version and client capabilities in _meta",
        requirement: "MIK-7215.STATELESS.1, .2, .8, .9",
        role: Role::Server,
        transport: Transport::Http,
        evidence: &[
            "mik_7215_acs::ac_stateless_1_a_request_carrying_its_own_version_is_modern",
            "mik_7215_acs::ac_stateless_1_each_request_carries_its_own_version",
            "mik_7215_acs::http::ac_stateless_2_a_modern_result_identifies_the_server",
            "mik_7215_acs::http::ac_stateless_8_one_endpoint_serves_both_eras",
        ],
    },
    Row {
        statement: "3. Add server/discover: servers MUST implement this RPC",
        requirement: "MIK-7217.DISCOVER.1, .2",
        role: Role::Both,
        transport: Transport::Any,
        evidence: &[
            "mik_7217_acs::ac_discover_1_document_matches_the_specified_shape",
            "mik_7217_acs::http::ac_discover_1_http_dispatch_answers_server_discover",
            "gateway::server::tests::ac_discover_1_stdio_dispatch_answers_server_discover",
            "mik_7217_acs::era::ac_discover_4_a_discovery_document_means_modern",
        ],
    },
    Row {
        statement: "4. Replace the HTTP GET endpoint and resources/subscribe with \
                    subscriptions/listen",
        requirement: "MIK-7272.SUB.1, .2",
        role: Role::Server,
        transport: Transport::Http,
        evidence: &[
            "mik_7272_subscriptions_acs::http::ac_sub_1_the_gateway_serves_subscriptions_listen",
            "mik_7272_subscriptions_acs::http::ac_sub_1_resources_subscribe_is_refused_on_the_modern_path",
            "mik_7272_subscriptions_acs::ac_sub_2_a_request_scoped_notification_is_not_a_subscription_notification",
        ],
    },
    Row {
        statement: "5. Remove ping, logging/setLevel and notifications/roots/list_changed; \
                    log level is per-request",
        requirement: "MIK-7215.STATELESS.6, .7",
        role: Role::Server,
        transport: Transport::Http,
        evidence: &[
            "mik_7215_acs::http::ac_stateless_6_ping_is_refused_on_the_modern_path",
            "mik_7215_acs::http::ac_stateless_6_ping_still_works_on_the_legacy_path",
            "mik_7215_acs::ac_stateless_7_a_log_notification_is_never_delivered_to_a_subscriber",
        ],
    },
    Row {
        // The extension ships NOT implemented and NOT advertised, which is a
        // conformance position rather than a gap in the matrix: no client
        // negotiates a capability the gateway does not offer. The evidence is
        // the refusal, not an implementation. MIK-7311 owns the extension.
        statement: "6. Move tasks into an official extension, polled via tasks/get",
        requirement: "MIK-7272.TASK.1",
        role: Role::Server,
        transport: Transport::Http,
        evidence: &[
            "mik_7272_exploit_acs::tasks::ac_task_1_a_task_is_polled_not_awaited",
            "mik_7272_subscriptions_acs::http::ac_task_1_tasks_get_reports_that_it_is_not_implemented",
            "mik_7272_subscriptions_acs::http::ac_task_1_tasks_get_is_not_reachable_on_the_legacy_path",
        ],
    },
    Row {
        statement: "7. Multi Round-Trip Requests replace server-initiated requests",
        requirement: "MIK-7212.MRTR.1-.10",
        role: Role::Both,
        transport: Transport::Any,
        evidence: &[
            "mik_7212_acs::retry::ac_mrtr_1_a_retry_carries_its_inputs_and_state",
            "mik_7212_acs::ac_mrtr_2_a_minted_envelope_round_trips",
            "mik_7212_acs::inflight::ac_mrtr_6_a_retry_landing_elsewhere_is_sent_to_the_holder",
            "mik_7212_acs::reverse::ac_mrtr_7_a_legacy_client_is_asked_the_way_it_expects",
        ],
    },
    Row {
        statement: "8. All results carry resultType; a missing field from an earlier peer \
                    is complete",
        requirement: "MIK-7272.RESULT.1, .2",
        role: Role::Both,
        transport: Transport::Any,
        evidence: &[
            "mik_7213_acs::http::ac_result_1_every_modern_result_carries_result_type",
            "mik_7213_acs::http::ac_result_1_a_legacy_result_carries_none",
            "mik_7213_acs::ac_result_2_a_missing_result_type_reads_as_complete",
        ],
    },
    Row {
        statement: "9. Remove SSE resumability and message redelivery; a broken stream \
                    is re-issued as a new request",
        requirement: "MIK-7272.SUB.3, .4",
        role: Role::Server,
        transport: Transport::Http,
        evidence: &[
            "mik_7272_subscriptions_acs::reissue::ac_sub_4_a_reissued_call_is_the_same_call",
            "mik_7212_acs::idempotency::ac_mrtr_10_a_retry_does_not_collide_with_the_call_it_continues",
        ],
    },
];

/// The minor changes that carry a normative obligation. Numbered as the
/// changelog numbers them, so a reader can check this list against it.
const MINOR: &[Row] = &[
    Row {
        statement: "1. extensions field on client and server capabilities",
        requirement: "MIK-7272.EXT.1",
        role: Role::Both,
        transport: Transport::Any,
        evidence: &[
            "mik_7272_exploit_acs::ac_ext_1_the_gateway_declares_its_extensions",
            "mik_7272_exploit_acs::ac_ext_1_an_unsupported_extension_reverts_to_core_behaviour",
        ],
    },
    Row {
        statement: "2. OpenTelemetry trace context propagation through _meta",
        requirement: "MIK-7272.OTEL.1",
        role: Role::Both,
        transport: Transport::Any,
        evidence: &[
            "mik_7272_exploit_acs::ac_otel_1_a_trace_context_is_read_from_request_meta",
            "mik_7272_exploit_acs::ac_otel_1_the_context_is_propagated_to_the_backend_unchanged",
        ],
    },
    Row {
        statement: "3. Servers SHOULD return tools in a deterministic order",
        requirement: "MIK-7272.ORDER.1",
        role: Role::Server,
        transport: Transport::Http,
        evidence: &["mik_7213_acs::http::ac_order_1_the_tool_order_is_stable_across_callers"],
    },
    Row {
        statement: "4. Require Mcp-Method and Mcp-Name headers; support x-mcp-header",
        requirement: "MIK-7214.HEADER.1-.6",
        role: Role::Server,
        transport: Transport::Http,
        evidence: &[
            "mik_7214_acs::ac_header_2_mcp_name_is_required_for_exactly_three_methods",
            "mik_7214_acs::ac_header_4_the_specifications_encoding_table_decodes",
            "mik_7214_acs::http::ac_header_3_a_disagreeing_method_header_is_refused_over_http",
            "mik_7214_acs::http::ac_header_2_a_legacy_request_needs_no_headers",
        ],
    },
    Row {
        statement: "5. Require ttlMs and cacheScope on the five cacheable results",
        requirement: "MIK-7213.CACHE.1, .2, .3",
        role: Role::Server,
        transport: Transport::Http,
        evidence: &[
            "mik_7213_acs::http::ac_cache_1_a_cacheable_result_carries_ttl_and_scope",
            "mik_7213_acs::http::ac_cache_3_no_response_from_this_gateway_claims_public",
            "mik_7213_acs::http::ac_cache_1_a_non_cacheable_result_carries_no_cache_fields",
        ],
    },
    Row {
        statement: "6. Resource-not-found moves from -32002 to -32602",
        requirement: "MIK-7272.ERROR.2",
        role: Role::Server,
        transport: Transport::Any,
        evidence: &[
            "mik_7213_acs::ac_error_1_no_renumbered_code_sits_in_the_implementation_defined_range",
        ],
    },
    Row {
        statement: "7. Validate a present iss against the recorded issuer (RFC 9207)",
        requirement: "MIK-7272.OAUTH.1",
        role: Role::Client,
        transport: Transport::Any,
        evidence: &[
            "mik_7272_oauth_acs::issuer::ac_oauth_1_a_different_issuer_is_refused_before_redemption",
            "mik_7272_oauth_acs::issuer::ac_oauth_1_the_comparison_is_exact",
        ],
    },
    Row {
        statement: "8. Specify application_type during Dynamic Client Registration",
        requirement: "MIK-7272.OAUTH.2",
        role: Role::Client,
        transport: Transport::Any,
        evidence: &[
            "mik_7272_oauth_acs::ac_oauth_2_dynamic_registration_declares_an_application_type",
        ],
    },
    Row {
        statement: "9. Key persisted client credentials by issuer",
        requirement: "MIK-7272.OAUTH.3",
        role: Role::Client,
        transport: Transport::Any,
        evidence: &[
            "mik_7272_oauth_acs::ac_oauth_3_credentials_are_keyed_by_the_issuer_that_granted_them",
        ],
    },
    Row {
        statement: "10. Loosen inputSchema and outputSchema to JSON Schema 2020-12",
        requirement: "MIK-6865.SCHEMA.1",
        role: Role::Server,
        transport: Transport::Any,
        evidence: &[
            "mik_7272_exploit_acs::schema::ac_schema_1_no_meta_tool_nests_an_object_inside_an_array",
        ],
    },
    Row {
        statement: "12. Error-code allocation policy; renumber HeaderMismatch, \
                    MissingRequiredClientCapability and UnsupportedProtocolVersion",
        requirement: "MIK-7272.ERROR.1",
        role: Role::Both,
        transport: Transport::Any,
        evidence: &[
            "mik_7213_acs::ac_error_1_the_renumbered_codes_are_at_their_new_numbers",
            "mik_7215_acs::http::ac_stateless_4_an_unsupported_version_is_refused_with_its_own_error",
        ],
    },
];

fn all_rows() -> Vec<&'static Row> {
    MAJOR.iter().chain(MINOR.iter()).collect()
}

#[test]
fn matrix_has_no_empty_cells() {
    // The finding this file exists to produce. A statement listed with no test
    // naming it is an obligation nobody is holding — and it is invisible in a
    // green suite, because a test that does not exist cannot fail.
    let empty: Vec<&str> = all_rows()
        .iter()
        .filter(|row| row.evidence.is_empty())
        .map(|row| row.statement)
        .collect();

    assert!(
        empty.is_empty(),
        "these normative statements have no evidence: {empty:#?}"
    );
}

#[test]
fn every_statement_names_the_requirement_that_owns_it() {
    // Traceability in the other direction: a row whose requirement is unnamed
    // cannot be closed against the requirements document, so its verdict has
    // nowhere to go.
    for row in all_rows() {
        assert!(
            row.requirement.contains("MIK-"),
            "no owning requirement for: {}",
            row.statement
        );
    }
}

#[test]
fn the_client_role_is_covered_and_not_only_the_server_one() {
    // NFR.COMPAT.4, and the reason the matrix crosses roles at all. Every
    // increment was built server-first, so the client role is where coverage
    // silently thins — the gateway is an MCP client to every backend it talks
    // to, and a statement verified in one role is verified at half.
    let client_side = all_rows()
        .iter()
        .filter(|row| matches!(row.role, Role::Client | Role::Both))
        .count();

    assert!(
        client_side >= 7,
        "only {client_side} statements are verified in the client role; the \
         gateway is a client to every backend and that half regresses silently"
    );
}

#[test]
fn both_transports_carry_the_statements_that_apply_to_them() {
    // stdio is the transport that gets forgotten: it has no headers, no status
    // codes and no session, so a statement checked only over HTTP says nothing
    // about it.
    let stdio_or_any = all_rows()
        .iter()
        .filter(|row| matches!(row.transport, Transport::Stdio | Transport::Any))
        .count();

    assert!(
        stdio_or_any >= 10,
        "only {stdio_or_any} statements apply beyond HTTP; stdio is a transport \
         this gateway serves and a matrix that ignores it is an HTTP matrix"
    );
}

#[test]
fn the_matrix_covers_every_major_change() {
    // Nine major changes in the changelog, nine rows. Counted rather than
    // eyeballed: a change dropped from this list is a change nobody notices is
    // missing, since the tests that remain all pass.
    assert_eq!(
        MAJOR.len(),
        9,
        "the 2026-07-28 changelog lists nine major changes; this matrix has {}",
        MAJOR.len()
    );
}

#[test]
fn every_cited_test_exists() {
    // A cell naming a test that does not exist reads exactly like a covered
    // one, and the shape check that preceded this passed it: it asserted the
    // string LOOKED like a test path. It did — and one of the two tests it
    // named had never been written. Checking the shape of evidence is not
    // checking the evidence, so the name is now resolved against the source.
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    // Both trees: an integration test lives under `tests/`, a unit test inside
    // the module it covers under `src/`, and the matrix cites both shapes.
    let mut sources = String::new();
    let mut stack = vec![root.join("src"), root.join("tests")];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir)
            .expect("source tree is readable")
            .flatten()
        {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|e| e == "rs") {
                sources.push_str(&std::fs::read_to_string(&path).expect("source file is readable"));
            }
        }
    }

    for row in all_rows() {
        for name in row.evidence {
            let function = name.rsplit("::").next().unwrap_or_default();

            assert!(
                name.contains("::") && function.starts_with("ac_"),
                "evidence for '{}' is not a test path: {name}",
                row.statement
            );

            assert!(
                sources.contains(&format!("fn {function}(")),
                "evidence for '{}' names {name}, and no such test is defined anywhere in the tree",
                row.statement
            );
        }
    }
}
