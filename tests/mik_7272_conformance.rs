// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The conformance matrix (NFR.COMPAT.4, NFR.CONFORMANCE.1, U6).
//!
//! One row per normative statement in the 2026-07-28 changelog, crossed with
//! the four axes NFR.CONFORMANCE.1 requires: role, transport, revision and
//! outcome. The product is total — every statement emits every cell — and a
//! cell is answered in exactly one of two ways: evidence that names a real
//! test, or an exemption that names a rule and a witness.
//!
//! The matrix exists because per-increment tests inherit each increment's
//! shape: they check what was built, in the role it was built for. A statement
//! verified server-side only is verified at half, and nothing in a green suite
//! says which half. The same holds for the other three axes: a statement
//! checked only over HTTP says nothing about stdio, a statement checked only
//! on the modern path says nothing about what legacy peers still get, and a
//! statement checked only in the positive direction says nothing about what
//! happens when the precondition fails.
//!
//! **An empty cell is the finding.** `every_cell_is_covered_or_exempt` fails
//! on any cell that is neither evidenced nor exempt.
//!
//! **A blanket exemption is also the finding.** Every statement here comes from
//! the 2026-07-28 changelog, so one unscoped `REVISION-PREDATES-STATEMENT`
//! rule would sweep every legacy cell in the matrix — including the retained
//! legacy behaviour this criterion demands evidence for. Two guards stop that:
//! `an_exemption_rule_is_scoped_on_at_least_one_axis` refuses a rule that
//! names no axis, and `a_cell_carrying_evidence_matches_no_exemption_rule`
//! turns the collision between a rule and real evidence into a failure rather
//! than a silent pass.

/// Which side of the connection the gateway is on for a cell.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// The gateway answering a client.
    Server,
    /// The gateway calling a backend.
    Client,
}

/// Which transport a cell is about.
///
/// WebSocket is deliberately not a value here (D1). `src/transport/mod.rs` has
/// a WebSocket client implementation and `src/gateway/server/mod.rs` spawns a
/// listener, but no MCP dispatch sits behind it — so every WebSocket cell could
/// only ever be answered by a test that asserts nothing. `UNOWNED_BEYOND_THE_MATRIX`
/// records the silence in as many words; 440 vacuous cells would hide it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    /// Streamable HTTP.
    Http,
    /// stdio.
    Stdio,
}

/// The direction a cell verifies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// The statement holds when its preconditions are met.
    Positive,
    /// The statement's refusal path: the precondition fails and the gateway
    /// says so, rather than degrading quietly.
    Negative,
}

/// The modern revision. Absent from `SUPPORTED_VERSIONS` by design: the
/// handshake is retired, so the modern era is not a negotiable version.
const MODERN: &str = "2026-07-28";

/// The negotiable revisions, as `src/protocol/mod.rs` lists them.
const LEGACY: &[&str] = &["2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"];

/// Every revision the matrix crosses: the union of both lists.
fn revisions() -> Vec<&'static str> {
    std::iter::once(MODERN)
        .chain(LEGACY.iter().copied())
        .collect()
}

/// Which revisions a piece of evidence speaks for.
///
/// `AnyLegacy` is coarse on purpose. The retained-legacy tests
/// (`ac_stateless_3_a_legacy_response_still_carries_the_session_header` and
/// its siblings) drive one legacy request and do not distinguish 2025-11-25
/// from 2024-11-05. Recording that coarseness is honest; claiming four
/// separate verifications from one test would not be.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Revisions {
    /// The modern path only.
    Modern,
    /// Every legacy revision, undifferentiated.
    AnyLegacy,
    /// Both eras.
    Both,
}

impl Revisions {
    fn covers(self, revision: &str) -> bool {
        match self {
            Revisions::Modern => revision == MODERN,
            Revisions::AnyLegacy => revision != MODERN,
            Revisions::Both => true,
        }
    }
}

/// A test, and the coordinates of the cells it actually covers.
///
/// The coordinates are the point. Before this, a row carried one role and one
/// transport and the evidence carried none, so the matrix could say "this
/// statement is verified" without ever saying where — and the places it was
/// not verified had no cell to be empty in.
pub struct Evidence {
    /// The test function path. Resolved against the source tree by
    /// `every_cited_test_exists`; a name that resolves to nothing fails.
    pub test: &'static str,
    pub roles: &'static [Role],
    pub transports: &'static [Transport],
    pub revisions: Revisions,
    pub outcomes: &'static [Outcome],
}

impl Evidence {
    fn covers(&self, role: Role, transport: Transport, revision: &str, outcome: Outcome) -> bool {
        self.roles.contains(&role)
            && self.transports.contains(&transport)
            && self.revisions.covers(revision)
            && self.outcomes.contains(&outcome)
    }
}

/// One normative statement and the evidence for it.
pub struct Row {
    /// The changelog item, quoted closely enough to be found again.
    pub statement: &'static str,
    /// The requirement identifier that owns it.
    pub requirement: &'static str,
    /// Tests that verify it, each naming the cells it covers.
    pub evidence: &'static [Evidence],
}

/// The closed vocabulary of reasons a cell can be non-applicable.
///
/// Closed on purpose, and by decision of
/// `docs/design/2026-09-02-conformance-matrix.md`: a reason outside this list
/// is a design event, not a test edit. "N/A" with no code is what this
/// criterion exists to forbid.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExemptionCode {
    /// The statement has no surface in that role. Witness: the statement text.
    NoSurfaceInRole,
    /// The transport has no mechanism the statement could apply to. Witness:
    /// the transport's capability declaration.
    TransportLacksMechanism,
    /// The revision predates the statement. Witness: the version entry plus
    /// the change that introduced the obligation.
    RevisionPredatesStatement,
}

/// A rule that answers cells with a reason instead of a test.
///
/// Every axis field is a filter, and an empty filter means "every value on
/// this axis". A rule with every filter empty would answer the whole matrix,
/// which is why `an_exemption_rule_is_scoped_on_at_least_one_axis` refuses it.
pub struct Exemption {
    pub code: ExemptionCode,
    /// Why the cell cannot exist. Checked for being non-empty, and read by
    /// humans; this is the "reason" the criterion requires of every N/A cell.
    pub witness: &'static str,
    /// Scoped by owning requirement id, not by statement text: the id is
    /// short, stable, and already unique per row.
    pub requirements: &'static [&'static str],
    pub roles: &'static [Role],
    pub transports: &'static [Transport],
    pub revisions: &'static [&'static str],
    pub outcomes: &'static [Outcome],
}

impl Exemption {
    fn matches(
        &self,
        requirement: &str,
        role: Role,
        transport: Transport,
        revision: &str,
        outcome: Outcome,
    ) -> bool {
        (self.requirements.is_empty() || self.requirements.contains(&requirement))
            && (self.roles.is_empty() || self.roles.contains(&role))
            && (self.transports.is_empty() || self.transports.contains(&transport))
            && (self.revisions.is_empty() || self.revisions.contains(&revision))
            && (self.outcomes.is_empty() || self.outcomes.contains(&outcome))
    }

    /// Whether the rule narrows the matrix on any axis at all.
    fn is_scoped(&self) -> bool {
        !self.requirements.is_empty()
            || !self.roles.is_empty()
            || !self.transports.is_empty()
            || !self.revisions.is_empty()
            || !self.outcomes.is_empty()
    }
}

// Coordinate shorthands. Spelled once so a cell's coordinates read as data
// rather than as five repeated literals.
const SERVER: &[Role] = &[Role::Server];
const CLIENT: &[Role] = &[Role::Client];
const HTTP: &[Transport] = &[Transport::Http];
const STDIO: &[Transport] = &[Transport::Stdio];
const EITHER_TRANSPORT: &[Transport] = &[Transport::Http, Transport::Stdio];
const POSITIVE: &[Outcome] = &[Outcome::Positive];
const NEGATIVE: &[Outcome] = &[Outcome::Negative];
const EITHER_OUTCOME: &[Outcome] = &[Outcome::Positive, Outcome::Negative];

/// Spelled as a function so a cell reads as one line of data. The field order
/// is the axis order of the criterion: role, transport, revision, outcome.
const fn ev(
    test: &'static str,
    roles: &'static [Role],
    transports: &'static [Transport],
    revisions: Revisions,
    outcomes: &'static [Outcome],
) -> Evidence {
    Evidence {
        test,
        roles,
        transports,
        revisions,
        outcomes,
    }
}

const MODERN_ONLY: Revisions = Revisions::Modern;
const LEGACY_ONLY: Revisions = Revisions::AnyLegacy;
const EITHER_ERA: Revisions = Revisions::Both;

/// The nine major changes of the 2026-07-28 changelog, in its own order.
const MAJOR: &[Row] = &[
    Row {
        statement: "1. Remove protocol-level sessions and the Mcp-Session-Id header; \
                    list endpoints no longer vary per-connection",
        requirement: "MIK-7215.STATELESS.3, MIK-7272.ORDER.2",
        evidence: &[
            ev(
                "mik_7215_acs::http::ac_stateless_3_a_modern_response_carries_no_session_header",
                SERVER,
                HTTP,
                MODERN_ONLY,
                POSITIVE,
            ),
            // The retained legacy half. The criterion asks for modern removal
            // *versus* retained legacy behaviour; this is the second term.
            ev(
                "mik_7215_acs::http::ac_stateless_3_a_legacy_response_still_carries_the_session_header",
                SERVER,
                HTTP,
                LEGACY_ONLY,
                POSITIVE,
            ),
            ev(
                "gateway::router::tests::ac_order_2_a_modern_request_is_given_no_session_even_when_it_offers_one",
                SERVER,
                HTTP,
                MODERN_ONLY,
                NEGATIVE,
            ),
            // The profile clause is not an HTTP mechanism: it is refused in the
            // meta-MCP layer, above the transport, so it holds on stdio too.
            ev(
                "gateway::router::tests::ac_order_2_a_modern_caller_is_refused_gateway_set_profile",
                SERVER,
                EITHER_TRANSPORT,
                MODERN_ONLY,
                NEGATIVE,
            ),
            ev(
                "gateway::meta_mcp::tests::ac_order_2_set_profile_is_refused_without_a_session",
                SERVER,
                EITHER_TRANSPORT,
                MODERN_ONLY,
                NEGATIVE,
            ),
            ev(
                "gateway::meta_mcp::tests::ac_order_2_get_profile_is_refused_without_a_session",
                SERVER,
                EITHER_TRANSPORT,
                MODERN_ONLY,
                NEGATIVE,
            ),
            ev(
                "gateway::meta_mcp::tests::ac_order_2_initialize_binds_no_profile_without_a_session",
                SERVER,
                EITHER_TRANSPORT,
                MODERN_ONLY,
                NEGATIVE,
            ),
        ],
    },
    Row {
        statement: "2. Make MCP stateless: remove the initialize handshake; every request \
                    carries its version and client capabilities in _meta",
        requirement: "MIK-7215.STATELESS.1, .2, .8, .9",
        evidence: &[
            ev(
                "mik_7215_acs::ac_stateless_1_a_request_carrying_its_own_version_is_modern",
                SERVER,
                EITHER_TRANSPORT,
                MODERN_ONLY,
                POSITIVE,
            ),
            ev(
                "mik_7215_acs::ac_stateless_1_each_request_carries_its_own_version",
                SERVER,
                EITHER_TRANSPORT,
                MODERN_ONLY,
                POSITIVE,
            ),
            ev(
                "mik_7215_acs::http::ac_stateless_2_a_modern_result_identifies_the_server",
                SERVER,
                HTTP,
                MODERN_ONLY,
                POSITIVE,
            ),
            // One endpoint serving both eras is the legacy half of this row: the
            // handshake is gone for modern callers and still answered for legacy
            // ones, on the same URL.
            ev(
                "mik_7215_acs::http::ac_stateless_8_one_endpoint_serves_both_eras",
                SERVER,
                HTTP,
                EITHER_ERA,
                POSITIVE,
            ),
            ev(
                "mik_7215_acs::http::ac_stateless_4_an_unsupported_version_is_refused_with_its_own_error",
                SERVER,
                HTTP,
                EITHER_ERA,
                NEGATIVE,
            ),
        ],
    },
    Row {
        statement: "3. Add server/discover: servers MUST implement this RPC",
        requirement: "MIK-7217.DISCOVER.1, .2",
        evidence: &[
            ev(
                "mik_7217_acs::ac_discover_1_document_matches_the_specified_shape",
                SERVER,
                EITHER_TRANSPORT,
                MODERN_ONLY,
                POSITIVE,
            ),
            ev(
                "mik_7217_acs::http::ac_discover_1_http_dispatch_answers_server_discover",
                SERVER,
                HTTP,
                MODERN_ONLY,
                POSITIVE,
            ),
            // The stdio half, and the reason the transport axis earns its keep:
            // this row would read as covered from the HTTP test alone.
            ev(
                "gateway::server::tests::ac_discover_1_stdio_dispatch_answers_server_discover",
                SERVER,
                STDIO,
                MODERN_ONLY,
                POSITIVE,
            ),
            ev(
                "mik_7217_acs::era::ac_discover_4_a_discovery_document_means_modern",
                CLIENT,
                EITHER_TRANSPORT,
                EITHER_ERA,
                POSITIVE,
            ),
        ],
    },
    Row {
        statement: "4. Replace the HTTP GET endpoint and resources/subscribe with \
                    subscriptions/listen",
        requirement: "MIK-7272.SUB.1, .2",
        evidence: &[
            ev(
                "mik_7272_subscriptions_acs::http::ac_sub_1_the_gateway_serves_subscriptions_listen",
                SERVER,
                HTTP,
                MODERN_ONLY,
                POSITIVE,
            ),
            ev(
                "mik_7272_subscriptions_acs::http::ac_sub_1_resources_subscribe_is_refused_on_the_modern_path",
                SERVER,
                HTTP,
                MODERN_ONLY,
                NEGATIVE,
            ),
            ev(
                "mik_7272_subscriptions_acs::ac_sub_2_a_request_scoped_notification_is_not_a_subscription_notification",
                SERVER,
                EITHER_TRANSPORT,
                MODERN_ONLY,
                NEGATIVE,
            ),
        ],
    },
    Row {
        statement: "5. Remove ping, logging/setLevel and notifications/roots/list_changed; \
                    log level is per-request",
        requirement: "MIK-7215.STATELESS.6, .7",
        evidence: &[
            ev(
                "mik_7215_acs::http::ac_stateless_6_ping_is_refused_on_the_modern_path",
                SERVER,
                HTTP,
                MODERN_ONLY,
                NEGATIVE,
            ),
            // Removal proved against retention: the same method, the other era.
            ev(
                "mik_7215_acs::http::ac_stateless_6_ping_still_works_on_the_legacy_path",
                SERVER,
                HTTP,
                LEGACY_ONLY,
                POSITIVE,
            ),
            ev(
                "mik_7215_acs::ac_stateless_7_a_log_notification_is_never_delivered_to_a_subscriber",
                SERVER,
                EITHER_TRANSPORT,
                MODERN_ONLY,
                NEGATIVE,
            ),
        ],
    },
    Row {
        statement: "6. Move tasks into an official extension, polled via tasks/get",
        requirement: "MIK-7272.TASK.1",
        evidence: &[
            ev(
                "mik_7272_exploit_acs::tasks::ac_task_1_a_task_is_polled_not_awaited",
                SERVER,
                EITHER_TRANSPORT,
                MODERN_ONLY,
                POSITIVE,
            ),
            ev(
                "mik_7272_subscriptions_acs::http::ac_task_1_tasks_get_reports_an_unknown_handle",
                SERVER,
                HTTP,
                MODERN_ONLY,
                NEGATIVE,
            ),
            // Legacy clients cannot reach this surface at all, which is the
            // legacy half of the statement rather than an absence of coverage.
            ev(
                "mik_7272_subscriptions_acs::http::ac_task_1_tasks_get_is_not_reachable_on_the_legacy_path",
                SERVER,
                HTTP,
                LEGACY_ONLY,
                NEGATIVE,
            ),
        ],
    },
    Row {
        statement: "7. Multi Round-Trip Requests replace server-initiated requests",
        requirement: "MIK-7212.MRTR.1-.10",
        evidence: &[
            ev(
                "mik_7212_acs::retry::ac_mrtr_1_a_retry_carries_its_inputs_and_state",
                SERVER,
                EITHER_TRANSPORT,
                MODERN_ONLY,
                POSITIVE,
            ),
            ev(
                "mik_7212_acs::ac_mrtr_2_a_minted_envelope_round_trips",
                SERVER,
                EITHER_TRANSPORT,
                MODERN_ONLY,
                POSITIVE,
            ),
            ev(
                "mik_7212_acs::inflight::ac_mrtr_6_a_retry_landing_on_another_replica_fails_explicitly",
                SERVER,
                EITHER_TRANSPORT,
                MODERN_ONLY,
                NEGATIVE,
            ),
            // The bridge: a legacy client is still asked the old way, which is
            // the retained behaviour the modern removal is measured against.
            ev(
                "mik_7212_acs::reverse::ac_mrtr_7_a_legacy_client_is_asked_the_way_it_expects",
                CLIENT,
                EITHER_TRANSPORT,
                LEGACY_ONLY,
                POSITIVE,
            ),
        ],
    },
    Row {
        statement: "8. All results carry resultType; a missing field from an earlier peer \
                    is complete",
        requirement: "MIK-7272.RESULT.1, .2",
        evidence: &[
            ev(
                "mik_7213_acs::http::ac_result_1_every_modern_result_carries_result_type",
                SERVER,
                HTTP,
                MODERN_ONLY,
                POSITIVE,
            ),
            ev(
                "mik_7213_acs::http::ac_result_1_a_legacy_result_carries_none",
                SERVER,
                HTTP,
                LEGACY_ONLY,
                POSITIVE,
            ),
            ev(
                "mik_7213_acs::ac_result_2_a_missing_result_type_reads_as_complete",
                CLIENT,
                EITHER_TRANSPORT,
                LEGACY_ONLY,
                POSITIVE,
            ),
            ev(
                "mik_7272_result_2::ac_result_2_response_cache_stores_a_reply_without_a_result_type",
                CLIENT,
                EITHER_TRANSPORT,
                LEGACY_ONLY,
                NEGATIVE,
            ),
            ev(
                "mik_7272_result_2::ac_result_2_idempotency_completes_a_reply_without_a_result_type",
                CLIENT,
                EITHER_TRANSPORT,
                LEGACY_ONLY,
                NEGATIVE,
            ),
        ],
    },
    Row {
        statement: "9. Remove SSE resumability and message redelivery; a broken stream \
                    is re-issued as a new request",
        requirement: "MIK-7272.SUB.3, .4",
        evidence: &[
            ev(
                "mik_7272_subscriptions_acs::reissue::ac_sub_4_a_reissued_call_is_the_same_call",
                SERVER,
                HTTP,
                MODERN_ONLY,
                POSITIVE,
            ),
            ev(
                "mik_7212_acs::idempotency::ac_mrtr_10_a_retry_does_not_collide_with_the_call_it_continues",
                SERVER,
                HTTP,
                MODERN_ONLY,
                NEGATIVE,
            ),
        ],
    },
];

/// The minor changes that carry a normative obligation, numbered as the
/// changelog numbers them, followed by the two statements NFR.CONFORMANCE.1
/// names by hand.
///
/// The changelog's numbering skips 11 and 13. Those numbers are left out
/// rather than guessed: the changelog is not in this repository, so a number
/// assigned here would be an invention that reads as a citation. For the same
/// reason there is no `covers_every_minor_change` counterpart to
/// `the_matrix_covers_every_major_change` — a totality test needs an
/// authoritative denominator, and one built on a guessed count asserts
/// something false while looking like coverage. Tracked below.
const MINOR: &[Row] = &[
    Row {
        statement: "1. extensions field on client and server capabilities",
        requirement: "MIK-7272.EXT.1",
        // Empty, and tracked. The two tests named here until now exercised
        // `ExtensionSet` negotiation and never the `extensions` field on
        // serialised capabilities, which is what this statement is about.
        // The honest evidence is E1-E5 of
        // `docs/design/2026-08-31-cluster-b-capability-and-trace-metadata-test-plan.md`.
        evidence: &[],
    },
    Row {
        statement: "2. OpenTelemetry trace context propagation through _meta",
        requirement: "MIK-7272.OTEL.1",
        evidence: &[
            ev(
                "mik_7272_exploit_acs::ac_otel_1_a_trace_context_is_read_from_request_meta",
                SERVER,
                EITHER_TRANSPORT,
                MODERN_ONLY,
                POSITIVE,
            ),
            ev(
                "mik_7272_exploit_acs::ac_otel_1_the_context_is_propagated_to_the_backend_unchanged",
                CLIENT,
                EITHER_TRANSPORT,
                MODERN_ONLY,
                POSITIVE,
            ),
        ],
    },
    Row {
        statement: "3. Servers SHOULD return tools in a deterministic order",
        requirement: "MIK-7272.ORDER.1",
        evidence: &[
            // A SHOULD that predates the modern era: the order was stable for
            // legacy callers too, so this is not a modern-only obligation.
            ev(
                "mik_7213_acs::http::ac_order_1_the_tool_order_is_stable_across_callers",
                SERVER,
                EITHER_TRANSPORT,
                EITHER_ERA,
                POSITIVE,
            ),
        ],
    },
    Row {
        statement: "4. Require Mcp-Method and Mcp-Name headers; support x-mcp-header",
        requirement: "MIK-7214.HEADER.1-.6",
        evidence: &[
            ev(
                "mik_7214_acs::ac_header_2_mcp_name_is_required_for_exactly_three_methods",
                SERVER,
                HTTP,
                MODERN_ONLY,
                POSITIVE,
            ),
            ev(
                "mik_7214_acs::ac_header_4_the_specifications_encoding_table_decodes",
                SERVER,
                HTTP,
                MODERN_ONLY,
                POSITIVE,
            ),
            ev(
                "mik_7214_acs::http::ac_header_3_a_disagreeing_method_header_is_refused_over_http",
                SERVER,
                HTTP,
                MODERN_ONLY,
                NEGATIVE,
            ),
            // Both directions in one test, and legitimately so: it withholds
            // the headers the modern path requires (the negative precondition)
            // and asserts the legacy request still succeeds (the positive
            // outcome). That is the retained-legacy half of this row.
            ev(
                "mik_7214_acs::http::ac_header_2_a_legacy_request_needs_no_headers",
                SERVER,
                HTTP,
                LEGACY_ONLY,
                EITHER_OUTCOME,
            ),
        ],
    },
    Row {
        statement: "5. Require ttlMs and cacheScope on the five cacheable results",
        requirement: "MIK-7213.CACHE.1, .2, .3",
        evidence: &[
            ev(
                "mik_7213_acs::http::ac_cache_1_a_cacheable_result_carries_ttl_and_scope",
                SERVER,
                HTTP,
                MODERN_ONLY,
                POSITIVE,
            ),
            ev(
                "mik_7213_acs::http::ac_cache_3_no_response_from_this_gateway_claims_public",
                SERVER,
                HTTP,
                MODERN_ONLY,
                NEGATIVE,
            ),
            ev(
                "mik_7213_acs::http::ac_cache_1_a_non_cacheable_result_carries_no_cache_fields",
                SERVER,
                HTTP,
                MODERN_ONLY,
                NEGATIVE,
            ),
        ],
    },
    Row {
        statement: "6. Resource-not-found moves from -32002 to -32602",
        requirement: "MIK-7272.ERROR.2",
        evidence: &[ev(
            "mik_7213_acs::ac_error_1_no_renumbered_code_sits_in_the_implementation_defined_range",
            SERVER,
            EITHER_TRANSPORT,
            MODERN_ONLY,
            NEGATIVE,
        )],
    },
    Row {
        statement: "7. Validate a present iss against the recorded issuer (RFC 9207)",
        requirement: "MIK-7272.OAUTH.1",
        evidence: &[
            ev(
                "mik_7272_oauth_acs::issuer::ac_oauth_1_a_different_issuer_is_refused_before_redemption",
                CLIENT,
                EITHER_TRANSPORT,
                MODERN_ONLY,
                NEGATIVE,
            ),
            ev(
                "mik_7272_oauth_acs::issuer::ac_oauth_1_the_comparison_is_exact",
                CLIENT,
                EITHER_TRANSPORT,
                MODERN_ONLY,
                NEGATIVE,
            ),
        ],
    },
    Row {
        statement: "8. Specify application_type during Dynamic Client Registration",
        requirement: "MIK-7272.OAUTH.2",
        evidence: &[ev(
            "mik_7272_oauth_acs::ac_oauth_2_dynamic_registration_declares_an_application_type",
            CLIENT,
            EITHER_TRANSPORT,
            MODERN_ONLY,
            POSITIVE,
        )],
    },
    Row {
        statement: "9. Key persisted client credentials by issuer",
        requirement: "MIK-7272.OAUTH.3",
        evidence: &[ev(
            "mik_7272_oauth_acs::ac_oauth_3_credentials_are_keyed_by_the_issuer_that_granted_them",
            CLIENT,
            EITHER_TRANSPORT,
            MODERN_ONLY,
            POSITIVE,
        )],
    },
    Row {
        statement: "10. Loosen inputSchema and outputSchema to JSON Schema 2020-12",
        requirement: "MIK-6865.SCHEMA.1",
        evidence: &[ev(
            "mik_7272_exploit_acs::schema::ac_schema_1_no_meta_tool_nests_an_object_inside_an_array",
            SERVER,
            EITHER_TRANSPORT,
            MODERN_ONLY,
            NEGATIVE,
        )],
    },
    Row {
        statement: "12. Error-code allocation policy; renumber HeaderMismatch, \
                    MissingRequiredClientCapability and UnsupportedProtocolVersion",
        requirement: "MIK-7272.ERROR.1",
        evidence: &[
            ev(
                "mik_7213_acs::ac_error_1_the_renumbered_codes_are_at_their_new_numbers",
                SERVER,
                EITHER_TRANSPORT,
                MODERN_ONLY,
                POSITIVE,
            ),
            ev(
                "mik_7215_acs::http::ac_stateless_4_an_unsupported_version_is_refused_with_its_own_error",
                SERVER,
                HTTP,
                EITHER_ERA,
                NEGATIVE,
            ),
        ],
    },
    // The two statements NFR.CONFORMANCE.1 names by hand. Neither is a
    // re-citation: of the 124 `ac_*` functions in this tree, none names
    // elicitation, completion, structured results, `outputSchema`, scalar,
    // array or arbitrary JSON. Anyone sizing this row from the existing test
    // count sizes it wrong.
    Row {
        statement: "Modern URL-elicitation completion removal: a modern URL-mode \
                    elicitation completes through the MRTR continuation and emits no \
                    server-initiated completion, while the legacy bridge retains \
                    elicitation/create",
        requirement: "MIK-7272.ELICIT.1",
        // Empty, and tracked. `notifications/elicitation/complete` appears
        // nowhere in `src/` or `tests/`, and `ElicitationCreateParams` carries
        // no `elicitationId`, so the modern arm of this statement is absent by
        // omission rather than implemented. A test asserting "no completion
        // notification is emitted" would pass trivially and keep passing if
        // the whole elicitation path were deleted — the exact vacuous evidence
        // this file exists to prevent. The discriminating pair needs the
        // modern continuation wired first.
        evidence: &[],
    },
    Row {
        statement: "Arbitrary-JSON structured results: scalar, array and object \
                    structured content, with outputSchema preserved through the \
                    transform chain",
        requirement: "MIK-7272.STRUCT.1",
        evidence: &[],
    },
];

fn all_rows() -> Vec<&'static Row> {
    MAJOR.iter().chain(MINOR.iter()).collect()
}

/// Every cell of the matrix, in axis order.
fn cells() -> Vec<(&'static Row, Role, Transport, &'static str, Outcome)> {
    let mut out = Vec::new();
    for row in all_rows() {
        for role in [Role::Server, Role::Client] {
            for transport in [Transport::Http, Transport::Stdio] {
                for revision in revisions() {
                    for outcome in [Outcome::Positive, Outcome::Negative] {
                        out.push((row, role, transport, revision, outcome));
                    }
                }
            }
        }
    }
    out
}

/// Cells that are empty on purpose, each naming the work that fills it.
///
/// A gap is not an exemption. An exemption says the cell cannot exist; a gap
/// says it should exist and nobody has written it yet. Collapsing the two is
/// how a matrix comes to look complete while the obligation goes unheld, so
/// they are separate tables with separate tests.
pub struct Gap {
    /// The work that closes it, named specifically enough to be chased.
    pub owner: &'static str,
    pub requirements: &'static [&'static str],
    pub roles: &'static [Role],
    pub transports: &'static [Transport],
    pub revisions: &'static [&'static str],
    pub outcomes: &'static [Outcome],
}

impl Gap {
    fn matches(
        &self,
        requirement: &str,
        role: Role,
        transport: Transport,
        revision: &str,
        outcome: Outcome,
    ) -> bool {
        (self.requirements.is_empty() || self.requirements.contains(&requirement))
            && (self.roles.is_empty() || self.roles.contains(&role))
            && (self.transports.is_empty() || self.transports.contains(&transport))
            && (self.revisions.is_empty() || self.revisions.contains(&revision))
            && (self.outcomes.is_empty() || self.outcomes.contains(&outcome))
    }
}

// Server-only statements: what the gateway answers, not what it asks.
const SERVER_ONLY: &[&str] = &[
    "MIK-7215.STATELESS.3, MIK-7272.ORDER.2",
    "MIK-7215.STATELESS.1, .2, .8, .9",
    "MIK-7272.SUB.1, .2",
    "MIK-7215.STATELESS.6, .7",
    "MIK-7272.TASK.1",
    "MIK-7272.SUB.3, .4",
    "MIK-7272.ORDER.1",
    "MIK-7214.HEADER.1-.6",
    "MIK-7213.CACHE.1, .2, .3",
    "MIK-7272.ERROR.2",
    "MIK-6865.SCHEMA.1",
    "MIK-7272.ERROR.1",
];

// Statements whose mechanism is an HTTP construct with no stdio counterpart.
const HTTP_MECHANISM: &[&str] = &[
    "MIK-7272.SUB.3, .4",
    "MIK-7214.HEADER.1-.6",
    "MIK-7213.CACHE.1, .2, .3",
];

// Statements the 2026-07-28 changelog introduced outright, with no retained
// legacy behaviour anywhere in their evidence.
const MODERN_INTRODUCTIONS: &[&str] = &[
    "MIK-7272.SUB.1, .2",
    "MIK-7272.SUB.3, .4",
    "MIK-7272.OTEL.1",
    "MIK-7213.CACHE.1, .2, .3",
    "MIK-7272.ERROR.2",
    "MIK-7272.OAUTH.1",
    "MIK-7272.OAUTH.2",
    "MIK-7272.OAUTH.3",
    "MIK-6865.SCHEMA.1",
];

/// Cells that cannot exist, each naming the rule and the witness for it.
///
/// Every rule here narrows the matrix on at least one axis, and no rule may
/// answer a cell that evidence already proves — the two guards below enforce
/// both, because a reason that covers everything explains nothing.
const EXEMPTIONS: &[Exemption] = &[
    Exemption {
        code: ExemptionCode::NoSurfaceInRole,
        witness: "the statement governs what the gateway answers as a server; \
                  acting as a client to a backend it never serves these methods, \
                  so there is no behaviour to verify",
        requirements: SERVER_ONLY,
        roles: CLIENT,
        transports: &[],
        revisions: &[],
        outcomes: &[],
    },
    Exemption {
        code: ExemptionCode::NoSurfaceInRole,
        witness: "the gateway is the OAuth client: it registers, redeems and \
                  stores credentials. It issues none, so the server role has no \
                  authorization surface for these statements",
        requirements: &["MIK-7272.OAUTH.1", "MIK-7272.OAUTH.2", "MIK-7272.OAUTH.3"],
        roles: SERVER,
        transports: &[],
        revisions: &[],
        outcomes: &[],
    },
    Exemption {
        code: ExemptionCode::TransportLacksMechanism,
        witness: "stdio frames carry no HTTP headers, no status codes and no GET \
                  endpoint; SSE resumability, the required request headers and the \
                  cache directives are all HTTP constructs with nothing on the \
                  other side of the transport to apply to",
        requirements: HTTP_MECHANISM,
        roles: &[],
        transports: STDIO,
        revisions: &[],
        outcomes: &[],
    },
    Exemption {
        code: ExemptionCode::RevisionPredatesStatement,
        witness: "introduced by the 2026-07-28 changelog and absent from every \
                  entry of SUPPORTED_VERSIONS in src/protocol/mod.rs; a legacy peer \
                  neither sends nor expects it, and the gateway's legacy path \
                  retains no counterpart",
        requirements: MODERN_INTRODUCTIONS,
        roles: &[],
        transports: &[],
        revisions: LEGACY,
        outcomes: &[],
    },
];

/// Cells that should exist and do not, each naming the work that fills it.
///
/// Widening the matrix from 20 statement rows to 880 cells is what produced
/// this list. The four axes were previously collapsed into one role field and
/// one transport field per row, so a statement proved over HTTP on the modern
/// path in the positive direction read as proved — and the stdio, legacy,
/// client-role and refusal-direction cells it never touched had no cell to be
/// empty in. They do now.
const TRACKED_GAPS: &[Gap] = &[
    Gap {
        owner: "Cluster B writes E1-E5 of \
                docs/design/2026-08-31-cluster-b-capability-and-trace-metadata-test-plan.md",
        requirements: &["MIK-7272.EXT.1"],
        roles: &[],
        transports: &[],
        revisions: &[],
        outcomes: &[],
    },
    Gap {
        // O1 of the test plan. The modern arm of this statement is absent by
        // omission: `notifications/elicitation/complete` appears nowhere in
        // src/ or tests/, and ElicitationCreateParams carries no
        // elicitationId. A test asserting the gateway emits no completion
        // would pass trivially and keep passing if the elicitation path were
        // deleted outright, so the honest artifact is this entry.
        owner: "MIK-7387.STDIO.1-.3 and CONFORM.2 wire the modern MRTR \
                continuation; until the modern arm exists there is nothing to \
                contrast the retained legacy elicitation/create against",
        requirements: &["MIK-7272.ELICIT.1"],
        roles: &[],
        transports: &[],
        revisions: &[],
        outcomes: &[],
    },
    Gap {
        // The product side of this one is clear: every `output_schema: None`
        // site in src/provider/transforms/ and src/provider/composite_provider.rs
        // sits below that file's #[cfg(test)] line, so they are fixtures and
        // not production constructors dropping an upstream schema. Nothing is
        // broken; the acceptance tests simply do not exist yet.
        owner: "MIK-7272.STRUCT.1 acceptance tests: scalar, array and object \
                structuredContent with outputSchema preserved through the \
                transform chain. No ac_* test in this tree names them",
        requirements: &["MIK-7272.STRUCT.1"],
        roles: &[],
        transports: &[],
        revisions: &[],
        outcomes: &[],
    },
    Gap {
        owner: "stdio conformance: server/discover is the only statement driven \
                over stdio by an ac_* test. stdio is a transport this gateway \
                serves and every other statement is verified over HTTP only",
        requirements: &[
            "MIK-6865.SCHEMA.1",
            "MIK-7212.MRTR.1-.10",
            "MIK-7215.STATELESS.1, .2, .8, .9",
            "MIK-7215.STATELESS.3, MIK-7272.ORDER.2",
            "MIK-7215.STATELESS.6, .7",
            "MIK-7217.DISCOVER.1, .2",
            "MIK-7272.ERROR.1",
            "MIK-7272.ERROR.2",
            "MIK-7272.OAUTH.1",
            "MIK-7272.OAUTH.2",
            "MIK-7272.OAUTH.3",
            "MIK-7272.ORDER.1",
            "MIK-7272.OTEL.1",
            "MIK-7272.RESULT.1, .2",
            "MIK-7272.SUB.1, .2",
            "MIK-7272.TASK.1",
        ],
        roles: &[],
        transports: STDIO,
        revisions: &[],
        outcomes: &[],
    },
    Gap {
        owner: "legacy-era conformance: four tests carry the retained legacy \
                behaviour (session header, ping, resultType absence, headers not \
                required) and nothing else on the legacy path is driven by an \
                ac_* test, though the gateway still serves it",
        requirements: &[
            "MIK-7212.MRTR.1-.10",
            "MIK-7215.STATELESS.3, MIK-7272.ORDER.2",
            "MIK-7215.STATELESS.6, .7",
            "MIK-7217.DISCOVER.1, .2",
            "MIK-7272.ERROR.1",
            "MIK-7272.ORDER.1",
            "MIK-7272.RESULT.1, .2",
            "MIK-7272.TASK.1",
        ],
        roles: &[],
        transports: &[],
        revisions: LEGACY,
        outcomes: &[],
    },
    Gap {
        owner: "client-role conformance: the gateway is an MCP client to every \
                backend it routes to, and these statements are verified only in \
                the role where they were built",
        requirements: &[
            "MIK-7212.MRTR.1-.10",
            "MIK-7217.DISCOVER.1, .2",
            "MIK-7272.OAUTH.1",
            "MIK-7272.OAUTH.2",
            "MIK-7272.OAUTH.3",
            "MIK-7272.OTEL.1",
            "MIK-7272.RESULT.1, .2",
        ],
        roles: CLIENT,
        transports: &[],
        revisions: &[],
        outcomes: &[],
    },
    Gap {
        owner: "refusal-direction conformance: these statements are verified \
                only where their precondition holds, so nothing says what the \
                gateway does when it does not",
        requirements: &[
            "MIK-7217.DISCOVER.1, .2",
            "MIK-7272.ORDER.1",
            "MIK-7272.OTEL.1",
            "MIK-7272.RESULT.1, .2",
        ],
        roles: &[],
        transports: &[],
        revisions: &[],
        outcomes: NEGATIVE,
    },
    Gap {
        owner: "success-direction conformance: these statements are verified \
                only by their refusal path, so nothing says the behaviour they \
                require actually happens",
        requirements: &[
            "MIK-6865.SCHEMA.1",
            "MIK-7215.STATELESS.6, .7",
            "MIK-7272.ERROR.2",
        ],
        roles: &[],
        transports: &[],
        revisions: &[],
        outcomes: POSITIVE,
    },
];

/// Obligations this matrix cannot hold a cell for, recorded so the silence is
/// explicit rather than implied.
///
/// D1 ruled WebSocket out of the transport axis: `src/transport/websocket.rs`
/// speaks the transport and `src/gateway/ws_listener.rs` accepts connections,
/// but no MCP dispatch sits behind the listener, so the 440 cells the axis value
/// would add could only ever be answered vacuously. That ruling leaves nothing
/// in `TRACKED_GAPS` able to hold the obligation — a gap naming no cell is stale
/// by `a_tracked_gap_is_still_a_gap` — so it is recorded here, in as many words,
/// instead of living in a doc comment where nothing checks it.
const UNOWNED_BEYOND_THE_MATRIX: &[&str] = &[
    "WebSocket conformance is unowned: no ticket, test plan or team in this tree \
     claims it. The gateway speaks the transport and accepts connections on it, \
     and not one statement in this matrix is verified over it, so every cell it \
     would add is empty and nobody is named to fill them",
];

#[test]
fn every_cell_is_covered_or_exempt() {
    // The finding this file exists to produce, now over the whole product
    // rather than over the statement list. A cell that is neither evidenced,
    // exempt nor tracked is an obligation nobody is holding — and it is
    // invisible in a green suite, because a test that does not exist cannot
    // fail.
    let mut empty: Vec<String> = Vec::new();

    for (row, role, transport, revision, outcome) in cells() {
        let evidenced = row
            .evidence
            .iter()
            .any(|e| e.covers(role, transport, revision, outcome));
        let exempt = EXEMPTIONS
            .iter()
            .any(|x| x.matches(row.requirement, role, transport, revision, outcome));
        let tracked = TRACKED_GAPS
            .iter()
            .any(|g| g.matches(row.requirement, role, transport, revision, outcome));

        if !evidenced && !exempt && !tracked {
            empty.push(format!(
                "{} / {role:?} / {transport:?} / {revision} / {outcome:?}",
                row.requirement
            ));
        }
    }

    assert!(
        empty.is_empty(),
        "{} of {} cells are neither evidenced, exempt nor tracked:\n{}",
        empty.len(),
        cells().len(),
        empty.join("\n")
    );
}

#[test]
fn every_exemption_names_a_known_code_and_a_witness() {
    // The criterion requires a reason on every N/A cell. A code with no
    // witness is a label, not a reason: it says the cell was classified and
    // not why, so nobody can check the classification.
    for exemption in EXEMPTIONS {
        assert!(
            matches!(
                exemption.code,
                ExemptionCode::NoSurfaceInRole
                    | ExemptionCode::TransportLacksMechanism
                    | ExemptionCode::RevisionPredatesStatement
            ),
            "exemption code outside the closed vocabulary: {:?}",
            exemption.code
        );
        assert!(
            !exemption.witness.trim().is_empty(),
            "exemption {:?} carries no witness",
            exemption.code
        );
    }
}

#[test]
fn an_exemption_rule_is_scoped_on_at_least_one_axis() {
    // Without this, three rules turn all 880 cells green. An unscoped rule is
    // not a statement about the protocol; it is a statement about wanting the
    // suite to pass.
    for exemption in EXEMPTIONS {
        assert!(
            exemption.is_scoped(),
            "exemption {:?} ({}) narrows no axis and would answer the entire \
             matrix by itself",
            exemption.code,
            exemption.witness
        );
    }
}

#[test]
fn a_cell_carrying_evidence_matches_no_exemption_rule() {
    // The load-bearing guard. Every statement in this matrix comes from the
    // 2026-07-28 changelog, so one blanket `REVISION-PREDATES-STATEMENT` over
    // the four legacy revisions would answer roughly 640 cells on a single
    // rule — and it would swallow exactly the retained-legacy evidence this
    // criterion demands: the legacy session header, the legacy ping, the
    // legacy result with no resultType, the legacy request needing no headers.
    //
    // A cell cannot be both proven and impossible. When a rule collides with
    // real evidence, the rule is too broad, and this turns that into a failure
    // instead of a silent pass.
    let mut collisions: Vec<String> = Vec::new();

    for (row, role, transport, revision, outcome) in cells() {
        let Some(evidence) = row
            .evidence
            .iter()
            .find(|e| e.covers(role, transport, revision, outcome))
        else {
            continue;
        };

        for exemption in EXEMPTIONS {
            if exemption.matches(row.requirement, role, transport, revision, outcome) {
                collisions.push(format!(
                    "{} / {role:?} / {transport:?} / {revision} / {outcome:?} is proven by {} \
                     and declared impossible by {:?} ({})",
                    row.requirement, evidence.test, exemption.code, exemption.witness
                ));
            }
        }
    }

    assert!(
        collisions.is_empty(),
        "{} cells are both evidenced and exempt; the rule is broader than the \
         behaviour:\n{}",
        collisions.len(),
        collisions.join("\n")
    );
}

#[test]
fn a_tracked_gap_is_still_a_gap() {
    // The other half of the exemption, and it fails two ways. A gap whose
    // cells have since been evidenced is an exemption nothing needs, and it
    // would silently absolve the next regression into the same cells. A gap
    // naming no cell at all is worse: the obligation has left the matrix and
    // every other test here stays green, because they all iterate cells and
    // there is no longer a cell to iterate.
    let all = cells();
    let mut stale: Vec<String> = Vec::new();

    for gap in TRACKED_GAPS {
        let mut matched = 0usize;
        let mut evidenced = 0usize;

        for (row, role, transport, revision, outcome) in &all {
            if !gap.matches(row.requirement, *role, *transport, revision, *outcome) {
                continue;
            }
            matched += 1;
            if row
                .evidence
                .iter()
                .any(|e| e.covers(*role, *transport, revision, *outcome))
            {
                evidenced += 1;
            }
        }

        if matched == 0 {
            stale.push(format!("names no cell: {}", gap.owner));
        } else if evidenced == matched {
            stale.push(format!(
                "every cell it tracks now has evidence: {}",
                gap.owner
            ));
        }
    }

    assert!(
        stale.is_empty(),
        "these tracked gaps no longer describe an empty part of the matrix: {stale:#?}"
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
    //
    // Expressed over cells now rather than over a row-level role field: a
    // statement counts only if some cell in the client role actually carries
    // evidence, which is a stricter reading of the same guard.
    let client_side = all_rows()
        .iter()
        .filter(|row| row.evidence.iter().any(|e| e.roles.contains(&Role::Client)))
        .count();

    assert!(
        client_side >= 7,
        "only {client_side} statements carry evidence in the client role; the \
         gateway is a client to every backend and that half regresses silently"
    );
}

#[test]
fn both_transports_carry_the_statements_that_apply_to_them() {
    // stdio is the transport that gets forgotten: it has no headers, no status
    // codes and no session, so a statement checked only over HTTP says nothing
    // about it. Also expressed over cells: evidence must actually name stdio.
    let stdio_side = all_rows()
        .iter()
        .filter(|row| {
            row.evidence
                .iter()
                .any(|e| e.transports.contains(&Transport::Stdio))
        })
        .count();

    assert!(
        stdio_side >= 10,
        "only {stdio_side} statements carry evidence beyond HTTP; stdio is a \
         transport this gateway serves and a matrix that ignores it is an HTTP \
         matrix"
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
    // checking the evidence, so the name is resolved against the source.
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
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
        for evidence in row.evidence {
            let name = evidence.test;
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

#[test]
fn the_matrix_records_what_it_cannot_hold_a_cell_for() {
    // The mirror of `a_tracked_gap_is_still_a_gap`, for an obligation with no
    // cell to be empty in. The note is only honest while WebSocket stays off
    // the axis: the moment it becomes an axis value, the silence has cells of
    // its own and belongs in TRACKED_GAPS, where the staleness guard can reach
    // it. Two records of one silence is how one of them goes stale unnoticed.
    assert!(
        !UNOWNED_BEYOND_THE_MATRIX.is_empty(),
        "the matrix claims to hold every obligation; D1 says otherwise"
    );

    for note in UNOWNED_BEYOND_THE_MATRIX {
        assert!(
            note.contains("unowned"),
            "an off-matrix note that does not say the work is unowned records \
             nothing: {note}"
        );
    }

    assert!(
        cells()
            .iter()
            .all(|(_, _, transport, _, _)| matches!(transport, Transport::Http | Transport::Stdio)),
        "the transport axis has grown past HTTP and stdio; move the off-matrix \
         notes into TRACKED_GAPS so the staleness guard covers them"
    );
}
