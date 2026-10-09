// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `MetaMcp` MCP protocol handlers: `server/discover`, initialize and `tools/list`.

use super::{
    CallerStanding, InvokeScope, JsonRpcResponse, MetaMcp, RequestId, ToolTotal, Value,
    build_code_mode_tools, build_discovery_preamble, build_initialize_result, debug,
    extract_client_version, negotiate_version, project_tool_descriptor_trust_card,
    project_tool_descriptors_trust_cards, session_fp, session_key, tool_total,
    tools_list_result_with_trust_cards, warn,
};

// ============================================================================
// MCP protocol handlers — initialize + tools
// ============================================================================

impl MetaMcp {
    /// Build the `server/discover` document (MCP 2026-07-28).
    ///
    /// The revision removes the `initialize` handshake, so this RPC is how a
    /// peer learns what the gateway speaks. Servers **MUST** implement it, and
    /// a client **MAY** call it before anything else — on stdio it is also the
    /// backward-compatibility probe, since a legacy server answers it with an
    /// error rather than a document.
    ///
    /// The version list and identity come from the same source as the
    /// `initialize` result (`build_initialize_result`). Assembling them
    /// separately would let the two answers drift, and a peer would get one
    /// story from the handshake and another from discovery.
    #[must_use]
    pub fn discover_document(&self, modern_enabled: bool) -> serde_json::Value {
        // Modern: this document IS the 2026 surface. Only identity and the version
        // list are taken from it; capabilities are rebuilt below.
        let handshake = crate::gateway::meta_mcp_helpers::build_initialize_result(
            crate::protocol::PROTOCOL_VERSION,
            "",
            crate::protocol::meta::Era::Modern,
            self.change_feed(),
        );

        // Field names and placement are the specification's (`DiscoverResult`),
        // never invented: `supportedVersions`, `serverInfo` under its reverse-DNS
        // `_meta` key, and the required `ttlMs` and `cacheScope`, whose absence
        // made a 2026-07-28 client load no tools (MIK-8009). A wire format that
        // agrees only with its own tests is not one anyone else can read.
        // Discovery advertises what this gateway can actually serve, which is
        // the legacy negotiation list plus the modern revisions when the switch
        // that serves them is on. Leaving the modern revision out made enabling
        // it unreachable: a conforming peer asks discovery which revisions
        // exist, and the one the switch had just turned on was not among them.
        //
        // Added HERE and not to `SUPPORTED_VERSIONS`, which is what a legacy
        // `initialize` negotiates over. A stateless revision cannot be reached
        // through a handshake it deleted, so advertising it there would offer a
        // 2025 client a version the handshake can never settle on.
        let mut versions: Vec<&str> = crate::protocol::SUPPORTED_VERSIONS.to_vec();
        if modern_enabled {
            for version in crate::protocol::meta::MODERN_VERSIONS {
                if !versions.contains(version) {
                    versions.push(version);
                }
            }
        }

        // Capabilities are rebuilt here rather than taken from `handshake`,
        // and that is the one thing discovery does NOT share with the
        // handshake. The extension set is era-specific: `initialize` answers
        // 2025 clients, which cannot use a 2026 extension and whose result is
        // pinned byte-for-byte by an existing criterion, while this document is
        // the 2026 surface and is where a peer looks for what the gateway
        // speaks. Identity and the version list still come from one source, so
        // the drift this guards against stays guarded.
        let capabilities = crate::gateway::meta_mcp_helpers::build_server_capabilities(
            crate::gateway::meta_mcp_helpers::discovery_extensions(),
            self.change_feed(),
        );

        let capabilities = self.capabilities_with_events(capabilities);
        let mut document = serde_json::json!({
            "resultType": "complete",
            "supportedVersions": versions,
            "capabilities": capabilities,
            "_meta": {
                "io.modelcontextprotocol/serverInfo": handshake.server_info,
            },
        });
        if let Some(object) = document.as_object_mut() {
            crate::protocol::cacheable::write_cache_hints(
                object,
                "server/discover",
                crate::protocol::cacheable::LIST_TTL_MS,
            );
        }
        document
    }

    /// Handle `initialize` with version negotiation and optional profile binding.
    pub fn handle_initialize(
        &self,
        id: RequestId,
        params: Option<&Value>,
        session_id: Option<&str>,
        header_profile: Option<&str>,
        era: crate::protocol::meta::Era,
        scope: InvokeScope<'_>,
    ) -> JsonRpcResponse {
        // MIK-7996: the profile binding below is a session write.
        let _session = self.hold_session(session_id);
        let client_version = extract_client_version(params);
        let negotiated_version = negotiate_version(client_version);
        // NFR.OBS.1. The session is served under this value from here on, and
        // the observation record has to report it rather than the client's ask
        // -- the two differ whenever the ask is unsupported. Bound at the one
        // site that negotiates, so no second derivation can drift from it.
        crate::protocol_revision_telemetry::bind_session_revision(session_id, negotiated_version);
        debug!(
            client = client_version,
            negotiated = negotiated_version,
            "Protocol version negotiation"
        );
        let profile_hint = header_profile.or_else(|| {
            params
                .and_then(|p| p.get("profile"))
                .and_then(serde_json::Value::as_str)
        });

        if let (Some(sid), Some(name)) = (session_key(session_id), profile_hint) {
            if self.profile_registry.contains(name) {
                self.session_profiles.set_profile(sid, name);
                debug!(
                    session_id = %session_fp(sid),
                    profile = name,
                    "Session bound to routing profile at initialize"
                );
            } else {
                warn!(
                    session_id = %session_fp(sid),
                    requested = name,
                    "Requested profile not found at initialize; using registry default"
                );
            }
        }

        let instructions = self.build_instructions(scope, session_id);
        // `era` is threaded from the dispatcher rather than re-derived from
        // `params` here: the dispatcher reads the mirrored header as well as
        // `_meta`, and a second derivation is the two-predicate defect
        // `protocol::meta::classify_request` records.
        let result =
            build_initialize_result(negotiated_version, &instructions, era, self.change_feed());
        let result = self.initialize_with_events(result);
        JsonRpcResponse::success(id, result)
    }

    /// The initialize instructions as this caller may read them: counts over
    /// what it could invoke, and a guide naming only those capabilities (A3).
    pub(super) fn build_instructions(
        &self,
        scope: InvokeScope<'_>,
        session_id: Option<&str>,
    ) -> String {
        let (tool_total, server_count) = self.admitted_counts(scope, session_id);
        let mut instructions =
            build_discovery_preamble(tool_total, server_count, &self.meta_tool_exposure);

        if let Some(cap) = self.get_capabilities()
            && self.admits_backend(&cap.name, scope, session_id)
        {
            let caps = self.guide_capabilities(&cap, scope, session_id);
            let entries: Vec<_> = caps
                .iter()
                .map(|(name, category, chains_with)| {
                    crate::gateway::meta_mcp_helpers::RoutingEntry {
                        name,
                        category,
                        chains_with,
                    }
                })
                .collect();
            let routing =
                crate::gateway::meta_mcp_helpers::build_routing_guide(&entries, &cap.name);
            if !routing.is_empty() {
                instructions.push_str(&routing);
            }
        }
        instructions
    }

    /// Compute live (`tool_count`, `server_count`) from the cached backend statuses.
    ///
    /// Uses only the in-memory cache — no I/O.  Both counts are 0 when the
    /// registry is empty (e.g. in unit tests).
    pub(super) fn backend_counts(&self) -> (ToolTotal, usize) {
        let backends = self.backends.all();
        let server_count = backends.len();
        (tool_total(&backends), server_count)
    }

    /// Handle `tools/list` — Code Mode returns 2 tools; Traditional returns full set.
    ///
    /// When surfaced tools are configured, their schemas are appended after the
    /// meta-tools (subject to routing profile filtering).  Tools whose backend
    /// cache is empty are silently omitted rather than blocking the response.
    pub fn handle_tools_list(&self, id: RequestId) -> JsonRpcResponse {
        // Admin standing: this wrapper has no caller to read and no production
        // call site — every live path (`..._with_url_override` for HTTP,
        // `..._with_params` for stdio) supplies real standing. It answers the
        // "what is the whole meta surface" question the surface-count gates
        // ask, so lowering it here would shrink a documented count without any
        // caller's disclosure actually changing.
        self.handle_tools_list_for_session(id, None, InvokeScope::unscoped(CallerStanding::Admin))
    }

    pub(super) fn shadow_tools_list_assembly(
        &self,
        session_id: Option<&str>,
        request_variant: bool,
    ) -> crate::protocol_revision_telemetry::ToolsListShadow {
        // Static Code Mode returns the same two meta-tools only on the standard
        // path. A spec-preview query returns filtered backend tools instead.
        if self.code_mode_enabled && !request_variant {
            return crate::protocol_revision_telemetry::observe_tools_list(
                crate::protocol_revision_telemetry::ListFilters::default(),
            );
        }
        let profile = self.active_profile(session_id).is_restrictive()
            && (request_variant || !self.surfaced_tools.is_empty());
        #[cfg(feature = "spec-preview")]
        let session = !self.promoted_tools_for_session(session_id).is_empty();
        #[cfg(not(feature = "spec-preview"))]
        let session = false;
        crate::protocol_revision_telemetry::observe_tools_list(
            crate::protocol_revision_telemetry::ListFilters {
                // The caller's invoke predicate shapes the surfaced tools (A3),
                // so it shapes this list exactly when there are any to shape.
                principal: !self.surfaced_tools.is_empty(),
                profile,
                session,
                request: request_variant,
            },
        )
    }

    /// Session-aware variant of `handle_tools_list` used by the router.
    pub fn handle_tools_list_for_session(
        &self,
        id: RequestId,
        session_id: Option<&str>,
        scope: InvokeScope<'_>,
    ) -> JsonRpcResponse {
        self.shadow_tools_list_assembly(session_id, false);
        let standing = CallerStanding::from(scope);
        let tools = self.meta_tools_for(standing, self.admitted_counts(scope, session_id));
        let mut tool_descriptors =
            self.meta_projections
                .project("gateway:meta", "mcp-gateway", &tools);

        // Append surfaced tools (skip in Code Mode — it uses a fixed 2-tool schema).
        if !self.code_mode_enabled {
            for surfaced in &self.surfaced_tools {
                if let Some(tool) = self.resolve_surfaced_tool(surfaced, session_id, scope) {
                    let server_id = if self.backends.get(&surfaced.server).is_some() {
                        format!("backend:{}", surfaced.server)
                    } else {
                        format!("capability:{}", surfaced.server)
                    };
                    tool_descriptors.push(project_tool_descriptor_trust_card(
                        server_id,
                        &surfaced.server,
                        &tool,
                    ));
                }
            }
        }

        // Append session-promoted tools (spec-preview only).
        // Promoted tools are de-duplicated against surfaced tools: if a tool
        // was promoted AND is already surfaced, we skip the promoted copy.
        #[cfg(feature = "spec-preview")]
        if !self.code_mode_enabled {
            let promoted = self.promoted_tools_for_session(session_id);
            for (server, tool) in promoted {
                if self
                    .may_invoke(&server, &tool.name, scope, session_id)
                    .is_err()
                {
                    continue;
                }
                let already_present = tool_descriptors
                    .iter()
                    .any(|t| t.get("name").and_then(Value::as_str) == Some(tool.name.as_str()));
                if !already_present {
                    tool_descriptors.push(project_tool_descriptor_trust_card(
                        "gateway:promoted",
                        "mcp-gateway",
                        &tool,
                    ));
                }
            }
        }

        JsonRpcResponse::success(id, tools_list_result_with_trust_cards(tool_descriptors))
    }

    /// Dispatch the `tools/list` request with optional params — entry point for the router.
    ///
    /// When the `spec-preview` feature is active and the params contain a `query`
    /// key, delegates to the filtered handler (SEP-1821).  Otherwise falls back to
    /// the standard session-aware handler so baseline behaviour is unchanged.
    /// The filtered handler may spawn a cache fill, so call it inside a Tokio
    /// runtime.
    pub fn handle_tools_list_with_params(
        &self,
        id: RequestId,
        #[cfg_attr(not(feature = "spec-preview"), allow(unused_variables))] params: Option<&Value>,
        session_id: Option<&str>,
        scope: InvokeScope<'_>,
    ) -> JsonRpcResponse {
        #[cfg(feature = "spec-preview")]
        if let Some(q) = params.and_then(|p| p.get("query")).and_then(Value::as_str) {
            return self.handle_tools_list_filtered(id, q, session_id, scope);
        }
        self.handle_tools_list_for_session(id, session_id, scope)
    }

    /// Variant of [`handle_tools_list_with_params`] that accepts a per-request
    /// Code Mode override from the URL query parameter `?codemode=search_and_execute`.
    ///
    /// Precedence rules:
    /// - If the static config already has `code_mode.enabled = true`, the
    ///   result is always Code Mode regardless of `url_override`.
    /// - If `url_override` is `true`, Code Mode is active for this request only.
    /// - If both are `false`, the standard full meta-tool list is returned.
    ///
    /// When Code Mode is active via the URL override, the spec-preview filtered
    /// path is bypassed (Code Mode always returns exactly two tools).
    pub fn handle_tools_list_with_url_override(
        &self,
        id: RequestId,
        params: Option<&Value>,
        session_id: Option<&str>,
        url_override: bool,
        scope: InvokeScope<'_>,
    ) -> JsonRpcResponse {
        let effective_code_mode = self.code_mode_enabled || url_override;
        if effective_code_mode && !self.code_mode_enabled {
            // URL-activated Code Mode: return the two fixed tools directly.
            crate::protocol_revision_telemetry::observe_tools_list(
                crate::protocol_revision_telemetry::ListFilters {
                    request: true,
                    ..crate::protocol_revision_telemetry::ListFilters::default()
                },
            );
            // Still filtered - a URL parameter must not widen what the
            // operator exposed.
            let mut tools = self.meta_tool_exposure.filter(build_code_mode_tools());
            tools.retain(|tool| CallerStanding::from(scope).permits(&tool.name));
            let tool_descriptors =
                project_tool_descriptors_trust_cards("gateway:meta", "mcp-gateway", &tools);
            return JsonRpcResponse::success(
                id,
                tools_list_result_with_trust_cards(tool_descriptors),
            );
        }
        // No override (or static config already handles it): follow normal path.
        self.handle_tools_list_with_params(id, params, session_id, scope)
    }
}
