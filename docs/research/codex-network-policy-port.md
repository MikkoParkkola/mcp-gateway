# Codex Network-Policy + Identity-Binding Port to mcp-gateway

**Ticket:** MIK-3542 | **Status:** Research (INSPIRE, P2, ROI 12x) | **Date:** 2026-05-19

## Source (V — fetched 2026-05-16)

- https://openai.com/index/running-codex-safely/ (OpenAI, 2026-05-08)
- https://developers.openai.com/codex/config-basic

## Codex Primitives (verbatim from config schema)

### 1. Network policy (`[experimental_network]`)

```toml
enabled = true
allow_local_binding = false
denied_domains = ["pastebin.com"]
allowed_domains = ["login.microsoftonline.com", "*.openai.com"]
allowed_web_search_modes = ["cached"]
```

Properties: declarative domain allow/deny lists, wildcard support, local-binding gate (blocks 127.0.0.1 / 0.0.0.0 SSRF tail risk), cached-only web-search default (kills live-fetch unless explicitly opted-in).

### 2. Identity binding (credential storage + forced workspace)

```toml
cli_auth_credentials_store = "keyring"        # OS keychain, not disk
mcp_oauth_credentials_store = "keyring"        # MCP OAuth tokens in keychain
forced_login_method = "chatgpt"                # pinned identity provider
forced_chatgpt_workspace_id = "<uuid>"         # pinned tenant
```

Properties: OS-native keychain storage (macOS Keychain / libsecret / Windows Credential Manager); identity provider + workspace pinned at config time, not negotiated per session.

## Map to mcp-gateway

| Codex primitive | mcp-gateway today | Gap | Module to extend |
|---|---|---|---|
| `denied_domains` / `allowed_domains` | None — per-server allowlists only at tool granularity (`examples/per-client-tool-scopes.yaml`: `allowed_tools` / `denied_tools`) | High — no URL-level egress filter | `src/session_sandbox.rs` + new `src/gateway/network_policy.rs` |
| `allow_local_binding = false` | None | High — SSRF tail risk on local MCP backends | `session_sandbox.rs` (extend bind validator) |
| `allowed_web_search_modes = ["cached"]` | None — brave/jina/parallel tools fetch live | High — repeat-query token spend + freshness leakage | New cache-gate middleware in router; integrate hebb cache (B2-MEM) |
| `mcp_oauth_credentials_store = "keyring"` | `src/gateway/oauth/mod.rs` stores via env / .env / 1Password | Medium — disk leakage + SOC2/ISO27001 procurement blocker | `oauth/mod.rs` + new `oauth/keyring_store.rs` (keyring-rs crate) |
| `forced_login_method` / `forced_chatgpt_workspace_id` | OAuth config exists (`docs/OAUTH_CONFIG.md`) but no pin enforcement | Low — additive constraint on existing `oauth/audit.rs` | `src/gateway/auth.rs` + `config/features/auth.rs` |

Existing surfaces to reuse (B4-PLATFORM): `gateway.example.yaml` schema, per-server config plumbing, `session_sandbox`, `oauth/audit.rs`, `key_server/oidc.rs`.

## Adoption Steps (3-5)

1. **Schema extension** (`gateway.example.yaml` + `src/config/features/`): add `network_policy` block per-server with `allowed_domains`, `denied_domains`, `allow_local_binding`, `web_search_mode` (live | cached | cache-or-fail). Default `allow_local_binding = false`. Existing configs without the block keep current behavior (backward-compat).
2. **Network policy crate** (`src/gateway/network_policy.rs`): wildcard domain matcher, precedence rule (per-server allowlist > deny > allow > default-deny), `log_denied` reuses existing audit hook. Wire into router egress for web-fetch tools (brave, jina, parallel, fetch).
3. **Cached web-search gate**: introduce cache-mode middleware that routes web-fetch tool calls through hebb cache before live fetch; cache-miss behavior configurable (`block | fall-through | log-warn-and-fetch`). Default `log-warn-and-fetch` during transition, flip to `cached` after 30-day telemetry.
4. **Keychain credential store** (`src/gateway/oauth/keyring_store.rs`): keyring-rs backend (macOS Security framework, libsecret, Windows Credential Manager). Migration: read keyring first, fall back to .env / 1Password with deprecation warning. Flip default after 30 days.
5. **Docs + cite Codex doctrine**: update `README.md` + `docs/OAUTH_CONFIG.md` + `gateway.example.yaml` comments with the new primitives. Cite OpenAI's "Running Codex safely" as third-party validation (regulated-buyer narrative for SOC2/ISO27001 procurement gate).

## Bets check

- **B1-IDENT**: keychain storage = MCP OAuth platform identity layer (on-thesis)
- **B2-MEM**: cache-gate extends hebb to web-fetch (consolidate, don't fork)
- **B3-DURABLE**: schema versioned; omitting blocks = legacy behavior
- **B4-PLATFORM**: reuse `session_sandbox` + `oauth` + `config/features` plumbing — no rewrite

## Rollback

Per-server: omit `network_policy` block → existing behavior. Keychain: deprecation-only initially; default flip gated on 30-day error-rate telemetry.
