<!-- SPDX-FileCopyrightText: 2026 Mikko Parkkola -->
<!-- SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0 -->
# Privacy

mcp-gateway runs on your machine and sends nothing to its author or to any
analytics, telemetry, crash-reporting or update service. It connects only to
the places listed below: ones you configured, ones a command you typed names,
and, if you turn events on, callback addresses your authenticated clients
registered.

Each statement here names the code or the check that makes it true. The list of
call sites is enforced: `scripts/dev/check-outbound-clients.py` fails CI when
product code gains a new place that can open an outbound connection that
`scripts/dev/outbound-sites.tsv` and this page do not list.

## What it does not do

- **No telemetry, analytics, crash reports or update checks.** No dependency
  provides one (`Cargo.toml:253-254`: the only metrics crates are `metrics`, imported as
  `telemetry_metrics` for local counters, and `metrics-exporter-prometheus`), and no call site in the table below sends to
  such a service.
- **Metrics stay local.** Prometheus metrics are served at the gateway's own
  `/metrics` endpoint for you to scrape (`src/gateway/routes.rs:24`); nothing pushes
  them anywhere.
- **The protocol-revision counters stay local.** `src/protocol_revision_telemetry/`
  keeps in-process counters, debug log lines, Prometheus counters and a
  `window.json` file under the gateway's data directory
  (`src/protocol_revision_telemetry/durable.rs:73`); the module opens no connection.
- **Audit and SIEM exports are files.** The export sink writes a local file
  (`src/control_plane/export.rs:384`, `FileExportSink`).
- **The web UI loads nothing from other hosts.** Its pages and scripts are
  served by the gateway itself, under a `script-src 'self'` content security
  policy (`src/gateway/ui/shell.rs:77`, `src/gateway/ui/mod.rs`).

## Where it connects

| Call site | When | Where to |
|---|---|---|
| `src/transport/http/client.rs` | the gateway talks to an HTTP backend | the backends you configured (A2A included) |
| `src/transport/websocket_pinned.rs` | the gateway talks to a WebSocket backend | the backends you configured |
| `src/oauth/client/destination.rs` | a backend needs OAuth | the discovery and token endpoints of the servers you configured |
| `src/identity_propagation/token_exchange.rs` | identity propagation is configured | the identity provider you configured |
| `src/key_server/oidc_jwks_cache.rs` | the key server verifies a token | the signing keys (JWKS) of the issuers you configured |
| `src/capability/executor/client.rs` | a capability runs | the URL written in that capability file |
| `src/gateway/router/accounts/bridge.rs` | a personal account is used | the provider you configured |
| `src/events/client.rs` | events are on (off by default, `src/config/features/events.rs:186`) | callback URLs your authenticated clients registered; pending deliveries resume after a restart (`src/events/runtime.rs:188`) |
| `src/security/ssrf/mod.rs` | the shared client for addresses the gateway does not trust: `cap install --from-github`, `import-url`, the UI import, personal-account providers, capability calls | the address the command, the import or the configuration names; DNS is pinned and the environment proxy ignored |
| `src/gateway/ui/import.rs` | you import from a URL in the web UI | the URL you entered |
| `src/commands/skills.rs` | you run `skills` with an `http(s)` source | that URL |
| `src/commands/doctor/npm_pin.rs` | you run `doctor` | `registry.npmjs.org`, about the npx packages your enabled stdio backends pin; User-Agent `mcp-gateway-doctor`, no version or host details. Off with `--no-registry-check`, `MCP_GATEWAY_DOCTOR_NO_REGISTRY_CHECK` or `security.posture: hardened` |
| `src/commands/doctor.rs`, `src/commands/doctor/ws_reach.rs` | you run `doctor` | your configured HTTP and WebSocket backends |
| `src/commands/doctor/health.rs`, `src/commands/stats.rs`, `src/commands/dashboard_link.rs`, `src/commands/config_export/mod.rs` | you run `doctor`, `stats`, `dashboard` or `config export` | the local gateway |

`cap install --from-github` fetches from `raw.githubusercontent.com/<repo>`
only when you run it (`src/registry/mod.rs:298`, `src/commands/cap.rs:322`).

## What other programs do

Backends you configure as stdio commands are separate programs the gateway
starts; their own network traffic is theirs, not the gateway's. A backend run as
`npx <package>` downloads that package from npm, and `mcp-gateway init` can
write such starter backends (`src/commands/mod.rs:137`).

## Where secrets are kept

Secrets are never stored in the config file. They go to the OS keychain (macOS
Keychain, Linux Secret Service, Windows Credential Manager) or to a new
owner-only file, as `secrets.store` chooses: `auto`, the default, prefers the
keychain (`src/secret_store/mod.rs:176-190`, `src/secret_store/files.rs:3`; SECURITY.md).
On Windows, files holding a secret are created owner-only with a protected
access list, and a volume that keeps no access lists is refused; see
SECURITY.md, "Known limitations".
