<!-- SPDX-FileCopyrightText: 2026 Mikko Parkkola -->
<!-- SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0 -->
# Privacy

mcp-gateway runs on your machine and sends nothing to its author or to any
analytics, telemetry, crash-reporting or update service. Its outbound
connections go only to the destinations in the table below. Those are:

- addresses you configured;
- a URL you type in a command, enter in the web UI, or write into a capability file;
- a URL a capability builds from values the calling MCP client passes: a capability's
  endpoint can take arguments, and a shipped one takes its whole URL from its caller
  (`capabilities/media/video_download.yaml:37`, `src/capability/executor/request.rs:49`);
- callback URLs your authenticated clients registered, if you turn events on;
- two fixed public services, each contacted only by the command that names it:
  `registry.npmjs.org` when you run `doctor` (on by default, with three
  switches to turn it off) and `raw.githubusercontent.com` when you run
  `cap install --from-github`.

A destination in the table is where a connection starts. An HTTP redirect it
answers with can lead somewhere else: the gateway checks each hop against its
address policy before following it (`src/security/ssrf/mod.rs`,
`ssrf_redirect_policy`). On a direct connection, host names are resolved
through your operating system's resolver (`src/security/ssrf/resolver.rs:42`).
Through a proxy you set (`capabilities.egress_proxy` for capabilities,
`HTTPS_PROXY` where the environment proxy is used), the proxy resolves them
(`src/capability/executor/client.rs:24-28`).

## How this list is kept honest

`scripts/dev/check-outbound-clients.py` runs in CI. It looks for a fixed set of
client-constructor names (HTTP, WebSocket, TCP, UDP) in product code, counts
them per source file and per kind, once per line, and fails when a count
changes until `scripts/dev/outbound-sites.tsv` is updated. It also fails when a
listed file is not named on this page.

It is a tripwire, not a proof. It does not see a constructor spelled another
way, one site replaced by another of the same kind in the same file, a new
caller of a client an existing site builds, a change of destination at an
existing site, a DNS lookup, a child process's traffic, or a request your
browser makes. Those are reviewed by hand against this page.

## What it does not do

- **No telemetry, analytics, crash reports or update checks.** No dependency
  provides one (`Cargo.toml:253-254`: the only metrics crates are `metrics`,
  imported as `telemetry_metrics` for local counters, and
  `metrics-exporter-prometheus`), and no place in the table below sends to such
  a service.
- **Metrics stay local.** Prometheus metrics are served at the gateway's own
  `/metrics` endpoint for you to scrape (`src/gateway/routes.rs:24`); nothing
  pushes them anywhere.
- **The protocol-revision counters stay local.** `src/protocol_revision_telemetry/`
  keeps in-process counters, debug log lines, Prometheus counters and a
  `window.json` file under the gateway's data directory
  (`src/protocol_revision_telemetry/durable.rs:73`); the module opens no
  connection.
- **Audit and SIEM exports are files.** The export sink writes a local file
  (`src/control_plane/export.rs:384`, `FileExportSink`).
- **The web UI loads nothing from other hosts.** Both the dashboard (`/ui`,
  `/ui/classic`) and the new shell serve their scripts from the gateway itself
  and send a `script-src 'self'` content security policy
  (`src/gateway/ui/mod.rs`, `src/gateway/ui/shell.rs:77`).

## Where it connects

| Call site | When | Where to |
|---|---|---|
| `src/transport/http/client.rs` | the gateway talks to an HTTP backend | the backends you configured (A2A included) |
| `src/transport/websocket_pinned.rs` | the gateway talks to a WebSocket backend | the backends you configured |
| `src/oauth/client/destination.rs` | a backend needs OAuth | the discovery and token endpoints of the servers you configured, and the client-registration endpoint their metadata advertises (`src/oauth/client/registration.rs:139`) |
| `src/identity_propagation/token_exchange.rs` | identity propagation is configured | the identity provider you configured |
| `src/key_server/oidc_jwks_cache.rs` | the key server verifies a token | the signing keys (JWKS) of the issuers you configured |
| `src/capability/executor/client.rs` | a capability runs | the URL in that capability file, with any `{argument}` filled from the calling client's values, checked against the address policy; through `capabilities.egress_proxy` if you set one |
| `src/gateway/router/accounts/bridge.rs` | a personal account is used | the provider you configured |
| `src/events/client.rs` | events are on (off by default, `src/config/features/events.rs:186`) | callback URLs your authenticated clients registered; pending deliveries resume after a restart (`src/events/runtime.rs:188`) |
| `src/security/ssrf/mod.rs` | the shared client for addresses the gateway does not trust: `cap install --from-github`, `cap import <URL>` (`src/capability/openapi/convert.rs:162`), `import-url`, the web UI import, personal-account providers and capability calls | the address the command, the import or the configuration names. `import-url <URL>` probes several well-known API description paths on that URL's host (`src/capability/discovery/mod.rs:168`) |
| `src/gateway/ui/import.rs` | you import from a URL in the web UI | the URL you entered |
| `src/commands/skills.rs` | you run `skills` with an `http(s)` source | that URL |
| `src/commands/doctor/npm_pin.rs` | you run `doctor`; on by default, off with `--no-registry-check`, `MCP_GATEWAY_DOCTOR_NO_REGISTRY_CHECK` or `security.posture: hardened` (`src/commands/doctor/npm_pin.rs:62`) | `registry.npmjs.org`, one request per npx package an enabled stdio backend pins. The request path is the package name (`:150`); the pinned version is compared locally, not sent. The User-Agent is `mcp-gateway-doctor` (`:31`). An `HTTPS_PROXY` you set is used |
| `src/commands/doctor.rs`, `src/commands/doctor/ws_reach.rs` | you run `doctor` | your configured HTTP and WebSocket backends |
| `src/commands/doctor/health.rs`, `src/commands/stats.rs`, `src/commands/dashboard_link.rs`, `src/commands/config_export/mod.rs` | you run `doctor`, `stats`, `dashboard` or `config export` | the gateway your config names, normally this machine's; `stats --url` points it at another |

`cap install --from-github` fetches from `raw.githubusercontent.com/<repo>`
only when you run it (`src/registry/mod.rs:298`, `src/commands/cap.rs:322`).

## What other programs do

- **Backends you configure as stdio commands** are separate programs the
  gateway starts; their network traffic is theirs, not the gateway's. A
  backend run as `npx <package>` downloads that package from npm, and
  `mcp-gateway init` can write such starter backends (`src/commands/mod.rs:137`).
- **OAuth sign-in** opens your default browser at the provider's page
  (`src/oauth/client/browser.rs:53`, `:59`). What that page loads is between
  your browser and the provider.

## Where secrets are kept

- **Secrets you save through the gateway** go to the OS keychain (macOS
  Keychain, Linux Secret Service, Windows Credential Manager) or to a new
  owner-only file, as `secrets.store` chooses: `auto`, the default, prefers the
  keychain (`src/secret_store/mod.rs:176-190`, `src/secret_store/files.rs:3`).
- **The admin token `mcp-gateway init` generates** is, today, written into the
  config file as `auth.bearer_token` (`src/commands/mod.rs:215`). On Unix that
  file is written readable only by you. Do not commit it. To keep the token out
  of the file, set `bearer_token: "env:MCP_GATEWAY_TOKEN"` and put the token in
  that variable (docs/QUICKSTART.md).
- **OAuth tokens** for backends are kept as JSON files written owner-only
  (0600 from creation) through a scratch file (`src/oauth/storage.rs:330-346`),
  not through `secrets.store`.
- **On Windows**, files holding a secret are created owner-only with a protected
  access list, and a volume that keeps no access lists is refused. See
  SECURITY.md, "Known limitations".
