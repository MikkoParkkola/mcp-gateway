<!-- SPDX-FileCopyrightText: 2026 Mikko Parkkola -->
<!-- SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0 -->
# Privacy

mcp-gateway runs on your machine. Its author receives one thing from it: a
small daily heartbeat from a released server, described under
[Daily heartbeat](#daily-heartbeat), which `DO_NOT_TRACK=1` turns off. It sends
nothing to any analytics, crash-reporting or update service. Its outbound
connections go only to the destinations in the table below. Those are:

- the heartbeat receiver, once a day at most;
- addresses you configured;
- a URL you type in a command, enter in the web UI, or write into a capability file;
- a URL a capability builds from values the calling MCP client passes: a capability's
  endpoint can take arguments, and a shipped one takes its whole URL from its caller
  (`capabilities/media/video_download.yaml`, `src/capability/executor/request.rs`);
- callback URLs your authenticated clients registered, if you turn events on;
- two fixed public services, each contacted only by the command that names it:
  `registry.npmjs.org` when you run `doctor` (on by default, with three
  switches to turn it off) and `raw.githubusercontent.com` when you run
  `cap install --from-github`.

A destination in the table is where a connection starts. An HTTP redirect it
answers with can lead somewhere else: the gateway checks each hop against its
address policy before following it (`src/security/ssrf/mod.rs`,
`ssrf_redirect_policy`). On a direct connection, host names are resolved
through your operating system's resolver (`src/security/ssrf/resolver.rs`).
Through a proxy you set (`capabilities.egress_proxy` for capabilities,
`HTTPS_PROXY` where the environment proxy is used), the proxy resolves them
(`src/capability/executor/client.rs`).

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

- **No analytics, crash reports or update checks, and no telemetry beyond the
  daily heartbeat.** No dependency provides one (`Cargo.toml`: the only metrics
  crates are `metrics`, imported as `telemetry_metrics` for local counters, and
  `metrics-exporter-prometheus`), and the heartbeat row is the only place in the
  table below that sends to the author.
- **Metrics stay local.** Prometheus metrics are served at the gateway's own
  `/metrics` endpoint for you to scrape (`src/gateway/routes.rs`); nothing
  pushes them anywhere.
- **The protocol-revision counters stay local.** `src/protocol_revision_telemetry/`
  keeps in-process counters, debug log lines, Prometheus counters and a
  `window.json` file under the gateway's data directory
  (`src/protocol_revision_telemetry/durable.rs`); the module opens no
  connection.
- **Audit and SIEM exports are files.** The export sink writes a local file
  (`src/control_plane/export.rs`, `FileExportSink`).
- **The web UI loads nothing from other hosts.** Both the dashboard (`/ui`)
  and the new shell serve their scripts from the gateway itself
  and send a content security policy that limits what the browser loads and
  connects to over the network to the gateway's own origin
  (`src/gateway/ui/mod.rs`, `src/gateway/ui/shell.rs`). The new shell's
  policy is `script-src 'self'`. The dashboard's policy also allows `data:`
  images and keeps `'unsafe-inline'` for its own inline script and styles,
  which limits what it can fetch, not what it can run. A test refuses
  off-origin `src`, `srcset`, `url()`, `@import`, `import()`, meta-refresh and
  `<link href>` sources in the UI files; connections made by script (fetch,
  WebSocket, event streams) are held to the gateway's own origin by the policy
  itself, not by that test.

## Daily heartbeat

A released mcp-gateway server (from 4.0.0, and from 3.5.3 on the 3.5 line)
sends at most one POST per UTC day for each data directory that persists to
`https://telemetry.revaluator.ai/v1/heartbeat`.
On the 3.5 line, builds for Windows send no daily heartbeat. "Released" means any build
without debug assertions, which the release profile is, including one you build
yourself with `cargo install` or `cargo build --release`; only builds with debug
assertions are skipped as development builds. The JSON has five fields and no
others: `project`, always `mcp-gateway`; `event`, always `heartbeat`; the
mcp-gateway version; the operating system and processor architecture, such as
`linux/x86_64`; and `install_id`, a random value stored in
`heartbeat/install-id` under the gateway's data directory (by default
`~/.mcp-gateway/heartbeat/install-id`, or under `MCP_GATEWAY_CONFIG_DIR` when
you set it).

It contains no hostname, no username, no configuration, no backend or tool
name, and nothing a client sent. Cloudflare terminates the connection, so
Cloudflare sees the connecting address and the ordinary connection and request
details any HTTPS server sees. The receiver does not write the address into the
heartbeat record; what Cloudflare itself logs about connections is governed by
Cloudflare's own policies. From that address, Cloudflare's geolocation supplies
a city name and a country code, and the record stores those two values together
with the five fields and the time the heartbeat arrived. They are approximate:
a VPN, relay or mobile network can place the city at the network exit, and some
connections have no city. The install id stays the same until you delete
`heartbeat/` from the data directory, so one install's heartbeats, their times
and their cities can be linked into a series. Deleting it starts a new id; it
does not remove records already stored. The id is random and contains nothing
about you. Beside it the gateway keeps one empty file per day it claimed for a heartbeat,
named by the date and kept whether or not a send followed: a local record of
those days that never leaves your machine. Records
are kept for three months (the receiver's own statement: trvl's PRIVACY.md,
"Daily heartbeat").

A deployment whose data directory does not survive a restart, such as a
container without a volume or the Helm chart's default `state` volume, gets a
new id at each fresh start and can send once per start.

Only the server sends it (`mcp-gateway serve` and the stdio server): it checks
at start and then hourly for the day's slot. Command-line tools such as
`doctor` never send it. The request times out after 3 seconds and a failure is
ignored. It never sends from a development build, `security.posture: hardened`,
a run where a CI variable such as `CI` or `GITHUB_ACTIONS` reaches the gateway
set to anything other than empty, `0` or `false`, or an environment where
`HTTPS_PROXY`, `HTTP_PROXY` or `ALL_PROXY` is set to a non-empty value. Only
those proxy variables are read: a proxy set only in your system settings is not
detected. Set `DO_NOT_TRACK=1` to turn it off; `NO_TELEMETRY=1` is honoured
too.

## Where it connects

| Call site | When | Where to |
|---|---|---|
| `src/heartbeat.rs` | a released server starts, then hourly; at most one send a UTC day, off with `DO_NOT_TRACK=1` (see [Daily heartbeat](#daily-heartbeat)) | `telemetry.revaluator.ai` |
| `src/transport/http/client.rs` | the gateway talks to an HTTP backend | the backends you configured (A2A included) |
| `src/transport/websocket_pinned.rs` | the gateway talks to a WebSocket backend | the backends you configured |
| `src/oauth/client/destination.rs` | a backend needs OAuth | the discovery and token endpoints of the servers you configured, and the client-registration endpoint their metadata advertises (`src/oauth/client/registration.rs`) |
| `src/identity_propagation/token_exchange.rs` | identity propagation is configured | the identity provider you configured |
| `src/key_server/oidc_jwks_cache.rs` | the key server verifies a token | the signing keys (JWKS) of the issuers you configured |
| `src/capability/executor/client.rs` | a capability runs | the URL in that capability file, with any `{argument}` filled from the calling client's values, checked against the address policy; through `capabilities.egress_proxy` if you set one |
| `src/gateway/router/accounts/bridge.rs` | a personal account is used | the provider you configured |
| `src/events/client.rs` | events are on (off by default, `src/config/features/events.rs`) | callback URLs your authenticated clients registered; pending deliveries resume after a restart (`src/events/runtime.rs`) |
| `src/security/ssrf/mod.rs` | the shared client for addresses the gateway does not trust: `cap install --from-github`, `cap import <URL>` (`src/capability/openapi/convert.rs`), `import-url`, the web UI import, personal-account providers and capability calls | the address the command, the import or the configuration names. `import-url <URL>` probes several well-known API description paths on that URL's host (`src/capability/discovery/mod.rs`) |
| `src/preview_sandbox/proxy.rs` | a command preview fetches its `npx` or `uvx` package (not reachable from a route yet) | `registry.npmjs.org`, `pypi.org` or `files.pythonhosted.org` on port 443, never an address on the deny list or one of this machine's own |
| `src/gateway/ui/import.rs` | you import from a URL in the web UI | the URL you entered |
| `src/commands/skills.rs` | you run `skills` with an `http(s)` source | that URL |
| `src/commands/doctor/npm_pin.rs` | you run `doctor`; on by default, off with `--no-registry-check` or `security.posture: hardened` (`src/commands/doctor/npm_pin.rs`) | `registry.npmjs.org`, one request per npx package an enabled stdio backend pins. The request path is the package name; the pinned version is compared locally, not sent. The User-Agent is `mcp-gateway-doctor`. An `HTTPS_PROXY` you set is used |
| `src/commands/doctor.rs`, `src/commands/doctor/ws_reach.rs` | you run `doctor` | your configured HTTP and WebSocket backends |
| `src/commands/doctor/health.rs`, `src/commands/stats.rs`, `src/commands/dashboard_link_admin.rs`, `src/commands/api.rs`, `src/commands/config_export/mod.rs` | you run `doctor`, `stats`, `dashboard-link`, `api`, `events dead-letters` or `config export` | the gateway your config names, normally this machine's; `stats`, `api` and `events dead-letters` take `--url` to point at another |

`cap install --from-github` fetches from `raw.githubusercontent.com/<repo>`
only when you run it (`src/registry/mod.rs`, `src/commands/cap.rs`).

## What other programs do

- **Backends you configure as stdio commands** are separate programs the
  gateway starts; their network traffic is theirs, not the gateway's. A
  backend run as `npx <package>` downloads that package from npm, and
  `mcp-gateway init` can write such starter backends (`src/commands/mod.rs`).
- **OAuth sign-in** opens your default browser at the provider's page
  (`src/oauth/client/browser.rs`). What that page loads is between
  your browser and the provider.

## Where secrets are kept

- **Secrets you save through the gateway** go to the OS keychain (macOS
  Keychain, Linux Secret Service, Windows Credential Manager) or to a new
  owner-only file, as `secrets.store` chooses: `auto`, the default, prefers the
  keychain (`src/secret_store/mod.rs`, `src/secret_store/files.rs`).
- **The admin token `mcp-gateway init` generates** is stored through
  `secrets.store`, in the same keychain or owner-only file as your other saved
  secrets, and the config file holds only a reference in `auth.bearer_token`
  (`src/cli_support/init.rs`); neither the config nor the sample files it
  writes contain the token. `mcp-gateway doctor` names where it lives, and
  docs/QUICKSTART.md says how to read it back for a client. A config written
  by an earlier `init` still holds the token as a literal and keeps working:
  do not commit it, and move it by setting
  `bearer_token: "env:MCP_GATEWAY_TOKEN"` with the token in that variable.
- **OAuth tokens** for backends are kept as JSON files written owner-only
  (0600 from creation) through a scratch file (`src/oauth/storage.rs`),
  not through `secrets.store`.
- **On Windows**, files holding a secret are created owner-only with a protected
  access list, and a volume that keeps no access lists is refused. See
  SECURITY.md, "Known limitations".
