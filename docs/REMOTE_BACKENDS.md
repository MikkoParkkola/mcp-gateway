# Adding Remote MCP Backends

Remote MCP servers — anything reachable over HTTP or SSE — plug into
mcp-gateway the same way local `stdio` servers do: one entry under `backends:`
in your `gateway.yaml`. No new code, no capability YAML, no proxy glue.

This guide uses [GitMCP](https://gitmcp.io) as a worked example because it is
free, requires no auth, and instantly gives your AI a searchable view of any
public GitHub repository.

## The 30-second recipe

Add this to your `gateway.yaml`:

```yaml
backends:
  gitmcp_docs:
    url: "https://gitmcp.io/docs/sse"
    description: "GitMCP — on-demand docs + code search for any GitHub repo"
    timeout: 30s
```

Restart (or hot-reload) the gateway. That's it. Your AI can now call GitMCP's
tools through `gateway_search_tools` / `gateway_invoke`.

## How the gateway picks the transport

The gateway infers transport from the shape of the backend entry:

| Entry field | Transport | When to use |
|---|---|---|
| `command:` | stdio | Subprocess you spawn locally |
| `url:` with `http://` or `https://` | Streamable HTTP, or SSE | Remote MCP servers: the gateway POSTs first and falls back to the SSE handshake when the server answers 4xx |
| `url:` with `ws://` or `wss://` | WebSocket | Servers that speak MCP over one shared socket |

See [`src/config/mod.rs`](../src/config/mod.rs) `TransportConfig` for the exact
rules. GitMCP serves SSE at its `/sse` URL; the gateway detects that at connect, so
you get streaming notifications and long-lived sessions for free.

## Dynamic vs. repo-pinned routes

GitMCP exposes two URL shapes:

1. **Dynamic dispatcher**: `https://gitmcp.io/docs/sse`
   - One backend covers every public GitHub repo.
   - Tools take a repo URL as an argument:
     `fetch_generic_url_content`, `search_generic_code`,
     `search_generic_documentation`.
   - Best when you browse many repos.

2. **Repo-pinned route**: `https://gitmcp.io/{owner}/{repo}/sse`
   - Scoped to one repository.
   - Tools are named after the repo, e.g.
     `fetch_mcp_gateway_documentation`, `search_mcp_gateway_code`.
   - Best when the gateway backs one project and you want clean tool names.

Both variants are just different `url` values. You can even define both in
the same config:

```yaml
backends:
  gitmcp_docs:
    url: "https://gitmcp.io/docs/sse"
    description: "GitMCP — any GitHub repo (dynamic)"

  gitmcp_self:
    url: "https://gitmcp.io/MikkoParkkola/mcp-gateway/sse"
    description: "GitMCP — pinned to mcp-gateway"
```

## Calling the tools through the gateway

Once a backend is registered, the usual Meta-MCP flow applies:

```jsonc
// 1. Find the tool
{
  "jsonrpc": "2.0", "id": 1, "method": "tools/call",
  "params": {
    "name": "gateway_search_tools",
    "arguments": { "query": "github documentation" }
  }
}

// 2. Invoke it
{
  "jsonrpc": "2.0", "id": 2, "method": "tools/call",
  "params": {
    "name": "gateway_invoke",
    "arguments": {
      "server": "gitmcp_docs",
      "tool": "fetch_generic_url_content",
      "arguments": {
        "url": "https://github.com/MikkoParkkola/mcp-gateway"
      }
    }
  }
}
```

No token cost for loading GitMCP's schemas into the model: the gateway's
Meta-MCP surface keeps discovery compact and the AI only pays for the tool it
actually calls.

## ShadowRadar before trusting remote endpoints

Use passive discovery to find remote or local MCP endpoints that bypass the
gateway:

```bash
mcp-gateway cap discover --shadow --format json
```

The `shadow_radar.v1` report lists unmanaged assets only and includes stable
IDs, source, ownership, transport exposure, trust status, data risk,
recommended action, confidence, confirmation requirement, verification step,
and rollback step. The default scan is local and passive: it reads known client
configs, environment hints, and the local process table, but it does not
handshake with discovered servers or invoke their tools.
The machine-readable schema and risk-code contract are documented in
[`SHADOW_SCAN.md`](SHADOW_SCAN.md).

Code that renders TrustCards, doctor findings, or control-plane inventory
consumes the derived `shadow_radar.handoff.v1` feed from
`ShadowScanReport::consumer_handoff()`. `mcp-gateway doctor --format json`
includes passive ShadowRadar findings as advisory warnings with category, risk,
manual review, verification, and rollback metadata; it does not trust, start, or
invoke unmanaged servers. The `/ui/api/control-plane` response and Control Plane
tab include the local passive ShadowRadar summary, unmanaged asset count,
severity, recommended action, and human-review requirement. The handoff keeps
the scan passive, preserves stable asset IDs, and carries only human-safe
evidence pointers such as sanitized endpoints, executable basenames, ports, and
config paths.

The same handoff also carries `shadow_radar.enterprise_boundary.v1`, an
explicit contract for the per-file license split. `free_core_scan` is always local,
passive, and lists network-range discovery, scheduled scans, fleet scope, tool
invocation, and config mutation under `denied_capabilities`. `enterprise_scan`
allows network-range discovery, scheduled scans, and fleet scope while still
denying tool invocation and config mutation; drift evidence, SIEM export, owner
assignment, and policy remediation remain enterprise capabilities. Evidence
export contracts are marked
`requires_enterprise_license: true` and `sensitive_values_included: false` so
downstream control planes can automate routing without carrying sensitive
values or turning local discovery into a network scanner.

For reviewed local findings, adoption is explicit:

```bash
mcp-gateway cap discover --shadow --write-config
```

Free/core includes local passive inventory and risk hints. Enterprise fleet
features are scheduled org-wide inventory, network-range discovery, drift
evidence, SIEM export, owner assignment, and policy remediation.

## Authenticated remote backends

For remote servers that need auth, add headers or OAuth:

```yaml
backends:
  my_saas:
    url: "https://mcp.example.com/sse"
    headers:
      Authorization: "Bearer ${MY_SAAS_TOKEN}"

  my_google:
    url: "https://mcp.googleapis.com/mcp"
    oauth:
      enabled: true
      scopes:
        - "https://www.googleapis.com/auth/drive.readonly"
      client_id: "env:GOOGLE_CLIENT_ID"
```

Credentials require TLS. An enabled backend whose `url` or `a2a_url` is
`http://` against a host off this machine is refused at config load when its
configuration is credential-bearing — an `oauth` section (including one with
`enabled: false`), identity propagation, secret injection, any static header
whatever its name, or userinfo or a query string in the URL itself. Such a
credential is readable by every host on the path and replayable for as long as it
is valid. The test is blunt on purpose: `X-Trace-Id` and `?page=2` trip it as
surely as a bearer token, because config load cannot tell which of them carries a
secret. Loopback is exempt. To accept the exposure knowingly — a link you terminate
yourself, say — set `allow_cleartext_credentials: true` on that backend.

That opt-out does not cover OAuth. Since 4.0.0 a backend whose `oauth` section is
`enabled: true` is refused at the *transport* layer whatever
`allow_cleartext_credentials` says: the backend fails to start with `refusing to
send an OAuth token in cleartext to <origin>`, and the token is checked again at
request time against the endpoint actually being posted to. A bearer token is
replayable by anyone on the path for as long as it is valid, and no flag makes
that acceptable — the flag remains the way to accept a readable static header,
identity propagation, secret injection, or a credential-bearing URL. Loopback is still exempt: `http://localhost`,
`127.0.0.0/8` and `::1`. `http://[::ffff:127.0.0.1]` is deliberately *not*
loopback — write `http://127.0.0.1`.

See [`examples/gateway-full.yaml`](../examples/gateway-full.yaml) for the full
set of backend fields, including timeouts, idle hibernation, secret injection,
and `passthrough` mode.

## Undeclared argument keys

A `tools/call` whose arguments carry a key the tool's `inputSchema` does not declare, at any
depth, is refused with `isError: true` before it reaches the backend. That applies on `/mcp` and on
the direct `/mcp/{name}` route, `passthrough` backends included. The schema is the one the
caller's own `tools/list` returned. For a tool the gateway has not listed for that caller yet, it
lists the backend's tools once, as that caller, before judging the call (see
[UPGRADING-4.0.md §59](UPGRADING-4.0.md#59-a-tool-call-on-a-cold-catalogue-lists-the-backend-first)).

`input_schema_enforcement` sets the rule per backend:

| Value | Behaviour |
|---|---|
| `closed` (default) | An object level that lists `properties` or `patternProperties` without stating `additionalProperties` is closed. `{"type": "object"}` and `properties: {}` stay free maps. |
| `standard` | JSON Schema's default: only `additionalProperties: false` closes a level. |
| `off` | No check. |

On a backend with identity propagation (each caller has its own catalogue), the mode governs only
the argument keys. Whatever its value, a tool the caller's own catalogue withholds (an invalid
`inputSchema`, a poisoned description) or does not list answers JSON-RPC `-32601`, exactly as a
name the gateway does not know, and nothing is sent. The shared catalogue is never consulted for
it. See [`upgrading.d/8356.md`](../upgrading.d/8356.md).

## Tools with a poisoned description

Every tool a backend lists is checked with the tool-poisoning rule (AX-010). A tool that fails it
at blocking severity is left out of every tool list and refused by name, for every caller of the
backend, once any listing has shown it. The gateway logs a `Tool withheld` warning once per
distinct description, with the rule's findings and a digest.

`allow_flagged_tools` serves a tool you have reviewed, pinned to that digest:

```yaml
backends:
  my-backend:
    allow_flagged_tools:
      tool_name: "<64-hex digest from the warning>"
```

A changed description gets a new digest and is withheld again. See UPGRADING-4.0 §75.

## Offering only some of a backend's tools

`allowed_tools` names the only tools a backend offers, to every caller:

```yaml
backends:
  my-backend:
    allowed_tools: [search, "get_*"]
```

Each entry is an exact name or a trailing `prefix*`, matched on `tool` or `my-backend:tool`, the
same grammar as an API key's `allowed_tools`. A tool outside the list is left out of every tool
list and refused by name as an absent tool, including one the server adds later. The admin tools
list still shows it, marked not selected, so it can be added, and the admin config view
(`/ui/api/config`) shows each backend's list as written. The web UI's add API takes the ticked tools
(`allowed_tools` in `POST /ui/api/backends`); the preview's checkboxes come with the Servers screen.

The list narrows and never widens. A call must pass all three tool scopes: the API key's
`allowed_tools` and `denied_tools`, the backend's `allowed_tools`, and the global
`security.tool_policy`. Each is judged when a call is admitted, so a call admitted before a
narrowing reload finishes its own retries. An older binary ignores `allowed_tools` and exposes
every tool: read the rollback note in UPGRADING-4.0 before you roll back.

## First-time OAuth interactive authorization

The first time an OAuth backend is exercised, the gateway opens a browser tab
for the user. As of v2.12.0 this handshake runs on a detached `tokio::spawn`
task that survives MCP-client request cancellation — the token persists to
`~/.mcp-gateway/oauth/<sha8>_tokens.json` even if the calling `tools/call`
times out. The second call from the client then proceeds with the cached
token.

For first-call success, add the backend to `meta_mcp.warm_start` so the
OAuth handshake runs at gateway boot (not inside a request future):

```yaml
meta_mcp:
  warm_start:
    - my_oauth_backend
```

See [OAUTH_CONFIG.md § First-time interactive authorization](OAUTH_CONFIG.md#first-time-interactive-authorization-mik-4486)
for details and tracked under MIK-4486.
