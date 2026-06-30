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
    http_url: "https://gitmcp.io/docs/sse"
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
| `http_url:` ending in `/sse` | SSE | Server-Sent Events handshake |
| `http_url:` with `streamable_http: true` | Streamable HTTP | Direct POST, no SSE |
| `http_url:` (other) | Plain HTTP | Legacy HTTP MCP servers |

See [`src/config/mod.rs`](../src/config/mod.rs) `TransportConfig` for the exact
rules. GitMCP supports SSE, so the `/sse` suffix is the right choice — you get
streaming notifications and long-lived sessions for free.

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

Both variants are just different `http_url` values. You can even define both in
the same config:

```yaml
backends:
  gitmcp_docs:
    http_url: "https://gitmcp.io/docs/sse"
    description: "GitMCP — any GitHub repo (dynamic)"

  gitmcp_self:
    http_url: "https://gitmcp.io/MikkoParkkola/mcp-gateway/sse"
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
explicit contract for the dual-license split. `free_core_scan` is always local,
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
    http_url: "https://mcp.example.com/sse"
    headers:
      Authorization: "Bearer ${MY_SAAS_TOKEN}"

  my_google:
    http_url: "https://mcp.googleapis.com/mcp"
    streamable_http: true
    oauth:
      enabled: true
      scopes:
        - "https://www.googleapis.com/auth/drive.readonly"
      client_id: "env:GOOGLE_CLIENT_ID"
```

See [`examples/gateway-full.yaml`](../examples/gateway-full.yaml) for the full
set of backend fields, including timeouts, idle hibernation, secret injection,
and `passthrough` mode.

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
