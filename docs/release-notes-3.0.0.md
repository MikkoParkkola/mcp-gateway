# MCP Gateway v3.0.0: Trust Fabric

**Breaking change: the default OAuth posture changes for gateways with
authentication enabled.** See "Breaking change" and the upgrade guide below
before deploying this release on a shared or multi-user gateway.

## Highlights

- **Per-user OAuth isolation, on by default** (ADR-008). A gateway with
  `auth.enabled: true` no longer serves one stored OAuth token to every
  caller. A backend that requires a per-user identity now refuses a call
  that lacks a verified one, instead of falling back to a shared or
  another user's token. Enforced across both MCP backends and
  capability-backed REST connectors.
- **RFC 9728 protected-resource metadata.** The gateway advertises
  per-backend OAuth requirements so a capable MCP client can run its own
  browser-based login and attach its own token per request, without the
  gateway ever holding a copy.
- **Client-supplied OAuth passthrough.** A caller can attach its own
  backend credential on the request; the gateway forwards it and stores
  nothing, on both the direct backend route and meta-MCP dispatch.
- **End-user identity propagation** (ADR-007, the rest of the Trust Fabric
  milestone): the gateway can mint a per-user, gateway-signed credential
  for a backend configured with `identity_propagation`, fail closed when
  required, and keep per-user results isolated in the cache. Enforced on
  meta-MCP dispatch, Code Mode, and the direct backend route.
- **Upgrade posture notice.** On first startup after upgrading, the
  gateway backs up your existing `gateway.yaml` to
  `gateway.yaml.bak.<old_version>` and prints a one-time notice describing
  your deployment's OAuth posture. No config field is changed
  automatically.

## Breaking change

Before this release, a shared or multi-user gateway stored one OAuth token
per backend and attached it to every caller's request, regardless of who
made the request. A call to a personal-OAuth backend (Gmail, Superhuman,
and similar) could be served with another user's login.

3.0.0 closes this by making per-user OAuth isolation the fail-closed
default. If you run a shared or multi-user gateway with `oauth:`-configured
backends, some calls that previously succeeded with a shared credential
will now refuse until a per-user credential is resolved for that caller.

If your gateway is genuinely single-user, or a specific backend is meant to
run as a shared service account, add one line to keep the previous
behavior:

```yaml
auth:
  single_user: true
```

or, for one backend:

```yaml
backends:
  my-backend:
    oauth:
      shared_account: true
```

Full upgrade guide: [docs/UPGRADING-3.0.md](https://github.com/MikkoParkkola/mcp-gateway/blob/main/docs/UPGRADING-3.0.md)

Design rationale: [ADR-008](https://github.com/MikkoParkkola/mcp-gateway/blob/main/docs/adr/ADR-008-multi-user-oauth-isolation.md)

Full changelog: [CHANGELOG.md#300---2026-07-03](https://github.com/MikkoParkkola/mcp-gateway/blob/main/CHANGELOG.md#300---2026-07-03)

## Installation

### Cargo (Recommended)

```bash
cargo install mcp-gateway
```

### Manual Download

Download the appropriate binary for your platform from the release assets.

**Supported platforms:**

- `mcp-gateway-darwin-arm64` - macOS Apple Silicon (M1/M2/M3)
- `mcp-gateway-darwin-x86_64` - macOS Intel
- `mcp-gateway-linux-x86_64` - Linux x86_64 (static musl)
- `mcp-gateway-linux-aarch64` - Linux ARM64 (static musl)
- `mcp-gateway-windows-x86_64.exe` - Windows x86_64 (MSVC)

## Verify checksums

```bash
sha256sum -c SHA256SUMS.txt
```

## Quick Start

```bash
# Create config file
cat > servers.yaml << 'EOF'
server:
  port: 39400
meta_mcp:
  enabled: true
backends: {}
EOF

# Start gateway
mcp-gateway --config servers.yaml
```

See the [README](https://github.com/MikkoParkkola/mcp-gateway#readme) for
full documentation and the [upgrade guide](https://github.com/MikkoParkkola/mcp-gateway/blob/main/docs/UPGRADING-3.0.md)
if you're coming from 2.x.
