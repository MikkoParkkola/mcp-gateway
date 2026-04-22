# OAuth Configuration Reference

MCP Gateway supports OAuth 2.0 Authorization Code flow with PKCE for backends
that require user-delegated access.  This document covers every field in the
`oauth` stanza of a backend entry and provides ready-to-use examples for Slack
and Figma.

---

## Configuration Fields

All fields live under `backends.<name>.oauth`:

| Field | Type | Default | Description |
|---|---|---|---|
| `enabled` | bool | `true` | Toggle OAuth for this backend without removing the stanza. |
| `scopes` | `[string]` | `[]` | Scopes to request.  When empty the gateway uses the scopes advertised by the authorization server. |
| `client_id` | string | — | Pre-registered client ID.  When absent the gateway attempts dynamic client registration (RFC 7591) and falls back to a generated ID. |
| `client_secret` | string | — | Client secret for providers that require it (Slack, Figma, …).  Sent as `client_secret` in token-exchange and refresh requests. |
| `callback_host` | string | `"localhost"` | Hostname the local callback server binds to.  Defaults to `"localhost"`, which dual-binds `127.0.0.1` **and** `[::1]` so the redirect works regardless of how the browser resolves `localhost`. Set to `"127.0.0.1"` to force IPv4-only. |
| `callback_port` | integer | OS-assigned | Fixed port for the callback server.  **Required when the provider's app settings enforce an exact redirect URI** (Slack, Figma, Linear, …). |
| `callback_path` | string | `"/oauth/callback"` | URL path of the callback endpoint.  Override when the provider requires a specific path. |
| `token_refresh_buffer_secs` | integer | `300` | Seconds before token expiry at which the background task proactively refreshes. |

### Redirect URI construction

The redirect URI sent to the provider is built from the three `callback_*` fields:

```
http://<callback_host>:<callback_port><callback_path>
```

**Default** (no overrides):

```
http://localhost:<ephemeral-port>/oauth/callback
```

**Slack example** (fixed port + custom path):

```
http://localhost:8085/slack/oauth/callback
```

---

## Dual-Bind IPv4 / IPv6

On modern macOS and Linux, `localhost` often resolves to `::1` (IPv6) rather
than `127.0.0.1`.  When `callback_host` is `"localhost"` (the default) the
gateway binds **both** `127.0.0.1:<port>` and `[::1]:<port>` simultaneously.
The first address family that delivers the browser redirect wins.

If your system has no IPv6 loopback, the `[::1]` bind is silently skipped and
the server continues on IPv4 alone.

To opt out of dual-bind set `callback_host: "127.0.0.1"` explicitly.

---

## Structured Telemetry

The OAuth callback server emits structured `tracing` events at every lifecycle
step.  Set `RUST_LOG=mcp_gateway::oauth=debug` (or use the gateway's
`logging.level` config key) to see them.

| `event` field | Level | Emitted when |
|---|---|---|
| `oauth.callback_server.bind` | INFO | Server successfully bound a listening socket |
| `oauth.callback.received` | DEBUG | HTTP request arrived at the callback endpoint |
| `oauth.callback.success` | INFO | Authorization code received and forwarded |
| `oauth.callback.state_mismatch` | WARN | CSRF state check failed |
| `oauth.callback.provider_error` | WARN | Provider returned `error=…` in the redirect |
| `oauth.callback.missing_code` | WARN | Redirect arrived without an authorization code |
| `oauth.token_exchange.success` | INFO | Token endpoint responded with an access token |
| `oauth.token_exchange.failure` | WARN | Token endpoint returned a non-2xx status |

---

## Example: Slack

Slack requires a fixed redirect URI registered in your app's **OAuth & Permissions**
settings.  It also issues a `client_id` and `client_secret` pair that you must
supply explicitly.

**Slack app settings → OAuth & Permissions → Redirect URLs:**

```
http://localhost:8085/slack/oauth/callback
```

**`gateway.yaml`:**

```yaml
backends:
  slack:
    transport:
      http_url: https://slack.com/api
    oauth:
      client_id: "1234567890.9876543210"        # from api.slack.com/apps
      client_secret: "${SLACK_CLIENT_SECRET}"   # loaded from env / .env file
      scopes:
        - channels:read
        - chat:write
        - users:read
      callback_port: 8085                        # must match the Redirect URL above
      callback_path: /slack/oauth/callback       # must match the Redirect URL above
      token_refresh_buffer_secs: 600
```

**Why `callback_port` is required for Slack:** Slack validates the `redirect_uri`
parameter against the exact list in your app settings, so an ephemeral
OS-assigned port would not match on the next run.

---

## Example: Figma

Figma also issues fixed credentials and requires an exact redirect URI.

**Figma developer settings → Redirect URIs:**

```
http://localhost:8086/oauth/callback
```

**`gateway.yaml`:**

```yaml
backends:
  figma:
    transport:
      http_url: https://api.figma.com
    oauth:
      client_id: "${FIGMA_CLIENT_ID}"
      client_secret: "${FIGMA_CLIENT_SECRET}"
      scopes:
        - files:read
      callback_port: 8086          # fixed port matching the registered URI
      # callback_path defaults to /oauth/callback — matches Figma's requirement
```

**`callback_host` note:** `localhost` (default) is correct here.  The gateway
dual-binds `127.0.0.1:8086` and `[::1]:8086` so the redirect lands regardless
of which stack the Figma-redirected browser uses.

---

## Secret Management

Never commit `client_secret` values in plain text.  Use environment-variable
substitution or the `env_files` config key:

```yaml
env_files:
  - ~/.config/mcp-gateway/.env   # contains SLACK_CLIENT_SECRET=…

backends:
  slack:
    oauth:
      client_secret: "${SLACK_CLIENT_SECRET}"
```

See the [Deployment Guide](DEPLOYMENT.md) for mTLS and secret injection options.

---

## See Also

- [QUICKSTART.md](QUICKSTART.md) — zero-to-running walkthrough
- [REMOTE_BACKENDS.md](REMOTE_BACKENDS.md) — backend transport reference
- [CONTRIBUTING.md](../CONTRIBUTING.md) — how to add a new transport or OAuth provider
