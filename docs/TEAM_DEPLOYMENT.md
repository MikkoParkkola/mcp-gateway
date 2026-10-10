# Deploying the gateway for a team

This guide is the path from a gateway one person runs on a laptop to one that
several people reach over a network. It makes four decisions in order and links
to the page that covers each in depth:

1. [How callers authenticate](#1-how-callers-authenticate)
2. [How the credential is protected on the wire](#2-how-the-credential-is-protected-on-the-wire)
3. [What each caller may reach](#3-what-each-caller-may-reach)
4. [Where the audit log goes](#4-the-audit-log)

Then a [complete example config](#a-team-config-that-loads), the
[Helm chart as it is today](#kubernetes-with-the-helm-chart), and the
[checks to run before you hand out credentials](#before-you-hand-out-credentials).

Coming from 3.x? Several of the rules below refuse a 3.x config at startup. Read
[UPGRADING-4.0.md](UPGRADING-4.0.md) first. For backups and key rotation, see
the [backup, restore and key runbook](runbooks/backup-restore-and-keys.md).

## 1. How callers authenticate

The gateway refuses to start when it can be reached from off the machine and
its tools can be called without a credential, unless
`server.allow_unauthenticated_network_bind` declares that authentication
happens in front of it
([Authentication for Production](DEPLOYMENT.md#authentication-for-production)).
That exception only settles admission: with gateway auth off, every request
reaches the gateway as the same anonymous caller, so grants, the audit log and
per-caller caching cannot tell people apart. A team gateway needs one of the
credentials below. There are three separate questions, and the options below
answer different ones:

- **Admission**: may this request reach the gateway at all?
- **Identity**: which person or client is it, for grants, the audit log and
  per-caller caching?
- **Authorization**: which backends and tools may that identity reach?

| Option | Admission | Identity it carries | Authorization | Details |
|---|---|---|---|---|
| `auth.bearer_token` | yes | none: one shared credential, always admin | everything | [DEPLOYMENT.md](DEPLOYMENT.md#authentication-for-production) |
| `auth.api_keys` | yes | `api_key:<name>`, one per key | the key's `backends`, `allowed_tools`, `denied_tools` | [API keys](DEPLOYMENT.md#api-keys) |
| `key_server` (OIDC) | yes, with an exchanged or delegated token | `(issuer, sub)` from your identity provider | `key_server.policies`, first match wins | [MULTI_USER.md](MULTI_USER.md#1-who-is-calling) |
| `security.caller_identity` headers | no: only names the user behind an already admitted request | the header subject, or a Cloudflare Access `sub` | identity grants for personal capabilities; backend reach stays the admitting credential's | [Caller identity headers](identity_grants.md#caller-identity-headers) |
| `mtls` client certificates | yes, with `mtls.require_client_cert` | first SAN URI, else CN | mTLS policy | [TLS / mTLS](DEPLOYMENT.md#tls--mtls) |

Which to pick:

- **A small team, no identity provider**: one `auth.api_keys` entry per person,
  each with its own `backends` list. Keep `auth.bearer_token` for the operator
  only; it is not bound by any key's scopes.
- **A team with an identity provider**: the key server, with policy rules per
  group. See [MULTI_USER.md](MULTI_USER.md) end to end, including its
  step 0, which undoes two `mcp-gateway init` defaults that defeat it.
- **A proxy you control already authenticates users**: `security.caller_identity`
  with `mode: trusted_proxy` (exact `trusted_proxies` IPs, one `authority`) or
  `mode: cloudflare_access`. Headers name a user for identity grants and the
  audit log; they do not admit a request on their own, and they do not narrow
  which backends it reaches: that stays the reach of the credential that
  admitted it. In `trusted_proxy` mode each
  proxy must strip or overwrite every `X-Gateway-Identity-*` header a client
  sends: the allowlist proves the request came through the proxy, not that the
  proxy wrote the header.

When a request carries more than one identity, a verified key-server token
wins, then a header identity, then an mTLS certificate or agent JWT, then the
API key's name.

API keys are stored as digests, never as the key:

```bash
KEY="$(openssl rand -base64 32)"              # the key you hand out
printf %s "$KEY" | mcp-gateway hash-key       # prints sha256:<hex> for key_sha256
printf %s "$KEY" | mcp-gateway hash-key --verify sha256:<hex>   # exit 0 on a match
```

Give a key handed to someone temporary an `expires_at`; after that instant the
key is refused with 401 (UPGRADING-4.0 item 41).

## 2. How the credential is protected on the wire

A bearer token or API key sent over plain HTTP can be read by anything on the
path. When the listener can be reached from the network and accepts a
credential (`auth`, `agent_auth` or the key server), the gateway refuses to
start unless the listener is TLS (`mtls.enabled`) or `server.cleartext_http`
says who protects the traffic instead (UPGRADING-4.0 item 38):

| `server.cleartext_http` | Means | Use when |
|---|---|---|
| `refuse` | no plain HTTP on a network bind | you enable `mtls` on the listener |
| `tls_terminated_upstream` | a proxy terminates TLS in front of the gateway | nginx, Caddy, an ingress or a tunnel fronts it ([Reverse Proxy](DEPLOYMENT.md#reverse-proxy)) |
| `cluster_internal` | callers reach the pod only over the cluster network, by its Service name | Kubernetes, in-cluster callers only; `server.public_url` must be that Service name |
| `host_local_publish` | a container binds `0.0.0.0` and the host publishes the port on loopback only | Docker with `-p 127.0.0.1:...` ([Docker Deployment](DEPLOYMENT.md#docker-deployment)) |

Every value other than `refuse` is logged at WARN on each start.
`server.allow_unauthenticated_network_bind` does not answer this question: it
says authentication happens in front of the gateway, not encryption.

Set `server.public_url` to the name your team dials. On a `0.0.0.0` bind the
gateway admits requests addressed to that one name.

## 3. What each caller may reach

In 4.0 a caller sees and calls only what it was granted, on every discovery
surface, and cached results, backend notifications and `subscriptions/listen`
streams are kept per caller (UPGRADING-4.0 items 11, 14, 15, 24 and 26). A key
or key-server rule with no `backends` reaches no backend (item 32).

A new backend is reachable only by callers whose grant covers it. A grant of
`backends: ["*"]`, and the static `auth.bearer_token`, cover every backend,
including ones you add later. Prefer explicit backend lists for people.

That separation stops at the gateway. Unless a backend is configured with
`identity_propagation`, every caller reaches it with the gateway's own
credential, so the backend sees one user. For backends holding personal data,
follow [MULTI_USER.md, section 3](MULTI_USER.md#3-who-the-backend-thinks-is-calling)
and [Isolated personal accounts](MULTI_USER.md#isolated-personal-accounts).

The key server and managed accounts keep their state in one process, so a
gateway using either runs one replica
([Replica Count and per-process state](DEPLOYMENT.md#replica-count-and-per-process-state)).

## 4. The audit log

With `auth.enabled`, the tool-call audit log is required. It is on by default
when auth is on, so a config needs no line for it; one that sets
`security.transparency_log.enabled: false`, or a blank `path`, refuses to load
(UPGRADING-4.0 item 43). Each record names the caller, and tool calls that are
refused or fail are recorded too. If the log stops appending, calls are refused with 503
until it recovers (items 43 and 50). A 503 of this kind can arrive after the
backend already ran the call, so do not retry it blindly. The log rotates on
its own; do not rotate it with an external tool (item 49).

Keep the log on persistent storage. Backup and HMAC key rotation for it are in
the [runbook](runbooks/backup-restore-and-keys.md).

## A team config that loads

Two people with their own API keys, one of them temporary, behind a reverse
proxy that terminates TLS. The digests come from environment variables, which
must hold `sha256:<hex>` values, not keys. `tls_terminated_upstream` only
stops the startup refusal; it does not restrict who connects. Make the proxy
the only thing that can reach port 39400: bind `127.0.0.1` when the proxy runs
on the same host, or firewall the port to the proxy's address.

```yaml
server:
  host: "0.0.0.0"
  port: 39400
  public_url: "https://mcp.example.com"
  cleartext_http: tls_terminated_upstream
auth:
  enabled: true
  bearer_token: "env:MCP_GATEWAY_TOKEN"     # operator only
  public_paths: ["/health"]
  api_keys:
    - name: alice
      key_sha256: "env:ALICE_KEY_SHA256"
      backends: ["github", "jira"]
    - name: contractor-bob
      key_sha256: "env:BOB_KEY_SHA256"
      backends: ["jira"]
      expires_at: "2026-12-31T23:59:59Z"     # set your own end date
security:
  transparency_log:
    enabled: true
    path: "/var/lib/mcp-gateway/audit/transparency.jsonl"
backends:
  github:
    http_url: "https://github-mcp.example.com/mcp"
  jira:
    http_url: "https://jira-mcp.example.com/mcp"
```

`/livez` and `/readyz` stay open alongside `/health` whenever `/health` is
public, so probes keep working.

Defaults that matter here:

| Key | Default |
|---|---|
| `auth.enabled` | `false` |
| `server.host` | `127.0.0.1` |
| `server.cleartext_http` | `refuse` |
| `server.replicas` | `1` |
| `security.caller_identity.mode` | `off` |
| `security.transparency_log.enabled` | on when `auth.enabled`, else `false` |
| `key_server.enabled` | `false` |

## Kubernetes with the Helm chart

The chart in `deploy/helm/mcp-gateway` renders the gateway's `auth` section
itself, from `auth.mode`. Anything you put under `config.auth` is replaced.

| `auth.mode` | What the chart renders |
|---|---|
| `credential` (default) | `auth.enabled: true` with one bearer token from the Secret `auth.existingSecret` (key `auth.secretKey`), `public_paths: ["/health"]`, and the audit log at `/var/lib/mcp-gateway/audit/transparency.jsonl` on the `audit` volume |
| `api_keys` | `auth.enabled: true` with one `auth.api_keys` entry per `auth.apiKeys` item: `key_sha256: env:GATEWAY_API_KEY_<i>`, filled from the Secret key `apiKeys[i].secretKey`, which holds the digest from `mcp-gateway hash-key`, never the key. No master bearer. `backends` is required |
| `oidc` | `auth.enabled: true` and `key_server` with the providers and policies from `auth.oidc`; `key_server.admin_token` from the `adminTokenSecretKey` entry of `auth.oidc` when set. No master bearer. Forces one replica and `Recreate` |
| `mesh` | no `auth` section and `server.allow_unauthenticated_network_bind: true`, for a service mesh that authenticates before traffic reaches the pod. No audit volume |

In every mode but `mesh`, `server.cleartextHttp` becomes `server.cleartext_http`:

| `server.cleartextHttp` | Effect in the chart |
|---|---|
| `cluster_internal` (default) | an ingress-only NetworkPolicy is rendered even with `networkPolicy.enabled: false`, and the chart refuses to render a non-`ClusterIP` Service or a `config.server.public_url` other than this release's Service name |
| `tls_terminated_upstream` | an ingress terminates TLS; set `config.server.public_url` to the ingress host |
| `refuse` | the pod starts only with `mtls` on |

```yaml
# Helm values: an ingress in front, audit log on a volume claim
auth:
  mode: credential
  existingSecret: mcp-gateway-auth
server:
  cleartextHttp: tls_terminated_upstream
audit:
  existingClaim: mcp-gateway-audit
config:
  server:
    host: 0.0.0.0
    port: 39400
    public_url: "https://mcp.example.com"
```

Set `audit.existingClaim` for a team: the default `emptyDir` is deleted with the
pod, and the audit log with it. Keep `replicaCount: 1`; the chart refuses more
while per-process state is on
([Replica Count and per-process state](DEPLOYMENT.md#replica-count-and-per-process-state)).

```yaml
# Helm values: two people with their own keys, state kept on a claim
auth:
  mode: api_keys
  existingSecret: mcp-gateway-keys   # keys alice, bob: `printf %s "$KEY" | mcp-gateway hash-key`
  apiKeys:
    - {name: alice, secretKey: alice, backends: ["*"], admin: true}
    - {name: bob, secretKey: bob, backends: ["github"], expiresAt: "2026-12-31T00:00:00Z"}
persistence:
  enabled: true
```

`persistence.enabled` puts the `state` volume (task store, and the control-plane
store at `/var/lib/mcp-gateway/control-plane`) on a claim, forces one replica and
`Recreate`, and sets `fsGroupChangePolicy: OnRootMismatch`.

Backend secrets referenced as `env:VAR` come in through `extraEnv` (EnvVar list)
or `envFrom` (each entry needs a `prefix`). The chart refuses names starting
`MCP_GATEWAY_` in any case, since those override gateway config, and its own
`HOME`, `GATEWAY_API_KEY_*` and `GATEWAY_KS_ADMIN_TOKEN`. Every value is
readable by the gateway and its stdio backends, so scope the Secret to them.

## Before you hand out credentials

Work through [Before exposing the port](MULTI_USER.md#before-exposing-the-port)
in MULTI_USER.md. Then check the result, because an isolation mistake looks
like success:

1. Call `gateway_list_tools` as two different people. Each should see only
   the backends their grant names.
2. Send a request with no credential to `/mcp`. It must be refused with 401.
3. Remove one person's key and restart the gateway (a config reload does not
   apply `auth` changes; see
   [What a config reload applies](DEPLOYMENT.md#what-a-config-reload-applies)),
   or revoke their key-server token with `DELETE /auth/token/{jti}`, and confirm
   their next call is refused. A key past its `expires_at` is refused without a
   restart.
4. Call one backend tool as each person and confirm the audit log has a
   record for each call, naming the caller. The requests refused in steps 2
   and 3 are turned away by authentication, before a tool call exists, so
   they are not in the tool-call audit log.

## Related

- [MULTI_USER.md](MULTI_USER.md): key server, policies, identity propagation.
- [DEPLOYMENT.md](DEPLOYMENT.md): Docker, systemd, TLS, reverse proxy, monitoring.
- [identity_grants.md](identity_grants.md): grants and caller identity headers.
- [Backup, restore and key runbook](runbooks/backup-restore-and-keys.md).
- [UPGRADING-4.0.md](UPGRADING-4.0.md): what changed from 3.x.
