# Upgrading to 3.0.0

3.0.0 changes the default OAuth posture for gateways that have authentication
enabled. This guide explains what changed, who is affected, and the exact
config line to add if you want to keep the old behavior.

See [ADR-008](adr/ADR-008-multi-user-oauth-isolation.md) for the full design
rationale and [CHANGELOG.md](../CHANGELOG.md#300---2026-07-03) for the
complete list of changes in this release.

## What changed

Before 3.0.0, a gateway with `auth.enabled: true` stored one OAuth token per
backend and attached it to every caller's request, regardless of who made
the request. On a gateway shared by more than one person, a call to a
personal-OAuth backend (Gmail, Superhuman, and similar) could be served with
another user's login, because the token was keyed by `(backend, resource)`
and not by user.

3.0.0 makes per-user OAuth isolation the default. A backend that requires a
per-user OAuth identity now refuses a call that lacks a verified end-user
identity, instead of serving a token that belongs to someone else. This is
enforced for both MCP backends and capability-backed REST connectors.

## Who is affected

- **Shared or multi-user gateways** with one or more `oauth:`-configured
  backends are affected. If more than one person calls the gateway and it
  has `auth.enabled: true`, backends that need per-user OAuth will start
  refusing calls unless a caller-specific identity is resolved.
- **Single-user / personal gateways** (one person, one set of credentials)
  are not affected in practice, but the gateway still asks you to declare
  that posture explicitly so the fail-closed default has an unambiguous
  answer. See the opt-in below.
- **Gateways with `auth.enabled: false`** are not affected by the isolation
  guard itself (there is no per-user boundary to protect), but see the
  security note at the end of this guide.

## The opt-in: keep the previous shared-credential behavior

If your gateway is genuinely single-user, or a specific backend is meant to
run as a shared service account, add one line to `gateway.yaml`:

**Personal gateway, one operator:**

```yaml
auth:
  single_user: true
```

**One backend intentionally shared across users (a team Slack bot, a
service account, and so on):**

```yaml
backends:
  my-backend:
    oauth:
      shared_account: true
```

Both flags are explicit, logged opt-ins. Neither is set automatically by
the upgrade.

Note that declaring `single_user: true` does not override a hard multi-user
signal: if the gateway has more than one API key configured, or an OIDC
issuer configured, it is treated as multi-user regardless of the
`single_user` flag. A single shared API key or bearer token can be handed to
an entire team, so the gateway does not take your word for `single_user`
when the config itself indicates otherwise.

## What the upgrade does to your config

Nothing, automatically. When the gateway starts up for the first time after
upgrading to 3.0.0, it runs a one-time, read-only migration:

1. It copies your existing `gateway.yaml` to `gateway.yaml.bak.<old_version>`
   (for example `gateway.yaml.bak.2.19.0`) before anything else runs.
2. It reads the config to detect whether you've already declared a posture
   (`auth.single_user` or any backend's `oauth.shared_account`).
3. It prints a one-time startup notice describing what it found and, if
   your posture is undeclared, what to add.

The migration does not write to `gateway.yaml`. If parsing the config for
posture detection fails for any reason, the migration logs a warning
instead. It never blocks startup or the real config load.

## After upgrading

- If you run a personal gateway: add `auth.single_user: true`, or ignore the
  notice if your backends don't require per-user OAuth.
- If you run a shared gateway: decide, per backend, whether it should route
  through a per-user credential (the default) or an explicitly shared
  service account (`oauth.shared_account: true`).
- If a backend call starts failing with a refusal instead of succeeding as
  before, it means that backend was previously serving a shared credential
  it should not have been serving to that caller. Resolve a per-user
  credential for that caller, or, if the sharing was intentional, set
  `oauth.shared_account: true` on that backend.

## Security note for `auth.enabled: false` gateways

If authentication is disabled entirely, the admin UI and config endpoints
are reachable by anyone who can reach the port. This has not changed in
3.0.0, but the startup notice calls it out because it is the other half of
the same posture question. Bind to `127.0.0.1` or a trusted network, or
enable `auth.enabled: true`.
