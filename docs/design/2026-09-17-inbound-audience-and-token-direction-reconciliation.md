<!--
SPDX-FileCopyrightText: 2026 Mikko Parkkola
SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
-->

# Inbound audience, and which token direction owns which standard

MIK-6746.CONTRACT.1 · 2026-09-17

Three separate mechanisms in this repository all look like "OAuth for a
backend", and two of them have been mistaken for each other in ticket bodies.
This page fixes which one is which, and states the inbound invariant that
v4.0.0 now enforces at config load, at token validation, and at the route.

## 1. The inbound invariant

An agent token presented to this gateway must name **this gateway** in `aud`.

The reason is not ceremony. A gateway agent is configured with a signing key,
and a signing key is frequently shared with other relying parties — the same
HS256 secret or the same RS256 issuer also mints tokens for a billing API, an
internal service mesh, whatever else the operator runs. Without an expected
audience the verifier has no way to tell a token minted *for this gateway*
from one minted for *any other holder of that key*. Signature validity is not
identity.

Enforced in three places, each with its own failure mode closed:

| Where | What it refuses | Why the other two do not cover it |
|---|---|---|
| `Config::validate` (`src/config/mod.rs:922`) | An enabled agent with `audience` absent or blank, **before** the RS256 early-exit | A struct built in code can still carry `None`; and an operator's pre-4.0.0 YAML simply omits the key |
| `validate_agent_token` (`src/gateway/oauth/jwt.rs:114`) | A correctly-signed token whose agent definition has no audience | `AgentRegistry::register` is public and validates nothing, so `None` is reachable past config |
| `agent_auth_middleware` (`src/gateway/oauth/mod.rs:100`) | A wrong-audience token on `/mcp` **and** on `/mcp/{name}` | A verifier that refuses proves nothing about the path a client actually meets |

Route parity is asserted rather than assumed: the sibling agent-identity
defect closed in `d7a59a95` existed precisely because the direct per-backend
route lacked a guard the meta route had.

**Migration.** A pre-4.0.0 configuration file with agent auth enabled and no
`audience` key no longer loads. The refusal names the agent and the missing
key. The documented step is one line per agent:

```yaml
agent_auth:
  agents:
    - client_id: svc
      audience: "https://gateway.internal/mcp"   # the identifier this gateway is known by
```

A blank or whitespace-only value is refused like an absent one: `""`
distinguishes nobody, so accepting it would reopen the hole the key closes.

Coverage: `tests/mik_6746_contract_acs.rs` drives real YAML files through
`Config::load` and real requests through `create_router`, because the
pre-existing `--lib` rows build a `Config` struct and clear the field by
assignment (`src/config/tests.rs:1191`) — which a `#[serde(default)]` or a
`load` path that never reached `validate` would both survive.

## 2. The three directions, and which standard governs each

### Inbound discovery — RFC 9728, unbuilt, legitimate

ADR-008 rung 2 ("client-native OAuth") depends on the gateway *advertising*
each backend's auth requirement as protected-resource metadata, so a capable
client can run the browser dance itself. ADR-008 states the gap plainly
(`ADR-008:101`):

> passthrough (rung 2) is only smooth if the client knows to obtain a
> backend-audience token. That requires the gateway to *advertise* per-backend
> auth requirements (RFC 9728), which the gateway does not do today (it
> validates inbound Bearer tokens but publishes no protected-resource
> metadata).

This is standards-based new work, and it is the thing that makes rung 2 a
default rather than an austere refusal. It does not conflict with the inbound
invariant above: RFC 9728 tells a client *which* audience to ask for; §1
enforces that the token it brings back actually carries it.

### Attachment — `x-mcp-passthrough-authorization`, gateway-specific, not primary

The custom header (`src/gateway/router/backend_handlers.rs`) is a *delivery*
mechanism for a token the client already holds — the last mile of rung 2, not
a rung of its own and not a standard. The scope update is explicit that it is
to be reconciled rather than propagated
(`RELEASE-4.0.0-scope-update.md:65`):

> ADR-008's old ticket bodies and MIK-6746's custom header must be reconciled,
> not copied into new work.

Read together with the ADR: the header stays for clients that cannot do
better, the advertised RFC 9728 path is what new work builds toward, and no
new surface should acquire its own bespoke authorization header.

### Egress — RFC 8693 / 7523 / 8707, built

Outbound identity propagation is a different problem with its own standards:
token exchange (RFC 8693), JWT bearer grants (RFC 7523) and resource
indicators (RFC 8707), implemented in
`src/identity_propagation/token_exchange.rs`. Resource indicators are the
*outbound* mirror of §1 — the gateway naming the backend it wants a token for,
exactly as an agent must name the gateway.

## Summary

Inbound: prove the token was minted for us (§1, enforced, tested, falsified).
Discovery: tell capable clients what to ask for (RFC 9728, not built).
Attachment: the custom header is a fallback, frozen, not a pattern to copy.
Egress: RFC 8693/7523/8707, already in tree.

These are four answers to four questions, not four competing designs.
