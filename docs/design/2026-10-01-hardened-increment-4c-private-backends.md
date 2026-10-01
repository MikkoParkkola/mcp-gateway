# HARDEN increment 4c: `security.hardened.private_backends` (design delta + test plan)

Parent: `docs/design/2026-09-28-hardened-posture.md` §2 item 4, rows 13 and 17 (its
`private_backends` refusal); T14 from the 4b plan (#2504). Decision: operator decision 8, row 26
of `docs/requirements/RELEASE-4.0.0-operator-decisions.md` (approve, conditional on always
denying `fd00:ec2::254`). Base: 4b's `DestinationPolicy` (`src/security/ssrf/destination.rs`).
Only `security.posture: hardened` changes; under `standard` the key is accepted and inert.

## 1. Behaviour

- **Config.** `security.hardened.private_backends: [names]`, default `[]` (new
  `HardenedConfig` under `SecurityConfig`; the name is M1's).
- **Policy.** A third variant, `DestinationPolicy::Private`, for a listed backend. One predicate,
  `DestinationPolicy::denies(ip)`, decides every check:
  - `Configured`: nothing.
  - `Public`: `is_private_or_reserved(ip)`, which is today's behaviour, unchanged.
  - `Private`: what `Public` denies, except loopback (127.0.0.0/8, ::1), RFC 1918 (10/8,
    172.16/12, 192.168/16) and unique-local (fc00::/7). An always-deny list is checked first and
    holds `fd00:ec2::254`, the AWS IPv6 instance-metadata address. Every other special-use range
    `Public` denies stays denied, link-local (169.254/16, fe80::/10) included. An IPv4-mapped
    IPv6 address is judged by its embedded IPv4.
- **Where it applies.** Every site 4b made policy-aware calls `denies` rather than
  `is_private_or_reserved`:
  - `check_literal` (transport start, every OAuth URL and redirect hop);
  - the pinning resolver (HTTP backend client and OAuth client);
  - the WebSocket pinned connect (`websocket_pinned.rs`), which now treats `Private` as pinned
    just as it treats `Public`.
  - The proxy-time check (`router/authorization.rs:337-344`) applies the backend's own stamped
    policy when it is `Private`. Without that, a listed backend would connect and then have
    every tool call refused by the generic literal check.
- **Stamping.** `BackendRegistry::enforce_destination` takes the list as well as the posture
  policy and stamps `Private` on each listed backend, `Public` on every other. This holds at
  startup and on reload add or modify. A backend's policy never downgrades from `Public` to
  `Configured` (4b's invariant).
- **Startup refusal (row 17).** Under `hardened`, a listed name that is not a configured backend
  refuses start, naming it.
- **Reload.** `security.hardened` is restart-only: a reload that changes it is refused, with the
  posture's refusal shape.

## 2. Test plan (red-first; each row names the mutant that must redden it)

| Row | Test | Asserts | Mutant |
|---|---|---|---|
| 13 | `listed_private_backend_policy` | for a listed backend, an RFC 1918 literal and a loopback hostname connect, while 169.254.169.254, fe80::1 and fd00:ec2::254 (also as a resolved name) are refused with 0 connections; an unlisted backend is still refused at loopback | allow link-local / drop the always-deny / stamp every backend `Private` |
| 13 | `private_policy_denies` (unit, table) | `denies` across the allowed, denied and mapped forms for each policy | each range edge |
| 13 | `listed_private_backend_tool_call_passes_proxy_check` | under hardened, a tool call to a listed loopback backend is served (backend saw it); an unlisted one is refused | keep the generic literal check |
| 17 | `hardened_refuses_unknown_private_backend` | start refused, naming the unknown name | drop the check |
| 16 | `standard_ignores_private_backends` | under standard the key is accepted and no backend is stamped | stamp under standard |
| reload | `reload_refuses_private_backends_change` | changing the list on reload is refused | drop the diff |
| T14 | `pinned_websocket_connect_times_out_whole` | a listed WebSocket backend whose loopback server accepts TCP and never answers the upgrade fails with "WebSocket connect timed out" within the configured timeout plus slack | wrap only the upgrade, or drop the timeout |

## 3. Upgrade guide and ledger
UPGRADING item: the next free number at merge, kept contiguous. Changelog fragment. HARDEN.1 is
graded after this merges.
