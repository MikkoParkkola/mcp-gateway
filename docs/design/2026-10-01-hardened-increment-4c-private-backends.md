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
    `Public` denies stays denied, link-local (169.254/16, fe80::/10) included. Only an
    IPv4-mapped address (::ffff:0:0/96) gets the private allowance by its embedded IPv4. No
    other encoding gets it. So `Private` reaches an encoded address exactly when `Public` does:
    `Public` denies the whole NAT64, 6to4 and Teredo prefixes (`ranges.rs:150-170`) and judges
    IPv4-compatible (::/96) by the embedded IPv4. `::8.8.8.8` is reachable under both, and
    `::10.0.0.1` under neither.
- **Where it applies.** Every site 4b made policy-aware calls `denies` rather than
  `is_private_or_reserved`:
  - `check_literal` (transport start, every OAuth URL and redirect hop);
  - the pinning resolver (HTTP backend client and OAuth client);
  - the WebSocket pinned connect (`websocket_pinned.rs`), which now treats `Private` as pinned
    just as it treats `Public`.
  - The proxy-time check (`router/authorization.rs:337-344`) applies the backend's own stamped
    policy when it is `Private`. Without that, a listed backend would connect and then have
    every tool call refused by the generic literal check.
- **Stamping.** `BackendRegistry::enforce_destination` installs one immutable snapshot, the
  posture policy plus the listed names, under the lock `register` inserts under (4b's race-free
  rule). It stamps `Private` on each listed backend and `Public` on every other. This holds at
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
| 13 | `private_policy_denies` (unit, table) | `denies` for each policy across allowed, denied, mapped, IPv4-compatible, NAT64, 6to4 and Teredo forms of an allowed and a denied IPv4, plus fd00:ec2::254, `::8.8.8.8` (reachable under both) and `::10.0.0.1` (denied under both) | each range edge / decode a non-mapped encoding |
| 13 | `listed_private_backend_oauth_policy` | the OAuth client of a listed backend reaches a loopback authorization server, while a metadata or link-local literal in a discovered endpoint, a redirect hop, and a name resolving to fd00:ec2::254 are refused with 0 connections | build the OAuth client `Public` / skip a hop |
| reload | `reload_stamps_listed_backends_private` | with the list unchanged, a reload-added listed backend is `Private` and a reload-modified unlisted one stays `Public`, on the gateway's registry and on a caller-built one | stamp only at startup |
| 13 | `listed_private_backend_tool_call_passes_proxy_check` | under hardened, a tool call to a listed loopback backend is served (backend saw it); an unlisted one is refused | keep the generic literal check |
| 17 | `hardened_refuses_missing_private_backend` | start refused, naming the unknown name | drop the check |
| 16 | `standard_ignores_private_backends` | under standard the key is accepted and no backend is stamped | stamp under standard |
| reload | `reload_refuses_private_backends_change` | changing the list on reload is refused | drop the diff |
| T14 | `pinned_websocket_connect_times_out_whole` | a listed `ws://` backend whose loopback server accepts TCP and never answers the upgrade, and a listed `wss://` backend whose server never answers the TLS handshake, each fail with "WebSocket connect timed out" within the configured timeout plus slack | drop the timeout |

## 3. Upgrade guide and ledger
UPGRADING item: the next free number at merge, kept contiguous. Changelog fragment. HARDEN.1 is
graded after this merges.

## 4. Review dispositions (design round 1)

- ACCEPTED, seat A: OAuth under `Private` was untested. Added `listed_private_backend_oauth_policy`.
- ACCEPTED, both seats: reload stamping was untested. Added `reload_stamps_listed_backends_private`.
- ACCEPTED in part, seat A: T14's upgrade stall cannot catch a timeout around the upgrade only.
  A `wss://` TLS stall is added, so the timeout must cover TLS too. A resolver stall needs a
  test seam: the timeout site resolves through `SystemResolver` (`websocket.rs`), and the lead
  ruled a seam out. TCP connect to loopback cannot stall. The pinned connect is one call (TCP,
  TLS, upgrade), so the natural mutant is dropping the timeout, which both cases kill.
- ACCEPTED in part, seat 2 (HIGH): IPv6 encodings of IPv4. `Private` decodes only the mapped
  form. Every other encoding stays denied because it is outside the allowance, and `Public`
  already denies those whole prefixes (`ranges.rs:150-170`, verified at source), so nothing is
  reachable through them. The encodings are now in the unit table.
- Improvements taken: one immutable snapshot under the registration lock; refusals asserted by
  policy error text with 0 connections. Not taken: an integration case per encoded form (the
  unit table covers the predicate every site calls); asserting no port opened for row 17 (the
  refusal happens at config load, before any listener).

## 5. Review dispositions (seat A, delta round 2)

- ACCEPTED as a wording fix: "every other encoding stays denied" was false for IPv4-compatible
  public addresses. `Public` judges ::/96 by its embedded IPv4 (verified, `ranges.rs:148-150`),
  and `Private` reaches exactly what `Public` reaches outside its three ranges, so no change in
  behaviour is needed. `::8.8.8.8` and `::10.0.0.1` were added to the unit table.
- Recorded limit: a timeout moved to after DNS and TCP would survive T14. Loopback TCP cannot
  stall, and DNS is the system resolver at that site. Placement is verified at source instead:
  the timeout wraps `pinned::connect`, which resolves, connects, then runs TLS and the upgrade.
