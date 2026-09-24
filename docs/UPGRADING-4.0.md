# Upgrading to 4.0.0

From any 3.x release. Your `gateway.yaml` loads unchanged — no migration edits it, and the
gateway makes no automatic change to your configuration on upgrade.

On the first `serve` after the upgrade, the gateway prints a one-time notice to stderr listing
items 1-4 below, then stamps the new version. The notice is printed rather than logged, so
`--log-level error` and `RUST_LOG` filters cannot swallow it.

The rest of the list has no startup notice, for two different reasons. Items 5 and 9 are
changes to the license and to a removed CLI surface rather than to running behaviour. Items
6-8 are decided per request or per backend, so there is no single moment at startup at which
the binary could know whether a given deployment is affected. Item 10 changes the shipped
deployment files, not the binary's behaviour on an existing route.

**Items 2 and 8 refuse the gateway's start. Item 7 permanently fails the backend it names,
with one warning, and the gateway starts without it.** Read those three first if you are
upgrading a running deployment.

## What changed

| # | Change | Action needed |
|---|---|---|
| 1 | OAuth credentials are stored per issuer | Re-authorize each OAuth backend once |
| 2 | A malformed `env_files` line fails startup | Fix the line the error names |
| 3 | Protocol `2024-10-07` is no longer advertised | None for conforming clients — see below |
| 4 | Rate-limited responses no longer trip the breaker | None — this removes a failure mode |
| 5 | One license across the repository | Commercial users need a commercial license |
| 6 | Caching requires an identifiable protocol revision | Send the version header, or `initialize` the session |
| 7 | An OAuth backend must be on TLS or loopback | Put TLS in front of it, or move it to `127.0.0.1` — no opt-out |
| 8 | A credential-bearing backend on plain `http://` is refused at load | Use TLS, or set `allow_cleartext_credentials: true` on that backend |
| 10 | Shipped probes move from `/health` to `/livez` and `/readyz` | Repoint your own probes; `/health` still answers |
| 9 | The savings estimates are gone from stats | Drop `--price`; compute cost from `total_cached_tokens` yourself |

## 1. OAuth credentials are stored per issuer

Tokens stored by 3.x are **not migrated**. Nothing is lost and nothing is silently reused
under a new key: each OAuth backend simply re-authenticates on its next use.

Expect one authorization prompt per OAuth backend, once. No config change is needed. If your
deployment is unattended, trigger each backend deliberately rather than discovering the prompt
on a user's first call.

## 2. A malformed line in an `env_files` file now fails startup

In 3.x a line that could not be parsed was skipped silently, so a typo cost one missing
environment variable and the gateway started anyway — usually failing later, somewhere
unrelated.

In 4.0.0 the same typo refuses the start and names the offending line. This is the change most
likely to surprise a running deployment, because a file that "worked" for months can hold a bad
line that never mattered until now.

Before upgrading a production gateway, start it once against your real `env_files` in a
throwaway environment. A refused start with a line number is a one-minute fix; a refused start
during a deploy window is not.

## 3. Protocol version `2024-10-07` is no longer advertised

`2024-10-07` is not a revision the MCP specification has ever defined. It was listed in the
gateway's supported set from the first negotiation commit until 4.0.0, where it was removed
(`src/protocol/mod.rs:32-37`).

The removal changes what the gateway *claims*, not how it answers. `server/discover` publishes
the supported set as the gateway's own statement of what it speaks, so an invented revision in
that list was a false claim. Negotiation itself was never affected: `negotiate_version` matches
exactly, and no conforming client can request a revision that does not exist.

Nothing is rejected. A client naming `2024-10-07` in `initialize` gets `2025-11-25` back —
the same fallback any unrecognized version string gets, before and after this release
(`tests/integration.rs:37`). There is no error and no refused session.

`2024-11-05` and every later revision negotiate exactly as before. The startup notice advises
upgrading a client that speaks only `2024-10-07`; in practice such a client would have been
getting the fallback all along.

## 4. Rate-limited backend responses no longer count as failures

HTTP 429 and its equivalents are excluded from the error budgets and from the circuit breaker
(GH #475). In 3.x a backend that was merely busy could be tripped open and taken out of
rotation — the gateway punished a backend for applying backpressure correctly.

There is nothing to change. Expect fewer spurious breaker openings, and note that a genuinely
broken backend that happens to answer 429 will now stay in rotation longer.

One boundary is deliberate and worth knowing: a capacity failure worded as a throttle — for
example `request throttled: upstream out of capacity` — is still treated as rate limiting and
therefore still exempt. Narrowing that needs a rate-limit co-signal and is not in 4.0.0.

## 5. One license across the repository

4.0.0 retires the MIT core and the per-file allowlist that enumerated it. Every first-party file
in this repository is now under the **PolyForm Noncommercial License 1.0.0**
([ADR-013](adr/ADR-013-single-noncommercial-license.md), [LICENSES.md](../LICENSES.md)).

Noncommercial use is unaffected. Commercial use requires a commercial license — see
[COMMERCIAL.md](../COMMERCIAL.md). If you adopted the gateway under the previous MIT core, this
is the change to route past whoever approves your licensing, not a runtime concern.

## 6. Responses are cached only for a known protocol revision

The response cache is now keyed by the protocol revision the request was served under, and a
request whose revision cannot be identified is not cached at all
(`cache_protocol_revision`, `src/protocol/meta.rs:514`). A modern request carries its revision
in the body. A legacy request must supply it in the `MCP-Protocol-Version` header, or have
bound one by completing `initialize` on the session.

In 3.x the cache had no such key, so a response fetched for a caller that declared no revision
could be served to a caller asking under a different one. Refusing to key what cannot be
identified is the safe half of that trade, and the skip is deliberate rather than a fallback.

**This is the item most likely to surprise you.** A client that sends no
`MCP-Protocol-Version` header *and* does not run `initialize` — a bare stateless `POST`, which
is common in load generators, probes and simple scripts — loses response caching entirely on
upgrade, and that traffic goes to your backends instead. Nothing errors; throughput and backend
load change. The gateway's own rate limits (default 100 rps, burst 50) then apply to calls that
previously never reached them.

Send `MCP-Protocol-Version` on stateless requests, or complete `initialize` and reuse the
session. Either restores caching; neither requires a configuration change.

## 10. Probes read `/livez` and `/readyz`, not `/health`

`/health` answers 503 whenever the health tracker marks any backend down. The Helm chart and
the enterprise-alpha manifests used it for the liveness, readiness and startup probes, so one
flapping upstream restarted every replica, and a backend that was down at deploy time kept new
pods from ever starting. The container `HEALTHCHECK` also dialled `localhost`, which the Host
gate refuses on a `0.0.0.0` bind with no `public_url`, so the image reported itself unhealthy.

4.0.0 adds two endpoints that never read backend health:

- `/livez` answers 200 while the process serves. Use it for liveness and container healthchecks.
- `/readyz` answers 200 once the config has loaded and the listener is up. Use it for readiness
  and startup. It deliberately does not fail on a backend: there is no per-backend `required`
  setting, and one unreachable upstream is not a reason to take the gateway out of rotation.

Both are public exactly when `/health` is. A config that lists only `/health` under
`auth.public_paths` exposes all three, and one that omits `/health` requires a credential on all
three. You do not need to add them to `public_paths`.

The shipped chart, manifests, `Dockerfile` and single-node compose file now point at the new
endpoints and dial `127.0.0.1`. If you wrote your own probes, or a load balancer health check,
against `/health`, repoint them. `/health` is unchanged and remains the place to read backend
state, so keep it for dashboards and alerts.

## After upgrading

- Confirm the version stamp advanced: the notice prints once and not again.
- Re-authorize OAuth backends at a time you choose rather than on a user's first call.
- If startup is refused, read the error — item 2 is the one that refuses rather than warns.

## Rolling back

Downgrading to 3.x loads the same `gateway.yaml`, because 4.0.0 never edited it. The upgrade
leaves the 3.x token files in place — its migration prints the notice and stamps the version,
and touches no credential (`src/commands/upgrade.rs:264`). A rollback therefore picks those
files back up rather than prompting again, unless the tokens expired in the meantime. What 4.0.0
wrote under the per-issuer key is simply not read by 3.x.
