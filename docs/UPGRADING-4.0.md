# Upgrading to 4.0.0

From any 3.x release. Your `gateway.yaml` loads unchanged — no migration edits it, and the
gateway makes no automatic change to your configuration on upgrade.

On the first `serve` after the upgrade, the gateway prints a one-time notice to stderr listing
the four behavioral changes below, then stamps the new version. The notice is printed rather
than logged, so `--log-level error` and `RUST_LOG` filters cannot swallow it.

The list here is the same one the binary prints, plus the license change, which is a legal
change rather than a runtime one and therefore has no startup notice.

## What changed

| # | Change | Action needed |
|---|---|---|
| 1 | OAuth credentials are stored per issuer | Re-authorize each OAuth backend once |
| 2 | A malformed `env_files` line fails startup | Fix the line the error names |
| 3 | Protocol `2024-10-07` is no longer advertised | None for conforming clients — see below |
| 4 | Rate-limited responses no longer trip the breaker | None — this removes a failure mode |
| 5 | One license across the repository | Commercial users need a commercial license |

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

## After upgrading

- Confirm the version stamp advanced: the notice prints once and not again.
- Re-authorize OAuth backends at a time you choose rather than on a user's first call.
- If startup is refused, read the error — item 2 is the one that refuses rather than warns.

## Rolling back

Downgrading to 3.x loads the same `gateway.yaml`, because 4.0.0 never edited it. The per-issuer
OAuth credentials written by 4.0.0 are not read by 3.x, so a rollback costs one more
re-authorization per backend in the other direction.
