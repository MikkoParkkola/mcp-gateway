# R35 — credential guard wording alignment

Scope: align the written R35 requirement with the guard as built, pin the
username-only case with a test, and settle code-scanning alerts #90 and #91.

Operator ruling (2026-09-08): the stricter behaviour is correct. The code stands;
the requirement text changes. The guard's behaviour is not touched by this work.

## The guard as built

`Config::reject_cleartext_credentials` — `src/config/mod.rs:1004-1040`.
Called from backend validation at `src/config/mod.rs:970` (`TransportConfig::Http`)
and `src/config/mod.rs:986` (`TransportConfig::A2a`, feature-gated). Both
transports are guarded on identical terms; stdio is not guarded because it opens
no network connection.

### Preconditions — the guard returns `Ok` without inspecting anything further

`src/config/mod.rs:1009`. Any one of these passes the backend:

| precondition | why |
|---|---|
| `!backend.enabled` | a disabled backend opens no connection, so it leaks nothing |
| `backend.allow_cleartext_credentials` | operator opt-out, still in force for every arm below |
| `url.scheme() != "http"` | `https` is encrypted; other schemes do not reach this path |

### Loopback exception

`src/config/mod.rs:1016-1019`. `crate::gateway::is_loopback_host(url.host_str())`
returns `Ok` — loopback traffic never leaves the machine, so there is no network
segment to observe. The classifier is shared with the Origin gate and the
transport guard so the three cannot drift. `host_str` yields a bare host,
brackets included for an IPv6 literal, so `[::1]` classifies; an IPv4-mapped IPv6
literal such as `[::ffff:127.0.0.1]` does **not** classify as loopback and is
therefore refused.

### Trigger — seven signals, OR'd

`src/config/mod.rs:1027-1034`. Any one of these makes the backend
credential-bearing and the guard refuses:

1. `backend.oauth.is_some()`
2. `backend.identity_propagation.is_some()`
3. `!backend.secrets.is_empty()`
4. `!backend.headers.is_empty()` — any static header, not a known-name list
5. `!url.username().is_empty()` — **a username alone, password or not**
6. `url.password().is_some()` — **a password alone, username or not**
7. `url.query().is_some()` — operator-supplied per-request material

Arms 5 and 6 are independent. A username with no password is refused, and a
password with no username is refused, because the predicate ORs the two.
This is the point on which the written requirement said "username and password"
and the code says either.

### Action

`src/config/mod.rs:1035-1039`. `Error::ConfigValidation`, refusing config load.
The message names the backend and nothing else — not the address — because it is
printed on startup and pasted into support threads (MIK-7221).

## R35's three clauses against the code

R35 (`docs/release/2026-09-08-team-lead-rulings.md:777-780`) asserts three things.
One is built; two are not.

| clause | state | evidence |
|---|---|---|
| refuse embedded credentials over plain `http`, loopback exempt | **built** | `src/config/mod.rs:1004-1040` |
| the refusal names the offending address | **not built** | `src/config/mod.rs:1035-1039` names the backend only |
| there is NO opt-out setting | **not built** | `src/config/mod.rs:1009` still short-circuits on `allow_cleartext_credentials` |

The two open clauses are already scoped as an amendment in
`docs/design/2026-09-04-cleartext-credential-backend-guard.md` ("R35's residual is
two edits, not a feature"), whose test-plan rows 3, 4 and 5 are marked
"yes — falsifier", i.e. able to fail against the current code. They are out of
scope for this wording change and are named here rather than rounded to a verdict.
