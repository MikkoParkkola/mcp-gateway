# Refuse a cleartext backend URL that would carry a credential

Date: 2026-09-04
Closes: code-scanning alerts #90, #91 (`rust/cleartext-transmission`, HIGH)
Policy owner: `docs/requirements/RELEASE-4.0.0-readiness-board.md`, section
"The CodeQL `#90`/`#91` policy question — decided by the agent, under a stated assumption"

## Problem

`validate_backend_urls` (`src/config/mod.rs`) checks a backend URL for non-empty and
parseable and nothing else. A configuration naming `http://internal-host:8080` with
`oauth.enabled` therefore starts, and the gateway sends `Authorization: Bearer` in
cleartext to a non-loopback host. The same repository already decides this exact question, correctly, one module away:
`well_known.rs:154-166` refuses plain `http` to a non-loopback host and rejects
userinfo outright, citing RFC 9728. The asymmetry between that path and the backend
path is the defect. (The OIDC check at `src/key_server/oidc.rs:592` is a weaker
analogue — no loopback carve-out, no userinfo rule — and is not the precedent followed.)

The policy is decided upstream and is not re-opened here: **refuse a plain-`http`
backend URL when a credential would ride on it, except when the host is loopback**,
with an explicit opt-in for an operator who wants cleartext on a trusted network.
This note covers the mechanism only.

## Constraints, measured

- The guard belongs in config validation, not the transport. The board's source pass
  established both flagged sinks are operator-provenanced, and the one
  backend-supplied input (`message_url`) is already pinned by `same_origin`
  (`src/transport/http/mod.rs:49`, called at `:796`).
- `validate_backend_urls` carries an in-function rule: the URL is never echoed in an
  error, because a malformed one still carries its userinfo and query, and the error
  is printed on startup and pasted into support threads (MIK-7221).
- Its sibling `validate_remote_backend_provenance` skips disabled backends.
- `BackendConfig` carries struct-level `#[serde(default)]`, so a new field with a
  `Default` entry is absent-safe in every existing config file.
- Every credential path is a field on `BackendConfig` itself, which is exactly what
  `validate_backend_urls` already holds as it iterates `&self.backends`. There is no
  global secret-injection or global OAuth config that could attach a credential to a
  backend from outside the struct (`secrets` appears on `BackendConfig` and nowhere
  else in `src/config/mod.rs`). The guard therefore needs no new plumbing and no
  relocation.
- The file already spells the OAuth-enabled test as
  `backend.oauth.as_ref().is_some_and(|o| o.enabled)` (`src/config/mod.rs:852`).
  Reused verbatim rather than re-derived.

## Mechanism

### Which config paths carry a credential

Three are structurally credential-bearing, one is a judgment call.

| path | credential-bearing when | basis |
|---|---|---|
| `oauth` | `Some(c)` and `c.enabled` | mints and sends a bearer token |
| `identity_propagation` | `Some(_)` — no enable flag exists, presence is the switch | mints a per-request user credential |
| `secrets` | non-empty | a `CredentialRule` exists to inject a credential |
| `headers` | non-empty | any static header may be a credential; see below |
| the URL's own userinfo | `url.username()` non-empty, or `url.password().is_some()` | `http://user:pass@host` is a credential in the URL |
| the URL's own query | `url.query()` is `Some` and non-empty | `?api_key=...` is a credential in the URL |

**`headers` is any header, not a list of known credential names.** The first draft
matched a fixed list (`authorization`, `x-api-key`, and so on) and named the gap as a
residual: `X-Custom-Token` would leak. A reviewer refused that, correctly. The test for
an elimination over a patch is whether the finding can still be stated afterwards — with
a list it can ("a credential header outside the list leaks"), and with `!headers.is_empty()`
it cannot. The opt-in already exists for the operator whose header is genuinely benign,
so the strict reading costs a config line in the rare case and closes the hole in the
common one. It also deletes the list.

**The same reasoning binds the query string, and on the second pass it changed my
answer.** I first refused to treat a query as credential-bearing, on the grounds that
`?tenant=acme` is ordinary configuration and a guard firing on ordinary configuration
gets switched off. A reviewer held the finding open. It was right and the refusal was
inconsistent: a benign `X-Trace-Id` header is at least as ordinary as a benign query
parameter, and I had already accepted the cost there on the strength of the opt-in.
One argument cannot decide two identical cases differently. Both now count, and
`?api_key=secret` can no longer ride a cleartext backend URL unnoticed. Note the guard
only fires on plain `http` to a non-loopback host, so the blast radius of the strict
reading is that narrow zone, not every backend.

### How loopback is detected

**By calling the existing classifier, not by writing a third copy of the rule.**
`is_loopback_host` (`src/gateway/router/well_known.rs:63`) strips
an IPv6 literal's brackets, case-folds `localhost`, and defers to
`IpAddr::is_loopback()` — so all of `127.0.0.0/8` and `::1`, at any spelling. It is
already the Origin gate's classifier. Two callers of one rule cannot drift; three
copies of it will. It is called with `url.host_str()` — a bare host, brackets included
for an IPv6 literal, never a whole URL and never `host:port`.

**It is not reachable as written, and the fix is one line.** `src/gateway/mod.rs:17`
declares `mod router;` privately, so `crate::gateway::router::is_loopback_bind` compiles
only from inside `gateway` (which is why `server/support.rs:79` can call it and
`src/config/mod.rs` cannot). A reviewer caught this; the claim that the `pub` on
`is_loopback_bind` made it crate-reachable was wrong, and checking it cost less than
the failed build would have. Repair: add
`pub(crate) use router::is_loopback_bind as is_loopback_host;` to `src/gateway/mod.rs`,
giving callers `crate::gateway::is_loopback_host(host)`. Crate-internal, so no public
API surface widens (D28); aliased back to the truthful name, since the callers classify
a backend host, not a bind address.

The third copy is the reason this is stated as a mechanism rather than a preference.
`is_loopback_url` (`src/discovery/shadow/helpers.rs:341`) is a string-match version and
it is **wrong in both directions**, measured, not inferred:

```
http://[::1]:8080/        host_str="[::1]"                -> classified NOT loopback
http://127.notloopback.test/  host_str="127.notloopback.test" -> classified loopback
```

`Url::host_str()` keeps the brackets on an IPv6 literal, so `host == "::1"` never
matches; and `host.starts_with("127.")` matches any domain name beginning `127.`. That
helper is pre-existing and outside this change's scope — see the disposal note at the
end.

The bare name `localhost` is accepted knowingly: `/etc/hosts` or DNS can point it
elsewhere. The board took that cost to avoid breaking every local development setup
and the part of the test suite that speaks plain HTTP to a local server.

**This is deliberately more permissive than the OIDC precedent, and the asymmetry is
not an oversight.** `oidc.rs:592` has no loopback carve-out; it refuses plain `http`
everywhere. A JWKS URI is remote-fetched by nature, so a loopback one is already
anomalous. An MCP backend on loopback is an ordinary deployment. The carve-out is the
operator-facing half of the decision, not an implementation shortcut — a later review
finding "we should refuse everywhere, like `:592`" would be the eliminate-over-patch
reflex firing on the wrong target, and it breaks local development and part of the
test suite.

### The opt-in

A per-backend `allow_cleartext_credentials: bool`, default `false`, on
`BackendConfig`. Per-backend rather than global, because the risk is per-backend and
the file already carries a per-backend security escape hatch of the same shape
(`passthrough`). Setting it makes the operator say so in the stanza that declares the
backend, next to the URL it excuses.

### What the error says

Diverges from the OIDC precedent deliberately. `OidcError::InsecureJwksUri` embeds the
offending URL; this one must not, because `validate_backend_urls` is under an explicit
no-echo rule (MIK-7221). Backend name and remedy only:

```
Backend 'name' sends a credential over cleartext http to a non-loopback host.
Use https, point the backend at loopback, or set allow_cleartext_credentials = true
for this backend to accept the risk.
```

### What breaks for existing operators

A configuration with a non-loopback `http://` backend plus any credential path stops
starting. That is the intended behaviour change and the reason the opt-in exists.
Unaffected: every `https` backend, every loopback backend at any spelling, every
stdio backend, every plain-`http` backend with no credential, and every disabled
backend.

## Design events (§P3) — decisions the board's section did not make

1. **The credential set includes `secrets` and `headers`, not only OAuth and identity
   propagation.** The board names the OAuth leak; excluding the other two spellings
   would leave the identical leak reachable by another route.
2. **Any configured header counts, and userinfo in the URL counts.** Both raised as
   gate findings on the first design review and accepted. A query string does NOT
   count — see the partial refusal below.
3. **Disabled backends are skipped — by the new guard only.** Mirrors
   `validate_remote_backend_provenance`. A disabled backend transmits nothing, so
   refusing startup for one is new breakage with no security gain. The skip must NOT
   be an early `continue` at the top of the loop: that would also drop the existing
   empty-URL and malformed-URL checks for disabled backends, weakening validation that
   holds today. Row 18 pins this.
4. **The error does not echo the URL**, against the instruction to mirror the OIDC
   wording, because the local no-echo rule (MIK-7221) is the stronger constraint.
5. **The A2A arm is guarded too**, under `#[cfg(feature = "a2a")]`. The function's own
   comment says fixing one spelling of a leak and not the other is how the first fix
   stops mattering.
6. **The opt-in is per-backend, not global.**
7. **A non-empty query counts, reversing a refusal recorded in the first revision.**
   Kept as a numbered event rather than edited away, because a design that hides having
   changed its mind teaches the next reader nothing.
8. **No faithful-host guard.** `well_known.rs:168-178` rejects a URL whose host the
   parser rewrote (decimal IPv4, punycode). That function returns an identifier that
   must match what the operator wrote; this guard asks only where the packets go.
   `http://2130706433/` parses to `127.0.0.1`, so the connection really is to loopback
   and allowing cleartext there is correct, not a bypass. Pinned by row 21 so a later
   reviewer cannot mistake the absence for an oversight.
9. **Loopback is decided by the existing classifier, re-exported crate-internally as
   `crate::gateway::is_loopback_host`, not by a local copy.** This adds a `config` ->
   `gateway` reference where none existed, and one `pub(crate) use` line. Named
   because it is a coupling decision (D27), and taken anyway: one shared classifier for
   a security rule beats a private duplicate that silently disagrees with the Origin
   gate. The alternative — lifting the helper somewhere neutral — is a larger move than
   this change should make, and is worth doing only if a third caller appears.

## Residual risks, stated

- `localhost` can be repointed by DNS or `/etc/hosts`. Accepted by the board.
- `::ffff:127.0.0.1` (IPv4-mapped IPv6) is not `Ipv6Addr::is_loopback()` and is
  refused. Not chased; an operator who hits it writes `127.0.0.1`.
- A backend whose plain-`http` non-loopback URL carries a benign query or a benign
  header now needs the opt-in line. Accepted, knowingly: that is the cost of the strict
  reading, and it is one line in the stanza that already declares the URL.
- A credential injected by a mechanism added later is not detected until this design is
  revisited.

## Correction to the record

The board and the task brief both state that `src/key_server/oidc.rs:377` and `:592`
"already require `https://`". Only `:592` refuses (`OidcError::InsecureJwksUri`).
Line 377 emits `warn!(issuer = %provider.issuer, "OIDC issuer is not HTTPS")` and
proceeds. The precedent mirrored here is `:592`.

## Test plan

One row per behaviour. Every row names whether it can go red before the guard exists,
so no row passes vacuously.

| # | case | expect | red before the guard? |
|---|---|---|---|
| 1 | `https://` non-loopback + oauth enabled | passes | no — guards against an over-broad guard |
| 2 | `http://internal-host:8080` + oauth enabled | REFUSED | yes |
| 3 | `http://internal-host:8080`, no credential | passes | no — over-broadness |
| 4 | `http://127.0.0.1:8080` + oauth enabled | passes | no — the loopback carve-out |
| 5 | `http://127.0.0.2:8080` + oauth enabled | passes | no — `is_loopback()` over `== 127.0.0.1` |
| 6 | `http://[::1]:8080` + oauth enabled | passes | no |
| 7 | `http://localhost:8080` + oauth enabled | passes | no |
| 8 | `http://LOCALHOST:8080` + oauth enabled | passes | no — the case-insensitive compare |
| 9 | row 2 + `allow_cleartext_credentials = true` | passes | no — the opt-in |
| 10 | `http://internal-host` + `identity_propagation` | REFUSED | yes |
| 11 | `http://internal-host` + non-empty `secrets` | REFUSED | yes |
| 12 | `http://internal-host` + `headers["Authorization"]` | REFUSED | yes |
| 13 | `http://internal-host` + `headers["X-Custom-Token"]` | REFUSED | yes — any header, not a known-name list |
| 14 | `http://user:pw@internal-host` alone, no other credential | REFUSED | yes — userinfo is itself the credential |
| 15 | row 2 with `enabled = false` | passes | no — the disabled-backend skip |
| 16 | `a2a_url = http://internal-host` + oauth enabled | REFUSED | yes — `a2a` feature only |
| 17 | `a2a_url = https://` + oauth enabled | passes | no |
| 18 | `http://` empty and malformed URLs on a **disabled** backend | REFUSED, as today | no — pins that the skip drops only the new guard |
| 19 | `http://internal-host/mcp?tenant=acme`, no other credential | REFUSED | yes — a query counts, benign or not |
| 19b | `http://internal-host/mcp?api_key=secret`, no other credential | REFUSED | yes |
| 20 | the refusal message from row 14 (`http://user:pw@internal-host`) | names the backend; contains none of the substrings `user:pw`, `internal-host`, `http://` | yes — an implementer copying `OidcError::InsecureJwksUri` fails it |
| 21 | `http://2130706433/` + oauth enabled | passes | no — decimal IPv4 is genuinely loopback |

Rows 2, 10, 11, 12, 13, 14, 16, 19, 19b and 20 go red before the guard exists. The rest exist to catch a
guard that refuses too much; they pass both before and after, which is what makes them
the over-broadness check rather than the correctness check.

## The second defect, disposed as REPAIR (§P0)

`is_loopback_url` (`src/discovery/shadow/helpers.rs:341`) is wrong in both directions,
per the probe above. I first disposed it as a ticket, reasoning that its severity was
the owner's call. Overruled, and the overrule was right: the owner traced it, so there
is nothing left for a human to decide. `local_only` feeds `auth_exposure` feeds
`classify_severity`'s `network_exposed` (`src/discovery/shadow.rs:826, :835, :941`), so
a host at an attacker-registrable name beginning `127.` has its severity DOWNGRADED —
a miss on precisely the ungoverned network-exposed server that shadow discovery exists
to find. A ticket meeting our own DoR would have been longer than the repair.

The repair is a delegation, not a rewrite: `is_loopback_url` parses the URL and hands
the host to `is_loopback_host`. It ships as its own commit with two regression cases,
and it makes this change SMALLER — three loopback classifiers were about to exist and
two will remain, one of them the only owner of the rule.

## Build order

The tests cannot compile until `allow_cleartext_credentials` exists, and a
compile failure proves nothing. Three commits:

1. the field, inert — `BackendConfig` + `Default` + the redacting `Debug` impl;
2. the tests — they compile, and rows 2/10/11/12/13/16 fail on the assertion;
3. the guard — every row green.
