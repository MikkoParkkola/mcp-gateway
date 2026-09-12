# CodeQL open-alert triage

Lane: codeql-triage. Read-only triage — no fixes, no dismissals. Alert numbers and
line numbers as of `main` @ `b864faad` / alert commit `2822323`.

## #90, #91 — `rust/cleartext-transmission` — no work in this lane

Owned by the `httpcreds-r35` lane (ruling R35). Predicted-closed once `fix/mrtr2-continuation-handle`
lands: `require_secure_oauth_target` already guards `src/transport/http/mod.rs` on that branch
(3 occurrences) against 0 on `main`. That is a prediction, not a fact — do not restate as closed
until the next default-setup analysis runs on `main` post-merge.

## #78 — `rust/cleartext-logging` — REAL, reachable from the production path

**CodeQL sink** (as flagged): `src/capability/executor/mod.rs:122`, `request.send().await`
inside `send_with_retry`. Consistent across both alert instances (`main` commit `2822323`, line 104;
PR #473 commit `5cb4f4e`, line 122 — same call, line drift is doc-comment churn).

**CodeQL source**: `src/capability/executor/params.rs:195`, `self.secret_resolver.resolve(&result)`
inside `substitute_string()` — resolves `{keychain.X}` / `{env.VAR}` placeholders to live plaintext
secrets.

**Flow, source to sink**:
1. `substitute_string()` (params.rs:195) resolves secrets into header value templates
   (`mod.rs:557`, `build_headers`) and request-body templates (`mod.rs:676`).
2. `build_headers` → `inject_auth` (`mod.rs:574`) puts a live Authorization header on the
   `reqwest::RequestBuilder`; the `auth.param` path (`mod.rs:446-450`) puts the same credential
   in as a query param via `request.query(...)`.
3. That builder reaches `request.send().await` at `mod.rs:122` inside `send_with_retry`.

**Why the sink is a log write, not a network call**: the gateway's own logging is clean —
`build_url` (`mod.rs:499-545`) never touches the secret resolver, so the app's explicit
`tracing::debug!(url=...)` at `mod.rs:431` does not leak. The actual sink CodeQL is modeling is
**reqwest/hyper's own internal trace-level instrumentation** of the `RequestBuilder` it is given,
which dumps header/request contents when trace logging is enabled for those crates.

**Enabling condition — this is what makes it live, not theoretical**: `src/lib.rs:114`,
`EnvFilter::try_from_default_env()` reads `RUST_LOG` from the process environment with no ceiling.
No code in this repo caps the filter below `trace` for `reqwest`/`hyper` targets.

**Reachability verdict: production path, not test/bench-only.**
`execute_provider_with_context` (`mod.rs:413`) — the function that builds the credential-bearing
request and calls `send_with_retry` — has exactly one non-test caller in the tree:
`src/capability/executor/rest.rs:117`. `rest.rs` is the REST-provider execution path used by
every REST-backed capability call the gateway serves at runtime; it is not a test or bench target.

**Net**: an operator (or a misconfigured deploy, or an attacker who can influence the process
environment) setting `RUST_LOG=trace` — or scoping it to `reqwest=trace`/`hyper=trace` — causes
live upstream API keys and bearer tokens, resolved moments earlier from keychain/env secrets, to be
written to stdout/stderr on every capability call, no code change required. This is a real,
reachable HIGH, not a false positive and not confined to a non-production surface.

## Workflow file absence — not a gap

`.github/workflows/codeql.yml` does not exist on the default branch. That is the expected shape:
code scanning here runs through GitHub **default setup** (`state: configured`, language `rust`,
`threat_model: remote`, weekly + default-branch-push triggers), which does not use a checked-in
workflow file. Do not file this as a missing control.
