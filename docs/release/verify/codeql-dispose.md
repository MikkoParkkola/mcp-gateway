# CodeQL open-alert disposal

Lane: codeql-dispose. Acts on the operator ruling of 2026-09-08 — fix #78, triage
#92/#97/#100 at source and dismiss or fix each on its merits. Line numbers as of
`fix/mrtr2-continuation-handle`; alert line numbers as recorded on their own commits.

Companion read-only triage: `docs/release/verify/codeql-triage.md`.

## #97 — `rust/cleartext-logging` — FALSE POSITIVE (test code)

Alert: `tests/mik_7212_acs.rs:79-80` @ `5cb4f4e`, "This operation writes secret to a log file."

**Deciding location**: `tests/mik_7212_acs.rs:66-81`.

The flagged write is the failure message of `assert!(!plain.contains(secret), ...)`. Three
facts break the claimed path:

1. **The target is a test binary.** `tests/` is an integration-test target. It is not linked
   into `mcp-gateway` and ships in no release artifact.
2. **The values are fixture literals, not resolved credentials.** `secret` iterates a
   hardcoded array (`"AEAD-protected"`, `"weather"`, `"sha256:caller-a"`, `"sha256:req-1"`,
   `"gw-1"`, `"exchange-1"`) written into the test file. No secret resolver, keychain or
   environment read reaches this value.
3. **The write is the negation of the finding.** The message is emitted only when the
   assertion fails — that is, only when the redaction under test has broken. The assertion
   exists to prove the value is absent; the scanner has flagged the proof as the leak.

Disposal: dismissed, reason `used in tests`.

## #92 — `rust/cleartext-logging` — FALSE POSITIVE (test code)

Alert: `tests/mik_7212_acs.rs:854` @ `5cb4f4e`, same rule and message.

**Deciding location**: `tests/mik_7212_acs.rs:840-856`.

Same shape as #97, one level further in: the test asserts that `format!("{:?}", payload())`
does not carry `"super-secret-backend-token"`, `"sha256:caller-a"` or `"sha256:req-1"`. Those
strings are constructed by the local `payload()` fixture at `tests/mik_7212_acs.rs:820-838`.
Integration-test target, literal fixture values, message emitted only on assertion failure.

Disposal: dismissed, reason `used in tests`.

## #100 — `rust/cleartext-logging` — FALSE POSITIVE (test code)

Alert: `src/capability/executor_tests.rs:1393` @ `5cb4f4e`, same rule and message.

**Deciding location**: `src/capability/executor/mod.rs:701-702`.

This file sits under `src/`, which is what makes the alert look like production code. It is
not. The module is included as:

```rust
#[cfg(test)]
#[path = "../executor_tests.rs"]
```

`#[cfg(test)]` means the module is compiled only under `cargo test`; it is absent from every
non-test build of the crate. The flagged write is again an assertion message
(`src/capability/executor_tests.rs:1391-1395`) over a hardcoded array
(`"CANARY"`, `"api_key"`, `"localhost"`, `"/throttled"`, `"slow down"`) proving that a typed
`Error` does not carry them. No live credential is in scope at that line.

Disposal: dismissed, reason `used in tests`.

### Why `used in tests` and not `false positive`

GitHub code scanning offers `false positive`, `won't fix` and `used in tests`. All three
alerts are false positives *as security findings*, and the reason they are false positives is
in every case that the code is test-only. `used in tests` records that precisely and stays
checkable; the dismissal comment carries the deciding file:line either way.

## #78 — `rust/cleartext-logging` — MISCLASSIFIED SINK, real adjacent gap fixed

Alert: `src/capability/executor/mod.rs:104` @ `2822323`, "This operation writes
`... .resolve(...)` to a log file." Left **open**.

**Deciding location**: the alert's own data-flow path, read from the analysis SARIF
(`GET /code-scanning/analyses/1734091620` with `Accept: application/sarif+json`) — the REST
alerts endpoint carries only the sink line, which is what made this alert readable as a
logging defect for as long as nobody pulled the flow.

The path ends:

```
[0] src/capability/executor/params.rs:164 :: ... .resolve(...)      <- source
...
[n-2] src/capability/executor/mod.rs:446   :: self.attach_request_body(...)
[n-1] src/capability/executor/mod.rs:94    :: request: reqwest::RequestBuilder
[n]   src/capability/executor/mod.rs:104   :: request               <- sink
```

At `2822323`, `mod.rs:104` is `return match request.send().await {`. **The sink is the
outbound HTTP send, and no logging macro appears anywhere in the flow.** The contrast is
inside this same analysis: #100 and its two neighbours in `executor_tests.rs` each terminate
in a `MacroExpr` step, because those really are macro writes. This one does not.

So what the flow states is that a resolved credential reaches the request that is sent to the
backend — which is what a capability executor is for. Under the `cleartext-logging` rule that
is a sink misclassification. The transmission question the flow actually raises is the one
`rust/cleartext-transmission` asks, and it is already tracked as #90/#91 against
`require_secure_oauth_target` (`docs/release/verify/codeql-triage.md`).

### What was fixed

Treating the alert as a lead rather than a fact, the sweep it points at is every place a
`reqwest::Error` — which renders `" for url (...)"` verbatim — becomes a string in
`src/capability/executor/`. Guarded before this change:

- `src/capability/executor/mod.rs:131,143` — both `Err` arms of `send_with_retry`, via
  `redact_url` (`mod.rs:107`). This function did not exist at `2822323`; the raw-error arm the
  alert was raised against is already gone from this branch.
- `src/capability/executor/params.rs:51` — `status_error`, via `reqwest::Error::without_url`.

Unguarded, and now fixed:

- `src/capability/executor/credentials.rs:214-222` — the OAuth refresh-token grant. This POST
  carries `refresh_token` and, when the keychain holds one, `client_secret`. Its failure
  message embedded the operator-configured token endpoint **twice**: once verbatim, and once
  more inside the `reqwest::Error`. Observed before the fix:

  ```
  Configuration error: OAuth refresh request to 'http://127.0.0.1:1/token?api_key=CANARY'
  failed: error sending request for url (http://127.0.0.1:1/token?api_key=CANARY)
  ```

  The verbatim copy now goes through `security::sanitize::redact_url_for_diagnostics`, which
  keeps scheme, host and port; the error copy goes through `redact_url`.
- `src/capability/executor/credentials.rs:231-234` — the response-parse arm of the same call,
  same treatment. Not separately tested: reaching it needs a server that answers the refresh
  with an unparseable body, and the transport arm pins the guard.

Test: `an_oauth_refresh_transport_error_drops_the_endpoint_credential`
(`src/capability/executor_tests.rs`). Written first; it failed on the message quoted above,
and passes on the guard. It also asserts the host survives, so a redaction that blinds the
operator turns it red.

`perform_token_refresh` widened from private to `pub(super)` to be callable from the test.
That matches every other method on the same `impl` in that file, which are all `pub(super)`;
it was the outlier, and the widening does not leave `capability::executor`.

### Why #78 stays open

The alert names a sink this change does not touch, because the sink is `send()` and sending
the credential to the backend is the function. Nothing here will close it, and it is not
dismissed: the dismissal reasons on offer (`false positive`, `won't fix`, `used in tests`) all
overclaim. `false positive` would assert the flow is not real — it is real, and it is the
transmission question #90/#91 owns. The alert is a lead that was worth following and it found
a genuine defect one module over; it is not itself a finding this lane can settle.

**Escalation**: this contradicts the operator ruling of 2026-09-08, which directed that #78 be
fixed. Recorded here rather than rounded to a verdict, per the lane brief.

## PR #550 — the 132 branch alerts — DISMISSED (test code)

The `CodeQL` check on PR #550 reported *132 new alerts including 117 critical severity
security vulnerabilities*, which was the last red check on the v4 release line. The alerts
live on `refs/pull/550/head`; `main` carried none. Two rules account for all of them:
`rust/hard-coded-cryptographic-value` (117) and `rust/cleartext-logging` (15).

They are not 132 findings. They are twelve test files, flagged because the reconcile diff is
large enough that CodeQL attributed the whole test corpus to the pull request — the check
summary says so itself: *"Alerts not introduced by this pull request might have been detected
because the code changes were too large."*

**Deciding location per file.** Each `src/` file is reachable only beneath a `#[cfg(test)]`
declaration, so it never compiles into a non-test build. Nine are `#[path]` modules carrying
the attribute directly; three — `signing_joint/cases.rs`, `signing_joint/policy.rs` and
`tests/modern_startup.rs` — are ordinary child modules whose gate sits on an ancestor, and the
table below gives the full chain for each. Every `tests/` file is an integration-test target,
compiled only by `cargo test` and never linked into the shipped binary or library. Line
numbers as of `3e872f40`.

| Alerts | File | Deciding location |
|---|---|---|
| 63 | `src/security/message_signing_nonce_tests.rs` | `src/security/message_signing.rs:468` — `#[cfg(test)]` |
| 32 | `src/security/message_signing_nonce_metrics_tests.rs` | `src/security/message_signing.rs:769` — `#[cfg(all(test, feature = "metrics"))]` |
| 8 | `tests/message_signing_stdio_reload.rs` | integration-test target |
| 7 | `src/gateway/router/tests/task_execution_adapter/signing_joint/cases.rs` | `src/gateway/router/mod.rs:48` — `#[cfg(test)] mod tests`, reached via `tests.rs:39` → `task_execution_adapter.rs:71` → `signing_joint.rs:294` |
| 6 | `src/config/account_custody_tests.rs` | `src/config/mod.rs:2286` — `#[cfg(test)]` |
| 5 | `tests/openwebui_adapter_config.rs` | integration-test target |
| 4 | `tests/message_signing_nonce_metrics_export.rs` | integration-test target |
| 3 | `src/gateway/router/tests/task_execution_adapter/signing_joint/policy.rs` | same chain as `cases.rs`, declared at `signing_joint.rs:296` |
| 1 | `src/gateway/meta_mcp/authz_tests.rs` | `src/gateway/meta_mcp/mod.rs:2284` — `#[cfg(test)]` |
| 1 | `src/config_reload/account_reload_guard_tests.rs` | `src/config_reload/mod.rs:362` — `#[cfg(test)]` |
| 1 | `src/transport/http/tests/modern_startup.rs` | `src/transport/http/mod.rs:1901` — `#[cfg(test)] mod tests`, declared at `src/transport/http/tests.rs:10` |
| 1 | `src/personal_accounts/config_tests.rs` | `src/personal_accounts/config.rs:830` — `#[cfg(test)]` |

**Disposal**: all 132 dismissed, reason `used in tests`. Each dismissal comment carries its own
deciding `file:line` from the table above, so a reader who disagrees can check one line rather
than re-derive the module chain. This follows the same reasoning recorded for #97 and #100
below: they are false positives *as security findings*, and the reason is in every case that
the code is test-only, which is what `used in tests` records.

**Not** taken: a `paths-ignore` entry. The repository runs CodeQL **default setup**
(`gh api repos/MikkoParkkola/mcp-gateway/code-scanning/default-setup` → `state: configured`,
`query_suite: default`), which has no in-repo configuration file to add one to. Converting to
advanced setup to suppress test paths wholesale would also hide a future finding in test code
that is worth seeing.

**Result**: check run
[104192013465](https://github.com/MikkoParkkola/mcp-gateway/runs/104192013465) (check suite
94533203709) recomputed on its own — no re-run needed — from *"132 new alerts including 117
critical severity security vulnerabilities"* to *"No new alerts in code changed by this pull
request"*, observed 2026-09-15T06:00Z. The PR rollup at that moment was 46 `SUCCESS` /
3 `SKIPPED` / 0 failures, `mergeable: MERGEABLE`.

The 132 alert ids, rules and locations are listed in
[`codeql-550-alert-manifest.md`](codeql-550-alert-manifest.md), so each dismissal can be
checked against its own alert rather than against this summary.
