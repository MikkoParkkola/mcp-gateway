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
