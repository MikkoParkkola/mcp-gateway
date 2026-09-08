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
