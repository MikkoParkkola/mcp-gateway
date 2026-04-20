## What this PR does



## Why

<!-- Linked issue and short problem statement -->

## How to test

```bash
cargo fmt --all && cargo clippy --all-features -- -D warnings && cargo test --all-features
```

## Checklist

Required:

- [ ] Tests for new behavior, not just regression
- [ ] `cargo fmt` and `cargo clippy -- -D warnings` clean on my branch
- [ ] CI passes on Linux (Windows flakes labelled `flaky-ci` are fine)
- [ ] Threat-model note below if this touches auth, OAuth, URL handling, path handling, secrets, deserialization of untrusted input

Encouraged:

- [ ] CHANGELOG entry under `[Unreleased]`
- [ ] PR description explains the problem, the shape of the fix, anything I am unsure about
- [ ] Config struct instead of 5+ positional arguments
- [ ] Doc comments on any user-facing config field

## Threat-model note (only for security-sensitive changes)

<!--
What inputs come from untrusted sources? What validation do you run? What did you choose not to validate and why? Leave blank if not applicable.
-->

## First time contributing?

Mention that in the description. We are happy to have you. See `CONTRIBUTING.md` for the full checklist.
