# PR #473 — CodeQL triage

Check run `101939020717` reports *5 new alerts, 5 high severity*. The check's
own summary carries the caveat that matters: "Alerts not introduced by this
pull request might have been detected because the code changes were too
large." Taking the headline at face value would have put three pre-existing
main-branch alerts on this branch's account.

## Which alerts are actually this branch's

`most_recent_instance.ref` separates them, and it disagrees with the headline.

| alert | rule | location | ref | this branch? |
|---|---|---|---|---|
| 78 | `rust/cleartext-logging` | `src/capability/executor/mod.rs:122` | `refs/heads/main` | no |
| 90 | `rust/cleartext-transmission` | `src/transport/http/mod.rs:933` | `refs/heads/main` | no |
| 91 | `rust/cleartext-transmission` | `src/transport/http/mod.rs:1126` | `refs/heads/main` | no |
| 98 | `rust/path-injection` | `src/config_persistence.rs:40` | `refs/pull/473/head` | yes |
| 99 | `rust/cleartext-transmission` | `src/transport/http/mod.rs:1265` | `refs/pull/473/head` | yes |

78, 90 and 91 are open on `main`, created 2026-08-28/29, and reproduce there
unchanged. They belong to the standing 28-alert backlog, not to this PR. 98
and 99 were created 2026-09-07 against `refs/pull/473/head`.

So the actionable set is two, not five.

## 98 — `rust/path-injection`, `config_persistence.rs:40`

`load_existing_or_default` opens the path it is handed. Both callers are CLI
subcommands — `src/commands/setup.rs:42,86` and `src/commands/add_remove.rs:72`
— and the path is the operator's own `--config` / `--output` argument.

The "user-provided value" CodeQL traces is the argument the operator typed
into their own shell. No privilege boundary is crossed: the process already
runs with that operator's file permissions, so a path they can name is a file
they can already read and write without the gateway's help. Constraining the
path would remove a documented capability and defend nothing.

Assessment: false positive. Dismissal is an operator decision and is not taken
here.

## 99 — `rust/cleartext-transmission`, `http/mod.rs:1265`

The notification send in `send_notification`. New to this branch only because
the surrounding path is new (`finalise_modern_headers` shapes the headers for
the modern era before the POST). The finding itself is the same class as the
main-branch pair 90 and 91: a backend URL configured as `http://` carries
whatever the header builder produced, credentials included.

This is one more call site under an existing posture, not a new exposure
class. It therefore belongs to the same decision as 90 and 91 — the plain-http
credential question already open with the operator — and should not be
dismissed or fixed separately, which would leave three sites answered two
different ways.

## What this leaves

CodeQL is the only non-green check on #473; every other check is SUCCESS,
NEUTRAL or SKIPPED. Both remaining alerts want an operator decision rather
than a code change, and one of them folds into a decision already pending.

---

# PR #473 — CodeQL retriage, check run `102909138871` (2026-09-10)

The section above records check run `101939020717`. That run is superseded.
The current failing run on head `482746c1` is `102909138871`, summary "5 new
alerts including 4 critical severity security vulnerabilities", and it is an
entirely different rule family — hard-coded cryptographic value and weak
sensitive-data hashing. It carries the same caveat as its predecessor:
"Alerts not introduced by this pull request might have been detected because
the code changes were too large."

**Verdict: no stop-the-line item. Zero of the three library hits is real.**
Three of the five are inherited from `origin/main` and untouched by this PR;
the remaining two are in a test target. No code change is warranted and none
was made.

## The alerts have no alert numbers

The `most_recent_instance.ref` separation used for run `101939020717` is not
available here. `code-scanning/alerts?state=open` returns exactly one alert
repo-wide (#101), and `?ref=refs/pull/473/merge` returns empty; the analyses
listing for that ref is empty too. These five exist only as check-run
annotations, which carry no alert number and no `ref` field:

```
gh api repos/MikkoParkkola/mcp-gateway/check-runs/102909138871/annotations
```

So provenance was established directly from git instead — comparing each
flagged line against `origin/main` and against this PR's own diff. That is a
stronger test than the `ref` field, not a weaker substitute: it shows not just
which branch CodeQL attributed a line to, but whether this PR ever touched it.
Merge base used throughout: `37ddab1e915f1713ba07b7c96051bfa676c58511`. Line
numbers are on the merge commit `748564c7d4ccb225d74ef43939921fb71d1930ab`.

## Which alerts are actually this branch's

| annotation | rule | severity | location | provenance | verdict |
|---|---|---|---|---|---|
| 1 | `rust/hardcoded-cryptographic-value` | critical | `src/config/mod.rs:275` | `origin/main` | inbound — not this branch's |
| 2 | `rust/hardcoded-cryptographic-value` | critical | `src/config/mod.rs:283` | `origin/main` | inbound — not this branch's |
| 3 | `rust/weak-sensitive-data-hashing` | high | `src/gateway/meta_mcp/support.rs:407` | `origin/main` (already alert #101) | inbound — not this branch's |
| 4 | `rust/hardcoded-cryptographic-value` | critical | `src/gateway/webhooks/tests.rs:471` | `refs/pull/473/head` | false positive — test target |
| 5 | `rust/hardcoded-cryptographic-value` | critical | `src/gateway/webhooks/tests.rs:508` | `refs/pull/473/head` | false positive — test target |

Same shape as last time: the headline says five, the branch owns two, and both
of those are tests.

## 1, 2 — `rust/hardcoded-cryptographic-value`, `config/mod.rs:275,283`

Not cryptographic values. The flagged spans are filesystem path literals in
`Config::fallback_config_path()`:

```rust
let p = home.join(".config/mcp-gateway/gateway.yaml");      // :275
let system = PathBuf::from("/etc/mcp-gateway/gateway.yaml"); // :283
```

Each is `.exists()`-checked and returned as a `PathBuf`. Neither reaches a key,
a cipher, or a MAC.

Inbound: `git show origin/main:src/config/mod.rs` carries both verbatim at
`:155` and `:163`, inside the same `fallback_config_path()` at `:143`. The PR
never touches them —
`git diff 37ddab1e..HEAD -- src/config/mod.rs | rg 'gateway.yaml|fallback_config_path'`
returns nothing. They surfaced only because the file drifted `+806/-78`, which
is precisely the condition the check's caveat names.

False on the merits as well, and this was tested rather than assumed. A
dataflow rule reports at the source literal but lands at a sink, so a new sink
added by this PR would make an old literal a genuinely new alert. There is no
such sink: `rg -i 'new_from_slice|Hmac|Sha256|Aes|cipher|signing_key|Key::|nonce|encrypt' src/config/mod.rs`
returns one hit, a doc comment at `:743`; the same pattern over this PR's diff
of the file returns nothing. No crypto sink exists in `src/config/mod.rs` at
all, so nothing can flow into one.

Assessment: inbound from main, and a false positive on its own terms. No fix.

## 3 — `rust/weak-sensitive-data-hashing`, `meta_mcp/support.rs:407`

The rule's three questions, answered directly.

*What algorithm?* SHA-256, via `Sha256::digest`, truncated to the first eight
bytes and hex-encoded: `format!("sha256:{}", hex::encode(&digest[..8]))`.

*On what value?* The `name` parameter of `fn auth_context_ref_hash(name: &str)`.
At the call site (`origin/main:272`) that argument is `api_key_name` — the
label a config file assigns to a credential entry, not the credential.

*Is it sensitive by the rule's definition?* No. The rule fires on passwords
and equivalent secrets, where the objection is that a fast hash is cheap to
brute-force. `api_key_name` is a config-chosen identifier with no secret to
recover; CodeQL classifies it as a password heuristically, from the identifier
text. The hash exists so the receipt contract stores a *reference* rather than
a raw identifier, keeping the name itself out of the `_meta` channel
(CWE-532). Truncating to eight bytes is consistent with that purpose — this is
a correlation token, not a credential digest.

Inbound: verbatim on `origin/main` at `:238-241`, with the same caller at
`:272`, and already tracked as open repo alert **#101** at `support.rs:240` on
`refs/heads/main`. The SARIF for analysis `1755392037` confirms containment —
the result's related locations are `support.rs:438` only, so the flow never
leaves this one unchanged function.

Assessment: inbound from main, duplicate of #101, and a false positive. No fix.
If the operator wants the heuristic silenced at the source, the honest change
is renaming the parameter away from credential-shaped wording — cosmetic, and
it belongs to main, not to this PR.

## 4, 5 — `rust/hardcoded-cryptographic-value`, `webhooks/tests.rs:471,508`

The only two genuinely new hits. `git show origin/main:src/gateway/webhooks/tests.rs | rg new_from_slice`
returns nothing and the PR's diff of that file is `+64/-0`, so both literals
arrive with this branch.

Both sit in tests that pin a hardening this PR *adds*:

- `:471`, in `webhook_handler_rejects_a_secret_that_resolves_to_nothing()`:
  `hmac::Hmac::<Sha256>::new_from_slice(b"")` forges a signature with a
  deliberately empty key, and the test asserts
  `assert_eq!(response.status(), StatusCode::UNAUTHORIZED)`. The literal is the
  attack input, not a credential.
- `:508`, in `webhook_handler_accepts_a_secret_an_env_file_assigns()`:
  `new_from_slice(b"well-known-test-value")` mirrors the tempdir `.env` written
  three lines earlier,
  `std::fs::write(&env_file, "MIK_7256_OVERLAY_SECRET=well-known-test-value\n")`.
  A throwaway fixture, created and destroyed inside the test.

The production guard they exist to pin is real, at `src/gateway/webhooks/mod.rs:456`:

```rust
if secret.is_empty() {
    return Err("Configured secret resolved to an empty value".to_string());
}
```

with the in-comment rationale that an empty HMAC key is computable by anyone,
so a signature check that cannot be failed is worse than no signature check
because it reports success. The production HMAC follows at `:470`. The PR
hardens webhook authentication; CodeQL simply has no test-module exclusion for
this rule in Rust.

This is the same "flagged the proof as the leak" shape already dispositioned
for #92 and #97. The tests ship in no release artifact.

Assessment: false positives. Deliberately **not** fixed — hoisting the literals
into constants would obscure what the tests demonstrate without removing them
from CodeQL's view. Dismissal is an operator decision and is not taken here.

## What this leaves

Nothing to fix and nothing proposed. Three alerts are inherited from main and
will not clear through this PR; two are test-fixture false positives that need
an operator dismissal. Until that dismissal, CodeQL stays red on #473.

No file in the working tree was modified by this triage beyond this document.
`cargo check --workspace` was not run and is N/A: the changeset is empty, so the
result would measure other in-flight work rather than anything recorded here.
