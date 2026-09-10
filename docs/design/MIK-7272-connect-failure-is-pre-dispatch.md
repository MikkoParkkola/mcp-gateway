# Design: a connect failure is provably pre-dispatch

Amends the ADR-012 settlement design for `MIK-7272.SUB.4`. Closes the red row
`pre_dispatch_failure_releases_its_key`
(`tests/mik_7272_sub4_adr012_acs.rs:481`). The test binds an ephemeral TCP port,
drops it, and calls the dead address twice; both attempts must return 500. Today
the second returns 200, because the first was settled as a terminal cached error
and the retry was served that stored terminal instead of being dispatched.

## Why the test oracle is right and the mechanism is missing

`Error::Transport` is too coarse. It carries both "could not connect" — zero
bytes ever left the gateway — and "the stream died after the request was
written", where the backend may already have acted. ADR-012 consequence 1
settles the second as terminal precisely because it is indistinguishable from
the first *at that variant*. It is not indistinguishable at the source.

The distinction already exists in the codebase and is discarded.
`request_error_category` (`src/security/http_diagnostics.rs:19-31`) branches on
`reqwest::Error::is_connect()` and renders it as the string `"connection
failed"`, which `safe_request_error` (`:41-43`) then flattens into
`Error::Transport`. The classification is computed and thrown away.

## Change

1. New variant `Error::TransportConnect(String)`, constructed at exactly one
   site: a new `safe_request_error_for(context, error, no_redirect_followed)`
   in `src/security/http_diagnostics.rs`, which returns `TransportConnect` only
   when `error.is_connect()` AND the caller vouches that the request followed
   no redirect. Every other case returns `Error::Transport`, exactly as today.
   The evidence for that second argument is a redirect counter on the
   transport — see the false-positive section below.
2. `safe_request_error` keeps its current signature and its coarse
   `Error::Transport` result. It stays the default for the five other call
   sites — the SSE reads (`src/transport/http/mod.rs:1065,1087,1340`), the
   notification send (`:1419`) and the A2A client (`src/a2a/client.rs:112,213`).
   An SSE read failure is post-dispatch by construction: the stream only exists
   because the request was already written. Leaving those coarse is the
   fail-safe direction, not an omission.
3. The single fine-grained caller is the JSON-RPC dispatch site,
   `src/transport/http/mod.rs:1279`, which samples the redirect counter two
   lines above the `map_err` and again inside it.
4. `Error::is_pre_dispatch` admits `TransportConnect` — a fourth entry on the
   tight allowlist beside `CircuitOpen`, `BackendNotFound`, `ToolNotFound`.
5. `to_rpc_code` maps it to `-32000` alongside `Transport`, so the wire contract
   does not change. This is an internal classification, not a new caller-visible
   error.
6. Narrowing a variant is a behaviour change for everything that matched on it.
   Two classifiers read `Error::Transport` to mean "transient, try again" and
   both must admit the new variant or a connect failure silently stops being
   retryable: `is_retryable` (`src/chains/retry.rs:186`) and `is_readiness_error`
   (`src/gateway/server/warmstart.rs:105`). Every other `Error::Transport`
   occurrence in the tree is a construction site or a test, not a matcher.

This is the "signal narrower than the variant" that the residual-risk section on
`BackendUnavailable` said a future change would need. It does NOT widen
`BackendUnavailable`, and it does not admit a variant with eight construction
sites: `TransportConnect` has one, guarded by a predicate reqwest computes.

## The false positive this design must answer

`is_connect()` means the failure happened while establishing a connection. On a
single-hop request that proves nothing was written. On a REDIRECTED request it
does not: if the gateway POSTs to origin A, A answers 307, and the connection to
the redirect target then fails to establish, `is_connect()` is true for the
overall request while the body was already delivered to A once. A 307/308
re-submits the body, so the side effect may have executed.

The redirect policy (`src/transport/http/mod.rs:541`, `evaluate_redirect` at
`:127-144`) refuses cross-origin targets and caps hops at 5, so the target is
always the operator-configured origin — which makes a connect failure to it
unlikely, since the pooled connection to that origin just served the 307. It is
not impossible.

Fail-safe direction: here a wrong `true` licenses a retry that re-executes a
side effect, which is the expensive direction. Two options:

- **A.** Accept the redirect false positive as a bounded residual risk, on the
  same footing as the same-origin redirect risk already recorded for SUB.4.
- **B.** Make the signal exact: only treat a connect failure as pre-dispatch
  when the request performed no redirect hop, so a redirected request keeps
  today's terminal settlement.

Resolved: **B**, and A is withdrawn rather than kept as a fallback. Both
reviewers rated the A branch blocking — one CRITICAL, one HIGH — on the same
ground: a wrong `true` licenses a retry that re-executes a side effect, and
that is not a risk to accept when an exact signal is available.

### The discriminator: a redirect counter, not `reqwest::Error::url()`

A first revision of this design used `error.url() == request_url` as the
signal, on the stated premise that reqwest rewrites the error's URL to the hop
that actually failed. **That premise is false, and the mandatory redirect
acceptance test below is what falsified it** — it went red against the
implemented mechanism, and its redness was correct.

At source, in `reqwest-0.13.4/src/async_impl/client.rs`:

- `:3093` — the connect-error branch returns
  `Err(e.if_no_url(|| self.url.clone()))`. `if_no_url` only *back-fills* a
  missing URL, and `self.url` is still the URL the caller posted to.
- `:3110` — `self.url = ...`, the assignment that advances the URL to the next
  hop, reads `tower_http::follow_redirect::RequestUri` out of the **response**
  extensions. It is on the success path, after every error branch has already
  returned.

So after a followed redirect the error carries the *original* URL, and the
comparison is equal in both cases. Empirically, from the falsifier:
`posted-to=http://127.0.0.1:52046/mcp
error.url()=Some("http://127.0.0.1:52046/mcp")`. The mechanism would have
classified a redirected connect failure as pre-dispatch — precisely the unsafe
outcome option B exists to prevent.

The signal that does work is a hop counter the gateway owns:

- `HttpTransport` holds an `Arc<AtomicU64>`, captured by the redirect policy
  closure built in `new_with_oauth` (`src/transport/http/mod.rs:559`). The
  `RedirectDecision::Follow` arm increments it (`SeqCst`) before returning
  `attempt.follow()`, and reqwest runs that closure before it dials the next
  hop — so the increment strictly precedes any connect failure it must
  explain.
- The dispatch site samples the counter immediately before `send()` and again
  after the await; an unchanged count is the evidence passed to
  `safe_request_error_for`.
- The other two policy arms leak nothing: `attempt.stop()` surfaces the 3xx as
  an ordinary response, and `attempt.error()` produces `is_redirect()`, not
  `is_connect()`.

The counter is client-global rather than per-request, which reqwest's policy
API gives no way to avoid: the closure cannot see which request it is serving.
A concurrent request's hop therefore inflates another request's delta. That
error is one-directional — it can only turn a genuine pre-dispatch failure
into the coarse `Error::Transport`, i.e. today's terminal settlement, costing
a retry that was safe to allow. It can never license one.

The acceptance test for the redirect case is mandatory, not conditional on
which option was chosen: a redirected side-effecting call whose next hop fails
to connect must NOT be retried.

## Acceptance

- `pre_dispatch_failure_releases_its_key` — currently red, must go green.
- `a_post_dispatch_transport_failure_keeps_its_key` and
  `a_settled_dispatched_error_keeps_its_key` — currently green, must stay green.
  They are the negative controls: a post-write stream death must still settle.
- `an_explicitly_read_only_call_is_still_resent` and
  `session_expiry_does_not_resend_an_unannotated_call` — green, must stay green;
  this change must not perturb the resend-permission seam landing beside it.

## Review round: what changed and why

Two independent reviews. Both rated the Option A branch blocking on the same
ground, and both proposed the same mechanism; A is withdrawn above rather than
recorded as a residual risk. The findings and their disposition:

**Accepted — the redirect false positive.** Rated CRITICAL by one reviewer and
HIGH by the other. Fixed by an exact signal, not by documenting the risk. The
discriminator both the review and the first revision of this design settled on
— `Error::url()` — turned out not to carry that signal at all; the section
above records the source evidence and the test that caught it. The finding
stands; only its proposed mechanism was replaced.

**Accepted — the narrowed variant escapes the retry allowlist.** Rated
MEDIUM/CERTAIN. Correct in substance: a variant split out of `Error::Transport`
stops matching everything that matched `Transport`, and `is_retryable` treats
`Transport` as retryable. Without the fix, splitting the variant would have
stopped retrying the one transport failure that is provably safe to retry —
the exact inversion of this design's purpose.

An earlier revision of this record claimed the cited `src/failsafe/retry.rs:96`
did not exist. It does, and this change edits it; the claim came from a search
run before that file was re-read, and it is withdrawn. The complete matcher set,
all five updated here:

| Matcher | Site | What it decides |
| --- | --- | --- |
| `is_retryable` | `src/chains/retry.rs:186` | whether the chain retries |
| `is_retryable` | `src/failsafe/retry.rs:96` | whether the failsafe retries |
| `is_readiness_error` | `src/gateway/server/warmstart.rs:105` | whether warm-start keeps waiting |
| `classify_dispatch_error` | `src/gateway/meta_mcp/invoke.rs:3427` | the dispatch outcome class |
| `to_rpc_code` | `src/error.rs` | the JSON-RPC code on the wire |

The two `is_retryable` copies are an identical rule maintained by hand, and
they have already diverged once. Deduplicating them is recorded as follow-up
rather than done here: it touches two modules that are not what this change is
for, and both reviewers rated it an improvement, not a defect.

`is_readiness_error` is the one the review missed, and it is the expensive
miss: a connect failure is the canonical "not up yet", so omitting it there
would have made warm-start give up on exactly the backend it exists to wait
for. A tree-wide search confirms every other `Error::Transport` occurrence is a
construction site or a test, not a matcher.

### Assumption: one connection attempt per dispatch

The counter proves no *redirect* hop was taken. It does not, by itself, rule
out a transport-level retry underneath reqwest -- an HTTP/2 protocol NACK can
make reqwest re-issue a request the gateway believes was attempted once. That
cannot arise in this build: `Cargo.toml:74` enables reqwest with
`default-features = false` and no `http2` or `http3` feature, so every dispatch
is HTTP/1.1 and single-attempt. If either feature is ever added, this proof
needs re-establishing before the variant stays on the `is_pre_dispatch`
allowlist.

**Accepted — make the redirect acceptance test mandatory.** It is
`a_connect_failure_after_a_redirect_is_not_pre_dispatch`, and it does not
depend on the A/B choice.

**Accepted — record the resolved decision.** This section is that record.

**Declined — assert a successful execution after making the backend available.**
The suggestion is a good test; it is a different one. The row asks whether a
retry was *admitted*, and a second 500 answers that: a served terminal is a 200
carrying the stored error, so the status code alone separates the two outcomes.
Adding a live success would make the row depend on backend startup timing to
answer a question about key settlement. Filed as a separate row rather than
folded into this one.

**Declined as out of scope — deployment environment.** The reviewer noted no
deployment scope is stated and that the review read source without running the
suite. Both true. This is a design for a code change inside one release
criterion; the environment is the release, and the executed results are the
acceptance suite recorded above, which runs in CI like every other row.

## Where the new tests live

Two levels, because the mechanism and the classifier are no longer the same
thing.

`src/transport/http/tests.rs` holds the load-bearing pair, built on a real
`HttpTransport` with its real redirect policy:

- `a_connect_failure_after_a_followed_redirect_is_not_pre_dispatch` — a
  one-shot server answers 307 to a same-origin path and closes its port before
  replying, so the followed hop is deterministically refused. It asserts both
  that the counter moved and that the failure was not released. This is the
  row that falsified the previous mechanism, and it is the only place the
  claim "the policy closure increments on every followed hop" is actually
  exercised.
- `an_unredirected_connect_failure_is_pre_dispatch_end_to_end` — the positive
  control. Without it, wiring the evidence bit to a constant `false` would
  leave the falsifier green.

The redirect target is `localhost` rather than `127.0.0.1` because
`evaluate_redirect` refuses a cross-origin hop and the SSRF guard refuses a
loopback IP literal; a same-origin name is the one shape a real deployment
would also present.

`src/security/http_diagnostics.rs` keeps cheap rows for the classifier itself —
`reqwest::Error` cannot be constructed by hand, so each makes a real one
against a dead port or an accept-but-never-answer server. They pin that
`is_connect()` alone never upgrades and that the evidence bit is honoured in
both directions. They are no longer coverage of the redirect case: they pass
the bit in by hand, so they cannot detect a counter that fails to increment.

## Handoff: two files this change does not commit

`src/transport/http/mod.rs` and `src/transport/http/tests.rs` carry SUB.4 hunks
that are **not** in the SUB.4 commit. Both files were being edited concurrently
for the resend-permission seam (`ResendPermission`, `resend_permission`), and
committing them here would have published that unrelated, separately-reviewed
work under this change's authorship. They land in the resend-permission commit
instead. The SUB.4 hunks to expect there:

| File | Hunk |
| --- | --- |
| `mod.rs` | the `redirects_followed: Arc<AtomicU64>` field on `HttpTransport` |
| `mod.rs` | the `RedirectDecision::Follow` arm incrementing it in `new_with_oauth` |
| `mod.rs` | the dispatch site sampling it either side of `send()` |
| `tests.rs` | `a_connect_failure_after_a_followed_redirect_is_not_pre_dispatch` |
| `tests.rs` | `an_unredirected_connect_failure_is_pre_dispatch_end_to_end` |

Consequence worth stating plainly: until that commit lands,
`safe_request_error_for` has no production caller, so `Error::TransportConnect`
is never constructed and the idempotency layer sees no behaviour change. The
mechanism is inert, not partially applied — the two halves are safe to land in
either order, and neither half alone can release a key it should not.
