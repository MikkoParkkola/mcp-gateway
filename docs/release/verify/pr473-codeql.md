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
