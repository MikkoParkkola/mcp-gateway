# mcp-gateway open backlog — triage against 4.0.0

88 issues in the Linear project are not closed. Read as a plan, that is not a
plan; it is a transcript. This document sorts every one of them into a
disposition and states which can still land in 4.0.0.

## The shape of the problem

The queue grows faster than it drains. Filing costs one line and a human's
attention forever, and roughly a third of these were filed as *notes* — an
adoption candidate, a competitor read, a research idea — in a tracker whose
only exit is someone doing engineering work. Working all 88 is not the way to
have no open follow-ups. Closing what was never going to be worked, and
shipping what is, is.

Three dispositions, and every open issue gets exactly one.

## A. In 4.0.0 already — waiting on the merge, not on work

These are the requirement sources for the release branch. Implementation is
complete, the suite is green, and four findings remain open behind a switch
that defaults off.

| issue | what it asked for |
|---|---|
| MIK-7272 | the release itself: two revisions behind, per-connection list endpoints banned |
| MIK-7217 | `server/discover` on every transport |
| MIK-7215 | inventory every session-keyed behaviour before removing sessions |
| MIK-7214 | `Mcp-Method` / `Mcp-Name` header contract |
| MIK-7213 | `cacheScope` on a per-connection `tools/list` leaks across tenants |
| MIK-7212 | MRTR continuation contract |
| MIK-7116 | data minimisation, session-scoped cross-tenant guard |

They move to Done when the branch merges, not before. An issue closed against
an unmerged branch is a false green.

## B. Can still land in 4.0.0 — same files, same release train

Small, mostly security and configuration hardening, in code the release branch
already touches. Shipping them separately costs a second review cycle for no
benefit.

| issue | P | why it rides along |
|---|---|---|
| MIK-7258 | P1 | empty HS256 secret makes JWTs forgeable — a startup refusal |
| MIK-7257 | P1 | dashboard locality proven from a caller-controlled header |
| MIK-7254 | P1 | reload can enter the network posture startup refuses (already In Review) |
| MIK-7252 | P1 | playbook steps run without the caller identity |
| MIK-7251 | P1 | sampling and elicitation broadcast to every session |
| MIK-7265 | P2 | the deployed build predates its own DNS-rebinding guard — the release *is* the fix |
| MIK-7249 | P2 | enabling auth by reload reports success and does not apply |
| MIK-7256 | P2 | a failed reload has already applied the config's `env_files` |
| MIK-7244 | P2 | refuse to start on a non-loopback bind with auth disabled |
| MIK-7221 | P2 | rescue the unmerged secret-redaction fixes |
| MIK-7222 | P2 | sweep the credential-disclosure class across every transport |
| MIK-7268 | P3 | `/health` reports healthy before the capability backend has loaded |
| MIK-7255 | P3 | a restart-only edit can invite a bounce into the startup refusal |
| MIK-7246 | P3 | destructive-confirmation gate fails open |
| MIK-7245 | P3 | write config files `0600` |
| MIK-7263 | P3 | callback-registration admin denial returned as a configuration error |
| MIK-7262 | P3 | an explicit `registers_external_callback` declaration is ignored in three shapes |
| MIK-7291 | — | `SessionLifecycle` is unreached on the 2026 path: wire it (ruled 2026-09-08) |

Eighteen issues; MIK-7291 was filed off this branch and is not in the project
filter. Five are P1 and every one of those is an authentication or
authorisation hole. They belong in the same release as a protocol rewrite
because they live in the same request path.

**Decided 2026-08-29: eighteen go into 4.0.0.** The release does not merge
until they land. Two were proposed for the cut, MIK-7268 and MIK-7291, and neither ticket
was cut in the end — one was put back whole and one was narrowed:
MIK-7268 stays, because a `/health` endpoint reporting ready before the
capability backend has loaded is what a deployment's own rollout gate reads —
a wrong answer there routes traffic at a gateway that cannot serve it, which
is an availability defect rather than polish. MIK-7291 is the narrowed one: it rides along as a
deletion only; wiring `SessionLifecycle` on a path that removes sessions would
be new work. **That deletion clause was withdrawn on 2026-09-08**
(`docs/release/2026-09-08-team-lead-rulings.md` §R3, ruling `8bbca3eb`): the
2026-08-29 narrowing binds the *ticket*, not the `CONTROL.4` criterion. "Dead
code" described the code's state — nothing calls `register`/`track`/`reap` —
and said nothing about whether the requirement is dead. The requirement is live
precisely because the 2026 transport removed the disconnect event that used to
trigger the cleanup: state reclaimed on disconnect is now reclaimed by nothing,
so deleting the mechanism would leave a blocking criterion unmet and remove the
evidence that anyone noticed. MIK-7291 now closes when `CONTROL.4` wires it, on
the 2026-09-07 terms that still stand — a maintenance-tick reaper, with the TTL
carried as a defensible default stated as an assumption rather than as a
settled operator decision. Nothing exploitable ships, and the hardening set is not split
across two releases where the reload-config family would be worked twice. They
are sequenced by shared code path, not by priority, so each batch is one design
and one review rather than twenty:

| batch | issues | shared surface |
|---|---|---|
| 1 — config reload | MIK-7254, 7256, 7255, 7249 | the reload path's posture and env-file handling |
| 2 — startup refusals | MIK-7258, 7244, 7245 | what the process refuses to start with, and file modes |
| 3 — caller identity | MIK-7252, 7251, 7257 | who the request is for, and how that is proven |
| 4 — callback registration | MIK-7263, 7262 | the `registers_external_callback` declaration |
| 5 — secret redaction | MIK-7221, 7222 | the credential-disclosure class across transports |
| 6 — loose ends | MIK-7268, 7246, 7291, 7265 | health readiness, the destructive gate, session-lifecycle wiring, the build |

## C. 4.1 — real product work, weeks not hours

Not deferrable by cleverness; each is a feature with its own design.

| theme | issues |
|---|---|
| end-user identity to backends | MIK-6704 (P0), MIK-6729 (P0), MIK-6207, MIK-6209 |
| per-user OAuth | MIK-6744, MIK-6745, MIK-6746 |
| audit and SIEM export | MIK-6726 (P0), MIK-6727 (P0), MIK-6710 (P0) |
| Kubernetes operator GA | MIK-6672, MIK-6680, MIK-6681, MIK-6682, MIK-6683, MIK-6684 |
| control-plane durability | MIK-6692 |
| tool surface | MIK-7084 (tiered disclosure), MIK-6865 (schema hardening), MIK-3051 (mutation-test the capability schemas) |
| deferred from 4.0.0 | MIK-7243 (admin credential through the setup wizard) |
| egress and firewall | MIK-6273, MIK-5465 |

Twenty-three issues. MIK-7243 is here because MIK-7244 — refusing to start on
a non-loopback bind with authentication disabled — closes the hole on its own,
and provisioning a credential through the wizard is interface work with its own
design. MIK-7250 leaves the release entirely: the 2026 path removes sessions,
so self-asserted session ids are re-verified against that path and then closed
or refiled, which is a verification rather than a change. The five P0s are the
4.1 spine; the Kubernetes block is a
single epic wearing six hats and should be re-parented as one.

## D. Close — a tracker is the wrong home for these

Research notes, competitive reads, adoption candidates and audits with no owner
and no trigger. Each was worth *writing*; none is worth *queueing*.

| kind | issues |
|---|---|
| competitive and positioning | MIK-6977, MIK-5843, MIK-6934, MIK-6933, MIK-7236, MIK-3031 |
| adopt / inspire candidates | MIK-6956, MIK-6923, MIK-6915, MIK-6912, MIK-6904, MIK-6907, MIK-3274, MIK-3233, MIK-3023, MIK-3033, MIK-3055, MIK-3127, MIK-2935 |
| audits and research with no trigger | MIK-6755, MIK-7004, MIK-7247, MIK-7235, MIK-7218, MIK-3444, MIK-3310, MIK-3293, MIK-6573 |
| tooling, not this product | MIK-7158, MIK-7145, MIK-6898, MIK-7141, MIK-5277, MIK-3145, MIK-6158, MIK-2950 |
| accepted rough edges and watchdogs | MIK-7047, MIK-7042, MIK-7187 |
| superseded by this release | MIK-2982 (annotations for 2025-11-25, two revisions behind 4.0.0's target) |

Forty issues. Closing them is not losing them: the durable ones become
observations, and an observation nobody must act on is exactly what the
disposal table in the development process says a note is for. What it must not
be is a row in a queue with no estimate, no parent and no order.

## Arithmetic

88 open in the project, plus MIK-7291 filed off the release branch. 7 in the
release, 18 riding along, 23 for 4.1, 1 verified and closed (MIK-7250), 40
closed — 89. Every open issue has a disposition; none is left to age.

## E. The GitHub tracker, which the sections above did not read

Sections A to D sort the Linear project. The repository has its own issues and
pull requests, and no earlier revision of this document referenced one. Nine
issues and ten pull requests were open on 2026-08-29; each now carries its
disposition as a comment on the issue itself, so the tracker and this document
do not have to be read together.

| issue | disposition |
|---|---|
| 463, 462, 453 | 4.0.0 batch 1 — the reload path, alongside MIK-7256 |
| 452, 451 | 4.0.0 batch 3 — session ownership on terminate, sampling and elicitation. 451 is MIK-7251's defect reported independently |
| 440 | 4.0.0 batch 6 — `surfaced_tools` is parsed and then ignored |
| 437 | 4.0.0 batch 2 — and a constraint on MIK-7245, below |
| 449 | 4.1 — it is MIK-7084 |
| 119 | post-release — directory submissions describe a protocol revision, so they follow the release rather than precede it |

**437 changes what MIK-7245 has to do.** MIK-7245 asks for configuration files
written `0600`. Issue 437 reports a running gateway restart-looping because a
`0600` file owned by one user was mounted for a container running as another,
with an error that named nothing useful. Shipping the file mode without a
readability check would make that report the expected behaviour. The two are
one change: the mode, plus a startup check that names the path, the mode and
the effective user when the file cannot be read.

Ten pull requests were open, all rebased onto current `main` and set to merge
when their checks pass. Eight are dependency bumps. Their checks had failed
against a five-day-old base — one advisory, RUSTSEC-2026-0258 in `h2`, which
current `main` already carries a fixed version of — so the red was stale rather
than a finding. The remaining two are 439, which reports backend names and
counts instead of configured values and belongs to the same credential-
disclosure class as MIK-7221 and MIK-7222, and 438, this release's own
dual-generation design note.

### Currency re-check — 2026-09-11

The table above is the state on 2026-08-29. Three of its rows have since resolved, and eight
issues have been filed that it could not have covered.

**Resolved since.** Issue **437** closed COMPLETED on 2026-09-04, so the `0600` readability check
it constrained is no longer a pending constraint on MIK-7245 — the mode change and the startup
check landed together as that disposition required. PRs **439** and **438** are both merged. Of the
ten pull requests open on 2026-08-29, none remains open: the eight dependency bumps merged once
their bases were current, which is what the stale-red diagnosis predicted.

**Open pull requests are now 14, all drafts** — the 13 held `codex/v4-*` branches, each carrying its
held disposition as a comment, plus #528, this release's own branch.

**Filed since, with no disposition in the table above.**

| issue | filed | disposition |
|---|---|---|
| 475 | 2026-09-04 | **In 4.0.0.** Fully represented in the criteria ledger as 50 `GH475.*` rows; the issue stays open until the release ships rather than because work is outstanding |
| 481 | 2026-09-05 | **Needs a scope decision.** The body asserts "blocking 4.0.0", and the criteria ledger carries no `GH481.*` row — so nothing in the release's own accounting blocks on it. The ledger is the authority on what blocks, and it records exactly one blocking criterion (NFR.SEC.7). Either the issue's claim is stale or a criterion is missing; that is a decision, not a defect, and it is recorded here rather than resolved silently |
| 482 | 2026-09-05 | **Explicitly deferred, and already documented.** The over-broad `is_rate_limited` substring match is stated as a known boundary in `docs/UPGRADING-4.0.md` §4: narrowing it needs a rate-limit co-signal and is not in 4.0.0. Narrowing it would move `GH475.RL.6`, an agreed acceptance criterion |
| 523 | 2026-09-11 | **Post-release.** POSIX `shlex::split` mangles Windows backslash paths in stdio `command` strings. Filed in the course of #522 and fixed by #527 |
| 524 | 2026-09-11 | **Post-release.** Windows CI compiles and never runs a test (`ci.yml:182-189`). A gap in the gate, not in 4.0.0 behaviour |
| 525 | 2026-09-11 | **Post-release.** The Windows arm of the stdio environment allowlist has no test; the only test over that function is `#[cfg(unix)]` |
| 526 | 2026-09-11 | **Post-release.** A stdio child that dies before `initialize` reports a request timeout while the cause sits unread in its stderr |
| 527 | 2026-09-11 | **Post-release.** One parser for a configured stdio command, used by spawn and doctor alike. Fixes 523 |

None of 481, 482 or 523–527 carries a criterion row in the release ledger, so none of them is in
4.0.0 scope by the release's own accounting. The five Windows issues are one cluster from a single
investigation and are best sequenced together after the release, with 524 first — a gate that never
runs a test is what let the other four stay invisible.
