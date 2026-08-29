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
| MIK-7250 | P3 | session ids are self-asserted — the 2026 path removes sessions; re-verify, then close or fix |
| MIK-7246 | P3 | destructive-confirmation gate fails open |
| MIK-7245 | P3 | write config files `0600` |
| MIK-7263 | P3 | callback-registration admin denial returned as a configuration error |
| MIK-7262 | P3 | an explicit `registers_external_callback` declaration is ignored in three shapes |
| MIK-7243 | P2 | provision an admin credential through the setup wizard — the other half of MIK-7244 |
| MIK-7291 | — | `SessionLifecycle` is dead code on the 2026 path: wire it or delete it |

Twenty issues; MIK-7291 was filed off this branch and is not in the project
filter. Five are P1 and every one of those is an authentication or
authorisation hole. They belong in the same release as a protocol rewrite
because they live in the same request path.

**Decided 2026-08-29: all twenty go into 4.0.0.** The release does not merge
until they land. Nothing exploitable ships, and the hardening set is not split
across two releases where the reload-config family would be worked twice. They
are sequenced by shared code path, not by priority, so each batch is one design
and one review rather than twenty:

| batch | issues | shared surface |
|---|---|---|
| 1 — config reload | MIK-7254, 7256, 7255, 7249 | the reload path's posture and env-file handling |
| 2 — startup refusals | MIK-7258, 7244, 7243, 7245 | what the process refuses to start with, and file modes |
| 3 — caller identity | MIK-7252, 7251, 7257, 7250 | who the request is for, and how that is proven |
| 4 — callback registration | MIK-7263, 7262 | the `registers_external_callback` declaration |
| 5 — secret redaction | MIK-7221, 7222 | the credential-disclosure class across transports |
| 6 — loose ends | MIK-7268, 7246, 7291, 7265 | health readiness, the destructive gate, dead code, the build |

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
| egress and firewall | MIK-6273, MIK-5465 |

Twenty-two issues. The five P0s are the 4.1 spine; the Kubernetes block is a
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
release, 20 riding along, 22 for 4.1, 40 closed — 89. Every open issue has a
disposition; none is left to age.
