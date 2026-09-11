# Merged-versus-listening drift check (NFR.SEC.7, MIK-7265)

Status: design, not yet reviewed. Author: automation, 2026-09-11.

## 1. The gap this closes

`NFR.SEC.7` asks for two things, and the repository has neither:

1. the listening build carries every merged security control;
2. merged-versus-listening drift is detected automatically.

The second is the durable deliverable. The first is a fact about one install at
one moment, and today it is false in a way nothing in the repository can see: the
listening process (`~/.local/libexec/mcp-gateway/3.4.0-f30539af`, 127.0.0.1:39401)
answers `tools/list` with HTTP 200 and the full tool list to a foreign `Origin`
and to a foreign `Host`, sixteen days after the origin guard merged. The guard is
at `src/gateway/router/origin_guard.rs`, wired at `src/gateway/router/mod.rs:313`,
added by `5d25f104` on 2026-08-28; `git merge-base --is-ancestor 5d25f104 f30539af`
is false. Merged, and not listening.

A green suite cannot catch this, and that is the point: every test in this
repository runs against a build made from the tree under test. Drift lives in the
distance between that tree and whatever is actually answering on a port.

## 2. Ruling — probe the behaviour, corroborate with provenance

Two mechanisms were on the table.

**Provenance comparison.** Embed the build commit (a `build.rs`, surfaced on
`/health`), keep a manifest of `control -> commit that introduced it`, and assert
each control commit is an ancestor of the build commit. Cheap, covers every
control at once, and needs no traffic.

**Behavioural probe.** For each control, send the request the control exists to
refuse and require the refusal.

The design takes the probe as the verdict and provenance as corroboration, in that
order, because ancestry is a proxy: a control can be merged into the build and
disabled by configuration, shadowed by a later refactor, or wired behind a feature
flag the install does not set. The listening build would then pass an ancestry
check while serving exactly the request the criterion says it must refuse. A
proxy that can be green while the property is false is not the assertion the
criterion asks for.

Provenance still earns its place: when a probe fails, "this build predates the
control by twelve days" is the difference between a diagnosis and a mystery. So
the check reports both, and only the probe decides pass or fail.

## 3. The manifest

One file, `security-controls.toml` at the repository root, one entry per control:

```toml
[[control]]
id = "origin-guard"
description = "a cross-origin browser request is refused before dispatch"
introduced_in = "5d25f104"
source = "src/gateway/router/origin_guard.rs"
probe = "foreign-origin"
```

`probe` names a probe implemented in the checker, not a shell fragment: a probe
has to construct a request, read a response, and decide, and a string in a
manifest cannot be reviewed as code. The manifest carries what changes per
control; the checker carries what it means to test one.

The admission rule for the manifest is the part that keeps it honest: **a control
belongs in the manifest exactly when its absence is observable from outside the
process.** A control that cannot be probed from the outside cannot drift
detectably, and listing it would buy a row in a report and no evidence. Controls
that fail the rule are recorded in the manifest as `probe = "none"` with the
reason, so the file states its own coverage rather than implying completeness.

## 4. The checker

`scripts/dev/check-control-drift.py <endpoint>`, exit non-zero on any probe that
does not refuse. Output is one line per control: `id`, probe verdict, and the
provenance note when ancestry is checkable.

Two callers:

- **CI**, against a server started from the tree under test. This does not detect
  drift — there is none by construction — it proves the probes still discriminate.
  A probe that has silently stopped exercising its control is the failure mode
  that makes the whole check ornamental, and running it where the answer is known
  is what catches that.
- **The operator, against a live install.** This is where drift is actually
  found, and it is a command rather than a job because the endpoint, the port and
  the credentials are the operator's.

The seed set is the two controls the ticket measured — foreign `Origin`, foreign
`Host` — because those are the ones with a reproduced failure. Growing the
manifest is per-control work with its own evidence; seeding it with every
plausible control would publish a coverage claim no one has tested.

## 5. Fail-first rows

| row | asserts | fails at HEAD because |
| --- | --- | --- |
| 1 | a probe against a server built from HEAD passes for every manifest control | the checker does not exist |
| 2 | a probe against a server with the origin guard removed **fails** | the checker does not exist; this is the row that proves the probe discriminates |
| 3 | a manifest entry naming a commit that is not an ancestor of the build reports drift in its provenance note, and the probe verdict still decides | no manifest, no provenance reader |
| 4 | a manifest entry with `probe = "none"` is reported as uncovered, not as passing | a checker that counts unprobed controls as green is the failure this row forbids |
| 5 | the checker exits non-zero when the endpoint refuses nothing, and distinguishes that from an endpoint that is not answering at all | an unreachable endpoint reading as "no drift" would make the check silently vacuous |

Row 2 is the load-bearing one. It needs a build without the control: the test
builds the server with the guard's wiring line removed via a test-only
configuration rather than a second compilation, and if that cannot be done
honestly the row is written against a stub server that answers everything, which
still discriminates a probe that always passes.

## 6. What this does not do

It does not upgrade the operator's install. The first half of `NFR.SEC.7` is a
fact about a deployed process, and moving a listening service is the operator's
call, not a script's. The check makes the gap visible and dated; closing it is a
deployment.

It does not gate merges on a live endpoint. CI has no listening install, and a
job that depends on one would fail for reasons that have nothing to do with the
change under review.
