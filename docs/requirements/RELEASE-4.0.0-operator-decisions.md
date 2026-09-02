# Release 4.0.0 — the decisions the operator actually made

Every row here is a verbatim question put to the operator and the answer they
selected. The source is the session transcript's record of the question tool, not
anyone's memory of the exchange. Regenerate with `scripts/release/extract-operator-decisions.py`.

Two failure modes this table exists to stop, both of which have happened:

- **An answer written by the author and attributed to the operator.** Eleven of
  these were found and removed in one pass.
- **A real answer withdrawn because a transcript search could not see it.** An
  answer given through the question tool arrives as a tool result, not as a user
  turn, so a search over user turns returns nothing and the ruling looks invented.
  Sixteen genuine decisions were withdrawn this way, then restored.

A ruling absent from this table is not thereby invented — it may have been given
in an ordinary message. It does mean the provenance has to be shown some other way.

18 decisions.

| # | question put to the operator | answer |
|---|---|---|
| 1 | The 20 small hardening issues (5 of them P1 auth holes) sit in the same request path 4.0.0 rewrites. Do they go into 4.0.0, or into a follow-on release right after it? | **Absorb all 20 into 4.0.0 first** |
| 2 | When a value spelled MCP_GATEWAY_* arrives from an env file and gets rotated, should a config reload apply it to the running gateway, or is a restart acceptable for that class of value? | **Apply live wherever safe** |
| 3 | How long should a paused tool call stay resumable? A 2026 backend can answer a call with "I need more input" instead of a result; the gateway hands the client a sealed token and the client comes back with the answers. That token has to expire. I picked 300 seconds while writing the design and nobody chose that — it decides both how long a stolen token is worth stealing and how much in-flight work a restart destroys. | **300 seconds (Recommended)** |
| 4 | Three acceptance criteria for multi-round-trip calls say MUST, and the test plan declares all three uncovered. Two of them can't be covered without building new machinery. Does 4.0.0 ship the feature as single-process-only? | **Build both before 4.0.0** |
| 5 | A backend MCP server publishes a tool whose inputSchema is not valid JSON Schema 2020-12, and the gateway re-publishes that schema to clients through gateway_list_tools. SCHEMA.1 says every schema the gateway exposes MUST be valid. What should the gateway do with that tool? | **Drop the tool, keep the backend (Recommended)** |
| 6 | Issue #449's design closes `ORDER.2` the way the criterion permits, and it is already reviewed — but it is not currently in the v4.0.0 scope. Should the release absorb it, or close `ORDER.2` the cheap way and ship #449 separately? | **Adopt 449.DERIVE now (Recommended)** |
| 7 | For the retry-protection key (idempotency key — a value a client sends so a retried call after a broken connection doesn't run the side effect twice), what should carry it? The gateway has two ways in: the meta route (the compact tool surface) and the direct route POST /mcp/{name}. This blocks all code for MIK-7272.SUB.4. | **_meta field, both routes (Recommended)** |
| 8 | What should happen to `gateway_set_profile` in 4.0.0 — the tool that lets a client narrow its own tool list mid-connection? | **Remove it (Recommended)** |
| 9 | When a backend sends a progress update partway through a tool call, that update should reach the client that made the call. The gateway now receives these correctly, but has nowhere to send them — there is no per-request channel back to the client. Should 4.0.0 build that channel, or should the criterion be narrowed to what already works? | **Meet it in 4.0.0** |
| 10 | Tool schemas are supposed to be valid under the JSON Schema 2020-12 standard — including schemas that backends hand us, which we do not control. Verifying that needs a validator library the repo does not have. Add one? | **Add the library (Recommended)** |
| 11 | Cluster F is four release decisions that need you rather than more engineering, and one of them gates two other clusters. Does the 2026 protocol revision join SUPPORTED_VERSIONS for 4.0.0 — i.e. does the gateway actually serve the modern revision in this release, or only advertise readiness for it? | **Serve it in 4.0.0 (Recommended)** |
| 12 | For 4.0.0, how should `exposed_meta_tools` enforcement ship? Background: the field has been documented but never enforced, so an operator who set it got no restriction. Enforcing it means `tools/list` and `tools/call` start honouring it — and an operator who upgrades without editing anything silently loses tools that used to answer. Our own release notes already call this breaking (`docs/release/v4.0.0-release-notes-DRAFT.md:38`), and requirement NFR.COMPAT.3 says an upgrading operator must not have to edit config to keep existing behaviour. So the release currently contradicts its own criterion, and only you can settle which side gives. | **Enforce now, accept it as breaking** |
| 13 | Release criterion NFR.COMPAT.4 says every requirement must be verified in BOTH roles the gateway can play — as a server answering callers, and as a client calling backends. Many requirements only have a server half (a rule about how the gateway answers a request has no client-side counterpart at all). As written, those requirements can never satisfy the criterion no matter how much work we do, and every one of them is currently graded against it. How should that be resolved? | **Leave it absolute; record the reason per cell (Recommended)** |
| 14 | The release criterion NFR.PERF.4 says the gateway's compact tool surface — the short list of tools an AI client sees, instead of hundreds of backend tools — must stay between 14 and 16 tools. But the repo's own published claims file records a real shipped configuration with 17 (the extra one appears when webhook status is surfaced). So the release criterion and the shipped product disagree, and nothing in the code enforces either. Which number moves? | **Keep 14-16; stop the 17th from counting (Recommended)** |
| 15 | The conformance matrix fills each cell with a reference to the evidence that proves it. How strong does that reference have to be? This decides how much continuous-integration plumbing is in scope for 4.0.0, and it is the difference between a check that runs anywhere and one that only runs at release-tag time. | **Existence now, executed-run as a tracked follow-up** |
| 16 | Should the conformance-matrix checker fail the build while cells are still unfilled, or only report the numbers? | **Report only, block at tag time (Recommended)** |
| 17 | Release criterion MIK-7246.CONFIRM.1b says, unqualified: "The gate MUST NOT proceed on a warning." The destructive-operation confirmation gate holds that on the modern (2026-07-28) path — it refuses. On the legacy path it still returns PROCEED_WITH_WARNING, and the code comment says that asymmetry is deliberate: a 2025 client that never declared elicitation has been served that way for the gateway's life, so tightening it now would be a breaking change made in passing. The criterion text does not say any of that, so as written the release fails it. Which should the release be graded against? | **Scope the requirement to the modern path (Recommended)** |
| 18 | In 4.0.0, should the gateway serve the 2026-07-28 protocol revision out of the box, or only when an operator turns it on? | **On by default (Recommended)** |
