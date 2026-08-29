# mcp-gateway 4.0.0 — Test plan

**Status**: DRAFT for review. Written before any test code exists, per `development-process.md` §P2.
**Requirements**: `docs/requirements/RELEASE-4.0.0-requirements.md`
**Design**: `docs/design/RFC-0061-protocol-2026-07-28-release-scope.md`

A test plan exists so the tests inherit the *requirements'* coverage instead of the design's happy
path. One row per acceptance criterion. **An empty evidence cell is the finding**, not an oversight
to be filled in later.

Reviewed against two questions, and no others:

1. Does every acceptance criterion have a case, or a stated reason it has none?
2. **Can each named case actually fail?** A case whose fixture makes its own assertion true, or whose
   staging removes the condition it observes, passes every coverage tool ever built.

V-model levels: **U** unit · **C** component (one module, real collaborators) · **I** integration
(gateway process, real transport) · **S** system (gateway + live peer).

---

## Increment 1 — Discovery and era detection

Chosen first because `server/discover` is additive: it breaks no existing client, and it is the only
negotiation surface that works in both directions once `initialize` and `ping` are gone. If
implementing it requires touching the legacy handshake path, the implementation is wrong — that is
the ticket's own stop-the-line, and row D3.b is what enforces it.

### Coverage rows

| AC | Case | Level | Type | Can it fail? |
|---|---|---|---|---|
| DISCOVER.1 | `server/discover` over **stdio** returns a result naming supported versions, capabilities and server identity | I | positive | Yes — no handler exists; the dispatcher returns method-not-found |
| DISCOVER.1 | `server/discover` over **Streamable HTTP** returns the same document as stdio for the same gateway | I | equivalence | Yes — two dispatchers, `server/mod.rs:1636` and `handlers.rs:528`, are separate `match` arms and drift is the default |
| DISCOVER.1 | `server/discover` over **WebSocket** returns the same document | I | equivalence | Yes — third dispatcher, `transport/websocket.rs` |
| DISCOVER.1 | The advertised version list equals `SUPPORTED_VERSIONS`, and every entry is a revision the specification defines | U | negative | Yes — **it fails today**: `src/protocol/mod.rs:23` advertises `2024-10-07`, which is not one of the five revisions the specification lists |
| DISCOVER.2 | Discovery answers on a connection that has sent no `initialize` and holds no session | I | positive | Yes — the HTTP path currently mints a session id for every request |
| DISCOVER.2 | Discovery answers before any credential exchange beyond transport authentication | I | positive | Yes — if discovery is placed behind the admin gate it fails |
| DISCOVER.3 | Given a 2025 client, When it sends `initialize`, Then the result is byte-identical to the same request against 3.5.0 | C | regression | Yes — golden captured in-process from the unchanged tree (which *is* 3.5.0 on this branch), so any field added to the handshake path breaks it. **This is the row that enforces "additive"** |
| DISCOVER.4 | Backend answering `DiscoverResult` → classified modern | C | positive | Yes — nothing classifies today |
| DISCOVER.4 | Backend answering `UnsupportedProtocolVersionError` → classified **modern** (a recognised modern error proves a modern peer) | C | boundary | Yes — the tempting implementation treats any error as legacy, and this row is the one that catches it |
| DISCOVER.4 | Backend answering `-32601 method not found` → classified legacy | C | positive | Yes |
| DISCOVER.4 | Backend answering an arbitrary application error → classified legacy | C | negative | Yes |
| DISCOVER.4 | Backend answering **nothing** until the probe deadline → classified legacy | C | timeout | Yes — needs a stalling fixture and a bounded deadline; an implementation that waits forever hangs the test rather than passing it |
| DISCOVER.4 | A backend classified legacy is then probed with `initialize` and serves normally | I | positive | Yes |
| DISCOVER.5 | Era is resolved once per backend and reused; a second call issues no second probe | C | positive | Yes — assert on a probe counter in the fixture transport, not on elapsed time |
| DISCOVER.5 | When a cached era assumption produces a failure, the backend is re-probed | C | recovery | Yes — the naive cache never invalidates, so this fails against it |
| DISCOVER.6 | Warm-start retries on its existing schedule when discovery finds nothing listening | C | regression | Yes — an implementation that replaces the retry loop with a single discovery probe fails it |

### The two questions, answered

**Every AC has a case.** Six criteria, sixteen rows, no empty cells.

**Every case can fail, and four are worth naming:**

- **The `2024-10-07` row fails on today's code.** That is not a defect in the plan; it is the plan finding a defect before the feature is written. The gateway advertises a protocol revision the specification has never defined. Either it is a typo for `2024-11-05` that has been advertised to every client since, or it is a private extension nobody documented. Resolve before implementing, because the discovery document repeats whatever this list says.
- **DISCOVER.3's golden fixture is captured, not written by hand.** A hand-written expectation of the handshake is a second implementation of it, and it agrees with whatever the author believed rather than with what shipped. Capture happens before the first line of discovery code, from the unchanged tree, and pins its Cargo feature set.
- **The timeout row needs a stalling fixture with a bounded deadline.** A backend that never answers and a test that waits forever are indistinguishable from a passing test that hangs CI.
- **DISCOVER.5 asserts a probe counter, never elapsed time.** Timing assertions are the classic flaky test, and a cache that is merely slow would pass one.

### Fixtures — what they may not do

A fixture that reimplements the production path tests the fixture. Two rules for this increment:

1. The backend fixture is a **transport**, answering bytes. It does not import the era classifier.
2. The golden handshake fixture is **captured output**, committed as data, never generated by the code under test at assertion time.

### Deliberately not covered in this increment

- Discovery's content beyond structure — the capability list is not stable until slice 3 defines `extensions`. Row: version list and identity only.
- Discovery over the deprecated HTTP+SSE transport. It is Deprecated in the specification and the gateway need not add new surface to it.

---

## Later increments — planned, not yet detailed

Listed so the shape of the whole is visible and so no increment is quietly dropped. Each gets its own
row set before its code is written, not before the release ends.

| Increment | Requirements | Note |
|---|---|---|
| 2 — Stateless dispatch | STATELESS.1–8 | Needs the dual-era fixture pair from increment 1 |
| 3 — Headers | HEADER.1–6 | HEADER.6 is a security case: a mismatched header must not reach authorization |
| 4 — Results, errors, cache fields | RESULT.\*, ERROR.\*, CACHE.\*, ORDER.\* | CACHE.2 needs two principals and a shared cache to be a real test |
| 5 — MRTR and the bridge | MRTR.1–10 | The largest. U8 runs first: if the four era pairs cannot be constructed, the design reopens |
| 6 — Controls that must survive | CONFIRM.\*, TENANT.\*, CONTROL.1–5 | Every case asserts a **refusal**, never a computed value |
| 7 — Identity | IDENT.1–5 | IDENT.1 is negative-first: a forged `clientInfo` must change no authorization outcome |
| 8 — Subscriptions | SUB.1–4 | Follows increment 6; the multiplexer is session-keyed today |
| 9 — Authorization server | OAUTH.1–3 | Independent of the rest; can run in parallel |
| 10 — Exploitation | EXT.1, OTEL.1, TASK.1, SURFACE.1, SCHEMA.1 | SURFACE.1 and PERF.2 are measurements, not tests |

## Cross-cutting suites

Two suites that no per-increment row set can express, because their subject is the interaction:

- **Conformance matrix** — one row per normative statement in the 2026-07-28 changelog, crossed with role (server ‖ client), transport, revision, and outcome (positive ‖ negative). Requirement NFR.COMPAT.4 means each row is verified in both roles; a matrix filled in one role is half a matrix.
- **Era-combination matrix** — all four client×backend era pairs, each with an elicitation in flight. U8 promoted from a one-off probe to a permanent suite, because the pairs are exactly what regresses silently.

## What would make this plan wrong

Stated so a reviewer has something to disagree with:

- If `server/discover` cannot be answered before a session exists on the HTTP path without restructuring request handling, increment 1 is not additive and its ordering is wrong.
- ~~If the 3.5.0 golden fixture cannot be captured — because the handshake response embeds a timestamp, a session id or any per-run value — DISCOVER.3 needs a normalising comparison.~~ **Checked 2026-08-29, and it is capturable.** `handle_initialize` (`src/gateway/meta_mcp/mod.rs:955-996`) returns `build_initialize_result(negotiated_version, &instructions)`; the instructions derive from the backend registry's tool counts, and nothing in the path reads a clock, a session id or a random source. Given a fixed registry the response is deterministic.

  Two consequences, both simplifications. The golden does **not** need capturing from a built 3.5.0 binary: this branch carries no code change yet, so the current tree *is* 3.5.0 for this purpose, and the fixture is captured in-process from `handle_initialize` before the first line of discovery code is written.

  **But it moves with Cargo features.** Under `spec-preview` the handshake advertises `capabilities.tools.filtering` and `.resolve` (`src/gateway/meta_mcp/spec_preview.rs`), so one golden is one feature set. The fixture MUST pin the feature set it was captured under, and the test MUST fail rather than pass when run under a different one — otherwise the regression row silently stops comparing, which is the failure mode this row exists to prevent.
