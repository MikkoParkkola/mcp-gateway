# MIK-7272 EXT.1 phase 2 — recovering the client's `extensions` declaration

Status: design note, pre-implementation. Phase 1 (server half: `extensions` on
the gateway's own capabilities, plus the conformance-matrix honesty edits) is
committed and stands on its own. Nothing here reopens it.

## What phase 1 left open

`ExtensionSet::from_capabilities` (`src/protocol/extensions.rs:82`) parses an
`extensions` object out of a peer's capability declaration. It has **zero
production callers** — `rg` finds only test call sites.

**Correction, found in review (gpt-review, verified at source).** An earlier
revision of this note, and the phase 1 comment and `TRACKED_GAPS` reason it was
drawn from, said "nothing on the `tools/call` path recovers client extensions".
That is false. `declares_tasks_extension` (`src/gateway/router/handlers.rs:182`,
called at `:1034`) reads
`_meta["io.modelcontextprotocol/clientCapabilities"].extensions` on every
request that reaches the tasks extension, and refuses the request with
`MISSING_REQUIRED_CLIENT_CAPABILITY` when the identifier is absent.

So the real defect is not "no reader". It is **two readers that disagree**:

| | `declares_tasks_extension` (live) | `ExtensionSet::from_capabilities` |
|---|---|---|
| parse | `pointer()` / chained `get()`, hand-rolled | shared, typed |
| `{"…/tasks": {}}` | accepted | accepted |
| `{"…/tasks": 3}` | **accepted** (`is_some`) | **rejected** (`is_object`) |
| `{"…/tasks": null}` | **accepted** | **rejected** |
| identifier it does not know | ignored (it looks only for tasks) | dropped |
| result | `bool` | `ExtensionSet` |

A client that declares `{"io.modelcontextprotocol/tasks": 3}` passes the live
gate today and enters task behaviour it never validly negotiated — which the
comment inside `from_capabilities` already argues against in as many words
("presence is not agreement").

**Headline, corrected: this is not a pure addition. Unifying the two readers
tightens a live gate.**

## 1. What reads the field

`classify_request` (`src/protocol/meta.rs:150`) is the single place the request
`_meta` envelope is parsed. It already narrows
`meta["io.modelcontextprotocol/clientCapabilities"]` to an object and hands it
to `Declared::parse`. The extension read belongs beside that call, on the same
value, on the same success arm — not at a second parse site, because a second
site is a second place for the two reads to disagree about what a malformed
envelope means.

Call-site detail, because the first revision of this note described something
that does not compile (caught by both reviewers). After the existing let-else,
`capabilities` is shadowed by a `&serde_json::Map<String, Value>`; before it,
it is an `Option<&Value>`. `from_capabilities` takes `&Value`. No rename is
needed — `Option<&Value>` is `Copy`, so one line hoisted above the narrowing
does it:

```rust
let declared_extensions = capabilities
    .map(ExtensionSet::from_capabilities)
    .unwrap_or_default();
```

No new parsing helper, no change to `from_capabilities`'s signature, no churn
at its existing test call sites.

## 2. Where the recovered set lives

A new `extensions: ExtensionSet` field on `RequestFields`
(`src/protocol/meta.rs:55`), populated on the `RequestShape::Modern` success arm
only, reached through a `RequestShape::declared_extensions()` accessor that
mirrors the existing `declared_capabilities()`.

That is the whole storage decision, and it is deliberately **not** a field on
`MetaMcpCallerContext`. `MetaMcpCallerContext` has 36 construction sites in
`src/`; `RequestFields` has one. Since nothing downstream behaves differently
(section 4), carrying the set past `RequestShape` would be 36 sites of churn
buying nothing.

It is also deliberately not a bool on `Declared`. `Declared` is five `Copy`
bools describing *capabilities*; extensions are a separate negotiation axis with
their own identifier namespace. `RequestFields` is already `Box`ed and not
`Copy`, so a `Vec`-backed `ExtensionSet` there costs nothing.

Lifetime: the request. `RequestShape` is produced per inbound request and
dropped with it. No caching, no session state.

## 3. Absent or malformed input

Every case already has an answer inside `from_capabilities`; none of them is new
behaviour, and none produces an error.

| Input | Result |
|---|---|
| No `extensions` key | `ExtensionSet::default()` — empty |
| `extensions` present but not an object | empty (`Value::as_object` fails) |
| Entry whose settings value is not an object (`null`, `3`, `"x"`, `[]`) | that entry dropped (`is_object` filter, `extensions.rs:93`) |
| Unknown extension identifier | dropped (`Extension::from_id` returns `None`) |
| `extensions: {}` (present, empty) | empty set — the same answer as absent |
| Entry whose settings value is `true`/`false` | dropped (`is_object`; booleans are scalars) |
| Mixed map: one valid, one malformed, one unrecognised | only the valid known entry survives |
| `RequestShape::Legacy` or `::Malformed` | `ExtensionSet::default()`, mirroring `Declared::NONE` |

**The non-Modern rule is a tightening, and it is an invariant, not a live-path
flip.** `declares_tasks_extension` read the `_meta` pointer directly, so it
answered from whatever bytes were there regardless of how the envelope
classified; `declared_extensions()` answers `ExtensionSet::default()` for
`Legacy` and `Malformed` by construction. Two source-verified facts say nothing
reachable changes behaviour:

- A request carrying `_meta["io.modelcontextprotocol/clientCapabilities"]` can
  never classify as `Legacy` — that field's presence is part of what makes the
  shape `Modern`, so "a legacy request that declared extensions" is not a
  representable state.
- `Malformed` is refused with `-32602` at `handlers.rs:819`, before the gate at
  `:1034` is reached. A malformed envelope never gets as far as being asked
  what it declared.

So the rule is what keeps the two halves consistent if the classifier ever
gains a shape, not a change to any request that exists today. Recorded because
"mirrors `Declared::NONE`" reads like a restatement of existing behaviour and
is not: it is a new guarantee with no live path to exercise it.
`ac_ext_1_e8_a_shape_without_a_finished_declaration_recovers_nothing` pins it
anyway — an invariant with no live path is exactly the one that rots.

Settings *content* is never inspected — only the object shape. Nothing in 4.0.0
reads what is inside an extension's settings body; that is MIK-7311's work.

The per-entry `is_object` filter is the load-bearing reason to route through
`from_capabilities` rather than hand-roll a read here: it matches what
`Declared::parse` already does one line away
(`capabilities.get("sampling").is_some_and(Value::is_object)`), so the two reads
treat a junk-shaped declaration identically. A hand-rolled read that only
rejected `null` would accept `{"…/tasks": 3}` and diverge from `Declared` for no
stated reason. That filter is what acceptance case E5 pins.

An unknown identifier is dropped rather than retained because carrying it would
let a peer's declaration decide what this gateway claims to understand — the
rationale already recorded on `Extension::from_id`.

## 4. Does anything downstream behave differently?

**Yes — one gate, and it needs a ruling before implementation.** The first
revision of this note said "no", which was wrong for the reason in the
correction above.

No *new* behaviour is proposed. But `declares_tasks_extension` already decides
dispatch on this exact field, and leaving it in place means shipping two
parsers that disagree about the same bytes. Two dispositions:

- **(i) Unify — RULED, and implemented.** Delete `declares_tasks_extension`; the gate at
  `handlers.rs:1034` consumes `RequestShape::declared_extensions()`. One
  parser, one answer, and the deletion is smaller than the duplication.
  **Behaviour change:** `{"…/tasks": 3}`, `null`, `[]` and `"x"` stop passing
  the gate and start receiving `MISSING_REQUIRED_CLIENT_CAPABILITY`. That is
  the spec reading, and it is a live-path tightening, so it was raised as the
  operator's call and ruled in favour of unifying.
- **(ii) Recover only — not taken.** Add the field, leave the gate alone. Smaller and
  strictly additive, but it ships the divergence table above as a known defect,
  and the matrix cell may then claim only that the declaration is *parseable*,
  not that the gateway acts on a validly negotiated one.

The four `input_capabilities: Declared` consumers (`handlers/tasks.rs:118`,
`:215`, `meta_mcp/task_confirmation.rs:106`, `meta_mcp/mod.rs:170`) are
untouched under both. `input_required` and extension-aware task behaviour
remain MIK-7311.

## 5. Acceptance cases (failing-first, before implementation)

Split one per shape, so a red case names exactly one mutation (kimi-review).

- **E4 — recovery**: a modern-era request declaring
  `{"extensions": {"<tasks id>": {}}}` classifies as `Modern` and
  `declared_extensions()` contains `Extension::Tasks`.
- **E5a — absent key**: no `extensions` key recovers an empty set.
- **E5b — shape discipline**: a non-object settings value recovers an empty
  set. This is the case a null-only filter turns red.

**Route-level, not parse-level (gpt-review).** Under disposition (i) at least
one case runs through the router to the gate at `handlers.rs:1034`, because a
parse-level assertion stays green while the live gate is broken — and a green
test over a divergent gate is exactly how the matrix ends up claiming coverage
it does not have. Fixture: `tests/mik_7272_task_1_acs.rs`, whose
`post` helper dispatches through the real in-process axum router
(`create_router(state).oneshot(request)`), beside the existing gate rows
`ac_task_1_4` and `ac_task_1_13`. Its `modern` builder took a `bool`, which
cannot express a settings value the specification disallows, so the body-builder
was split: `modern` keeps the two-declaration signature every other row uses and
delegates to `modern_declaring`, which takes the capabilities object verbatim.
(`tests/task_upstream_recovery/helper.rs` is not usable here: it spawns the
binary as a subprocess against a mock upstream, and its `_meta` builder is the
fake *peer's* side, not the client's.)

Landed as `ac_ext_1_e6_a_non_object_settings_value_does_not_declare_the_extension`
(five malformed settings values, each expecting `400` + `-32021`) and its
companion `ac_ext_1_e7_a_valid_settings_object_still_declares_the_extension`,
without which a gate that refused everything would satisfy E6. Failing-first
observed before the gate change: E6 red at `left: 200, right: 400`, E7 already
green.

## Falsifier

Mutate the new `extensions:` initializer on the success arm to
`ExtensionSet::default()`. E4 must go red and E5 must stay green (E5 asserts
emptiness). Mutate the `is_object` filter at `extensions.rs:93` to a null-only
check: E5 must go red and E4 must stay green. If either mutation leaves both
green, the pair is not discriminating and the tests are wrong.

## Not in scope

Extension-aware dispatch, `input_required`, the `initialize` result carrying
extensions (deliberately excluded — the 2026-07-28 lifecycle scopes the
handshake to "2025-11-25 and earlier"), and any change to `Declared`.
