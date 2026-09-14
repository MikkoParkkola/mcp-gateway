# MIK-7272 EXT.1 phase 2 — recovering the client's `extensions` declaration

Status: design note, pre-implementation. Phase 1 (server half: `extensions` on
the gateway's own capabilities, plus the conformance-matrix honesty edits) is
committed and stands on its own. Nothing here reopens it.

## What phase 1 left open

`ExtensionSet::from_capabilities` (`src/protocol/extensions.rs:82`) parses an
`extensions` object out of a peer's capability declaration. It has **zero
production callers**. Every client that declares
`_meta["io.modelcontextprotocol/clientCapabilities"].extensions` on a
`tools/call` has that declaration silently dropped, so the client half of EXT.1
has no evidence and the matrix cell stays empty. Phase 2 supplies the missing
read.

**Headline: this adds zero new error paths and changes no dispatch decision.**
It is recovery only.

## 1. What reads the field

`classify_request` (`src/protocol/meta.rs:150`) is the single place the request
`_meta` envelope is parsed. It already narrows
`meta["io.modelcontextprotocol/clientCapabilities"]` to an object and hands it
to `Declared::parse`. The extension read belongs beside that call, on the same
value, on the same success arm — not at a second parse site, because a second
site is a second place for the two reads to disagree about what a malformed
envelope means.

Call-site detail worth stating, because it does not typecheck otherwise: after
the existing let-else, `capabilities` is shadowed by a
`&serde_json::Map<String, Value>`, while `from_capabilities` takes the whole
`&Value` capability object and performs its own `.get("extensions")`. The
narrowed binding is therefore renamed so both the map (for `Declared::parse`)
and the original value (for `ExtensionSet::from_capabilities`) are in scope. No
new parsing helper is introduced.

## 2. Where the recovered set lives

A new `extensions: ExtensionSet` field on `RequestFields`
(`src/protocol/meta.rs:85`), populated on the `RequestShape::Modern` success arm
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
| `RequestShape::Legacy` or `::Malformed` | `ExtensionSet::default()`, mirroring `Declared::NONE` |

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

**No, and that is intentional for 4.0.0.** The doc comment on
`ExtensionSet::gateway_declares` states that the shipped task model is knowingly
short of the extension specification for this release — `input_required` is out
of scope by design, and MIK-7311 completes the model behind it. Acting on a
recovered extension is MIK-7311's work and is not authorized here.

So: the four `input_capabilities: Declared` consumers
(`handlers/tasks.rs:118`, `:215`, `meta_mcp/task_confirmation.rs:106`,
`meta_mcp/mod.rs:170`) are untouched. No gate reads the new field. What changes
is that the declaration is *recoverable* — which is exactly what EXT.1's client
half asserts, and exactly what is untestable today.

Consequence for the matrix: the cell becomes writable on the strength of E4/E5,
which test recovery. It does not become a claim that the gateway varies its
behaviour per extension. If a reviewer reads the regrade that way, the regrade
is worded wrong, not the code.

## 5. Acceptance cases (failing-first, before implementation)

- **E4 — recovery**: a modern-era request whose `clientCapabilities` carries
  `{"extensions": {"<tasks id>": {}}}` classifies as `Modern` and
  `declared_extensions()` contains `Extension::Tasks`. Red today: the accessor
  does not exist.
- **E5 — shape discipline**: the same request with a non-object settings value
  recovers an empty set, and one with no `extensions` key recovers an empty set.
  This is the case a null-only filter turns red.

Both address `classify_request` directly rather than through the route, because
the decision under test is the parse, not the dispatch.

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
