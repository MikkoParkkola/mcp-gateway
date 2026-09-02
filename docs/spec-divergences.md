# Deliberate divergences from the MCP specification

Every place in the source that departs from, extends, or does not implement
part of the Model Context Protocol specification, with the reason as the code
states it. Two entries. Search method below.

## 1. `2026-07-28` withheld from `SUPPORTED_VERSIONS`

**Location:** `src/protocol/mod.rs:38`

`SUPPORTED_VERSIONS` lists every protocol revision this gateway's classic
`initialize` handshake negotiates: `2025-11-25`, `2025-06-18`, `2025-03-26`,
`2024-11-05`. The `2026-07-28` revision is a specification-defined revision
the gateway does not list there.

**Reason (from the specification):** the 2026-07-28 lifecycle scopes
`initialize` to "`2025-11-25` and earlier", so the handshake negotiates legacy
revisions only, and listing `2026-07-28` there would have it negotiate a
revision that has no handshake. The omission is permanent, not an increment
waiting to land: `MODERN_VERSIONS` (`src/protocol/meta.rs:219`) carries the
revision for the stateless path that serves it.

**Scope note:** this is narrower than "2026-07-28 is unsupported." The
revision is separately advertised in `server/discover`'s `supportedVersions`
(`src/gateway/meta_mcp/mod.rs:1075-1082`) and partially served over the
stateless path when `server.modern_protocol` is enabled — the divergence is
specifically that the classic `initialize` handshake will never negotiate it,
by design, because that handshake does not exist in `2026-07-28`.

## 2. Backend and capability tools excluded from destructive-tool governance

**Location:** `src/gateway/destructive_confirmation.rs:151`

`DESTRUCTIVE_META_TOOLS` — the set of tools the destructive-confirmation gate
governs — is built only from the gateway's own compile-time meta-tool
definitions (`meta_mcp_tool_defs.rs`, both traditional and Code Mode). Backend
and capability tools reached through `gateway_invoke` / `gateway_execute` are
deliberately excluded from this governed set.

**Reason (from the code):** those tools are not part of
`meta_mcp_tool_defs.rs`; `infer_destructive_tool()` can only guess their
`destructiveHint` by substring match on unstructured data, and
`ConfirmationPolicy::for_modern()` is an unconditional refusal — so governing
them here "would refuse a large slice of the tool surface with no
confirmation path."

## How this list was produced

Searched `src/` (excluding `*_tests.rs` / `*tests.rs`) with `rg`, case
insensitive, in several passes for language a deliberate spec divergence
would use:

- `deliberately (absent|omit|does not|refus|divert|depart)`, `diverg`,
  `deviat`, `departs from`, `extends the spec`, `does not implement`,
  `not.?compliant`, `out of spec`, `non-conformant`, `contrary to the spec`
- `the spec(ification)?( says| requires| defines| allows| does)`,
  `departs? from the spec`, `MCP.{0,10}spec`
- `extends? the spec`, `extension to the (mcp )?spec`, `beyond what the spec`,
  `goes beyond the spec`, `spec is silent`, `spec leaves`,
  `our own extension`, `not part of the (mcp )?spec(ification)?`,
  `spec does not (define|specify|cover|mandate)`,
  `we (choose|elect|deliberately) not to`, `choos(e|ing) not to implement`,
  `refuses? to implement`
- `differs from the spec`, `our implementation differs`, `we depart`,
  `diverges from`, `violat(es|ion).{0,10}spec`
- `known gap`, `not (yet )?fully (mcp )?compliant`, `partial(ly)? implement`,
  `does not (yet )?support the (full |complete )?spec`

Every hit outside the two entries above cited the specification to explain
*compliance* (what it requires and how the code meets it) or filled a gap the
specification leaves unstated (which is not a divergence). None asserted a
deliberate departure. Two matches on `does not implement`
(`src/protocol/continuation.rs:196`, `src/skills/registry.rs:22`) were read in
context and are unrelated: the first is a doc-comment on an enum variant for
an unrecognized version string, the second is a module boundary note about
where execution lives, not a protocol divergence.
