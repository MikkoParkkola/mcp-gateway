# MIK-7775: unread provider keys, `cap validate`, and non-executable capabilities

Status: accepted (2026-10-02); reviewed by two seats, both SHIP. Follow-up to MIK-7768 (#2677).

## Facts (base 92f4ea24b)

1. The executor dispatches `rest`, `graphql` and `jsonrpc` only (`src/capability/executor/mod.rs:459-480`);
   any other `service` is mapped to REST with a warning (`ProviderConfig::protocol_config`, catch-all arm).
2. `RestConfig` has no `command`, `args`, `transport`, `env` or `response_transform` field, and
   `ProviderConfig`/`RestConfig` accept keys they do not read: serde drops them silently.
3. 25 shipped capabilities declare `service: cli` (19) or `service: mcp` (6) with no URL, so none can
   execute; v3.5.1 had no CLI or MCP executor either. Two more (`google/gmail_save_attachment`,
   `google/calendar_get_attachment`) carry a Python `config.response_transform` that nothing runs.
4. `cap validate` (`src/commands/cap.rs` `cap_validate`) runs only the legacy `validate_capability`, never
   the structural validator the loader runs (`src/capability/loader.rs:117-139`).

## Design

1. **CAP-012 (Warning)**, one per unread key, naming its dotted path from `providers`
   (`providers.primary.config.methd`). The providers deserializer
   (`src/capability/definition/providers.rs`, split out of `definition/mod.rs`) deserializes each named
   provider through a `DeserializeSeed` that wraps the deserializer in `serde_ignored`, so line numbers in
   parse errors are kept; fallback entries (already a `serde_json::Value`) go through the same seed.
   Paths are stored in a new `#[serde(skip)] ProvidersConfig::unread_keys` and turned into issues by
   `check_providers`. Keys whose last segment starts with `_` or `x-` are annotations and not reported,
   as in `config::strict_keys`. Warning, not Error, consistent with CAP-011: an unread key does not stop
   the primary from serving.
2. **`cap validate`** runs `validate_capability_definition` after the legacy check, prints every issue
   to stderr, and exits non-zero on any Error.
3. **Non-executable capabilities (openpencil and the 24 other `cli`/`mcp` ones) and the two dead
   `response_transform` keys:** operator ruling 2026-10-02, "build and fix": a separate lane (MIK-7782,
   handoff `cap-exec.md`) builds CLI and MCP capability execution and makes the attachment capabilities
   do what they describe. Nothing is removed here. Until that lands, CAP-012 warns on `command`, `args`,
   `transport`, `env` and `response_transform`, worded "not read by this gateway version"; it goes quiet
   for a key as soon as a provider field reads it, so it needs no change when the executors land.

## Tests (red first on CI)

- `src/capability/validator/tests/unread_keys.rs`: misspelled config key, key beside `config`, several
  keys, control.
- `tests/mik_7775_cap_validate.rs` (binary): CAP-011 shown and exit 0; CAP-012 shown with the path;
  CAP-005 error fails the command; a clean file prints no code.

## Falsifier

If `serde_ignored` reports a key that a field does read (a false positive), every shipped REST
capability would warn. Checked: a field-list scan of the 125 shipped files finds unread keys only in the
27 files named in fact 3.
