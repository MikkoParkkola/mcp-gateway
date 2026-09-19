# Work Plan: Web UI Server & Capability Management

**Design Doc**: `docs/design/RFC-0060-webui-management.md`
**Status**: Awaiting Approval

## Task Breakdown

### Phase 1: API Foundation (can be parallelized)

**Task 1.1: Extract CLI logic into reusable library functions**
- Move core add/remove/list logic from `src/commands/add_remove.rs` into `src/gateway/ui/` or a shared module
- Functions should take `&mut Config` and return `Result<T>`, not `ExitCode`
- Extract `cap import` OpenAPI parsing from `src/commands/cap.rs` into callable function
- Files: `src/commands/add_remove.rs`, `src/commands/cap.rs`
- Tests: existing tests remain, add unit tests for extracted functions

**Task 1.2: Backend management API endpoints**
- POST `/ui/api/backends` -- add backend (JSON body: `{name, command?, url?, env?, description?}`)
- DELETE `/ui/api/backends/:name` -- remove backend
- PATCH `/ui/api/backends/:name` -- update backend
- GET `/ui/api/registry` -- list 48 built-in servers as JSON
- GET `/ui/api/registry/search?q=` -- search registry
- All require admin auth (existing `is_admin()` pattern)
- Auto-trigger config write + hot-reload after mutations
- File: `src/gateway/ui/mod.rs` (extend existing)
- Tests: 8-10 handler tests

**Task 1.3: Capability management API endpoints**
- GET `/ui/api/capabilities` -- list all capability YAML files with metadata
- GET `/ui/api/capabilities/:name` -- return raw YAML content
- PUT `/ui/api/capabilities/:name` -- validate + write YAML
- POST `/ui/api/capabilities` -- create new capability from template/body
- DELETE `/ui/api/capabilities/:name` -- delete YAML file
- Path traversal prevention: sanitize names to `[a-z0-9_-]`
- AX-rules validation on write (reuse `validator` module)
- File: `src/gateway/ui/mod.rs` or new `src/gateway/ui/capabilities.rs`
- Tests: 8-10 tests including path traversal rejection

**Task 1.4: OpenAPI import API endpoints**
- POST `/ui/api/import/openapi/preview` -- fetch URL, parse spec, return tool list JSON
- POST `/ui/api/import/openapi` -- same + write selected tools as YAML files
- Body: `{url: "...", selected_tools?: ["tool1", "tool2"]}` (if selected_tools omitted, import all)
- Reuses extracted `cap import` logic from Task 1.1
- File: `src/gateway/ui/mod.rs` or new `src/gateway/ui/import.rs`
- Tests: 3-4 tests with mock specs

### Phase 2: UI Implementation

**Task 2.1: Server management UI**
- Extend Servers tab in `src/gateway/ui/index.html`
- "Add Server" button -> inline htmx form with:
  - Registry dropdown (`hx-get="/ui/api/registry"` to populate)
  - Search/filter on dropdown
  - Custom fields: name, command, URL, env vars (dynamic add rows)
  - Submit: `hx-post="/ui/api/backends"` -> swap server list
- Remove button on each server card: `hx-delete` with `hx-confirm`
- ~100 lines HTML/JS

**Task 2.2: Capabilities tab UI**
- New "Capabilities" tab in hash router
- File list with tool count per file
- Click to expand -> YAML content in editable `<textarea>`
- "New Capability" button -> pre-filled YAML template
- "Save" -> `hx-put="/ui/api/capabilities/:name"` -> inline validation result
- "Delete" -> `hx-delete` with `hx-confirm`
- ~120 lines HTML/JS

**Task 2.3: YAML editor enhancements**
- Monospace font, line numbers via CSS counter
- Tab key inserts 2 spaces (JS event handler)
- On blur: POST to validation endpoint, show errors inline
- "Revert" button re-fetches original content
- ~50 lines JS/CSS

**Task 2.4: OpenAPI import modal**
- "Import OpenAPI" button in Capabilities tab
- Modal with URL input + "Preview" button
- Preview: `hx-post="/ui/api/import/openapi/preview"` -> renders checklist of tools
- Each tool has checkbox (default checked) + name + description
- "Import Selected" -> `hx-post="/ui/api/import/openapi"` with selected tool names
- Success -> close modal, refresh capabilities list
- ~80 lines HTML/JS

### Phase 3: Polish

**Task 3.1: Integration testing**
- E2E test: add backend via API -> verify in config -> remove -> verify gone
- E2E test: create capability YAML -> verify in tools list -> edit -> verify changed -> delete
- E2E test: import mock OpenAPI spec -> verify capabilities created
- 6-8 integration tests

**Task 3.2: Documentation**
- Update Web Dashboard wiki page with management features
- Add screenshots/examples to README
- Update `/ui` help text

## Execution Order

```
Phase 1 (parallel):
  Task 1.1 ──┐
  Task 1.2 ──┤── all can run in parallel (separate files)
  Task 1.3 ──┤   (1.2-1.4 depend on 1.1 for shared functions,
  Task 1.4 ──┘    but can stub initially)

Phase 2 (sequential, depends on Phase 1):
  Task 2.1 -> Task 2.2 -> Task 2.3 -> Task 2.4
  (UI builds on top of API endpoints)

Phase 3 (after Phase 2):
  Task 3.1 -> Task 3.2
```

## Risks

| Risk | Mitigation |
|------|-----------|
| YAML round-trip loses comments | Document this; use append-only for `add`; full round-trip only for capability editor |
| Large OpenAPI specs (1000+ endpoints) | Preview with pagination; limit import to 100 tools per batch |
| Concurrent config writes (CLI + UI) | File locking with `flock` on config write |
| XSS via capability names/descriptions | Existing `esc()` function in index.html; server-side sanitization |

## Definition of Done

- [ ] All 11 acceptance criteria from RFC-0060 pass
- [ ] 2100+ tests pass (current 2105 + ~30 new)
- [ ] Clippy clean
- [ ] All files under 800 LOC
- [ ] Web UI accessible at `/ui` with management features
- [ ] Works without JS for basic viewing (progressive enhancement)
