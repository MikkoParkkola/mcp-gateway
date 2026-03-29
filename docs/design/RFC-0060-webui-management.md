# RFC-0060: Web UI Server & Capability Management

**Status**: Draft
**Author**: Mikko Parkkola
**Date**: 2026-03-13

## Problem

Users can manage backends via CLI (`add`/`remove`/`list`) but the Web UI at `/ui` is read-only. For non-developer users and quick iterations, a visual management interface would significantly reduce friction. Additionally, there's no visual way to import OpenAPI specs or edit capability YAML files.

## Goals

1. **Add/remove MCP backends** from the Web UI with the same power as the CLI
2. **Import OpenAPI specs** by URL to auto-generate capability tools
3. **Edit capability YAML** files visually (modify, remove, create tools)
4. **Live preview** of changes before applying

## Non-Goals

- Full config editor (auth, failsafe, etc.) -- keep CLI for advanced config
- Multi-user collaboration / RBAC on the UI (single-user tool)
- Custom CSS theming

## Architecture

### API Endpoints (new, under `/ui/api/`)

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/ui/api/backends` | GET | List all backends (existing) |
| `/ui/api/backends` | POST | Add backend `{name, command?, url?, env?, description?}` |
| `/ui/api/backends/:name` | DELETE | Remove backend by name |
| `/ui/api/backends/:name` | PATCH | Update backend config |
| `/ui/api/registry` | GET | List built-in server registry (48 entries) |
| `/ui/api/registry/search?q=` | GET | Search registry by keyword |
| `/ui/api/capabilities` | GET | List all capability YAML files |
| `/ui/api/capabilities/:name` | GET | Get single capability YAML content |
| `/ui/api/capabilities/:name` | PUT | Update capability YAML |
| `/ui/api/capabilities/:name` | DELETE | Delete capability file |
| `/ui/api/capabilities` | POST | Create new capability YAML |
| `/ui/api/import/openapi` | POST | Import OpenAPI spec `{url}` or `{spec: "yaml/json string"}` |
| `/ui/api/import/openapi/preview` | POST | Preview generated tools without saving |
| `/ui/api/reload` | POST | Trigger immediate config reload; returns `{status, changes, restart_required, restart_reason}` |

### UI Tabs (extend existing htmx app)

**Tab: Servers** (extend existing)
- Each server card gets Edit/Remove buttons
- "Add Server" button opens inline form:
  - Registry dropdown with search (autocomplete from 48 entries)
  - OR custom: name + command/URL + env vars
  - Submit -> POST `/ui/api/backends` -> auto-reload
- Remove -> confirmation dialog -> DELETE -> auto-reload

**Tab: Capabilities** (new)
- List all capability YAML files with tool count, description
- Click to expand -> shows YAML in editable textarea with syntax highlighting
- "New Capability" button -> template YAML pre-filled
- "Import OpenAPI" button -> modal:
  - URL input field (e.g. `https://petstore3.swagger.io/api/v3/openapi.json`)
  - "Preview" button -> shows generated tools in a checklist
  - User unchecks unwanted tools
  - "Import Selected" -> creates YAML files -> hot-reload
- Edit capability -> live YAML validation (client-side basic, server-side full AX-rules)
- Delete capability -> confirmation -> removes YAML file

**Tab: Tools** (extend existing)
- Add "Edit Source" link on each tool -> jumps to Capabilities tab with that YAML open

### YAML Editor

Lightweight, no heavy JS framework:
- `<textarea>` with monospace font and line numbers (CSS)
- Tab key inserts spaces (JS, ~10 lines)
- Basic YAML syntax error detection on blur (server-side POST to validate endpoint)
- "Save" button -> PUT to API -> shows validation result inline
- "Revert" button -> re-fetches original

### OpenAPI Import Flow

```
User pastes URL -> "Preview" ->
  Gateway fetches spec (via nab or reqwest) ->
  Runs existing `cap import` logic ->
  Returns list of generated tools with names/descriptions ->
  User selects which to keep (checkboxes, all selected by default) ->
  "Import" -> writes selected YAML files to capabilities/ dir ->
  Hot-reload triggers -> tools appear in Tools tab
```

### Security

- All management endpoints require admin auth (existing `is_admin()` check)
- YAML write operations validate against AX rules before saving
- OpenAPI URL fetch uses server-side request (no CORS issues)
- File writes restricted to configured `capabilities.directories` paths
- Path traversal prevention on capability names (sanitize to `[a-z0-9_-]`)

### State Management

- No new database or state files
- Backends: read/write `gateway.yaml` (same as CLI `add`/`remove`)
- Capabilities: read/write YAML files in capability directories
- Hot-reload after every supported write operation; restart-only changes stay on disk and are surfaced via `restart_required`

## Acceptance Criteria

1. **AC-1**: User can add a backend from the built-in registry via Web UI (select from dropdown, fill env vars, submit)
2. **AC-2**: User can add a custom backend (stdio command or HTTP URL) via Web UI
3. **AC-3**: User can remove a backend via Web UI with confirmation
4. **AC-4**: User can view and edit capability YAML files in the browser
5. **AC-5**: User can create new capability YAML files from a template
6. **AC-6**: User can delete capability YAML files with confirmation
7. **AC-7**: User can import an OpenAPI spec by URL with tool preview and selection
8. **AC-8**: YAML validation errors are shown inline before save
9. **AC-9**: All supported changes trigger hot-reload automatically, and restart-only changes are reported explicitly
10. **AC-10**: All management endpoints require admin authentication
11. **AC-11**: Path traversal is prevented on all file operations

## Technical Notes

- Existing `cap import` in `src/commands/cap.rs` handles OpenAPI parsing -- extract into a library function callable from HTTP handlers
- Existing `run_add_command`/`run_remove_command` operate on config files -- extract core logic into reusable functions (currently they're CLI-specific with `ExitCode` returns)
- htmx forms with `hx-post`/`hx-delete` keep the UI simple (no React/Vue needed)
- Registry data from `server_registry.rs` is already compiled in -- just needs a JSON endpoint
- Capability hot-reload uses the existing capability watcher; gateway config writes reuse `config_reload::ReloadContext`

## Estimated Scope

| Component | New Lines | Complexity |
|-----------|-----------|------------|
| API endpoints (8 new handlers) | ~400 | Medium |
| HTML/htmx UI additions | ~300 | Medium |
| YAML editor JS | ~50 | Low |
| OpenAPI preview flow | ~150 | Medium |
| Extract CLI logic to library | ~100 (refactor) | Low |
| Tests | ~200 | Medium |
| **Total** | **~1200** | |
