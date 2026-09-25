<!--
SPDX-FileCopyrightText: 2026 Mikko Parkkola
SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
-->

# F24: advertise only the change notifications the gateway delivers

**Defect.** `build_server_capabilities` (`src/gateway/meta_mcp_helpers.rs:206-210`) advertises
`resources.subscribe`, `resources.listChanged` and `prompts.listChanged` as `true` on every
surface. Nothing delivers `notifications/resources/updated`, `resources/list_changed` or
`prompts/list_changed`. The design note for the listen stream already says so
(`2026-08-29-subscriptions-listen-stream.md:89-92`). Backend notifications without a progress
token are dropped at `src/transport/stdio.rs:553-584`, and the HTTP decoder only forwards
notifications for a request still in flight. A client that subscribes waits forever and gets
no error.

**Tools: announced on some paths, not all.** `AppState::announce_tools_changed`
(`src/gateway/router/mod.rs:211-221`) reaches both eras: sessions on the pre-2026 GET stream
and `subscriptions/listen` listeners. Paths that change the tool set:

| Path | Where | Announced today |
|---|---|---|
| Admin UI add/remove backend | `ui/backends.rs:212,263` (writes config, reloads, then announces) | yes |
| Admin UI revive | `ui/backends.rs:295` | yes |
| Config-file reload adds, removes or modifies a backend | `config_reload/mod.rs:923-969` via `BackendRegistry::register`/`remove` | **no** |
| Capability file watcher reload | `capability/watcher.rs:159` | **no** |

`serve --stdio` has no producer wired to its stdout writer, which carries only progress
notifications. It advertises `listChanged: true` anyway.

**Decision.**

| Flag | HTTP, 2025 era (`initialize`) | HTTP, 2026 era (`server/discover`) | stdio (`initialize`, `server/discover`) |
|---|---|---|---|
| `tools.listChanged` | true | true | **false** |
| `resources.subscribe` | **false** | **false** | **false** |
| `resources.listChanged` | **false** | **false** | **false** |
| `prompts.listChanged` | **false** | **false** | **false** |

The `resources` and `prompts` objects stay, because their list, read and get methods are
served. `resources/subscribe` and `resources/unsubscribe` are refused (coordinator ruling,
2026-09-25; see below), so no subscription is accepted that would then wait for nothing.

**Wiring the missing producers.**
- One feed: an unbounded single-consumer channel of backend names, which the HTTP server
  drains into `announce_tools_changed`.
- `BackendRegistry::register` (on success) and `remove` (when an entry went) send on it. Every
  membership change goes through those two methods, including the UI's add and remove, which
  write the config and reload, so any new mutation path announces for free.
- The capability watcher sends after a reload that succeeded.
- The UI's add and remove drop their direct calls, so nothing announces twice. Revive keeps
  its own call, because it changes no registry entry.
- HTTP `tools.listChanged: true` therefore covers gateway membership, capability-file reloads
  and revive. A backend's own `notifications/tools/list_changed` stays dropped, as today;
  within a backend, the gateway's listing is refreshed from its metadata cache.

**Mechanism and tests.** One enum, `ChangeFeed { Http, None }`, selects the flag set. It is
passed into `handle_initialize` and `discover_document` and set at the four call sites: HTTP
`initialize`, HTTP `server/discover`, stdio `initialize` and stdio `server/discover`. The mode is
bound once, on `MetaMcp` when the HTTP server is built (stdio keeps the default, `None`), and `build_server_capabilities` reads it. The test
drives all four surfaces and compares against a flag set written literally in the test,
never read from production. Every flag a surface reports as true needs a delivery probe in
the same test file, one that fires the producer and sees the notification arrive. A flag
with no probe fails with "advertised, no delivery probe". Probes: reload add, reload remove,
reload modify and capability reload. Revive's direct announce is unchanged. Each must reach a `subscriptions/listen`
listener and a GET-stream session exactly once per action. The golden delta is derived from
the same literal per-surface sets.

**`resources/subscribe` and `resources/unsubscribe` are refused**, with `-32601`: "this gateway
does not deliver resources/updated". Forwarding them lets a client that ignores the flag
subscribe successfully and then wait forever, which is the defect itself. Failing fast is
the honest answer (breaking: item 52).

**Breaks.**
- The legacy `initialize` result is no longer byte-identical to 3.5.0. The MIK-7217 goldens
  stay as captured from 3.5.0. The test applies the documented three-flag delta before
  comparing. `nfr_compat_2` pins no capability flag, so it needs none. Recapturing would make
  the goldens agree with the change instead of pinning it.
- UPGRADING-4.0 item 52.
- Out of scope: capabilities a backend reports on the direct route `/mcp/{name}`, which are
  the backend's own.
