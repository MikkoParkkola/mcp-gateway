# Meta-tool exposure control (GH issue 449)

Status: proposed · Release 4.0.0 increment · Author: teammate agent

## Problem

An operator cannot trim which `gateway_*` meta-tools appear in `tools/list`.
Every deployment gets the same roster, so a gateway fronting three read-only
backends still advertises `gateway_kill_server` and `gateway_revive_server`.

## What the issue asks for, verified against the tree

| # | Desired behaviour | Verdict |
|---|---|---|
| 1 | Operator trims the listed meta-tool set | **ABSENT** — this increment |
| 2 | Per-API-key meta-tool sets (`auth.api_keys[].meta_tools`) | **OUT** — see below |
| 3 | Destructive meta-tools admin-only by default | **MET** (with a deliberate deviation) |

### #3 is already built — do not rebuild it

`ADMIN_META_TOOLS` (`src/gateway/router/authorization.rs:66`) covers
`gateway_kill_server`, `gateway_revive_server`, `gateway_reload_config`,
`gateway_reload_capabilities`. `require_admin_tool_access`
(`authorization.rs:77`) rejects with `-32600` and
`"Tool '{tool_name}' requires admin access"`. It is enforced twice: at the
router, and again at dispatch (`src/gateway/meta_mcp/mod.rs:1275`) so no entry
point can bypass it — the comment at `mod.rs:1260-1274` records that the
second gate was added after a live stdio defect.

**Deliberate deviation, stated as one:** the issue also names
`gateway_set_state`. The code excludes it, and excludes `gateway_set_profile`,
on the recorded grounds that both are session-local. The test
`anonymous_denied_admin_meta_tools` (`src/gateway/router/tests.rs:2059`)
*asserts* they stay out. This increment does not move them; reversing that
decision belongs to whoever owns `authorization.rs`.

### #2 is out of scope, and it is not nearly free

Per-key sets need a new `auth.api_keys[].meta_tools` field, and then the
authenticated caller threaded into the `tools/list` path — which today takes
only `(&self, id, session_id)` (`meta_mcp/mod.rs:1131`) and has no caller
identity to consult. That is a signature change in a file this change does not
own, for a control the admin gate already covers on the destructive subset.

## Decisions

### Allow-list, not deny-list

`exposed_meta_tools: Vec<String>`; empty or omitted means expose everything, so
existing deployments are untouched.

A deny-list fails **open**: ship a new destructive meta-tool and every operator
who wrote a deny-list is exposed to it until they edit their config. An
allow-list fails **closed**: the new tool is hidden from operators who set a
list, and they must opt in. For a surface whose whole point is reducing what a
model can reach, failing closed is the correct trade — and the cost is real and
accepted: a meta-tool added in 4.1 will be invisible to anyone pinning a list.

### Unknown names warn, they do not abort startup

Precedent is `with_surfaced_tools` (`src/gateway/meta_mcp/surfaced.rs:31-33`),
verbatim: *"Validation failures are logged as warnings rather than panics so the
gateway always starts — misconfigured surfaced tools are simply dropped."*
`src/gateway/server/mod.rs:825-834` warns the same way. A typo must not take a
production gateway down.

The asymmetry is worth one extra warning. A dropped `surfaced_tools` entry costs
one pinned tool. A typo in an allow-list that was supposed to name
`gateway_invoke` yields a gateway that can list backends and invoke nothing. So:
warn per unrecognised name, **and** warn separately when a non-empty list omits
`gateway_invoke`. Warnings, not errors.

### One predicate, consumed by both paths

Hiding a tool from `tools/list` while still executing it is security theatre.
There is exactly one predicate — `MetaToolExposure::is_exposed(name)` — and the
listed set is *derived from* it rather than maintained beside it:

- list path: `build_meta_tools_filtered` = `build_meta_tools(..)` piped through
  `is_exposed`. The two cannot disagree, because one is the other's output.
- call path: the same `is_exposed`, before the `match tool_name`.

`build_meta_tools` keeps its existing six-argument form and delegates with
`MetaToolExposure::expose_all()`, so the tree compiles at this commit with
`meta_mcp/mod.rs` untouched.

### Scope of the predicate: only tools it can list

`is_exposed` returns `true` for any name outside the set `build_meta_tools`
produces. That single rule settles two things that would otherwise be silent
breakage:

- **Surfaced tools** (`meta_mcp/mod.rs:1284`) are backend tools, not meta-tools;
  an operator's meta-tool list has nothing to say about them.
- **Code Mode** (`mod.rs:1137`) replaces the surface with two fixed tools,
  `gateway_search` and `gateway_execute`. Neither is produced by
  `build_meta_tools`, so Code Mode's surface is unaffected. Out of scope,
  deliberately: a two-tool surface is already minimal.

### Error shape for a hidden tool: identical to a name that does not exist

The fallback arm (`mod.rs:1328-1355`) returns `-32601` with
`"Unknown tool: {tool_name}"`, plus a `did_you_mean` hint when one is close.

A hidden tool returns `-32601` and `"Unknown tool: {tool_name}"` **with no
hint**. Running the hint against the roster would match the hidden name exactly
and answer *"did you mean gateway_kill_server?"* — an oracle confirming the tool
exists and is merely concealed. A distinct "hidden" error code would leak the
same fact.

## Drift hazard found (scope-relevant, not fixed here)

The 19-name meta-tool roster is hard-coded **three** times:

1. `META_TOOL_NAMES` — `src/gateway/meta_mcp/surfaced.rs:37-56`
2. inline `META_TOOLS` — `src/gateway/meta_mcp/mod.rs:1329-1349`
3. implicitly, the push order of `build_meta_tools` — `meta_mcp_tool_defs.rs:543`

Copies 1 and 2 already list `gateway_search` and `gateway_execute`, which
`build_meta_tools` never produces — they are Code Mode tools. The copies have
drifted from the builder.

This change therefore derives its known-name set from the builder
(`known_meta_tool_names()`) rather than minting a fourth copy. Collapsing the
existing three is a separate change in files this one does not own.

## Wiring diff — `src/gateway/meta_mcp/mod.rs` (not applied here)

Three hunks. The field default keeps a partially applied diff behaving as today.

```diff
@@ struct MetaMcp fields (~251-258)
     surfaced_tools: Vec<SurfacedToolConfig>,
     surfaced_tools_map: HashMap<String, String>,
+    /// Which meta-tools this gateway exposes. Governs `tools/list` and
+    /// `tools/call` through one predicate so they cannot disagree.
+    meta_tool_exposure: crate::gateway::meta_mcp_tool_defs::MetaToolExposure,

@@ constructor (~418-419)
     surfaced_tools: Vec::new(),
     surfaced_tools_map: HashMap::new(),
+    meta_tool_exposure:
+        crate::gateway::meta_mcp_tool_defs::MetaToolExposure::expose_all(),

@@ handle_tools_list_for_session (~1140-1147)
-            build_meta_tools(
+            build_meta_tools_filtered(
                 self.stats.is_some(),
                 self.get_webhook_registry().is_some(),
                 self.get_reload_context().is_some(),
                 true,
                 tool_count,
                 server_count,
+                &self.meta_tool_exposure,
             )

@@ handle_tools_call, after the surfaced-tools check (~1284), before `match tool_name`
+        // Same predicate as the list path: a meta-tool the operator hid is
+        // indistinguishable from one that does not exist. No did_you_mean hint
+        // here — it would confirm the hidden tool's existence.
+        if !self.meta_tool_exposure.is_exposed(tool_name) {
+            return Err(Error::json_rpc(
+                -32601,
+                format!("Unknown tool: {tool_name}"),
+            ));
+        }
```

Placement: **after** the surfaced-tools lookup at `1284`, so a pinned backend
tool is dispatched before the meta-tool predicate is ever consulted; and after
the admin gate at `1275`, so an admin-only tool still reports the admin error
rather than being masked as absent.

Builder side: `MetaMcp` is constructed from `MetaMcpConfig`, so the constructor
line becomes `MetaToolExposure::from_names(&config.exposed_meta_tools)` wherever
the config is available.

## Acceptance criteria

| ID | Criterion |
|---|---|
| 449.EXPOSE.1 | Empty/omitted `exposed_meta_tools` lists exactly today's roster |
| 449.EXPOSE.2 | A non-empty list yields only the named tools in `tools/list` |
| 449.EXPOSE.3 | `is_exposed` is false for an omitted tool and true for a named one |
| 449.EXPOSE.4 | A name outside the builder's roster is exposed (surfaced tools unaffected); every name a builder produces, Code Mode's included, is governed |
| 449.EXPOSE.5 | An unrecognised configured name is dropped, not fatal |
| 449.EXPOSE.6 | `build_meta_tools` (unfiltered) behaviour is unchanged |
| 449.EXPOSE.7 | `MetaMcpConfig::default()` exposes everything |

## Unknowns

Resolved. *Does a signature change to `build_meta_tools` break the tree?* —
read `meta_mcp/mod.rs:1131-1148`; it is the sole caller and is owned by another
agent; answer changed the design to an additive `build_meta_tools_filtered`.
*What does the call path return for a name it does not know?* — read
`mod.rs:1328-1355`; `-32601` + `Unknown tool:`; answer set the hidden-tool error
shape and removed the hint.

Deferred: none.

## Reviewed — 2026-08-31: the approach changes

Both vendors returned SHIP-WITH-FIXES and both rejected the shape, not the
details. The allow-list is withdrawn. Every acceptance criterion above
(449.EXPOSE.1-7) is superseded; they specify a mechanism that is being removed.

The issue reports two problems wearing one coat. "A general agent must not call
`gateway_kill_server`" is an **authorization** question, and it is already
answered: `ADMIN_META_TOOLS` and `require_admin_tool_access`
(`gateway/router/authorization.rs:66-89`), covered by
`meta_mcp_management_tool_requires_admin_client` and
`anonymous_denied_admin_meta_tools`. Omitting a tool from a list a client can
still call is obscurity, not a control. "Seventeen tools when five would do" is
a **visibility** question. A deployment-wide name list answers neither: it
cannot say "the agent key does not see this, the operator key does", which is
precisely the reporter's deployment, and set to the issue's own five-name
example it takes the management tools away from the operator too.

Listing is therefore derived, from two axes that already exist:

1. **Per-caller.** `tools/list` advertises what this principal may invoke.
   Reuse `ADMIN_META_TOOLS` — the same predicate that already rejects the call —
   so hidden and un-callable are one decision rather than two that can drift.
2. **Per-deployment.** Stop pushing `run_playbook`, the three profile tools and
   `set_state` unconditionally (`meta_mcp_tool_defs.rs:561-570`). List them when
   playbooks, routing profiles or session states are actually configured, the
   way `stats`, `webhooks`, `reload` and `cost_report` already work twelve lines
   above. A read-only three-backend gateway then advertises about five tools
   with no new configuration — the reporter's example, reached by deleting code.

`exposed_meta_tools`, `MetaToolExposure` and `from_names` are deleted. No new
config field ships. An operator wanting to hide a tool from an *admin* key
purely for token economy has no lever, and that is accepted for now: the moment
authorization owns the security half, such a knob is an ergonomics preference,
and an ergonomics preference must fail **open** — an allow-list silently
withholds every later release's new tools until someone edits config. If the
need is demonstrated, it returns as a deny-list over groups (core, stats,
session, ops, admin), never over names.

### Findings carried forward

- **The guides advertise what the list hides.** `meta_mcp/resources.rs:148-157`
  names `gateway_kill_server`, `gateway_revive_server` and the profile verbs in
  prose that is always served. An agent that never sees the tool still learns
  the verb and tries it. The guide sections are built from the same predicate as
  the list, or dropped when the tools are not advertised. Without this the whole
  change is cosmetic.
- **Three rosters drift.** `META_TOOL_NAMES`, the inline `META_TOOLS` table and
  `build_meta_tools` are hand-maintained copies, and two already name Code Mode
  tools the traditional builder never emits. One authoritative set, consumed by
  definitions, collision checks, suggestions and the admin gate.
- **Ordering.** The design ran the admin gate before the exposure check, so a
  hidden admin tool answered "requires admin access" and confirmed its own
  existence. Derived listing dissolves the question: there is one predicate.
- **`from_names` fails closed, not open, and neither is right.** A non-empty
  list whose names are all typos filters to an empty allowed set, so a running
  gateway lists and invokes nothing. Moot under deletion; recorded because the
  reviewers disagreed about the direction and the source settled it.
- **The wiring could not compile.** The snippet returned `Err(...)` from
  `handle_tools_call`, whose return type is `JsonRpcResponse`
  (`meta_mcp/mod.rs:1259`). Moot under deletion.

### Acceptance criteria (superseding 449.EXPOSE.1-7)

| ID | Criterion |
|---|---|
| 449.DERIVE.1 | A non-admin caller's `tools/list` omits every tool in `ADMIN_META_TOOLS` |
| 449.DERIVE.2 | An admin caller's `tools/list` is unchanged from today's roster |
| 449.DERIVE.3 | A tool omitted from a caller's list is rejected on call for that caller |
| 449.DERIVE.4 | `run_playbook` is listed only when playbooks are configured |
| 449.DERIVE.5 | The profile tools are listed only when routing profiles are configured |
| 449.DERIVE.6 | `set_state` is listed only when session states are configured |
| 449.DERIVE.7 | A read-only gateway with none of the above advertises the core surface only |
| 449.DERIVE.8 | The routing guide resource omits kill-switch and profile prose when those tools are not advertised for the caller |
| 449.DERIVE.9 | Adding a tool to `ADMIN_META_TOOLS` changes both list and call behaviour with no second edit |
