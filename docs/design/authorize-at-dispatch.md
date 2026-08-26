# Authorize at the dispatch chokepoint (MIK-7252)

## §P0 SCOPE

**FOR**: closing the path by which an internal orchestration caller reaches a
backend tool without the invoking caller's authorization checks running.

**OUT** (labelled, filed separately if raised):
- the router's own pre-check, its error envelopes, and the firewall hook
- admin gating of meta-tools (`is_admin_meta_tool`), already correct
- SSRF policy semantics, `trust_configured_backends` (MIK-3529 settled)
- rate limiting, cost budgets, identity grants — orthogonal controls
- the origin/Host gate and anonymous-admin work on this branch

## The defect

`authorize_tool_target` (`src/gateway/router/authorization.rs:105`) is the only
place the caller's backend scope, per-client tool scope, global tool policy,
mTLS policy and agent scope are checked. It is called from exactly two sites,
both in the router: `handlers.rs:547` and `backend_handlers.rs:82`.

The router decides WHICH targets to check with
`backend_tool_targets_for_call` (`authorization.rs:57`), which returns targets
for three shapes only — a surfaced tool, `gateway_invoke`, and
`gateway_execute`. Every other tool name returns an empty vector, and an empty
vector authorizes nothing.

`gateway_run_playbook` (`meta_mcp/mod.rs:1188`) is not one of the three. Its
steps reach `MetaMcp::invoke_tool` through `MetaMcpInvoker::invoke`
(`meta_mcp/support.rs:175`), and `invoke_tool_traced` performs only one
authorization check of its own — an admin gate on capabilities that register a
caller-addressed external destination (`invoke.rs:560`). Backend scope, tool
scope, tool policy, mTLS and agent scope are never consulted on that path.

`api_key_name` IS threaded down and is used for budget enforcement
(`invoke.rs:861`), provenance subject (`:1440`) and identity grants (`:1782`).
None of those is the client's backend/tool scope. **Carrying an identity that
the authorization checks never read is not a fix** — an earlier commit on this
branch claimed to close this ticket by threading that identity and was wrong.

## Unknowns, resolved before freezing this design

| question | what was run | answer | what it changed |
|---|---|---|---|
| Can the meta layer rebuild an `AuthenticatedClient` from `api_key_name`? | `rg` for a by-name lookup over `src/` | No such lookup exists; the value is produced by validating a presented credential (`auth.rs:333`) | Killed the "look it up at dispatch" option. The identity must be threaded, not recovered. |
| Are playbook step targets knowable before execution? | read `PlaybookStep` (`playbook.rs:86-104`) | `server` and `tool` are static strings; only `arguments` interpolate | A router-side pre-check IS possible — so the choice between patch and elimination is a real choice, not forced. |
| Does the code-mode chain have the same hole? | read `targets_from_code_mode_arguments` (`authorization.rs:209`) | No — it walks every `chain` step | Narrows the defect to the playbook path today, and shows the shape of the recurrence. |
| Would the check break working setups? | read `can_access_backend` (`auth.rs:366`), `check_tool_scope` (`auth.rs:378`) | Both default-permissive: empty backend list means all, absent allow/deny lists pass | UX risk is contained to clients that carry an explicit restriction, which is the population the check is for. |

## Options

**A — add `gateway_run_playbook` to `backend_tool_targets_for_call`.**
Smallest diff. Router walks the named playbook's steps and authorizes each.
Rejected: it is the patch, and the finding stays statable afterwards. The
defect is not "playbooks were forgotten", it is "authorization lives at the
router while dispatch lives in the meta layer, so every internal caller added
must remember to register itself". Code mode was the third such caller and was
remembered; the playbook was the fourth and was not. A fifth is a matter of
time. Rejected also because a step's `condition` can skip it, so the router
would authorize targets that never run — refusing a playbook for a step that
would not have executed is a UX regression invented by the fix.

**B — authorize inside `MetaMcpInvoker::invoke`.**
Fixes the playbook only. Same recurrence, one layer down. Rejected.

**C — authorize at the dispatch chokepoint (CHOSEN).**
`invoke_tool_traced` is the single point every backend invocation passes
through: router, surfaced tool, code-mode step, playbook step. Authorizing
there makes the finding unstatable — there is no path to a backend that skips
it, so no future caller can forget.

**D — a proof token (`AuthorizedTarget`) mintable only by the authorizer.**
Compile-time proof rather than runtime check. Stronger, and a larger diff:
every internal caller must obtain one, which is the same plumbing as C plus a
type. Deferred, not rejected — C's runtime check is what closes the hole, and
D can be layered later without redoing it.

## The design (C)

The meta layer cannot reach `AppState`, and must not hold it: `AppState` owns
`meta_mcp`, so storing an `Arc<AppState>` inside `MetaMcp` creates a reference
cycle that never frees. The authorization context is therefore **borrowed per
request, never stored**.

1. `MetaMcpCallerContext<'a>` gains `authorizer: &'a (dyn ToolAuthorizer + Sync)`.
2. `ToolAuthorizer` is a one-method port: `authorize(&self, server: &str, tool:
   &str) -> Result<(), AuthorizationError>`. The router's implementation
   captures `&AppState` plus the already-resolved `client`,
   `oauth_agent_identity` and `cert_identity`, and calls the existing
   `authorize_tool_target` unchanged. No authorization logic is duplicated or
   rewritten — it is the same function, reached from one more place.
3. `invoke_tool` takes `&MetaMcpCallerContext<'_>` instead of five loose
   parameters. The existing comment declining that refactor cites "no
   behavioural gain"; there is one now, and the parameter count drops.
4. `invoke_tool_traced` calls `caller.authorizer.authorize(server, tool)` after
   `server` and `tool` are extracted and before any dispatch, cache read,
   idempotency write or budget spend.
5. `run_playbook` passes the caller context into `MetaMcpInvoker`, so each step
   is authorized against the invoking caller at the moment it actually runs —
   after its `condition` has been evaluated.

**No `Option`, no default.** A missing authorizer cannot be represented, so the
guard cannot be silently absent. Tests that have no policy pass an explicit
`AllowAll`, visible in the test source rather than hidden in a struct default.

**The router keeps its pre-check.** It is now redundant for backend targets and
is retained deliberately: it produces the JSON-RPC error envelope clients
already receive, and it is where the firewall request scan hangs. Two layers
disagreeing is not possible — both call the same function with the same inputs.

## Acceptance criteria

- MIK.AUTHZ.1 A playbook step targeting a backend outside the caller's
  `backends` list is refused, and the refusal names the backend.
- MIK.AUTHZ.2 A playbook step targeting a tool outside the caller's
  `allowed_tools` is refused.
- MIK.AUTHZ.3 A playbook step hitting a tool blocked by global tool policy is
  refused.
- MIK.AUTHZ.4 An operator (admin, unrestricted) runs the same playbook
  unchanged — no new refusal.
- MIK.AUTHZ.5 A client with no explicit restrictions runs the same playbook
  unchanged — the default-permissive path is not narrowed.
- MIK.AUTHZ.6 A step skipped by its `condition` is never authorized, so an
  unreachable step cannot refuse the playbook.
- MIK.AUTHZ.7 The refusal happens before dispatch: no backend call, no cache
  write, no budget spend for a refused step.
- MIK.AUTHZ.8 The direct `gateway_invoke` and code-mode paths keep their
  current behaviour, refusal messages included.
- MIK.AUTHZ.9 Every construction of a served `MetaMcp` carries a real
  authorizer; `AllowAll` appears only in tests.
