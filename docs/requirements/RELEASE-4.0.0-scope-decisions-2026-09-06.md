# Scope decisions from the operator conversation

This ordinary-message record supplements the generated question-tool table in
[operator decisions](RELEASE-4.0.0-operator-decisions.md). Do not insert these
messages into that generated table or invent question-tool selections for them.
Source: the Codex conversation that located Claude's active mcp-gateway worktree
and reviewed release scope on 2026-09-06. The exact user messages below are the
approval evidence; the linked scope document is the engineering interpretation.

## Accepted safety additions

The user wrote:

> are there any other scoping decisions to do? I want 4.0 to be a strong release that lifts the capabilities with a leap. any open tickets or issues to include? I agree your earlier recommended additions

This approves GitHub #462 and #452, the gateway slice of MIK-7377, resolving
MIK-7334's cache boundary, and the missing conformance/performance/release gates.
It does not say those implementations are complete.

## Accepted capability expansion

After the recommendation to include full stdio bridging, full tasks with the
stated recovery behavior, MIK-6744/6745 personal-account fallback, MIK-3274
discovery, and MIK-7235/6710 companions, the user wrote:

> yes, agree. ask me one question at a time if there are some decisions or scoping clarifications needed. otherwise please update docs, plans, tests, etc that would not conflict with the active claude agent's work

The [scope update](RELEASE-4.0.0-scope-update.md) records those approved outcomes.
The [delivery plan](RELEASE-4.0.0-scope-delivery.md) handles design details and
in-flight ownership without treating ordinary implementation choices as new
operator approvals.

## Reference personal-account journey

Status: resolved. The offered journeys were Open WebUI → gateway → Google
Workspace and Claude Code → gateway → Google Workspace, with Open WebUI
recommended to prove the shared-user experience. The user selected it:

> yes, I think we should have openwebui installed on spark?

The required reference journey is **Open WebUI on Spark → gateway → Google
Workspace**, using two separate personal accounts and an unconnected user.
The Spark installation was verified read-only on 2026-09-06: Open WebUI reports
version 0.9.6, its Docker health is healthy, and `http://spark:8090/health`
returns HTTP 200 with `{"status":true}`. The `airlok-mcpo` and
`airlok-mcpo-system` containers are also running.

Existing installation resolves the environment choice; it does not prove the
gateway connection, adapter identity propagation or account isolation. Record
and pin the actual client/adapter versions and route used for acceptance before
running the real-client tests. No installation, restart or configuration change
was needed to establish this baseline.
