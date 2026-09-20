# Beyond compaction: making the tool surface earn its slots

Status: proposal, unreviewed. Target 4.1, except §3 which is 4.0.0-adjacent.
Prior work: `2026-09-16-meta-tool-surface-compaction.md` (built, green).

## 0. Where the compaction actually left us

The 17 -> 11 cut is capability-preserving by construction: every gated-off tool
stays dispatchable by name, proven by
`surface_compaction_tests::every_tool_the_cut_stops_listing_is_still_callable_by_name`.
That was the right move and it is finished. It is also the last cheap win on
that axis — the remaining eleven are each load-bearing for some caller.

Further reduction by deletion would cost capability. Further reduction by
gating has run out of honest gates. So the next order of magnitude has to come
from somewhere else: not fewer tools, but tools that carry more decision per
call.

## 1. The real surface is already two tools

`gateway_search` + `gateway_execute` span all 494 backend tools. `chain` inside
`gateway_execute` already subsumes `gateway_invoke` and `gateway_run_playbook`.
The other nine listed tools are operator plumbing, not model-facing capability.

Framed that way, the model-facing count is **2**, and the interesting question
stops being "how many" and becomes "how much does one call decide".

## 2. Server-side plans, not client-side loops (4.1)

`chain` today is a straight line: steps run in order, each may reference the
previous result. Every branch, every retry, every "if that returned empty, try
this instead" costs a full round trip to the model — seconds of latency and
thousands of tokens to re-establish context the gateway already holds.

Proposal: let a chain step carry a guard and an alternative. The model states
intent once; the gateway walks the graph locally. A local branch costs
microseconds against a round trip's seconds.

Deliberately out of scope: loops, user-defined functions, anything Turing
complete. A bounded directed graph with guards is the whole of it — a gateway
that can loop is a gateway that can hang, and the blast radius of a runaway
plan running with the caller's credentials is not worth the expressiveness.

Prerequisite already shipped: the interim-round seam (MRTR.12, `chain_interim.rs`)
means a chain can already report progress mid-flight, which is what makes a
longer server-side plan observable rather than opaque.

## 3. The surface should grow into the session (near-term)

Gating is keyed on operator configuration: profiles configured, playbooks
loaded, cost governance on. That is honest but static — every session of a
given deployment sees the same eleven.

The transport for something better already exists:
`broadcast_tools_list_changed()` (`src/gateway/router/mod.rs:175`) fans
`notifications/tools/list_changed` to connected clients. What does not exist is
a policy that uses it per session.

Proposal: open at the base four, and expand on demonstrated need — a caller
that invokes a gated tool by name, or whose search hits a gated capability,
gets that tool listed from then on. The mechanism is already there; only the
keying changes, from deployment to session.

Worth noting what this is not: it must never *hide* a tool a caller has used,
and it must stay inside the published 9..=17 band, which
`tests/nfr_perf_4_meta_tool_band.rs` already enforces universally.

## 4. The gateway is the only party that sees the label (4.1)

`RankingSignals::user_feedback` (`src/ranking/mod.rs:100-101`) is a boost from
"safe usage counters", weighted 0.02 (`:184`). That is a popularity prior, not
a relevance signal: it knows a tool gets called a lot, not that it was the
right answer to a particular question.

The gateway sees both halves of the pair — the search query, and which result
the model invoked next. That is a supervised relevance label, generated free,
and no other component in the stack can observe it. Today it is discarded.

Proposal: record (query, returned set, subsequently invoked tool) and let it
feed ranking as a query-conditioned term rather than a global counter. This is
the same objective `MIK-3274.RANKING.1`'s hand-tuned fuzzy scoring is reaching
for by hand, with the difference that traffic tunes it.

Privacy is the live constraint, not an afterthought: queries are caller
content. Per-session by default, aggregation only behind explicit operator
opt-in, and never across identity boundaries.

## 5. Why this ordering

§3 is cheap, uses a shipped mechanism, and is the only one worth weighing
against 4.0.0. §2 and §4 are 4.1: both want a design review before any code,
and §4 wants an operator ruling on aggregation before it collects anything.
