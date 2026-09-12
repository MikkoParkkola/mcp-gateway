# Stdio inbound request bridging

> **DO NOT IMPLEMENT — §5 targets the wrong module.**
> §5 describes the new `ClientChannel` implementation as wrapping or extending
> `StdioTransport`. That is the wrong direction. `src/transport/stdio.rs:5,161,178`
> spawns an MCP server as a *child process* and dials **out** to backends. The
> requirement here is inbound: the gateway answering its own client while its serve
> loop reads. The `NoClientChannel` sites this design cites
> (`src/gateway/server/mod.rs:2339,2933`) sit in that inbound serving path, whose loop
> is `run_stdio` at `src/gateway/server/mod.rs:1566`, reading `tokio::io::stdin()` at
> `:1640`. Any file:line in this document pointing at `src/transport/stdio.rs` — the
> routing point, the writer mutex — describes the outbound backend transport and does
> not apply. Re-source §5 against `run_stdio` before this document is reviewed again.
>
> `src/gateway/meta_mcp/invoke.rs:1888` names MIK-7387 as the only thing that lifts the
> deliberate stdio refusal, and pins the two halves separately: read that arm first.
>
> **The gap, stated precisely (verified at source).** The bridge is not unwired. It is
> constructed and driven in production: `src/gateway/meta_mcp/invoke.rs:1842` builds an
> `InputBridge` inside `invoke_tool_traced` (`:1079`) and `:1852` calls `bridge.run(...)`,
> with no `#[cfg(test)]` above either. What the stdio path lacks is a channel. That
> construction passes `channel: caller.channel`, and on the stdio serving sites
> (`src/gateway/server/mod.rs:2339,2933`) `caller.channel` is `NoClientChannel`, whose
> refusal is deliberate. `ProxyManager` implements `ClientChannel`
> (`src/gateway/proxy.rs:529`) but is HTTP-only. So the work is to implement
> `ClientChannel` over the `run_stdio` loop's writer and pass it at those two sites --
> not to give an orphaned bridge a caller.


Status: design, not implemented.

## 1. What is required

`docs/requirements/RELEASE-4.0.0-scope-update.md:33-35`:

> | MIK-7387.STDIO.1 | A declared client input request reaches a legacy stdio client, whose answer reaches the backend while the gateway continues reading. | BRIDGE |
> | MIK-7387.STDIO.2 | An input request cannot overtake the initialize response on legacy stdio. | BRIDGE |
> | MIK-7387.STDIO.3 | Concurrent stdio requests and replies emit complete, non-interleaved JSON frames. | BRIDGE |

`docs/requirements/RELEASE-4.0.0-scope-tests.md:15-17`:

> | MIK-7387.STDIO.1 | Enable the existing real-stdio AC in tests/mik_7212_mrtr7_stdio_acs.rs; assert the client's answer reaches the backend, not merely that a timeout returns. |
> | MIK-7387.STDIO.2 | Hold initialize write completion while a bridge request becomes ready; observe initialize first, then the input request. |
> | MIK-7387.STDIO.3 | Concurrent peer exchanges share the real writer; parse each emitted line independently and assert expected complete frames and correlation. |

Nothing beyond these six lines is required by this design.

## 2. The invariant this design preserves

`StdioTransport::handle_response` (`src/transport/stdio.rs:499-511`) refuses any inbound
`JsonRpcMessage::Request` it receives, because routing one into the pending-response map
would answer a waiting caller with a frame carrying neither `result` nor `error`.
`handle_response_rejects_inbound_request_and_leaves_caller_pending`
(`src/transport/stdio.rs:850-869`) pins this: a frame carrying `method` must not be treated
as a response, and the caller whose id it reused must stay pending, not be silently
completed.

This is correct and this design does not touch it. `handle_response` has exactly one
caller — the reader loop in `start()` (`src/transport/stdio.rs:234`) — and in production
that loop is the only source of inbound Requests it can ever see. The fix moves where a
Request is recognized, not what `handle_response` does with one it is handed.

## 3. The routing point

The read loop today (`src/transport/stdio.rs:226-247`) reads one line and hands it to
`handle_response` unconditionally:

```rust
Ok(Some(line)) => {
    ...
    if let Err(e) = transport.handle_response(&line) {
        error!(error = %e, line = %line, "Failed to handle response");
    }
}
```

`handle_response` does its own `serde_json::from_str::<JsonRpcMessage>(line)` and matches
on the result. The routing point is this call site: parse the line here first, and only
call `handle_response` on the `Response` and `Notification` cases. A `Request` case is
handed to the new bridging path instead of ever reaching `handle_response`.

**Smaller diff: parse the line twice, at both sites, rather than restructure
`handle_response` to take a parsed `JsonRpcMessage`.** `handle_response` has fourteen call
sites in its own test module (`src/transport/stdio.rs:826, 840, 858, 877, 885, 896, 906,
1204, 1220, 1261, 1278, 1327, 1354`, plus `906` which asserts on invalid JSON), every one
passing a raw `&str` line and asserting against `handle_response`'s `Result<()>` return.
Changing its signature to accept a `JsonRpcMessage` forces every one of those tests to
parse the JSON itself before calling in, for no behavioural gain — none of them exercise
the routing decision, they exercise what `handle_response` does with a message it has
already been handed. A second `serde_json::from_str` in the read loop is one parse of one
line on a path that already does a `BufReader::next_line().await` per message; it is not a
measurable cost here. `handle_response` keeps its current signature and test surface
unchanged.

The read loop becomes: parse the line; on `Request`, spawn (or hand to) the bridging path
described in §5 and continue the loop without calling `handle_response`; on `Response` or
`Notification`, pass the original line to `handle_response` exactly as today, so its own
parse and its own match arms are unchanged and its refusal arm becomes dead code reachable
only if this design's own routing is wrong — which is what its test continues to guard
against.

## 4. Writer-side concurrency

STDIO.3 requires concurrent peer exchanges to share the real writer and emit complete,
non-interleaved frames. This already exists and needs no sibling: `write_message`
(`src/transport/stdio.rs:532-553`) takes `self.writer.lock().await` — a `tokio::sync::Mutex`
— and holds it across both `write_all` calls (payload, then `\n`) and the `flush`, only
releasing it once the frame is fully on the wire. Any two callers of `write_message`,
however they got there, cannot interleave partial frames; the second caller's lock
acquisition simply waits for the first frame to finish. A bridged answer going out to the
backend, and an ordinary outbound `request()` call, or a second concurrent bridged answer,
compose correctly through this one path with no new synchronization primitive.

`PendingRequestGuard` (`src/transport/mod.rs:185`, used at `src/transport/stdio.rs:659` and
`:744`) is a different mechanism and is not writer-side concurrency: it is an RAII guard
over one entry in the *pending-response map*, dropped to release that entry on every exit
path including cancellation (`cancelled_request_does_not_strand_pending_entry`,
`src/transport/stdio.rs:960`). It is the correct shape to mirror for the bridge's own
pending state (§5), not for the writer.

## 5. How the client is reached

`InputBridge` (`src/gateway/input_bridge.rs:361-370`) reaches a client through a
`&dyn ClientChannel` field — it is already transport-agnostic; `InputBridge::run` needs no
new method and no change. What stdio has today is `NoClientChannel`
(`src/gateway/input_bridge.rs:323-337`), wired at both stdio caller sites in
`src/gateway/server/mod.rs:2339` and `:2933`, which unconditionally returns
`DeliveryError::NoSession`. Its own doc comment states this is provisional: "Refusing here
is also what MIK-7387 will change: until it lands, an initialized stdio caller stays
refused."

This is a new caller, not a new method: implement `ClientChannel` for a stdio-backed type
(wrapping or extending `StdioTransport`) whose `send_request(session_id, id, method,
params)` mints a request frame, sends it through `write_message` (§4), and awaits the
reply through the same pending-map/oneshot-channel mechanism `Transport::request`
(`src/transport/stdio.rs:632-670`) already uses for gateway-originated calls — the
`ClientChannel` trait's own doc comment (`src/gateway/input_bridge.rs:291-296`) names
`PendingRequestGuard` as the exact shape to hold across the awaited send, for the same
cancellation reason described in §4. The two `NoClientChannel` wiring sites in
`src/gateway/server/mod.rs` are replaced with this implementation when a stdio-connected
caller is what production has.

## 6. Explicitly out of scope

- Any change to `handle_response`'s refusal behaviour or its pinning test (§2).
- A second writer synchronization mechanism (§4) — `write_message`'s existing mutex covers
  every caller.
- `InputBridge::run` or the `ClientChannel`/`BackendInvoker`/`BridgeObserver` trait
  definitions in `src/gateway/input_bridge.rs` — unchanged; only a new implementer of
  `ClientChannel` is added.
- The HTTP `ClientChannel` implementation, `ProxyManager`, and anything under
  `src/transport/http/`.
- `NFR.COMPAT.1`'s stdio protocol-revision question and the `is_admin: true` stdio grant —
  both out under `docs/design/2026-09-02-cluster-g-stdio-dispatch-parity.md`'s OUT list and
  not reopened here.

## 7. The three ignored tests

- `ac_mrtr_7a_stdio_client_answers_while_serve_loop_reads`
  (`tests/mik_7212_mrtr7_stdio_acs.rs:356`) — assertions are correct as written for this
  design: it exercises exactly the read-loop routing decision in §3 and the `ClientChannel`
  path in §5.
- `ac_mrtr_7a_bridged_request_follows_the_initialize_response`
  (`tests/mik_7212_mrtr7_stdio_acs.rs:420`) — assertions are correct as written; ordering
  falls out of the read loop being sequential per line (§3) with no reordering introduced by
  this design.
- `ac_mrtr_7a_concurrent_bridged_requests_write_whole_frames`
  (`tests/mik_7212_mrtr7_stdio_acs.rs:470`) — assertions are correct as written; satisfied by
  the existing `write_message` mutex in §4 with no new mechanism.

## Pending revisions (drafted, not yet applied)

Six review fixes are outstanding. Four were drafted but never written into the text
above; the fifth and sixth are superseded by the module correction in the banner.

1. **Commit to spawn-per-request.** §3 currently says "spawn (or hand to)". Awaiting
   bridge capacity on the read loop stalls STDIO.1. Apply backpressure through
   `InputBridge`'s own timeout rather than an unbounded spawn.
2. **Order initialize ahead of concurrent dispatch.** The initialize dispatch and its
   client-facing response write must both complete before any concurrent dispatch
   begins. Gate this through the existing init phase, activated when routing activates.
3. **Namespace bridge ids.** Use the peer-supplied id on the reply frame, kept disjoint
   from the outbound counter that `next_id` advances.
4. **Keep malformed-line handling as log-and-continue.** The §3 path must not change
   this existing semantics.
5. **Make single-writer structural** — re-source against `run_stdio` first; the writer
   mutex cited in §4 belongs to the outbound backend transport.
6. **Fix the test section** — one test reference is duplicated, and a test-only call
   site is described as production wiring.
