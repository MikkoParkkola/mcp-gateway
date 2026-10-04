# MIK-7883: the judge scans the document that is emitted

Status: proposed, 2026-10-03. Scope: `src/gateway/outbound/judge.rs`, `src/gateway/outbound/stream.rs`, `src/gateway/streaming.rs`.

## Problem

The cross-tenant read judge (design section 4) is meant to scan "the whole emitted document of every payload, minus the top-level `jsonrpc` and `id`". Four paths scan something else:

1. A `Response` is scanned as separate pieces: `result`, `error.data` and `error.message` as bare values. The wrapper members (`error`, `message`, `code`, `data`) are never seen as member names.
2. A `Notification` is scanned as `params` values plus `method` as bare text, so its member names are never seen.
3. A GET-stream item that is not a `message` event is written as the whole tagged notification (`source`, `event_type`, `data`, `event_id`), but `admit_stream_item` receives only `data` and `event_type`. `source` and `event_id` are never scanned.
4. `cacheScope` is clamped when the frame is serialized, after the scan.

The `Answer`, `Request`, `Callback` and `Event` payloads already use `scan_document`, which matches a configured `arg_keys` name against member names and walks the children.

Reachable only with `arg_keys` configured, the mode not `off`, and an `arg_keys` entry equal to one of those wrapper members. When reachable the control fails open.

## Design

One helper builds the document the judge scans from the same value the sink serializes, and the document scan is added to the existing scan, not substituted for it (design seats, 2026-10-03):

- `emitted_document(&Payload) -> Option<Value>`: a `Response` and a `Notification` become their serialized JSON object (the same `Serialize` the sink uses, so a new field is in the scan by default). Other payloads keep their value as today. The `Callback` exception stays: its `data` member carries pre-redaction attribution and is excluded, as `scan` does now, because rescanning a redaction marker reads as a tenant of its own.
- `scan` for `Response` and `Notification` unions two scans: the existing piecewise scan of the raw `result`, `error.data`, `error.message`, `params` and `method` (unclamped, so no attribution that exists today is lost), and `scan_document(&doc, &["jsonrpc", "id"])` over the serialized document, which adds the wrapper member names.
- The serialized response is already clamped (`serialize_delivered_result` rewrites a non-`private` `cacheScope` to `"private"`). The gateway wrote that `"private"`, so it is not evidence and must name no tenant: `emitted_document` puts the raw `result` and `error.data` back into the serialized document before scanning. The document then carries the wrapper member names and exactly what the backend sent, so with `cacheScope` as a configured key a delivery of `{"cacheScope": B}` attributes exactly B, never B and `private`. The clamp cannot hide a tenant for the same reason.
- `admit_stream_item` also scans the whole tagged notification for a non-message event (`source`, `event_id`, `event_type`, `data`), unioned with the `data` scan it does now. A `message` event keeps scanning its `data`.

A test enumerates the `Payload` variants and fails when a new variant has no row, so a new payload cannot bypass the scan.

## Compatibility

- Judging ignores the tenant guard's `enabled` flag: it runs when `arg_keys` is set and the mode is not `off`. Deployments affected: those whose `arg_keys` contain a wrapper member name (`message`, `method`, `source`, `event_id`, `result`, `error`, `code`, `data`, `params`, `cacheScope`).
- `source` and `event_id` are strings; the scan decodes JSON inside strings, so a JSON-looking `source` or `event_id` containing an ordinary configured key now attributes. This only matters when such a value is emitted.

## Acceptance mapping

- SCAN.1: `a_non_message_event_is_judged_with_its_wrapper_fields` (stream level).
- SCAN.2: `wrapper_members_of_an_error_and_a_notification_are_scanned` (judge level).
- SCAN.3: `a_clamped_cache_scope_cannot_hide_a_tenant` (a proof-by-test pin, not a red test: it passes before and after, and asserts the attribution is exactly the original tenant, never the clamp's `private`).
- SCAN.4: the shared helper plus a variant-enumeration test, added with the fix.

## Risks

- Scan cost: one serialization to a `Value` per judged `Response`/`Notification`, only when judging (default off).
