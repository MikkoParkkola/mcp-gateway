# MIK-7084 — tiered `gateway_search` disclosure

FOR: cut unusable ranking telemetry and stop paying invocation-detail
cost at the selection step. OUT: ranking algorithm, `gateway_search_tools`
L0/L1/L2 ladder, OpenViking source (concept only).

Ticket ACs `MIK.GW.T1`–`T6` are the spec. Decisions the ticket did not
name, recorded here because they change the wire:

| decision | choice | rejected |
|---|---|---|
| `detail` vs `include_schema` both set | `detail` wins | OR-ing `include_schema=true` up to L2 (surprising when the caller named a tier) |
| omitted `include_schema` | L0 | keep old default `true` (fights T1) |
| explicit `include_schema=true` | L2 | ignore it |
| explicit `include_schema=false` | L0 | a phantom "L1-without-schema" |
| L0 fields | `tool`, one-line `description`, `score` | `status`, `ranking`, schema |
| L1 extras | `when_to_use`, `required`, `signature`; `status` if present | full `input_schema` |
| `explain` default | false; T3 also on `gateway_search_tools` | leave the blob on the older meta-tool |
| glob path | no `score` (ranker skipped, as today) | fake `1.0` |
| one-line purpose | first sentence, keywords suffix stripped, max 120 chars | raw 500-char description |
| `when_to_use` | first paragraph, max 280 chars | copy the full description |

T3 fail-fast (lean `include_schema=false` payload, limit 2): ranking blob
is ~50–76% of the response depending on description length. Not far
below the ticket's ~60%. Ladder proceeds.
