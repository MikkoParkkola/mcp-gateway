<!--
SPDX-FileCopyrightText: 2026 Mikko Parkkola
SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
-->

# Backup, restore and key rotation

This runbook covers what a 4.0 gateway keeps on disk, what to back up, how to restore it, and
how to rotate the keys and secrets it holds. The gateway uses no database, but it keeps state
in files. Some of those files can't be recreated, and without their keys they can't be read.

## Where state lives

The data directory is `$MCP_GATEWAY_CONFIG_DIR` when set, otherwise `~/.mcp-gateway`. The Helm
chart sets `HOME=/var/lib/mcp-gateway`, so there it is `/var/lib/mcp-gateway/.mcp-gateway`.

### Back these up

| State | What it holds | Location (default) | If it is lost |
|---|---|---|---|
| Accounts store | Sealed access and refresh tokens of managed personal accounts | `accounts.store_dir` (no default; required when `accounts.enabled`) | Every user reconnects each account |
| Accounts authority | The sealed manifest the store is checked against, including hosted connection journeys | `accounts.authority_dir` (no default; required) | The whole accounts store becomes unreadable |
| Accounts keys | The keys that seal both of the above | `accounts.keys` (`env:` or `file:` references) and `accounts.current_key_id` | Every sealed grant is unreadable, with no way back |
| OAuth backend tokens | One token file per backend and issuer | `~/.mcp-gateway/oauth/` under the home directory, even when `MCP_GATEWAY_CONFIG_DIR` is set | Each OAuth backend authorizes again |
| Audit (transparency) log | The hash-chained tool-call and `admin_action` records | `security.transparency_log.path` (`~/.mcp-gateway/transparency/transparency.jsonl`; `/var/lib/mcp-gateway/audit/transparency.jsonl` in the chart), with its sealed segments `<log>.<20 digits>` and its high-water mark `<log>.hwm` beside it | Audit history is gone. The log is required with auth on |
| SIEM export | Only when SIEM export is on: the export file, and a cursor per log recording how far it has been exported | `control_plane.export.sink_path` (`~/.mcp-gateway/export/siem.ndjson`); each cursor next to its log as `<log stem>.export-cursor.json`: `transparency.export-cursor.json` beside the transparency log, and `audit.export-cursor.json` beside the governance log in `control_plane.store_dir` | Without the cursors the whole log is exported again. Restore the export file and its cursors from one snapshot: a cursor newer than the file skips records the file lost |
| Governance store | Control-plane policy, revocations and its own `audit.jsonl` | `control_plane.store_dir` (default: next to the config file, else `~/.mcp-gateway/control-plane`) | Policy edits and revocations are lost |
| Identity grants | Local identity-grant rows | `security.identity_grants.path` (`~/.mcp-gateway/identity-grants.yaml`) | Every local grant is lost |
| Task store | Tasks of the 2026-07-28 tasks extension, kept for `tasks.default_ttl_ms` (24 hours) | `tasks.store_dir` (`~/.mcp-gateway/tasks`). A stdio gateway's own store is its `stdio` subdirectory, so one copy of the directory holds both. Stop every gateway, HTTP and stdio, that writes under it before a backup or restore | Open task handles stop resolving |
| Cost spend | Today's cost-governance spend, saved every 5 minutes | `<data dir>/costs.json` | Budgets restart at zero for the day |
| Search ranking usage | Tool usage counts that rank search results, written only at a graceful shutdown of an HTTP gateway (`serve --stdio` loads the file but never saves it) | `<data dir>/usage.json` | Search ranking starts from no usage history. A copy taken while the gateway runs holds the counts from the last shutdown, not the current ones |
| Tool transitions | Which tool tends to follow which, used to predict the next call, written only at a graceful shutdown of an HTTP gateway (stdio never saves it) | `<data dir>/transitions.json` | Predictions start from no history. A live copy holds the data from the last shutdown |
| Protocol-revision telemetry (stdio only) | The restart-safe window counting which MCP revisions stdio clients speak; an HTTP gateway exports this through Prometheus instead and never writes the file | `<data dir>/protocol-revision-telemetry/window.json` | The stdio measurement window starts again empty |
| Firewall audit | Firewall decisions as NDJSON, when configured | `security.firewall.audit_log` (off by default) | That history is gone |
| mTLS material | Server certificate and key, CA, CRL | `mtls.server_cert`, `server_key`, `ca_cert`, `crl_path` | Clients cannot connect until certificates are reissued |
| Configuration | `gateway.yaml`, env files, capability files with their `sha256:` pins, and every file a `file:` secret reference names (for example `auth.bearer_token`, `auth.api_keys[].key_sha256`, `agent_auth.agents[].hs256_secret`, `key_server.admin_token`, `accounts.keys`, `server.metrics_token`) | where you keep them, each `file:` target at its original path and mode | The gateway does not start as it was: an unresolved secret reference fails the load (UPGRADING-4.0 item 40), with three exceptions. `server.metrics_token` logs a warning and leaves `/metrics` answering 401. A personal-account descriptor's `client_secret_ref` is read only when a token is requested, so a missing target lets the gateway start and then fails that account's token refresh, new connections at their callback, and revocation on disconnect. And a reference inside a disabled block (for example `key_server.admin_token` with the key server off, or `accounts.keys` with `accounts.enabled: false` and no `accounts.adapters` configured) is not read at all, so a missing target shows up only when the block is enabled. A clean start is therefore not proof that every `file:` target was restored |

Also in the data directory: `version.stamp` (the last version that ran). Losing it only means
the one-time upgrade notice prints again. Package caches under `pkg-cache/` are downloaded again
on demand.

### Held in memory, lost on every restart

Key-server tokens, idempotency entries, the response cache, sessions and mid-call
continuations. A restart revokes every key-server token, so each client gets a new one. No
backup covers these.

### On Kubernetes

The chart mounts two writable volumes:

- `state` at `/var/lib/mcp-gateway`. It is an `emptyDir`, so the task store and everything
  else under HOME survive a container restart but not the pod.
- `audit` at `/var/lib/mcp-gateway/audit`. It is an `emptyDir` unless `audit.existingClaim`
  names a PersistentVolumeClaim. In `mesh` auth mode the chart renders no audit volume.

The configuration is mounted read-only from its ConfigMap at `/etc/mcp-gateway`; back it up
where you keep your chart values.

Set `audit.existingClaim` for any deployment whose audit history matters. The chart has no
value that puts `accounts.store_dir`, `accounts.authority_dir` or `control_plane.store_dir` on
persistent storage, so point those settings at a volume you mount yourself.

## Taking a backup

1. **Stop the gateway, or take one atomic snapshot that covers every location in the first
   table that the gateway writes** (the configuration row is copied separately). If they are on different volumes that cannot be snapshotted together at one
   instant, stop the gateway. Two sets break when copied piece by piece from a running
   gateway. Each audit log, its sealed segments and its `.hwm` must come from one instant: a
   segment sealed between two copies breaks the chain, and a `.hwm` that runs ahead of the
   copied tail fails the live log's completeness check. And the accounts store and its
   authority are checked against each other: every record is sealed together with the
   authority's `store_epoch` and the versions it lists for that record. A copy of the store
   from one moment and the authority from another fails as "personal account credential
   authentication failed". Copying the files of a running gateway one by one can produce
   exactly that pair.
2. Copy every location in the first table, keeping each one's permissions. With SIEM export on,
   copy the export file and every cursor in the same stop or snapshot. The gateway refuses
   key, token and credential files that other users can read (UPGRADING-4.0 items 35 and 54), so
   a restore that widens modes does not start.
3. **Back up the accounts keys separately from the store**, the same way you back up other
   secrets. A backup that holds both the store and its keys hands anyone who reads it every
   user's tokens.
4. Record `accounts.instance_id` and the key ids in `accounts.keys` with the backup. Every record
   is sealed with the instance id and with the key id named in its own envelope, which is the id
   that was current when it was last written.

### Anchoring the audit log

A backup kept on the same host proves nothing after the host is compromised: an attacker who
deletes the sealed segments, cuts the active file back and rewrites `.hwm` to match leaves a log
that verifies. Copy `<log>.hwm` (200 bytes) off the host on your own schedule, for example with
each backup, and check the live log against the newest copy:

```bash
mcp-gateway audit verify --path <log> --anchor <copied .hwm>
```

The log must still hold the record the copy names; a wiped, rolled-back or replaced log fails
with exit 1. An anchor vouches for the log up to its own record only: records appended after it
are covered by the next copy. A copy taken from a host that is already compromised vouches for
the compromised log, and a rotated `shared_secret` makes older signed copies fail their MAC. With a `shared_secret`, the copy carries a MAC: verify with the same secret, or the
anchor is refused. An anchor older than the retained segments fails with "predates the retained
range" (for an unsigned log, so does one whose record has just expired); take anchors more often
than retention expires segments. UPGRADING-4.0 item 158 has the details.

## Restoring

1. Stop the gateway.
2. Put each location back at the path the config names. Restore `accounts.store_dir` and
   `accounts.authority_dir` from **the same snapshot**.
3. Keep `accounts.instance_id` unchanged, and make every key id that sealed a record resolve to
   the same key it held when the backup was taken.
4. Start the gateway. If the authority cannot be opened (its key id is not configured, or
   `instance_id` changed), the accounts store does not open. If a record does not match the
   authority, calls on that account fail with "personal account credential authentication
   failed". In either case, restore both directories again from one snapshot. If no snapshot is
   consistent, empty both, run `mcp-gateway accounts init-store --config <path>` (a start never
   creates the store by itself), start the gateway, and have users reconnect.
5. Expect to redo what the backup could not hold: clients fetch new key-server tokens, and calls
   that were waiting on a mid-call answer start again.

Restoring onto a different host is the same procedure. Only one gateway process may use an
accounts store at a time: opening it takes a lock in each directory, and a second process is
refused. The governance store's audit log (`<control_plane.store_dir>/audit.jsonl`) takes the
same writer lease as the main audit log (UPGRADING-4.0 item 49): a second gateway on the same
`control_plane.store_dir` is refused at startup after a 10-second wait, so stop the old gateway
before starting its replacement.

## Rotating keys and secrets

Every setting below is read at startup. A config reload reports the change as needing a
restart and does not apply it, so each rotation below ends with a restart unless its row says
otherwise.

### Accounts encryption keys

The accounts store holds a keyring. `accounts.keys` maps key ids to keys (base64 of exactly 32
bytes, through `env:` or `file:`), and `accounts.current_key_id` names the one that seals new
writes. A record opens with whichever configured key its envelope names, so older keys keep
older records readable.

To bring in a new key:

1. Add it under a new id in `accounts.keys`. Keep the old ids.
2. Set `accounts.current_key_id` to the new id.
3. Restart.

Each record is re-sealed under the new key the next time it is written, for example when its
token refreshes. The authority is re-sealed on every write to the store. Nothing re-seals a
record that is never written, and 4.0.0 has no command that forces it.

**Do not remove an old key id while any record may still be sealed with it.** A record whose key
id is missing from `accounts.keys` fails as "personal account credential authentication failed",
and if the authority is the one affected, the whole store fails. A key you have to retire, for
example because it leaked, can be removed safely only when every account has been written since
the new key became current, and 4.0.0 has no command that lists which records still name an old
key id. The hosted connection journeys in `accounts.authority_dir/journeys.json` need the same
care: that file is re-sealed only when the journey table changes, and while it names a removed
key every journey operation is refused. A missing file reads as no journeys, so when removing
the old key, stop the gateway and delete that one file. Connections started in the last 15
minutes have to be started again, and the ended journeys the file keeps for 24 hours are
gone too, so a late callback for one of them is no longer recognised as a replay. If the accounts
themselves cannot be shown to be re-sealed: stop the gateway, empty `accounts.store_dir` and
`accounts.authority_dir`, remove the old key id, run `mcp-gateway accounts init-store --config
<path>`, start the gateway, and have users reconnect their accounts.

### API keys

API keys are configured as `key_sha256` digests (UPGRADING-4.0 item 41). To rotate one:

1. Run `mcp-gateway hash-key` with the new key on stdin, and add a second entry with the new
   digest and its own name and `backends`.
2. Restart, and move clients to the new key.
3. Remove the old entry and restart again.

Setting `expires_at` on the old entry makes the gateway answer 401 for it after that time, even
if step 3 slips.

### Other secrets

| Secret | How to rotate |
|---|---|
| `server.metrics_token` | Change it and restart; update the scrape job at the same time (UPGRADING-4.0 item 33) |
| `file:` secret references | Replace the file with the same mode and restart; a reload reports `restart required for: file:<path>` (item 44). A `client_secret_ref` picks up the new file on its next use without a restart |
| OAuth backend tokens | Delete the backend's file under `~/.mcp-gateway/oauth/` and let the backend authorize again |
| Key-server tokens | Restart; every issued token is dropped with the process |
| mTLS certificates and CRL | Replace the files and restart; there is no live reload |
| Audit log HMAC (`security.transparency_log` `key_id` and `shared_secret`) | A log is verified with one secret, so one log cannot hold entries signed with two. Stop the gateway, archive the current log file with its sealed segments and `.hwm`, together with its old `key_id` and `shared_secret`, point `security.transparency_log.path` at a new file (or move the old file, its sealed segments and its `.hwm` away together; a segment or `.hwm` left behind joins the new log), set the new `key_id` and `shared_secret`, and restart. The governance log `<control_plane.store_dir>/audit.jsonl` is signed with the same `key_id` and `shared_secret`, so archive and move it away with its segments and `.hwm` in the same stop, and with SIEM export on, move each log's `<log stem>.export-cursor.json` with it |
