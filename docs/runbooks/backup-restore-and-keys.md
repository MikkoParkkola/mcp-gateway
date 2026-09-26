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
| OAuth backend tokens | One token file per backend and issuer | `<data dir>/oauth/` | Each OAuth backend authorizes again |
| Audit (transparency) log | The hash-chained tool-call and `admin_action` records | `security.transparency_log.path` (`~/.mcp-gateway/transparency/transparency.jsonl`; `/var/lib/mcp-gateway/audit/transparency.jsonl` in the chart) | Audit history is gone. The log is required with auth on |
| Governance store | Control-plane policy, revocations and its own `audit.jsonl` | `control_plane.store_dir` (default: next to the config file, else `~/.mcp-gateway/control-plane`) | Policy edits and revocations are lost |
| Identity grants | Local identity-grant rows | `security.identity_grants.path` (`~/.mcp-gateway/identity-grants.yaml`) | Every local grant is lost |
| Task store | Tasks of the 2026-07-28 tasks extension, kept for `tasks.default_ttl_ms` (24 hours) | `tasks.store_dir` (`~/.mcp-gateway/tasks`) | Open task handles stop resolving |
| Cost spend | Today's cost-governance spend, saved every 5 minutes | `<data dir>/costs.json` | Budgets restart at zero for the day |
| Firewall audit | Firewall decisions as NDJSON, when configured | `firewall.audit_log` (off by default) | That history is gone |
| mTLS material | Server certificate and key, CA, CRL | `mtls.server_cert`, `server_key`, `ca_cert`, `crl_path` | Clients cannot connect until certificates are reissued |
| Configuration | `gateway.yaml`, env files, capability files with their `sha256:` pins | where you keep them | The gateway does not start as it was |

Also in the data directory: `version.stamp` (the last version that ran). Losing it only means
the one-time upgrade notice prints again. Package caches under `pkg-cache/` are downloaded again
on demand.

### Held in memory, lost on every restart

Key-server tokens, idempotency entries, the response cache, sessions and mid-call
continuations. A restart revokes every key-server token, so each client gets a new one. No
backup covers these.

### On Kubernetes

The chart mounts two volumes:

- `state` at `/var/lib/mcp-gateway`. It is an `emptyDir`, so the task store and everything
  else under HOME survive a container restart but not the pod.
- `audit` at `/var/lib/mcp-gateway/audit`. It is an `emptyDir` unless `audit.existingClaim`
  names a PersistentVolumeClaim.

Set `audit.existingClaim` for any deployment whose audit history matters. The chart has no
value that puts `accounts.store_dir`, `accounts.authority_dir` or `control_plane.store_dir` on
persistent storage, so point those settings at a volume you mount yourself.

## Taking a backup

1. **Stop the gateway, or take an atomic snapshot of the volume.** The accounts store and its
   authority are checked against each other: every record is sealed together with the
   authority's `store_epoch` and the versions it lists for that record. A copy of the store
   from one moment and the authority from another fails as "personal account credential
   authentication failed". Copying the files of a running gateway one by one can produce
   exactly that pair.
2. Copy every location in the first table, keeping each one's permissions. The gateway refuses
   key, token and credential files that other users can read (UPGRADING-4.0 items 35 and 54), so
   a restore that widens modes does not start.
3. **Back up the accounts keys separately from the store**, the same way you back up other
   secrets. A backup that holds both the store and its keys hands anyone who reads it every
   user's tokens.
4. Record `accounts.instance_id` and `accounts.current_key_id` with the backup. Both are part of
   what each record is sealed with.

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
   consistent, empty both and have users reconnect.
5. Expect to redo what the backup could not hold: clients fetch new key-server tokens, and calls
   that were waiting on a mid-call answer start again.

Restoring onto a different host is the same procedure. Only one gateway process may use an
accounts store or a governance store at a time; there is no lease between processes.

## Rotating keys and secrets

Every setting below is read at startup. A config reload reports the change as needing a
restart and does not apply it, so each rotation ends with a restart.

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
the new key became current. If that cannot be shown, remove the key and have users reconnect
their accounts.

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
| `file:` secret references | Replace the file with the same mode and restart; a reload reports `restart required for: file:<path>` (item 44) |
| OAuth backend tokens | Delete the backend's file under `<data dir>/oauth/` and let the backend authorize again |
| Key-server tokens | Restart; every issued token is dropped with the process |
| mTLS certificates and CRL | Replace the files and restart; there is no live reload |
| Audit log HMAC (`security.transparency_log` `key_id` and `shared_secret`) | Change both together and restart. Each entry records the `key_id` it was signed under, and older entries verify only with the old secret, so archive that secret with the log |
