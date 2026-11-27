# The command line

How `mcp-gateway` commands report results and failures, so scripts can rely on them.

## Output rules

- Data goes to stdout. Messages, progress and errors go to stderr, so `mcp-gateway ... > out.json` captures
  only the data.
- A JSON document the CLI writes itself, such as an error from `api --json`, carries `schema_version`.
- `audit show` and `list --json` print a bare JSON array, without `schema_version`.
- JSON passed through from the gateway, such as an `events dead-letters` answer, keeps the gateway's shape.
- An error is two lines on stderr: `error: <what went wrong>`, then what to do next. With `api --json` or
  `dashboard-link --json`, the error is one JSON document instead.
- A verify command prints its verdict document with `--json` whether the verdict passes or fails; the exit code is 0 for a pass and 1 for a fail.
- A credential (`MCP_GATEWAY_TOKEN`), a looked-up email or a page token never appears in an error. If the
  report would still show one after redaction, a fixed sentence replaces it, or nothing prints at all.

## Exit codes

`api`, `dashboard-link`, `events dead-letters` and `audit lookup-email` exit with these codes. Every other command
exits 0 on success, 2 when it is called wrong and 1 for any other failure. A check that answers no (`validate`
with findings, a failed `audit verify`) keeps the code it has always had.

| Code | Meaning |
| --- | --- |
| `0` | ok |
| `1` | local failure |
| `2` | usage |
| `3` | auth refused |
| `4` | not found |
| `5` | network |
| `6` | gateway |
| `7` | declined (reserved) |
| `8` | uncertain outcome |
| `130` | interrupted (reserved) |

What each code tells a script:

- **1**: something on this machine failed, such as unreadable stdin or output that could not be written.
- **2**: the command, its arguments, its input or its settings are wrong. Fix them before retrying.
- **3**: `MCP_GATEWAY_TOKEN` is not set, the gateway refused the credential (401), or the credential lacks
  permission (403).
- **4**: the gateway does not have what was asked for.
- **5**: the gateway could not be reached, or its answer to a read was lost on the way. Retrying is safe.
- **6**: the gateway answered with an error, or with an answer the CLI cannot use.
- **8**: a change was sent, but whether the gateway applied it is unknown. Check the gateway's state before
  sending it again.
- **7** and **130** are reserved and not used yet.

## Where remote commands send their request

`api`, `audit lookup-email`, `dashboard-link`, `events dead-letters` and `stats` talk to a running gateway. Each
takes the gateway's base URL from the first of these that is set:

1. `--gateway URL`.
2. The `MCP_GATEWAY_URL` environment variable.
3. A saved login (not yet: until the CLI can sign in, this step is empty).
4. The address in `--config` (`server.host` and `server.port`), else `http://127.0.0.1:39400` for `stats`.

The old spellings `--url` and `-u` still work on these five commands. The credential is never a flag: it is the
`MCP_GATEWAY_TOKEN` environment variable.

## Request bodies

`api --data` takes a body inline, from `@FILE`, or from standard input (`-`), up to 16 MiB. It must be JSON, with
two exceptions chosen by the route, never by a flag: a PUT to one capability (`/ui/api/capabilities/NAME`, with or
without `?validate=1`) and a POST to its `validate` route send the body as `application/x-yaml`, byte for byte.

Saving or deleting a capability needs the revision of the copy you loaded, so a change someone else made in the
meantime is never overwritten. `api GET /ui/api/capabilities/NAME > NAME.yaml` prints the file and, on stderr, a
line `api: revision "<sha256>"; ...`. Edit the file, then
`api PUT /ui/api/capabilities/NAME --data @NAME.yaml --if-match '"<sha256>"'`, quoting the value exactly as
printed. Take the revision from the same load as the text you edited, never from the capability list. If the save
is refused because the file changed, load it again, make your change on the new text, and save with the new
revision. A delete takes `--if-match` the same way: load the file, check it is the version you mean to remove, then
`api DELETE /ui/api/capabilities/NAME --if-match '"<sha256>"'`. If the delete is refused because the file changed,
load it again and check the new version before deleting with the new revision.

## Command classes

Every command is in one class:

- `JSON_CAPABLE` commands have a JSON form: `--json`, or `--format json`.
- `JSON_DEFAULT` commands always print JSON:
  stdout is JSON, errors are human text on stderr, and a script reads the exit code.
- `PENDING_JSON` commands print data with no JSON form yet. None does today; a new one would be listed here.
- `ACTION` commands change something and print only status.
- `SCRIPT` commands print a script.

| Command | Class |
| --- | --- |
| `accounts init-store` | `ACTION` |
| `accounts migrate-credentials` | `ACTION` |
| `add` | `ACTION` |
| `api` | `JSON_CAPABLE` |
| `audit lookup-email` | `JSON_DEFAULT` |
| `audit show` | `JSON_DEFAULT` |
| `audit verify` | `JSON_CAPABLE` |
| `cap discover` | `JSON_CAPABLE` |
| `cap import` | `ACTION` |
| `cap import-url` | `ACTION` |
| `cap install` | `ACTION` |
| `cap list` | `JSON_CAPABLE` |
| `cap pin` | `ACTION` |
| `cap registry-list` | `JSON_CAPABLE` |
| `cap search` | `JSON_CAPABLE` |
| `cap test` | `JSON_CAPABLE` |
| `cap validate` | `JSON_CAPABLE` |
| `dashboard-link` | `JSON_CAPABLE` |
| `doctor` | `JSON_CAPABLE` |
| `events dead-letters` | `JSON_DEFAULT` |
| `get` | `JSON_CAPABLE` |
| `hash-key` | `JSON_CAPABLE` |
| `identity grants grant` | `JSON_CAPABLE` |
| `identity grants list` | `JSON_CAPABLE` |
| `identity grants revoke` | `JSON_CAPABLE` |
| `import apply` | `JSON_CAPABLE` |
| `import preview` | `JSON_CAPABLE` |
| `init` | `ACTION` |
| `kubernetes apply-plan` | `JSON_CAPABLE` |
| `kubernetes controller` | `JSON_CAPABLE` |
| `kubernetes plan` | `JSON_CAPABLE` |
| `list` | `JSON_CAPABLE` |
| `provenance public-key` | `JSON_DEFAULT` |
| `provenance verify` | `JSON_CAPABLE` |
| `ranking eval` | `JSON_CAPABLE` |
| `remove` | `ACTION` |
| `runtime compile` | `JSON_DEFAULT` |
| `serve` | `ACTION` |
| `setup export` | `ACTION` |
| `setup wizard` | `ACTION` |
| `skills generate` | `ACTION` |
| `skills import` | `ACTION` |
| `skills list` | `JSON_CAPABLE` |
| `skills remove` | `ACTION` |
| `skills search` | `JSON_CAPABLE` |
| `skills show` | `JSON_CAPABLE` |
| `stats` | `JSON_CAPABLE` |
| `tls init-ca` | `ACTION` |
| `tls issue-client` | `ACTION` |
| `tls issue-server` | `ACTION` |
| `tool completions` | `SCRIPT` |
| `tool inspect` | `JSON_CAPABLE` |
| `tool invoke` | `JSON_CAPABLE` |
| `tool list` | `JSON_CAPABLE` |
| `trust generate` | `JSON_CAPABLE` |
| `trust inspect` | `JSON_CAPABLE` |
| `trust lab evaluate` | `JSON_CAPABLE` |
| `trust validate` | `JSON_CAPABLE` |
| `upgrade` | `ACTION` |
| `validate` | `JSON_CAPABLE` |

## JSON forms

Every command that prints data has one JSON form. The forms added in 4.0.0 list their top-level keys; each key is
always present (`null` or `[]` when there is nothing to say), so a script can read one shape.

| Command | Flag | Shape |
| --- | --- | --- |
| `api` | `--json` | the gateway's JSON answer; errors as one JSON document on stderr |
| `audit lookup-email` | (none) | the gateway's lookup page, passed through |
| `audit show` | (none) | array of log entries |
| `audit verify` | `--json` | schema_version, ok, hmac_checked, signed_entry_seen, scope, entries_checked, segments_checked, segments_expired, failed_check, failed_at_counter, error, warnings, notes |
| `audit verify --export` | `--json` | schema_version, valid, reason, rows, truncated, integrity_failed, kid |
| `cap discover` | `--format json` | the discovered servers |
| `cap list` | `--json` | schema_version, directory, capabilities |
| `cap registry-list` | `--json` | schema_version, capabilities |
| `cap search` | `--json` | schema_version, query, capabilities |
| `cap test` | `--json` | schema_version, capability, arguments, result |
| `cap validate` | `--json` | schema_version, name, description, provider, auth, warnings |
| `dashboard-link` | `--json` | schema_version, url |
| `doctor` | `--format json` | the doctor report (`doctor.v1`) |
| `events dead-letters` | (none) | the gateway's answer, passed through |
| `get` | `--json` | schema_version, name, transport, description, enabled, command, url, env, headers |
| `hash-key` | `--json` | schema_version, key_sha256 |
| `identity grants grant` | `--format json` | the grant written |
| `identity grants list` | `--format json` | the grants |
| `identity grants revoke` | `--format json` | the grant revoked |
| `import apply` | `--format json` | the apply report |
| `import preview` | `--format json` | the preview |
| `kubernetes apply-plan` | `--format json` | the apply report |
| `kubernetes controller` | `--format json` | one report per reconcile cycle |
| `kubernetes plan` | `--format json` | the plan |
| `list` | `--json` | array of backend objects |
| `provenance public-key` | (none) | jwk, thumbprint |
| `provenance verify` | `--json` | schema_version, status, accepted, kid, reason |
| `ranking eval` | `--format json` | the evaluation report |
| `runtime compile` | (none) | the compiled plan |
| `skills list` | `--json` | schema_version, registry, skills |
| `skills search` | `--json` | schema_version, query, skills |
| `skills show` | `--json` | schema_version, name, description, version, effort, allowed_tools, triggers, keywords, source_path, auxiliary_files, code_blocks, body |
| `stats` | `--json` | schema_version, invocations, cache_hits, cache_hit_rate, tools_discovered, tools_available, top_tools |
| `tool inspect` | `--format json` | the tool's schema |
| `tool invoke` | `--format json` | the tool's result |
| `tool list` | `--format json` | the tools |
| `trust generate` | `--format json` | the generated TrustCards |
| `trust inspect` | `--format json` | the TrustCard |
| `trust lab evaluate` | `--format json` | the evaluation report |
| `trust validate` | `--format json` | the validation report |
| `validate` | `--format json` | the validation report |
