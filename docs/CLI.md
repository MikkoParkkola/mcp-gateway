# The command line

How `mcp-gateway` commands report results and failures, so scripts can rely on them.

## Output rules

- Data goes to stdout. Messages, progress and errors go to stderr, so `mcp-gateway ... > out.json` captures
  only the data.
- A JSON document the CLI writes itself, such as an error from `api --json`, carries `schema_version`.
- JSON passed through from the gateway, such as an `events dead-letters` answer, keeps the gateway's shape.
- An error is two lines on stderr: `error: <what went wrong>`, then what to do next. With `api --json`, the
  error is one JSON document instead.
- A credential (`MCP_GATEWAY_TOKEN`), a looked-up email or a page token never appears in an error. If the
  report would still show one after redaction, a fixed sentence replaces it, or nothing prints at all.

## Exit codes

`api`, `dashboard-link`, `events dead-letters` and `audit lookup-email` exit with these codes. Other commands
exit 0 on success and 1 on failure until they move to the same table.

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

## Command classes

Every command is in one class:

- `JSON_CAPABLE` commands have a JSON form: `--json`, or `--format json`.
- `JSON_DEFAULT` commands always print JSON:
  stdout is JSON, errors are human text on stderr, and a script reads the exit code.
- `PENDING_JSON` commands print data with no JSON form yet. Each gets one before 4.0.0.
- `ACTION` commands change something and print only status.
- `SCRIPT` commands print a script.

| Command | Class |
| --- | --- |
| `accounts init-store` | `ACTION` |
| `accounts migrate-credentials` | `ACTION` |
| `add` | `ACTION` |
| `api` | `JSON_CAPABLE` |
| `audit lookup-email` | `JSON_DEFAULT` |
| `audit show` | `PENDING_JSON` |
| `audit verify` | `PENDING_JSON` |
| `cap discover` | `JSON_CAPABLE` |
| `cap import` | `ACTION` |
| `cap import-url` | `ACTION` |
| `cap install` | `ACTION` |
| `cap list` | `PENDING_JSON` |
| `cap pin` | `ACTION` |
| `cap registry-list` | `PENDING_JSON` |
| `cap search` | `PENDING_JSON` |
| `cap test` | `PENDING_JSON` |
| `cap validate` | `PENDING_JSON` |
| `dashboard-link` | `PENDING_JSON` |
| `doctor` | `JSON_CAPABLE` |
| `events dead-letters` | `JSON_DEFAULT` |
| `get` | `PENDING_JSON` |
| `hash-key` | `PENDING_JSON` |
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
| `provenance verify` | `PENDING_JSON` |
| `ranking eval` | `JSON_CAPABLE` |
| `remove` | `ACTION` |
| `runtime compile` | `JSON_DEFAULT` |
| `serve` | `ACTION` |
| `setup export` | `ACTION` |
| `setup wizard` | `ACTION` |
| `skills generate` | `ACTION` |
| `skills import` | `ACTION` |
| `skills list` | `PENDING_JSON` |
| `skills remove` | `ACTION` |
| `skills search` | `PENDING_JSON` |
| `skills show` | `PENDING_JSON` |
| `stats` | `PENDING_JSON` |
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
