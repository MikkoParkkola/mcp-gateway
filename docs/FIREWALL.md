# Firewall rules

`security.firewall.rules` overrides what the firewall does with a finding, per tool, backend and key. Without a rule, every finding gets its severity's default: Critical and High block, Medium warns, Low is allowed.

```yaml
security:
  firewall:
    rules:
      - match: "*"
        servers: ["crm", "billing-*"]
        keys: ["support-bot"]
        scan: [credentials]
        action: allow
        reason: "the CRM returns account keys by design"
        except:
          - tool: "export_*"
```

## Keys of a rule

| Key | Required | Meaning |
|---|---|---|
| `match` | yes | A glob over the tool name (`*`, `?`, `[abc]`, `[!abc]`). |
| `action` | yes | `allow`, `warn` or `block`: what this rule does with a finding it decides. |
| `reason` | no | Text logged in the audit entry when the rule decides a finding. |
| `scan` | no | The finding types this rule decides (list below). Absent or empty: every type. |
| `servers` | no | Globs over the backend's registry name. Absent: every backend. A call to a tool the gateway serves itself has no backend, so a rule with `servers` never covers the call. An answer that names no single backend (a discovery listing, a notification, a gateway tool's answer) is judged as every registered backend could have sent it, so a `servers` rule does cover it. |
| `keys` | no | API key names, matched exactly. Absent: every caller. |
| `except` | no | Calls this rule skips. Each entry sets one or more of `server` (a glob), `tool` (a glob) and `key` (an exact name); a call is skipped when it matches every field the entry sets. |

## How a finding is decided

1. A rule covers a call when `match` covers the tool, `servers` (if set) covers the backend, `keys` (if set) holds the caller's key, and no `except` entry matches the call.
2. Each finding goes to the first covering rule, in file order, whose `scan` holds the finding's type. If no rule takes it, the finding gets its severity's default.
3. The call or answer takes the most restrictive result over all its findings: `block` over `warn` over `allow`.

So an `allow` rule written for credentials allows credentials only. A shell injection in the same call still falls to a later rule, or to its default.

**A caller whose key isn't known.** Some paths judge a call where the caller's key isn't available. There the firewall resolves the call under every key any rule names, and under no key, and takes the most restrictive result. So a `keys` rule that could apply does apply, and an `except` naming one possible key never exempts the call.

## Finding types for `scan`

`credentials`, `pii`, `prompt_injection`, `shell_injection`, `path_traversal`, `sql_injection`, `sequence_anomaly`, `memory_poisoning`, `cross_tenant_reach`, `budget_exceeded`, `collusion_relay`.

Two more types are output-only: only a folder rule's own check produces them, and a rule that lists either in `scan` is refused at load. `path_outside_root` is a declared path argument that resolves outside every allowed root. `root_refused` is a call a folder rule refused without judging a path; its reason codes are listed under [Folder rules](#folder-rules).

## Load rules

A rule that breaks one of these fails the config load. The error names the key path, for example `security.firewall.rules[2].servers`, and never prints a value.

- An unknown key anywhere under a rule is refused, as everywhere in `gateway.yaml`.
- `match`, every `servers` glob, and every `except` glob must parse. An invalid glob is never read as `*`.
- `servers`, `keys` and `except` must not be empty when present. Leave a key out to apply to all.
- An `except` entry must set at least one field.

## Folder rules

A rule with `allowed_roots` and `path_args` confines the path arguments of the calls it covers to those folders. It covers calls the same way every rule does: `match`, `servers`, `keys` and `except` mean what they mean above.

```yaml
- match: "read_text_file"
  servers: ["filesystem"]
  action: block
  allowed_roots: ["/srv/data", "~/projects"]
  path_args: ["path"]
```

- `allowed_roots`: the folders. Each must be absolute after expansion. A bare `~` or a leading `~/` uses the gateway's home directory, and further separators stay under it (`~//x` is `<home>/x`); `~user/...` and `~\...` are not expanded and are refused.
- `path_args`: the arguments that hold paths. `name` is a string, `name[]` an array of strings, `a.b` a nested key, and a trailing `?` (`name?`, `name[]?`) marks one a call may omit. A declared argument a call omits without `?` is refused.

A path outside every root is a `path_outside_root` finding, High severity, decided by the folder rule's own action: `block` refuses the call, `warn` lets it through with the finding.

A folder rule decides only its own findings:

- its `scan` must be absent or empty;
- its `action` must be `warn` or `block`; `action: allow` is refused at load;
- it never decides a content finding, and no other rule decides its findings.

Each value must be an absolute native path with no `.` or `..` segment. The gateway checks the exact string the backend receives and never rewrites it. It resolves the path without following links, then compares it with each root, both canonical, component by component: `/data2/x` is not inside `/data`.

**Reason codes.** A `root_refused` finding is a forced block, whatever the rule's action. Its description reads `<code>: rule <id>, argument <name>`, never a value, and the audit row's `reason` field holds the code.

| Code | Meaning |
|---|---|
| `not_absolute` | The value is not an absolute native path (a relative name, `~`, `$HOME`, a URI). |
| `not_normalised` | The value has a `.` or `..` segment or a NUL. On Windows it also has a trailing dot or space, or an 8.3 short name. |
| `device_path` | A Windows device-namespace path (`\\.\...`). |
| `missing_argument` | A declared argument without `?` is absent. |
| `wrong_type` | A declared argument is not a string, or not an array of strings. |
| `remote_backend` | The backend is reached over HTTP, WebSocket or A2A: its filesystem is not the gateway's. |
| `unknown_backend` | The backend is not registered. |
| `capability_not_checkable` | A capability call: its argument template rewrites the path after any check. Confine CLI capabilities with `capabilities.files`. |
| `injected_path_argument` | A secret rule matching the tool owns a declared path argument, or its top-level key. |
| `dangling_link` | A link on the path points at nothing. |
| `unresolvable` | A component could not be read, a link loops, or a folder could not be listed. |
| `root_unresolvable` | One of the rule's roots does not resolve. |
| `equivalent_spelling` | A folder holds another entry whose name matches under Unicode normalisation or a different space character. |
| `directory_too_large` | A folder on the path holds more than 10,000 entries. |
| `timeout` | Resolving the call took longer than 2 seconds. |
| `resolver_busy` | Every resolver thread is busy with another call. |

A name that is both a configured backend and the capability backend is not a folder-rule refusal: the gateway refuses every `gateway_invoke` call to it before dispatch, with error `-32001` and data reason `ambiguous_backend`, and refuses a reload that would create the clash. Under a covering rule, an outside path may be refused earlier, as `path_outside_root`.
