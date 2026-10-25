# ADR-027: Where UI saves put secrets: the OS keychain or owner-only files

- **Status**: Proposed, 2026-10-25
- **Ticket**: MIK-8908 (KC.1); extends ADR-016 (a second scoped `unsafe` module, §2a); amends ADR-024 (its secret sequence gains a store choice; its F5 is corrected); unblocks MIK-8860 (API8.7) and MIK-8859 (adopt with secrets)
- **Operator ruling 2026-10-25:** full keychain support in 4.0.0, and the store is a user setting (OS keychain or owner-only secret files). Lead default: keychain where the OS provides one, otherwise files; the setting overrides.

## Context

| # | Fact | Where |
|---|---|---|
| F1 | ADR-024 F5 says gateway.yaml names a keychain entry as `{keychain.name}`. It does not: `SecretRef`, "the one grammar for whole-value secret references", has `env:NAME`, `file:/abs/path` and literal only | `src/config/secret_ref.rs:1-44` |
| F2 | `{keychain.X}` exists only in capability files and a backend's `secrets:` rules, read-only | `src/secrets.rs:198-260`, `src/secret_injection.rs:14` |
| F3 | Existing readers shell out: macOS `security find-generic-password -s NAME -w` (secret on stdout), Linux `secret-tool lookup service NAME` | `src/secrets.rs:198-250` |
| F4 | `security-framework` 3.7 is already in `Cargo.lock` (via rustls); its `passwords` module is a safe API | `Cargo.lock` |
| F5 | No Secret Service crate is in the tree; `secret-tool store` reads the secret from stdin | `Cargo.lock`; `secret-tool(1)` |
| F6 | Windows Credential Manager is Win32 (`CredWriteW` / `CredReadW` / `CredDeleteW`), callable only through `unsafe`; the crate denies `unsafe` outside ADR-016's one module | `src/lib.rs` `#![deny(unsafe_code)]`, ADR-016 |
| F7 | `file:` references are validated owner-only (mode on unix, protected DACL on Windows via ADR-016) | `src/config/secret_file.rs`, ADR-016 |

## Decision

### 1. Grammar

`SecretRef` gains `keychain:NAME`, accepted everywhere `env:` and `file:` are, because every secret field already parses through `SecretRef`.
- `NAME` matches `[A-Za-z0-9._-]{1,128}`.
- A config naming an entry that does not exist, or is empty, **fails validation with a message naming the entry**. It never resolves to an empty value, the same C4 rule as `env:`.
- On a platform without a keychain backend, a `keychain:` reference fails validation, naming the platform.

### 2. Per-OS backend

| OS | Read | Write / delete | Unsafe in our crate | New dependency |
|---|---|---|---|---|
| macOS | `security-framework` only (never the `security` CLI) | create via `ItemAddOptions::add()` (`SecItemAdd`, which itself refuses a duplicate: create-only) / `delete_generic_password` | none | none (already locked, F4; becomes a direct macOS-only dependency) |
| Linux | `secret-tool lookup service NAME`, bounded and non-interactive (rule 5), stdout into a wiped buffer, no `trim()` | `secret-tool store --label=... service NAME` with the secret on **stdin**; `secret-tool clear service NAME` | none | none (runtime needs `libsecret-tools` and a Secret Service) |
| Windows | Credential Manager `CredReadW` | `CredWriteW` (`CRED_TYPE_GENERIC`, `CRED_PERSIST_LOCAL_MACHINE`; create-only: `exists()` first under the vault lock, rule 3) / `CredDeleteW` | **one new scoped module**, `src/win_cred.rs` (ADR-016 extension, §2a) | none: the `Win32_Security_Credentials` feature of the already-direct `windows-sys` 0.61 |

#### 2a. ADR-016 extension: a second scoped `unsafe` module (lead ruling 2026-10-25, option W1)

ADR-016 allowed one Windows-only file of `unsafe` code for owner-only DACLs. This decision allows a second, `src/win_cred.rs`, under the same rules:

- `#![allow(unsafe_code)]` only there, `#[cfg(windows)]`.
- Every export is a safe function (rule 8): `create(name, &[u8])`, `exists(name)`, `read(name) -> WipedBytes`, `delete(name)`. Callers never see a pointer, a handle or a Win32 type.
- Every `unsafe` block carries a `// SAFETY:` comment naming the contract it relies on:
  - buffer lengths;
  - NUL-terminated UTF-16 built and owned in the block;
  - `CredFree` only on a pointer from a `CredReadW` that returned TRUE, by a drop guard;
  - no aliasing of the blob.
- The secret blob is copied into `WipedBytes` and the Win32 copy freed immediately. The value never enters an error string; Win32 errors are reported by code.
- The module's own tests run on the Windows CI shard: create, read, delete, create-on-existing refused, read-missing named. The `unsafe` allow-list is rule 10.

Option W2, the `keyring` crate, was rejected. It moves the same `unsafe` into a dependency we do not review, and adds a tree on every OS. Option W3, a refusal on Windows, was rejected by the operator's ruling for full keychain support.

The macOS `security` CLI is **not** used to write: `add-generic-password -w SECRET` puts the secret in argv (KC.3).

### 3. Fresh names

Every UI secret write creates a new entry: `mcp-gateway.<slug>.<unix-ms>.<16 hex>` (rule 1).
- Example: `mcp-gateway.auth-bearer-token.1761418800123.9f3a1c2e04b7d815`.
- The service name is that string, and the account is `mcp-gateway`.
- Write is create-only (rule 3): an existing name is an error, never an overwrite, and is not retried.
- "Unused entries" are listed from the index (rule 6), never by enumerating the store.

### 4. The setting

```yaml
secrets:
  store: auto      # auto | keychain | files
```

- **`auto`** (default): `keychain` wherever the OS store answers a probe (macOS Keychain, a Linux Secret Service, Windows Credential Manager), otherwise `files`.
- **`keychain` or `files`** chosen explicitly is used as is. Its unavailability is a refusal (§5), never a silent switch.
- **`files`** writes each secret to a new owner-only file `<config dir>/secrets/<fresh name>` (created with mode 0600 or ADR-016's DACL, create-new and never overwriting). The config gets `file:<absolute path>`.
- The setting chooses only where **new** UI writes go. Existing references of any kind keep resolving.

### 5. Unavailable store

A save that needs a secret write to a store that is unavailable is refused before anything is written.
- **Unavailable** means: no Secret Service, a locked keychain, a headless session that cannot unlock, a missing `secret-tool`, or Credential Manager refusing the write (for example, a service account with no credential vault).
- **The refusal** names the reason and offers the switch: "set `secrets.store: files`, or unlock/install the keychain".
- **Nothing is half-written:** the probe (rule 7) and every value limit (rule 2) run before any entry is created, and ADR-024's sequence deletes only the entries this save created if a later write fails.

### 6. Both stores follow ADR-024's sequence unchanged

1. Prove the file edit.
2. Create every new entry.
3. Commit the file.
4. On a failed create, delete only this save's entries.
5. Never delete an old entry.
6. List unused entries from the index (rule 6), for both stores, that no loaded config names.

### 7. Secrets never leak

The value never appears in argv, logs or error text. Readers and writers pass it through stdin or the API, and errors name the entry, never the value. A test greps every captured log, error and spawned argv for a sentinel secret (KC.3).

## Consequences

- One grammar, so no second resolver. Capability `{keychain.X}` templates keep their own syntax and reader. Unifying them is out of scope.
- macOS gains a direct `security-framework` dependency (already compiled in). Linux needs `libsecret-tools` at runtime for the keychain store. `auto` falls back to files without it.
- Windows gains a second scoped `unsafe` module (§2a), reviewed with this ADR, plus one `windows-sys` feature.
- Entry names change on every secret change, and unused entries accumulate until an admin deletes them (ADR-024).
- Rollback: the `keychain:` prefix stays reserved. A build without keychain support refuses `keychain:NAME` by name, never reading it as a literal secret. A binary older than this ADR would read it as a literal, so UPGRADING says to convert keychain references to `file:` before downgrading.

## Rules from review (binding)

### Names and limits

1. **Names.** `mcp-gateway.<slug>.<unix-ms>.<16 hex>`.
   - The slug is the field path, with every byte outside `[A-Za-z0-9-]` mapped to `-`, runs collapsed, capped at 40.
   - The 16 hex characters come from the OS CSPRNG (64 bits).
   - The same string is the keychain service name, the `files` basename, and the `secret-tool`/Windows label: the name, never the value. It always fits `[A-Za-z0-9._-]{1,128}`.
2. **Value limits.** Every value is checked against the chosen store's limit before any entry is created; a refused value names the limit and offers `files`.
   - An empty value is refused on every store.
   - Windows: 2,560 bytes (`CRED_MAX_CREDENTIAL_BLOB_SIZE`).
   - Linux: 8,192 bytes (`secret-tool` 0.21.8 truncates piped input past it).
   - `files`: 64 KiB (the existing `file:` limit).

### Create-only writes

3. **One vault lock.** Several gateways can share one user's keychain (ADR-024), and the config writer lock is per `gateway.yaml`. So every secret write holds one per-user lock: `<user data dir>/mcp-gateway/secrets.lock`, using the same flock mechanism as `config_persistence_lock`, from the absence check through commit or rollback.
   - macOS: `SecItemAdd` refuses a duplicate itself.
   - Linux and Windows: `exists(name)` false, then create, under that lock.
   - Rollback deletes only names this save confirmed absent and then created.

### Exists and read

4. **`exists(name)` never returns the value.**
   - macOS: `SecItemCopyMatching` with attributes only.
   - Windows: `CredReadW`, then immediately `CredFree`, with the blob wiped first.
   - Linux: `secret-tool lookup`, its stdout read into a wiped buffer and dropped.
5. **Reads return exact bytes.** Strict UTF-8, no `trim()` (`file:` keeps its one-trailing-newline rule).
   - Reads are non-interactive and bounded like the probe (rule 7). A locked store or a refused interaction fails validation, naming the entry.
   - Bytes are held in one shared crate-private `WipedBytes` buffer (the existing `WipedToken` wipe, widened from `String` to bytes), not a second secret type.

### Listing unused entries

6. **An inventory without enumeration.** `CredEnumerateW`, `secret-tool search` and `security dump-keychain` are never called (each returns values).
   - The owner-only index is `<config dir>/secrets-index.jsonl`, **outside** `secrets/`. It is never listed as unused and never deletable.
   - `{name, store, created_at}` is appended and `sync_all`'d, with its directory synced, **before** each create. A truncated last line is dropped on the next open.
   - A name this save rolled back is recorded as removed.
   - Listing reads the index, keeps names `exists()` confirms, and drops names a loaded config references.

### Availability

7. **The probe.** Read-only, non-interactive, bounded at 2 s, run before anything is written; the same bound applies to every store and read call.
   - **macOS:** query a missing name with authentication UI set to fail. `errSecItemNotFound` means available; `errSecInteractionNotAllowed` (-25308) or `errSecAuthFailed` means unavailable. If `security-framework` 3.7 cannot express the fail mode without new `unsafe`, the implementing PR stops and brings the options to the lead.
   - **Linux:** `secret-tool` missing, no session bus, or the timeout means unavailable. Readiness itself is read over D-Bus with `gdbus` (part of GLib, present wherever libsecret is): the default collection exists and its `Locked` property is false. Locked means unavailable, and no unlock prompt is ever triggered. A `secret-tool` exit status is never used to tell "not found" from a bus failure.
   - **Windows:** a missing name's `CredReadW` giving `ERROR_NOT_FOUND` means available; `ERROR_NO_SUCH_LOGON_SESSION` or any other error means unavailable.

### Windows `unsafe` module

8. **`win_cred.rs`** replaces §2a's first bullet list where they differ.
   - Exports: safe `create(name, &[u8])`, `exists(name)`, `read(name) -> WipedBytes`, `delete(name)`.
   - `CredFree` only on a pointer from a `CredReadW` that returned TRUE, through a guard.
   - `GetLastError` captured as the first call after a failing Win32 call.
   - The blob is the UTF-8 bytes with `CredentialBlobSize` set, never UTF-16. Names reject interior NUL.
   - `CRED_TYPE_GENERIC`, `CRED_PERSIST_LOCAL_MACHINE`.
   - `// SAFETY:` on every block. Tests run on the Windows CI shard.

### Coverage and the `unsafe` allow-list

9. **Field coverage.** `keychain:` is accepted and read through the same path as `file:` in:
   - `SecretRef` and its arm-matching callers (reload recording, `server.metrics_token`, message signing);
   - `accounts.keys` and the adapter HMAC references, and `ReferenceKey` identity;
   - `validate_api_key_material` (`src/config/features/api_key.rs`);
   - `EnvSecrets::resolve` (`src/personal_accounts/provider.rs`);
   - `client_secret_ref`.

   KC.2 has a test per secret field.
10. **The `unsafe` allow-list.** Production `unsafe` lives in exactly `src/win_acl.rs` and `src/win_cred.rs`; ADR-016's test-only `src/gateway/server/tests/alloc_meter.rs` stays. A source-scan test pins the list, and the implementing PR updates ADR-016's "exactly one module" sentence and the `src/lib.rs` comment. This supersedes §2a's two-file scan.
11. **Capability files are out of scope.** Their `keychain:` and `{keychain.X}` keep the old readers, and a UI save never writes a `keychain:` reference into capability YAML until they share these backends (MIK-8902).
