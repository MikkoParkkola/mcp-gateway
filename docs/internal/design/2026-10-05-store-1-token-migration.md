# MIK-6744.STORE.1: carry 3.x OAuth tokens into 4.0 on first use (design, no code)

Status: design for review, 2026-10-05. No code. The operator's ruling decides whether this lands
before the 4.0.0 freeze or in 4.0.1.

## 1. Problem and scope
4.0.0 keys an OAuth backend's credentials by issuer. 3.x keyed them by backend name and resource
URL, so a 3.x token is never read and every OAuth backend re-authenticates once (notice item 1,
`src/commands/upgrade_notice_items.rs:16-26`). The criterion asks for "readable/migrated
single-user data and no silent loss". The docket (`docs/release/v4.0.0-decision-docket.md:64,75`)
records two things: building this changes a notice operators have already read, and the
decryption obstacle the earlier grading assumed does not exist.

Facts at the release-line tip (V = read in code, I = inferred):
- 3.x tokens are plaintext JSON `TokenInfo` at `~/.mcp-gateway/oauth/{k}_tokens.json`, where
  `k = hex(sha256(backend_name ":" http_url)[..8])`. Dynamic client ids are in `{k}_client.json`.
  Files are mode 0600 (`src/oauth/storage.rs:170-191, 232-246, 271-274`). The format is
  byte-identical to v3.5.1, and 4.0 parses it with no key (`src/oauth/upgrade_path_tests.rs:51-61,
  93-120`). V
- A 3.x record carries no issuer. Its only issuer evidence is the optional `token_endpoint`
  (`storage.rs:19-51`; `src/cli/mod.rs:197-201`). V
- 4.0 has two sinks:
  - (a) plain `backends.X.oauth`: the same directory and `TokenStorage`, keyed
    `storage_key(backend_name, issuer)` (`src/oauth/client/mod.rs:109-111, 389-395`). The issuer
    is known only after discovery (`:349-358`). V
  - (b) the encrypted personal-accounts store (`src/personal_accounts/`), written by the manual
    `accounts migrate-credentials` command, which requires an operator-asserted `--legacy-issuer`
    (`migration_precondition.rs:101-137`). V
- 3.x had no personal accounts. Every 3.x token is therefore a sink (a) token. I
- The upgrade framework's `Migration::apply` gets only `data_dir` and runs before the config loads
  (`src/commands/upgrade.rs:53-65`; `src/main.rs:611, 669`). It cannot discover issuers. V

Scope: an automatic carry for sink (a), done lazily at the first OAuth initialisation of each
backend. Sink (b) keeps the manual command: an account's issuer cannot be established without
the operator, and defaulting it from the descriptor would defeat `IssuerMoved` (§7).

## 2. Where it runs: lazy, in `OAuthClient::initialize`
After discovery, `initialize` loads the 4.0 entry under `credential_key()` (`client/mod.rs:362-367`).
The carry runs only when that load returns nothing:
1. Read the 3.x record at `storage.token_path(backend_name, resource_url)` through the existing
   guarded reader (`read_legacy_source`: no symlink, private regular file, parseable). Any refusal
   means no carry.
2. Apply the issuer rule (§3). A refusal means no carry.
3. Copy the record (and the 3.x `{k}_client.json`, when present and the client has no client id)
   to the 4.0 key with create-new semantics (§5).
4. Load the 4.0 entry as today.

Why lazily and not as an upgrade migration: only the running client knows the discovered issuer,
the resource URL and the SSRF-checked endpoints. A start-up pass would need network discovery
before serving, for every backend, including ones never used again.

## 3. Per-issuer mapping: what lets a 3.x token in
A 3.x token is carried under issuer `I` only with positive evidence that it was issued by `I`:
- the record has a `token_endpoint`, and
- it is exactly equal (after URL normalisation: scheme, host and port lowercased, default port
  dropped, path kept byte-for-byte) to the `token_endpoint` in `I`'s discovered metadata, which
  `check_advertised_endpoints` already passed.

Origin equality is not enough. Multi-tenant authorization servers share an origin across issuers
(for example, a path per tenant), and an origin rule would re-home a credential across tenants.

Refused, with a fallback to re-authentication: no `token_endpoint`, a different one, an
unparseable one, or a token endpoint that discovery did not advertise.

Why this cannot hand a refresh token to the wrong server: the 4.0 key exists so that a credential
is never presented to an issuer that did not issue it. Under this rule the refresh token is only
ever sent to the endpoint it was already used with in 3.x. A swapped or compromised metadata
document names a different endpoint and is refused, because exact equality fails.

## 4. Non-destructive: 3.x files are never written
- Only reads touch 3.x paths: `{k}_tokens.json` and `{k}_client.json` are opened read-only. Nothing
  renames, truncates, chmods or deletes them. The carry writes only new 4.0-keyed files.
- A rollback to 3.x reads its own files unchanged. The stated caveat stays: once 4.0 refreshes
  against a provider that rotates refresh tokens, the 3.x copy's refresh token is dead, and 3.x
  re-authenticates that backend once. This is the same grant, used twice, and there is no fix for
  it short of not refreshing.

## 5. Conflict with an existing 4.0 entry
- A 4.0 entry under the issuer key always wins. The carry runs only when the 4.0 load found
  nothing, and the write is create-new (`config_persistence::create_new_private`, the primitive
  `save_client_id` already uses). If two clients race, one creates and the other's create fails;
  the loser then loads the winner's entry. A 4.0 entry is never overwritten by 3.x material.
- After a carry, ordinary 4.0 saves (refresh, re-authorization) replace the carried entry as they
  replace any entry. That is the existing save path, unchanged.
- A 4.0 entry that was deliberately removed (logout or revocation that deletes the file) would
  let the carry run again on the next start. To stop that resurrection, the carry writes a 4.0-side
  marker `{k4}_carried_from_3x` (create-new, empty, 0600) beside the entry, and never carries while
  the marker exists. The marker lives under the 4.0 key, so 3.x never sees it.

## 6. Failure falls back to today's behaviour
Every refusal or I/O error in steps 1-3 is logged once per backend at `info` (reason only, no
token material) and leaves the client exactly as today: the 4.0 load finds nothing, so
`has_valid_token()` is false and `authorize()` runs on next use (`transport/http/startup.rs:76-79`).
A carried token that the server then rejects (401 on use, `invalid_grant` on refresh) goes through
the existing `get_token` path (cache, then refresh, then authorize; `client/mod.rs:448-478`). That
is re-authentication once, the same as today. The carry never makes an outcome worse than the
current default.

## 7. Out of scope, with reasons
- Personal-accounts backends (sink b). Their issuer comes from `accounts.descriptors`. Carrying
  automatically under it would bypass `IssuerMoved` (`migration_precondition.rs:31-34`), so the
  manual `accounts migrate-credentials` stays the only route, as now.
- REST capability credentials (`capability/executor/credentials.rs:341-342`) use their own keying
  in the same directory. They are untouched.
- A backend renamed, or whose `http_url` changed, since 3.x hashes to a different 3.x path. It
  is not carried and re-authenticates once. The manual command's `--legacy-backend-name` covers
  the rename case for sink (b) only.

## 8. Notice wording (item 1) and docs
The current item 1 says every OAuth backend re-authenticates once by default. That is the
sentence this change falsifies. Replacement:

> OAuth credentials are now stored per authorization server. On each OAuth backend's first use,
> 4.0.0 carries over its 3.x token when the token records the same token endpoint the backend's
> authorization server now advertises. Otherwise that backend re-authenticates once: expect one
> authorization prompt for it. No config change is needed. Account-bound backends do not carry
> automatically; run `mcp-gateway accounts migrate-credentials --config PATH --descriptor-id ID
> --legacy-issuer URL` per backend to keep a credential. Your 3.x token files are never modified
> and stay in `~/.mcp-gateway/oauth/` at mode 0600. Delete them once every backend has carried
> over, re-authorized or migrated AND been used successfully: a carried credential is still the
> same grant, so the first refresh against a provider that rotates refresh tokens retires the
> copy in the old file.

The same text goes into `docs/UPGRADING-4.0.md` item 1 and a `changelog.d` fragment. The docket
concern: the published text promised a re-authorization the operator could plan for. The new
text promises fewer prompts, never more, and the one-time-prompt worst case still holds, so an
operator who planned for it loses nothing.

## 9. Test plan (each RED row is shown RED on the base first)
1. RED: a 3.x token whose `token_endpoint` equals the discovered one is carried. No
   `authorize()` (a mock authorization server records zero authorize requests), the backend
   request carries the 3.x access token, and the 4.0 key file exists. The oracle is the
   recorded authorize count, not a log line.
2. RED: the 3.x `{k}_client.json` is carried too, so a refresh presents the 3.x client id (the
   mock token endpoint records it).
3. RED: after the carry, the 3.x files' bytes, mode and mtime are unchanged, and
   `TokenStorage::load(backend_name, http_url)` (the 3.x read) returns the identical record (the
   rollback oracle).
4. Guard (green on the base, must stay green): a different `token_endpoint` (same origin, other
   path) means no carry and one authorize. Repeat with an absent `token_endpoint`, a 0644 file,
   a symlink and an unparseable file.
5. Guard: an existing 4.0 entry is untouched (bytes) and the 3.x file is not opened (the test
   makes it unreadable and still passes).
6. RED: the marker stops resurrection. After a carry, delete the 4.0 entry and restart: no carry,
   one authorize.
7. RED: a race. Two clients initialise concurrently; exactly one file is created, and both end
   up with the same token.
8. Guard: refresh goes only to the recorded endpoint. A carried expired access token refreshes
   against the mock endpoint, and a metadata document advertising another endpoint means no carry.
9. The notice and registry tests are updated: `upgrade_notice_tests.rs` (item 1 substrings, the
   `(1, "re-authenticate")` pairing with UPGRADING), and `oauth/upgrade_path_tests.rs:131-162`
   inverted (the record is now reachable on first use; its "untouched" assertion is kept).
Mutant rows: drop the exact-equality check; carry over an existing entry; open the 3.x file
writable; skip the client-file carry; skip the marker check. Each must turn a row above RED.

## 10. Files touched (planned)
- `src/oauth/client/mod.rs`: the carry call in `initialize`, after the 4.0 load misses.
- `src/oauth/legacy_carry.rs` (new): the guarded read, the issuer rule, the create-new copy and
  the marker. It needs the guarded read in `read_legacy_source`, which is
  `pub(in crate::personal_accounts)` (`src/personal_accounts/migration_source.rs:95`). Reusing it
  from `oauth` widens its visibility to `pub(crate)` or moves it to a shared module. That
  widening is an operator decision, recorded here as open. It is not copied.
- `src/oauth/storage.rs`: a create-new save beside `save`.
- `src/commands/upgrade_notice_items.rs`: item 1. Also `docs/UPGRADING-4.0.md` and
  `changelog.d/<pr>.changed.md`.
- Tests: `src/oauth/legacy_carry_tests.rs` (new), `src/oauth/upgrade_path_tests.rs`,
  `src/commands/upgrade_notice_tests.rs`.
- Not touched: `src/commands/upgrade.rs` (no new migration, so the registry tests and
  `backup_config` are unaffected) and `src/personal_accounts/*`.

## 11. Estimate (steps)
1. Write the RED rows (1, 2, 3, 6, 7) and the guards (4, 5, 8) against a mock authorization
   server; show the RED rows RED on the base.
2. Add the create-new save and the legacy_carry module (read, rule, copy, marker).
3. Wire it into `initialize`; run the rows to green.
4. Item 1 text, UPGRADING, changelog; update the notice tests and upgrade_path_tests.
5. Spark: lib and integration suites, clippy all-features and no-default-features.
6. Two-seat code review and fixes.
7. Mutant batch (5 rows) and CI.
That is about 7 steps, with risk concentrated in step 1. Existing OAuth client tests already serve
discovery documents (`src/oauth/client/tests.rs`, `authorize_tests.rs`), so the mock authorization
server extends an in-tree fixture rather than starting a new one.
