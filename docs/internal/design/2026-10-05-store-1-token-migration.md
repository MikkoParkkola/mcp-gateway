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

## 12. Amendments after design review round 1 (kimi SWF; gpt pending at writing)
- **Sink (b) exclusion guard (kimi F1).** The carry runs only in an `OAuthClient` built from a
  backend's own `backends.X.oauth` block. It is skipped, before any 3.x path is opened, when the
  backend is bound to an `accounts.descriptors` entry (the same `account_bindings::compile`
  predicate `resolve_legacy_backend_name` uses). Row 10: a backend that has both an `oauth` block
  and an account binding, with a matching 3.x file, does not carry; the 3.x file is made
  unreadable to prove it is not opened, and the binding is the only difference from row 1.
- **Marker before entry (kimi F2).** The carry creates the marker first (create-new), then the
  entry (create-new). A crash in between leaves a marker with no entry: no carry next time, and
  one re-authorization (fail-safe). The reverse order could resurrect a later logout. Row 11 kills
  the process between the two writes (a test hook) and asserts no carry on the next start.
- **Row 5 rebuilt (kimi F3).** The 3.x file is readable, private and carries the matching
  endpoint. A 4.0 entry holds a different token. Oracles: the 4.0 entry's bytes are unchanged, and
  the backend request carries the 4.0 token, not the 3.x one. The "carry over an existing entry"
  mutant now turns it RED.
- **Observability (kimi improvement).** A successful carry logs once at `info` with the backend
  name and issuer (no token material), so operators can tell when every backend has carried over
  before deleting 3.x files.
- **Deterministic race (kimi improvement).** Row 7 uses a barrier hook so both clients reach
  create-new together.
- **Normalisation rows (kimi improvement).** Normalisation applies to both sides. Unit rows pin the
  safe negatives (trailing slash, percent-encoding case, explicit default port): each is a
  one-time re-authorization, never a carry across a real difference.
- **Notice wording (kimi improvement).** The last sentence is split, the revocation caveat gets
  its own sentence, and the capitalised AND is dropped.

## 13. Round 1 outcome: the automatic carry has no evidence to act on (gpt SWF, verified)
gpt-20261005T003052Z-53104 found that genuine v3.5.1 output never records `token_endpoint`.
Verified at tag v3.5.1:
- `TokenInfo::from_response` sets `token_endpoint: None` (`src/oauth/storage.rs:101`).
- Every backend OAuth save goes through it: authorize (`src/oauth/client/mod.rs:439`), refresh
  (`:789`) and client credentials (`:841`).
- Only a test fixture sets the field (`storage.rs:934`).

So §3's rule (positive evidence by exact `token_endpoint` equality) refuses every real 3.x
backend token. The automatic carry would ship and migrate nothing. gpt's CRITICAL F1 (an issuer
that advertises the legacy endpoint once and then moves it) also shows that endpoint equality at
one moment does not establish who issued the grant.

A 3.x token file carries no issuer evidence at all. Any carry therefore needs the issuer
asserted by someone outside the file, and only the operator can do that.

### Recommended replacement (for the operator's ruling)
An offline, operator-asserted command for plain backends (sink a), the sibling of
`accounts migrate-credentials`:
`mcp-gateway oauth migrate-legacy --config PATH --backend NAME --issuer URL`.
- It reads the 3.x record and client file for `NAME` + `http_url` through the guarded reader, and
  writes them create-new under `storage_key(NAME, URL)`, with the marker written first. 3.x files
  are never written.
- The runtime needs no change. `initialize` loads under the discovered issuer, so the copy is used
  only if discovery returns exactly the asserted issuer. A wrong assertion is never used and costs
  one re-authorization.
- Refresh goes to the asserted issuer's discovered token endpoint, the same trust model as the
  account command (the operator vouches for the issuer). Re-running is a no-op when an entry
  exists (conflict rule §5).
- Existing notice item 1 already offers a manual command, `accounts migrate-credentials`. That
  command writes only the personal-accounts store, so it cannot keep a plain backend's
  credential, and every 3.x token belongs to a plain backend (3.x had no accounts). The item is
  misleading for the common case today, whatever the ruling. The new command gives it a true
  referent: "To keep a credential instead, run `mcp-gateway oauth migrate-legacy ...` per backend
  (`accounts migrate-credentials` for account-bound backends)". The default stays
  re-authenticate once, so the published default does not change.
- The round-1 findings that still apply carry over: the commit protocol (scratch file plus
  atomic first-writer-wins publish, marker first), the 401-on-unexpired path, the client-id
  conflict with an existing 4.0 registration, the rollback note on rotated refresh tokens, and a
  mutant row that detects a writable open.
- Estimate (steps): (1) RED rows against the CLI and the runtime load; (2) the command and the
  publish protocol; (3) the CLI wiring; (4) notice item 1, UPGRADING and changelog; (5) Spark
  suites and lint; (6) two-seat review; (7) mutants and CI.
- src/ files: `src/cli/mod.rs`, `src/commands/` (new `oauth_migrate.rs`), `src/oauth/storage.rs`
  (create-new publish), `src/oauth/legacy_carry.rs` (new), `src/commands/upgrade_notice_items.rs`,
  plus tests. The `read_legacy_source` visibility decision (§10) still applies.

The automatic design in §§2-12 is kept above as the record of what was considered and why it was
rejected.
