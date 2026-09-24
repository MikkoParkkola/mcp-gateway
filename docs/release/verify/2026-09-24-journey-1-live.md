# MIK-6745.JOURNEY.1 live run on the release line, 2026-09-24

Gateway: `mcp-gateway 4.0.0` built from `438583c15866598653fa4a3de7c4c4ace9de851f`
(release line tip), default features, `cargo build --release --locked`, binary sha256
`5f5271e4be000bbf57b55109c3f00fa7bfea416a52df684d083c69a74660eb18`, listening on
127.0.0.1:39430 behind the Cloudflare tunnel rule `chat.raxor.ai ^/accounts/v1/`.
Open WebUI 0.11.4 (`sha256:4ff8bcc8...`) at https://chat.raxor.ai behind Cloudflare Access.
Provider: Google, scope `gmail.readonly`, `access_type=offline`, `prompt=consent`, PKCE S256.
Driver: agent-browser on a copy of the operator's Chrome profile. The BROWSER legs
(connect, deny, expired, replay, reconnect) ran for real through Cloudflare Access and
Open WebUI: Google IdP for user A, an emailed one-time code for user B. The TOOL-CALL
legs (use, refresh, restart, interleave, independence, revoke) did NOT go through Open
WebUI: `owui_call.py` minted the signed `X-OpenWebUI-User-Jwt` header with the adapter
secret and posted to 127.0.0.1:39430 directly. Row 25 closes that gap with one real
Open WebUI chat tool call.
Users: A = Open WebUI 192d56a7 (Google account G1), B = Open WebUI 9aecce54 (a second Open WebUI login).
Only one Google account exists for this test, so A and B both consent as Google account G1.
Times are UTC. Personal e-mail addresses are replaced by the labels G1 and G2.

| # | Element | Observed | Result |
|---|---|---|---|
| 1 | Unconnected user gets an actionable connect link | 14:23 both A and B refused with `-32001 ... produced no credential for this caller` and their own `/accounts/v1/journeys/<id>/start` link | PASS |
| 2 | CONNECT A, real Google consent | 14:24:43 browser Allow -> gateway page "Account connection: connected" | PASS |
| 3 | USE A | `gmail_search "cloudflare newer_than:1d"` as A -> resultSizeEstimate 2 (A mailbox data) | PASS |
| 4 | REPLAYED callback | A consumed callback re-delivered with its `state` -> "Account connection: already used"; A still works afterwards | PASS |
| 5 | BROWSER CANCELLATION, real Google Deny | 14:28:07 Google redirected `error=access_denied` -> gateway "Account connection: user_denied"; journey status as owner B: 200 `reason: user_denied`; as A: 404 not_found | PASS |
| 6 | CONNECT B | 14:30:24 Allow -> "connected" | PASS |
| 7 | Interleaved use, two users | 10 concurrent calls each as A and B -> 20/20 answered (3 results each); two distinct token records in the store | PASS |
| 8 | EXPIRED consent state, real Google | 14:31:39 B journey `ac5b66ae` parked on the Google consent screen; 14:42:36 (past CALLBACK_WINDOW 600 s) Allow -> real code delivered -> gateway "Account connection: expired"; status 200 `status: expired, reason: expired`; B existing grant still answers afterwards | PASS |
| 9 | Gateway restart keeps grants | 14:23 restart onto the 438583c1 binary: prior state (both disconnected) preserved; restart with both connected: see row 11 | see 11 |
| 10 | Gateway restart keeps grants (both connected) | 15:15:05 gateway stopped; restarted 15:26:57 (new pid); 15:27:04 A and B both answer with no reconnect. (The scheduled 15:15 restart killed its own driver shell because `pgrep -f` matched the command line that contained the pattern; the gateway was down 15:15-15:26 as a result, not from any gateway fault.) | PASS |
| 11 | REFRESH A, real Google token endpoint | A connected 14:24:43, Google access tokens live 3600 s; 15:27:04 call as A: gateway opens `oauth2.googleapis.com` before the Gmail call and the call succeeds; A token record mtime 15:27:05 (rewritten), B record unchanged since 14:30 connect | PASS |
| 12 | REFRESH B, real Google | B connected 14:30:24; 15:31:00 call as B after expiry answers; B token record mtime 15:31:00 (rewritten) | PASS |
| 13 | REVOKE A: gateway side | 15:31:01 `DELETE /accounts/v1/connections/google-workspace` as A -> 200 `status: revoked`; A token record removed; next A call refused with a fresh connect link; B answers at 15:31 and again 15:32:02 | PASS |
| 14 | REVOKE A: provider side | Same DELETE reported `provider_revocation: failed`; log `provider refused the revocation status=400 provider_error="invalid_token"` (one refusal only). Cause: refresh token revoked first (200); Google then kills the derived access tokens, so the access-token revocation is answered 400 invalid_token. The grant IS revoked; the report is a false failure. RFC 7009 s2.2 treats an invalid submitted token as success. Fix in progress. | DEFECT FOUND, fix pending |
| 15a | ~~Provider-level independence on one Google account~~ (superseded by 15b) | After the A refresh token was revoked at Google, B (its own consent and refresh token) still answers at 15:31 and 15:32; a B refresh after 16:31 confirms the B refresh token survived | PARTIAL, pending 16:31 |
| 15b | CORRECTION to row 15a | The earlier B checks (15:31-15:35) returned real data, but by 15:37 B's calls fail with Google `401 Unauthorized` while the freshly reconnected A works. A and B consented as the same Google user to the same OAuth client, which Google treats as ONE grant; revoking A's refresh token revoked B's at Google too, taking effect within minutes. Provider-level independence therefore FAILS on a single Google account by provider design and can only be shown with two Google accounts. Gateway-side isolation (row 13) stands. | FAIL (provider semantics; needs 2 accounts) |
| 16 | Gateway handling of a provider-rejected token | B's call returns Google's 401 as a tool result with `isError: false`; the gateway keeps releasing token_revision 2 until its expiry time (about 16:31) instead of treating the 401 as a signal to refresh or ask for reconnect | GAP, tracked separately |
| 17 | LATE REPLAY | 15:34:22, 70 min after use, A's consumed callback re-delivered -> "already used" (not "expired"); journey status `connected`, `replay_refused: true`, `replay_refusals: 2` | PASS |
| 18 | RECONNECT A after revoke | 15:35:03 real consent -> "connected"; A returns data (resultSizeEstimate 3) | PASS |
| 19 | ROLLBACK (L04) on a restored copy | Store snapshot `accounts-backup-20260924T173529.tgz` restored into `live-l04/`, config copied with all paths repointed, port 39431, `accounts.hosted` removed. DOCUMENTED ROLLBACK IS INCOMPLETE: the gateway refuses to start, `accounts.adapters[0]: session requires accounts.hosted; without it no bridge is mounted`. With the adapter `session` block also removed it starts; `/accounts/v1/{journeys,callback,journeys/<id>/start,connections/<id>}` all 404 (403 at the Host guard for chat.raxor.ai); a never-connected user is refused with no connect link; B's preserved grant is still released (`token_revision=2`), i.e. rollback keeps grants usable rather than mapping them to a shared credential | PASS after doc fix; doc defect found |

## Final build e2c34b78 (after #756), two separate Google accounts

Gateway rebuilt at `e2c34b78` (release line tip after #756), `cargo build --release --locked`, binary sha256 `d380224aaeac20c69185ca4bfca8413701f6965ae1ab4e055c40336216e6a539`. Test user added by the operator: B now consents as Google account G2, a Google account separate from A's Google account G1.

| # | Element | Observed | Result |
|---|---|---|---|
| 20 | CONNECT B on a second Google account | 16:08:52 real consent as Google account G2 (2FA from the account's authenticator) -> "connected" | PASS |
| 21 | Seeded discriminator, two accounts | same query `cloudflare newer_than:2d`: A 5 results, B 0; `newer_than:2d`: B 2 -- each user reads only its own mailbox | PASS |
| 22 | Restart onto the final build, both connected | 16:09:34 restart onto e2c34b78; A 5, B 0 with no reconnect | PASS |
| 23 | REVOKE A, provider side, final build | 16:09:35 DELETE as A -> 200 `status: revoked`, `provider_revocation: confirmed`; log `token already invalid at the provider` for the access-token leg (the #756 path) | PASS |
| 24 | Revoking A does not affect B, at Google | B answers at 16:10:37, 16:15:37 and 16:22:38 (13 min, well past the 2-6 min propagation seen when both shared one Google account); A refused each time with a fresh connect link | PASS |
| 25 | USE through real Open WebUI chat, final build | 16:40:45 as B in the Open WebUI chat window: tool "JOURNEY.1 test (Gmail read)" enabled, model deepseek-v4-flash asked to call gateway_invoke gmail_search `newer_than:2d`; Open WebUI itself sent `tools/call` (gateway log 16:40:46.89) and the chat answered `2`, B's own count (row 21) | PASS |
| 26 | Cached data cannot return after revoke | A's `cloudflare newer_than:2d` answered 5 at 16:09:34; the same query at 16:10:37, inside the capability's 300 s result cache, returned a connect link, not the cached result. The result cache is keyed per caller (`cache_binding`, `src/capability/execution_context.rs:44`), and an A-then-B probe earlier returned B's own 401, not A's cached count | PASS |

## Build difference between rows 1-19 and rows 20-26

Rows 1-19 ran on `438583c1`, rows 20-26 on `e2c34b78`. `git diff --stat 438583c1..e2c34b78 -- src/`
touches only the personal-accounts revocation path (#756): `provider/grant_flow.rs`,
`revoke.rs` and their tests and fixtures. The revoke rows were re-run on `e2c34b78` (row 23).

## Disclosures and residuals

- A read-only test capability `gmail_get` (Gmail `messages.get`, `format=minimal`, same
  scope and account binding as `gmail_search`) was added to the TEST gateway's capability
  directory only, to read the Cloudflare one-time code for user B through A's grant instead
  of a browser Gmail session. It is not in the repository.
- Not inspected: A's Google Account permissions page after revoke (the design's L03-revoke
  asks for it); the provider response `confirmed` (row 23) and B's continued access are
  the evidence used instead.
- Found, not blocking: after a provider-side revoke the gateway keeps releasing the old
  access token until its expiry time and returns the provider's 401 as a tool result
  with `isError: false` (row 16); filed for 4.0.x.
- Found and fixed: the documented rollback (remove `hosted`) does not start; the adapter
  `session` block must be removed too (row 19). Docs corrected in the same change.
- Operator ruling to close the row: 2026-09-24, see the ledger decision entry.
