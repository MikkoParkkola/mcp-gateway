# OWUI browser-identity proof harness

Proof only. Not a product. Not canonical gateway principal mapping.

A browser logged into real Open WebUI at the isolated upstream
`http://127.0.0.1:19080` can establish the **same stable OWUI user-id** at this
same-origin HTTPS bridge. Browser B, stolen A links, anonymous, CSRF, duplicate
`token` cookies, and replay must not bind.

**Boundary:** no OAuth token exchange; no account-store changes; fixture owner
is not taken from a browser query principal. Upstream to loopback HTTP has no
TLS verify (out of scope). All browser traffic is HTTPS. Authenticated lookup
forwards **only** the `token` cookie; duplicate `token` cookies are refused.
Login UI never displays credentials or raw OWUI bodies. Logs never include
cookies, passwords, JWTs, raw upstream bodies, or the fixture owner id (use
labels A/B and pass/fail). Status pages show sanitized HTML and numeric
counters only.

## Launch (root)

Root supplies disposable TLS cert/key and the isolated OWUI. Port is an argument.

```sh
python3 bridge_harness.py \
  --port 8443 \
  --cert /path/to/harness.crt \
  --key /path/to/harness.key \
  --https-origin https://127.0.0.1:8443 \
  --expected-user-id '<synthetic-id-of-A>'
```

`--https-origin` is required and must be `https://…` (exact Origin match on confirm).

Alternatively omit `--expected-user-id` and set the fixture owner from **loopback
only** with the random harness admin capability (generated at process start, **not
printed**). Root injects it into the process; browsers must not receive it:

```
GET https://127.0.0.1:8443/control/owner
  Host loopback
  Header X-Harness-Admin: <capability>
  Header X-Expected-User: <synthetic-id-of-A>
```

## Browser cases (root drives)

1. **A login** — open `https://127.0.0.1:<port>/ui/login`. Sign up / sign in via
   the form (real `/api/v1/auths/signup` or `/signin`). Expect `ok`/`fail` only.
   Session cookie: Secure, HttpOnly, SameSite=Lax (`token` from OWUI, re-issued
   by the harness).
2. **A start** — same browser, `GET /bridge/start`. Must match fixture owner via
   live `/api/v1/auths/` (id only; token/profile ignored). Renders CSRF form;
   **does not bind**. Sets challenge + CSRF cookies.
3. **A confirm** — `POST /bridge/confirm` with exact Origin, pre-existing
   challenge cookie, synchronizer CSRF, revalidated OWUI identity. Binds once.
   Status: `ok`. Counters: `bind_ok` increments.
4. **A replay** — repeat confirm. Must **fail**. Journey is one-use.
5. **B** — other browser (no A session, or B’s session). `/bridge/start` and
   `/bridge/confirm` must **fail**. No bind.
6. **Stolen link** — open `/bridge/start` or `/bridge/confirm` without A’s
   session / without challenge cookie. **fail**.
7. **Anonymous** — no `token`. **fail**.
8. **CSRF / cross-origin** — POST with wrong or missing Origin. **fail**.
9. **Duplicate cookies** — two `token` cookies. **fail**, never forwarded.
10. **Status** — `GET /status` shows `bound:0|1` and numeric counters only.

Unit tests (no browser, no network):

```sh
python3 -m unittest test_bridge_harness.py -v
```

Root runs integration (TLS, real OWUI, browsers A/B). This tree does not.
