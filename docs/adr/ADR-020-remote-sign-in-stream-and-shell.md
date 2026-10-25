# ADR-020: Remote sign-in, the live stream, and how the shell is delivered

- **Status**: Proposed, 2026-10-25
- **Ticket**: MIK-8839 (ADR.4 and ADR.7, decided together because each constrains the other); unblocks U3 (MIK-8856, live stream), UI1 (MIK-8875, shell) and UI12 (MIK-8886, progressive enhancement)
- **Base**: `docs/ranking-1-release-line` at `d13b042cb`

## Context

| # | Fact | Where |
|---|---|---|
| F1 | A one-time dashboard link signs a browser in with a session cookie. The link is redeemed only from a loopback peer. | `src/gateway/ui/session.rs:154-167` |
| F2 | The handoff (#2130) carries that sign-in to a remote browser: the loopback redemption shows a one-time code, and the operator enters it in a same-origin form on the gateway's HTTPS `public_url` (served through a proxy), which sets the same session cookie there. The code never travels in a URL. | `src/gateway/auth_handoff.rs:3-12` |
| F3 | The other path is the API key typed into the page, held in page memory and sent as a bearer header; a reload signs out. | api-gaps.md section 3 "Sign-in today" |
| F4 | `EventSource` cannot send an `Authorization` header; a cookie it can send. | WHATWG HTML, EventSource |
| F5 | The new shell is one static document and content-hashed assets, unauthenticated and holding no gateway data; all data comes from `/ui/api/*`, which is authenticated. Its CSP allows scripts, fetches and form posts to its own origin only. | `src/gateway/ui/shell.rs:3-7`, `:24-28` |

So a cookie session is already available remotely, wherever the gateway is served on an HTTPS `public_url` and the operator can reach the host once to mint the code. What does not exist is a remote sign-in that needs no access to the host.

## Options

1. **Cookie first, bearer as fallback, no new auth surface.** The UI signs in with the session cookie from the link (F1) or the handoff (F2); live updates use `EventSource` with that cookie. An operator with only a key signs in with it (F3), and the live feed for that session is a streamed `fetch` response carrying the bearer header.
2. **A new interactive remote login** (password or key exchange over the network that issues the cookie with no host access). Needs brute-force limits, CSRF on every form, mandatory TLS and its own security review.

## Decision

Option 1 for 4.0.0.

- **Shell.** The shell stays static and unauthenticated (F5). Every number comes from authenticated `/ui/api` calls.
- **No-JS fallback.** For cookie sessions, the gateway also serves server-rendered pages for reading and for every write, as plain HTML forms posted to its own origin. Each form carries a CSRF token tied to the session, and the existing origin check refuses a cross-origin post. This is where UI12's "works without JavaScript" holds: on loopback and behind the handoff. The pages live under `/ui/plain/...`; `plain` is added to the shell catch-all's exclusions beside `api` and `assets` (`src/gateway/ui/shell.rs:32-36`), so the catch-all never answers there; the shell's `<noscript>` link points there. They need a valid cookie session and answer `Cache-Control: private, no-store`. The cookie is already `HttpOnly` and `SameSite=Strict` (`src/gateway/auth.rs:399-402`), so a cross-site form cannot carry it; the CSRF token is the second check, and a later change to those cookie attributes reopens this ADR.
- **Stream.** U3 serves one event feed two ways: as `text/event-stream` for cookie sessions, and as a streamed `fetch` response for bearer sessions. A dropped stream reconnects with backoff, and the top bar shows "Updates stopped at HH:MM · reconnecting" (frame 40s).
- **Bearer sessions.** The key stays in page memory, never in `localStorage` or a cookie; a reload asks for it again, and the page says so once. Bearer sessions need JavaScript.
- **Later.** A remote login with no host access (Option 2) is a v4.1.0 decision with its own security review.

## Consequences

- No new authentication code in 4.0.0; the server-rendered fallback adds form handlers and a CSRF token on top of the existing cookie session.
- UI12's criterion reads "reading and writing work without JavaScript for cookie sessions (loopback, or the handoff on an HTTPS public_url); key-only sessions need JavaScript".
- The shell holds no per-user data, so it stays cacheable.
- U3 maintains two transports for one feed; both are covered by the same reconnect test.
