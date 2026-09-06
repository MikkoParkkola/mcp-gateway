<!--
SPDX-FileCopyrightText: 2026 Mikko Parkkola
SPDX-License-Identifier: MIT
-->

# An OAuth-bearing HTTP transport must reach TLS or loopback

CodeQL `rust/cleartext-transmission` #90/#91 (CWE-319): `get_oauth_token`
(`src/transport/http/mod.rs`) mints a bearer token that
`send_request_with_headers` then posts to `&message_url` — a URL whose scheme
the transport never checked. A token on a cleartext hop is readable by every
host on the path and replayable for its whole lifetime.

## What changed

One guard, `require_secure_oauth_target`, at the shared root cause rather than
at the two reported lines. Called twice, both on the dataflow path CodeQL
traces:

1. `new_with_oauth`, on the base origin, when an OAuth client is present — the
   transport's `initialize()` runs `oauth.initialize()`/`authorize()` and spawns
   the refresh task *before* any header is built, so a request-time-only check
   would mint a credential it is then forbidden to send.
2. `get_oauth_token`, on `self.get_message_url()`, before the token is fetched —
   the SSE handshake can move the message endpoint after construction, and this
   is the only placement between CodeQL's source and its sink.

Loopback (`localhost`, `127.0.0.0/8`, `::1`) is exempt: a local backend has no
certificate and the packet never leaves the machine. The classifier is
`crate::gateway::is_loopback_host`, the one the Origin gate and the config-load
credential guard already use, so the three cannot drift.

## Design events (§P3 — decisions the design did not make)

**`allow_cleartext_credentials` no longer covers OAuth.** `Config::validate`
already refuses a credential-bearing cleartext backend at load
(`reject_cleartext_credentials`, `src/config/mod.rs`), and documents an opt-out
flag. That flag now has no effect on an `oauth: {enabled: true}` HTTP backend:
the transport refuses it regardless. This is a breaking change to a documented,
tested feature, taken deliberately — a defeatable load-time check is exactly why
#90/#91 stayed open, and a flag that re-enables a HIGH finding leaves the alert
open forever. 4.0.0 is the release that may break it. The refusal message names
the non-coverage so an operator who set the flag is not left guessing, and
`docs/REMOTE_BACKENDS.md` carries the carve-out.

**The split between the two guards is deliberate, not an omission.** OAuth gets
an undefeatable transport guard. Every other credential class — static headers,
identity propagation, secret injection, a credential-bearing URL, and the
per-user `Authorization: Bearer <assertion>` that `send_request_with_headers`
merges from `extra_headers` (MIK-6704, transports built by `new()` with
`oauth_client: None`) — keeps the config-load guard with its opt-out. Those
credentials are operator-supplied and their sensitivity is not decidable at the
transport; the OAuth token is one the gateway itself mints and is unambiguously
a bearer credential.

**`http://[::ffff:127.0.0.1]` is refused.** `Ipv6Addr::is_loopback` is false for
an IPv4-mapped address; rather than widen the classifier for a form no backend
uses, the safe answer is to refuse and write `http://127.0.0.1`. Pinned by a
test so it cannot become an accident.

## Not verified here

Whether CodeQL models the guard as a barrier and marks #90/#91 fixed — the
refusal returns `Err` *before* `oauth.get_token()` runs, which is the shape a
sanitizer takes, but only the next CodeQL run answers it.
