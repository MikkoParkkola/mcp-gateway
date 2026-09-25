# NFR.SEC.7 drift probe, 2026-09-13

A re-probe, not a first one — the row records a two-way verification on 2026-09-11. What
is new is the revision: a release build of `bd1adbb4` (`origin/main`), the same revision
the performance re-measurement was taken against, started on a free loopback port on
`bench-host` and probed by the checker on that tree.

```
$ python3 scripts/dev/check-control-drift.py http://127.0.0.1:39411/mcp
origin-guard: refused 403; legitimate request 200 [provenance unavailable: v4.0.0 is not a tag in this repository]
host-guard: refused 403; legitimate request 200 [provenance unavailable: v4.0.0 is not a tag in this repository]
unsafe-code-denied: uncovered -- a compile-time lint leaves no signal on the wire, drift is caught by the build, not by a request
2 probed, 1 uncovered, 0 failing
$ echo $?
0
```

This says the controls are live in the `origin/main` build. It says nothing about the
deployed `3.4.0-f30539af` install, which is the endpoint the criterion is about and which
still answers a foreign `Origin` and a foreign `Host`. The row stays PARTIAL and blocking
until that install is cut over and re-probed.
