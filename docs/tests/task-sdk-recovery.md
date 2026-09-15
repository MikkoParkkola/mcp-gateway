# Real SDK task recovery

This test starts the production gateway with OIDC authentication, a pinned
FastMCP task server, and Redis. It checks crash/restart recovery, owner isolation,
revoked access, a retained upstream handle, and exactly one original dispatch.

Run on Linux with Python 3, venv support, Docker, and the Rust toolchain:

```sh
scripts/test-task-sdk-recovery.sh
```

The runner installs FastMCP 4.0.3, fastmcp-tasks 4.0.3, and pydocket 0.25.0 in
an isolated venv. Its disposable Redis image is pinned by digest. Redis binds
only to loopback and is removed on exit. The runner retains Cargo output,
image identity, and cleanup logs, and requires exactly one passing test with
no ignored tests. It preserves the caller's warning settings.

On Spark, reuse the already provisioned pinned interpreter by setting
`MCP_GATEWAY_TASK_SDK_PYTHON`. An externally owned loopback Redis instance may
be supplied with `MCP_GATEWAY_TASK_SDK_REDIS_URL`; the runner only removes
containers it created. Use a dedicated empty Redis instance for this fixture.
Set `MCP_GATEWAY_TASK_SDK_LOG_DIR` to choose the evidence directory.

The test target requires the `task-sdk-recovery` feature, so ordinary
`cargo test` does not need these external services. The complete all-feature
verification is split into two required steps:

```sh
cargo test --all-features -- --skip a_real_sdk_job_outlives_the_gateway_and_its_owner_reads_the_result
scripts/test-task-sdk-recovery.sh
```

The ordinary CI test job excludes only this named external journey. The SDK
job executes it through the same runner. Both CI container publication and
the release workflow depend on the SDK job; a green ordinary suite cannot
replace this evidence. Running `cargo test --all-features` directly also runs
the SDK test and requires its Python and Redis environment to be provisioned.
