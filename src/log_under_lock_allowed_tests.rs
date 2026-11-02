// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The log-under-lock scan's allowlist, apart from the scan for the file-size
//! ceiling.

/// Sites that log under a guard on purpose, each with why it cannot block,
/// and sites the scan reads as holding a guard when none is held, each with
/// what the matched name really is: (file, function, "macro!: message",
/// reason). Keyed by the message, so a
/// new line in an allowed function is still a hit. None of them can block:
/// every tracing line goes through the lossy stderr writer, which never waits.
pub(super) const ALLOWED: &[(&str, &str, &str, &str)] = &[
    (
        "src/backend/package_cache.rs",
        "repair_while_locked",
        "warn!: could not clear package cache",
        "the repair lock is the retry's exclusion and is held to its end; the lossy writer never waits",
    ),
    (
        "src/backend/package_cache.rs",
        "repair_while_locked",
        "warn!: moving the package cache aside did not finish in time; abandoning the repair",
        "the repair lock is the retry's exclusion and is held to its end; the lossy writer never waits",
    ),
    (
        "src/backend/package_cache.rs",
        "repair_while_locked",
        "warn!: package cache cleared after a failed start; retrying once",
        "the repair lock is the retry's exclusion and is held to its end; the lossy writer never waits",
    ),
    (
        "src/backend/package_cache.rs",
        "retire_cache_dir",
        "warn!: package cache rename task failed",
        "the guard has moved into the rename task, which the scan cannot see; the lossy writer never waits",
    ),
    (
        "src/backend/package_cache.rs",
        "start_reporting_with",
        "warn!: start failed; reporting how the child ended, not what it printed",
        "the line precedes the repair the same guard is handed to; the lossy writer never waits",
    ),
    (
        "src/backend/stop.rs",
        "stop",
        "info!: Stopping backend",
        "the stop's exclusion is held for the whole teardown on purpose; the lossy writer never waits",
    ),
    (
        "src/backend/stop.rs",
        "stop",
        "warn!: Replaced transports still had live callers at shutdown; abandoning their cleanup",
        "the stop's exclusion is held for the whole teardown on purpose; the lossy writer never waits",
    ),
    (
        "src/backend/stop.rs",
        "stop",
        "warn!: Restart still in flight after the shutdown wait; proceeding without exclusion",
        "the stop's exclusion is held for the whole teardown on purpose; the lossy writer never waits",
    ),
    (
        "src/backend/stop.rs",
        "stop",
        "warn!: Restart still in flight at the end of the shutdown drain; its cleanup may not run",
        "the stop's exclusion is held for the whole teardown on purpose; the lossy writer never waits",
    ),
    (
        "src/gateway/server/persistence.rs",
        "write_costs",
        "warn!: Clock reads before 1970; cost save skipped, the last saved spend stands",
        "the cost-write turn is borrowed from the caller; the lossy writer never waits",
    ),
    (
        "src/gateway/task_service/execution/pending_cancel.rs",
        "claim",
        "warn!: upstream cancel claim not written; nothing sent",
        "the parked guard is borrowed from the caller; the lossy writer never waits",
    ),
    (
        "src/oauth/client/refresh_flight.rs",
        "refresh_stored",
        "warn!: Refresh state unreadable; retiring the stored token",
        "the cause precedes the retirement that runs under the guard; the lossy writer never waits",
    ),
    (
        "src/protocol/era.rs",
        "reprobe_with",
        "info!: fields backend slot hit",
        "the record precedes the probe that runs under the observation guard; the lossy writer never waits",
    ),
    (
        "src/protocol/era.rs",
        "resolve_triggered",
        "info!: fields backend slot hit",
        "the record precedes the probe that runs under the observation guard; the lossy writer never waits",
    ),
    (
        "src/protocol/era.rs",
        "restart_while_serving",
        "info!: fields backend slot hit",
        "the record precedes the probe that runs under the observation guard; the lossy writer never waits",
    ),
    (
        "src/protocol/era.rs",
        "restart_while_serving",
        "info!: fields backend slot reason",
        "the record precedes the probe that runs under the observation guard; the lossy writer never waits",
    ),
    (
        "src/protocol/era_install.rs",
        "store",
        "info!: fields backend slot outcome evidence error_code trigger",
        "the record is written with the install, under the caller's guard; the lossy writer never waits",
    ),
    (
        "src/protocol/era_install.rs",
        "store",
        "info!: fields backend slot outcome evidence trigger",
        "the record is written with the install, under the caller's guard; the lossy writer never waits",
    ),
    (
        "src/protocol/era_install.rs",
        "store",
        "info!: fields backend slot reason outcome evidence trigger",
        "the record is written with the install, under the caller's guard; the lossy writer never waits",
    ),
    (
        "src/security/firewall/allowed_root.rs",
        "warn_at_load",
        "warn!: secret {:?} of backends.{name} owns {owned:?}, a declared argument in {path}.path_args: covered calls are refused",
        "not a guard: config.backends is the plain HashMap at config/mod.rs:142, not the registry DashMap the scan matches by field name",
    ),
    (
        "src/transport/http/startup.rs",
        "connect_as",
        "info!: OAuth required - initiating authorization flow",
        "the line precedes the login that runs under the client mutex; the lossy writer never waits",
    ),
    (
        "src/transport/http/transport_impl.rs",
        "request_with_headers",
        "warn!: Backend session expired; re-initializing and retrying once",
        "the line precedes the resend that runs under the reinit lock; the lossy writer never waits",
    ),
];
