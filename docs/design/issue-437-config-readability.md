# Issue 437: actionable config-readability diagnostics

Status: locally validated; remote delivery pending

Issue: <https://github.com/MikkoParkkola/mcp-gateway/issues/437>

## Problem

The official image runs as `gateway` (UID/GID 1001). A Linux bind mount keeps the host file ownership and mode, so a root-owned `0600` `gateway.yaml` exists inside the container but cannot be read by the process. `Config::load` currently checks only `Path::exists`; Figment then reports a generic YAML-file permission error. Under a Docker restart policy, the same non-zero startup failure repeats without telling the operator which security-preserving ownership change is required.

The report also describes `usage.json` and `transitions.json` being replaced by empty arrays. Current-main control flow does not support that as a consequence of the unreadable-config startup itself: both HTTP and stdio return immediately from `Config::load`, before `Gateway::new_with_path` constructs or loads either persistence object. The persistence observation remains important, but it needs an independent failing sequence before changing persistence semantics.

## Scope

FOR:

- identify an unreadable selected config before Figment parsing;
- name the path, OS error, and current-process ownership requirement;
- give a secure official-container remediation using UID/GID 1001 without recommending world-readable secrets;
- preserve fail-loud startup and the existing `Error::Config` public behavior;
- document the requirement beside every official Docker bind-mount example;
- add a regression-first Unix test for the actual unreadable-file path.

OUT:

- changing Docker restart policy or hiding the non-zero exit;
- running as root or weakening the image user;
- automatically chmod/chowning a host bind mount from inside the container;
- changing persistence writes without a reproduced persistence failure;
- Windows ACL interpretation, which has no Unix UID/mode equivalent.

## Evidence and constraints

- `Dockerfile` creates and selects UID/GID 1001.
- `Config::load` accepts an existing path and lets two Figment extraction passes open it.
- `run_server` and `run_stdio_server` return before gateway construction when `Config::load` fails.
- ranker and transition state are loaded only in `Gateway::build_meta_mcp` and saved only after the server run returns.
- Config files may contain bearer tokens and API keys. `chmod 644`, while sufficient for readability, contradicts the repository's owner-only security policy.
- GitNexus reports LOW impact for `Config::load`, but its Rust graph lists no incoming callers. Source search finds call sites in serve, doctor, validate, setup, add/remove, config export, reload, and tests; validation therefore covers the shared loader rather than trusting the incomplete graph result.

## Options

### A. Open preflight, then keep Figment authoritative — selected

After resolving the chosen path, attempt `std::fs::File::open`. Map `PermissionDenied` to an actionable `Error::Config`; map other open failures to a path-specific read error. If the open succeeds, retain the existing Figment parsing pipeline unchanged.

Pros:

- classifies the OS error structurally rather than scraping Figment prose;
- minimal behavioral change and no new dependency;
- applies consistently to explicit and auto-discovered paths;
- keeps YAML parsing and environment merging in one existing implementation.

Cons:

- the file can change between preflight and Figment open (diagnostic TOCTOU only);
- opens the file one extra time at startup.

### B. Read the file once and feed its contents to Figment

Pros: one read and fully controlled read errors.

Rejected because it changes Figment provider construction, path/source reporting, and two-pass env-file extraction; that is a larger parser refactor for a diagnostic defect.

### C. Rewrite Figment errors containing “Permission denied”

Pros: smallest apparent diff.

Rejected because it depends on human prose, OS localization, and upstream formatting. It can misclassify permission errors from referenced env files as the main config.

## Detailed behavior

For a selected config path that cannot be opened:

1. Return `Error::Config` before either Figment extraction.
2. Include the displayed path and original OS error.
3. State that the current process must own or be granted read access.
4. State that the official container runs as UID/GID 1001.
5. On Unix, recommend creating an owner-only deployment copy with `install -m 600` before applying `chown 1001:1001`, or using an equivalently narrow group/ACL grant.
6. If a containing directory denies traversal, say that the process also needs directory search (`+x`) access; changing the file alone is insufficient.
7. Explicitly warn against making a credential-bearing config world-readable.

Missing explicit paths retain the existing “Config file not found” error. Valid and invalid readable YAML retain current behavior. Windows receives a path-specific read/ACL error without Unix ownership commands.

The selected path is the explicit CLI/config argument when present; otherwise it
is the single default path returned by the existing discovery logic. Discovery
behavior does not change, and the preflight runs only after that selection.

## Documentation

Update `README.md`, `docs/QUICKSTART.md`, `docs/DEPLOYMENT.md`, and
`deploy/single-node/README.md` beside their Docker bind-mount examples. Each
must say that the bind-mounted deployment copy must be readable by UID/GID 1001
and show an owner-only preparation command. Avoid implying that a local
developer's primary config must be given away to UID 1001; call it a deployment
copy.

## Persistence follow-up

Do not close the data-loss portion from source reasoning alone. Request the exact container volume mapping, whether the old state loaded successfully before the restart, shutdown logs, file ownership, and a before/after sequence. Candidate hardening such as suppressing a save after a load failure or atomic replacement belongs in a separate change only after a failing test demonstrates the destructive path.

## Acceptance criteria

- AC1: an unreadable file containing invalid YAML returns the readability error before parsing; the regression asserts that the message includes the selected path and literal `1001`. On Unix, the test skips with an explicit reason when effective UID is root, because root can bypass a `000` mode fixture.
- AC2: error guidance preserves secret confidentiality and names official-container UID/GID 1001.
- AC3: missing, readable-valid, and readable-invalid config behavior does not regress.
- AC4: official Docker bind-mount documentation states the ownership/readability requirement.
- AC5: no persistence behavior changes without an independent reproduction.

## Rollback

Revert the preflight and documentation commit. No stored data or configuration schema changes are involved.
