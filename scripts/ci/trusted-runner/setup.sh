#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# One-time setup of the project's self-hosted runner on an arm64 Linux host.
# Run as root:  sudo RUNNER_TOKEN=<registration token> scripts/ci/trusted-runner/setup.sh
# The token is read from the environment so it never appears in a process
# listing; mint it with
#   gh api -X POST repos/MikkoParkkola/mcp-gateway/actions/runners/registration-token --jq .token
#
# What it creates:
#   - user ghr-mcpgw: no sudo, no docker group, no other groups
#   - a 120 GiB ext4 image mounted as that user's home: the runner's work
#     tree, toolchain, cargo registry, diagnostics and temp files all live
#     there, so a job can never fill the host's root filesystem
#   - the runner in /opt/mcpgw-runner and the hooks in /usr/local/lib/mcpgw-runner,
#     both root-owned and read-only to the runner user, so an admitted job
#     cannot disarm the admission hook, edit the runner, or self-update it
#   - systemd unit mcpgw-runner.service with CPU, memory, IO and task limits
#     and a low scheduling weight, so it yields to other work on the host
set -euo pipefail

readonly USER_NAME=ghr-mcpgw
readonly HOME_DIR=/home/$USER_NAME
readonly IMAGE=/var/lib/mcpgw-runner/home.img
readonly IMAGE_GIB=120
readonly RUNNER_DIR=/opt/mcpgw-runner
readonly HOOK_DIR=/usr/local/lib/mcpgw-runner
readonly UNIT=/etc/systemd/system/mcpgw-runner.service
readonly RUNNER_VERSION=2.337.0
readonly RUNNER_SHA256=9b1dc70626422526e3c94767cf024896beb15da5342a3f4819bf2feac13e0393
readonly REPO_URL=https://github.com/MikkoParkkola/mcp-gateway
readonly LABEL=mcpgw-trusted-arm64
readonly RUNNER_NAME=mcpgw-arm64-1
here=$(cd -- "$(dirname -- "$0")" && pwd)

[[ $(id -u) -eq 0 ]] || { echo "run as root" >&2; exit 1; }
[[ $(uname -m) == aarch64 ]] || { echo "expects an aarch64 host" >&2; exit 1; }
: "${RUNNER_TOKEN:?set RUNNER_TOKEN to a fresh registration token}"
for tool in /usr/bin/python3 /usr/bin/git curl sha256sum mkfs.ext4 systemd-escape; do
  command -v "$tool" >/dev/null || { echo "missing $tool; install it first" >&2; exit 1; }
done

# 1. User with no supplementary groups.
if ! id "$USER_NAME" >/dev/null 2>&1; then
  useradd --create-home --home-dir "$HOME_DIR" --shell /bin/bash --user-group "$USER_NAME"
fi
if grep -qwE 'sudo|docker|adm|wheel' <<<"$(id -nG "$USER_NAME")"; then
  echo "$USER_NAME is in a privileged group; refusing" >&2; exit 1
fi

# 2. Bounded home filesystem.
if ! mountpoint -q "$HOME_DIR"; then
  mkdir -p "$(dirname "$IMAGE")"
  [[ -f $IMAGE ]] || { fallocate -l "${IMAGE_GIB}G" "$IMAGE"; mkfs.ext4 -q -F "$IMAGE"; }
  grep -q "^$IMAGE " /etc/fstab || echo "$IMAGE $HOME_DIR ext4 loop,nodev,nosuid 0 2" >>/etc/fstab
  mount "$HOME_DIR"
fi
install -d -o "$USER_NAME" -g "$USER_NAME" -m 0700 "$HOME_DIR" "$HOME_DIR/_work" "$HOME_DIR/_diag" "$HOME_DIR/tmp"

# 3. Runner, verified against the published checksum.
if [[ ! -x $RUNNER_DIR/config.sh ]]; then
  tarball=$(mktemp)
  curl -fsSL -o "$tarball" "https://github.com/actions/runner/releases/download/v$RUNNER_VERSION/actions-runner-linux-arm64-$RUNNER_VERSION.tar.gz"
  echo "$RUNNER_SHA256  $tarball" | sha256sum -c -
  install -d -o "$USER_NAME" -g "$USER_NAME" "$RUNNER_DIR"
  tar -xzf "$tarball" -C "$RUNNER_DIR"
  rm -f -- "$tarball"
  chown -R "$USER_NAME:$USER_NAME" "$RUNNER_DIR"
  "$RUNNER_DIR/bin/installdependencies.sh"
  # The runner reads ACTIONS_RUNNER_INPUT_<OPTION> for any option left off the
  # command line, so the token never appears in a process listing.
  export ACTIONS_RUNNER_INPUT_TOKEN=$RUNNER_TOKEN
  sudo -u "$USER_NAME" --preserve-env=ACTIONS_RUNNER_INPUT_TOKEN bash -c "cd '$RUNNER_DIR' && ./config.sh --unattended \
    --url '$REPO_URL' --name '$RUNNER_NAME' --labels '$LABEL' \
    --no-default-labels --work '$HOME_DIR/_work' --disableupdate --replace"
  unset ACTIONS_RUNNER_INPUT_TOKEN
fi
# Read-only to the runner from here on (group read for its own credentials).
chown -R "root:$USER_NAME" "$RUNNER_DIR"
chmod -R g+rX,g-w,o-rwx "$RUNNER_DIR"
install -d -m 0750 -o root -g "$USER_NAME" "$RUNNER_DIR/_diag"

# 4. Hooks, root-owned.
install -d -m 0755 "$HOOK_DIR"
install -m 0755 "$here/job-started.sh" "$here/job-completed.sh" "$HOOK_DIR/"

# 5. Unit.
cat >"$UNIT" <<UNIT
[Unit]
Description=mcp-gateway trusted self-hosted runner
After=network-online.target $(systemd-escape -p --suffix=mount "$HOME_DIR")
Requires=$(systemd-escape -p --suffix=mount "$HOME_DIR")

[Service]
User=$USER_NAME
WorkingDirectory=$RUNNER_DIR
# The listener itself, not run.sh: run.sh rewrites run-helper.sh in the
# runner directory on every start, which is read-only here.
ExecStart=$RUNNER_DIR/bin/Runner.Listener run --startuptype service
Environment=ACTIONS_RUNNER_HOOK_JOB_STARTED=$HOOK_DIR/job-started.sh
Environment=ACTIONS_RUNNER_HOOK_JOB_COMPLETED=$HOOK_DIR/job-completed.sh
Environment=TMPDIR=$HOME_DIR/tmp
Restart=on-failure
RestartSec=30s
KillMode=process
KillSignal=SIGTERM
TimeoutStopSec=5min
CPUQuota=800%
CPUWeight=20
IOWeight=20
MemoryHigh=12G
MemoryMax=16G
TasksMax=4096
NoNewPrivileges=yes
ProtectSystem=strict
ReadWritePaths=$HOME_DIR
BindPaths=$HOME_DIR/_diag:$RUNNER_DIR/_diag
BindPaths=$HOME_DIR/tmp:/tmp
BindPaths=$HOME_DIR/tmp:/var/tmp
ProtectHome=tmpfs
BindPaths=$HOME_DIR
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes

[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
systemctl enable --now mcpgw-runner.service

# 6. Checks from the runner user's side; any writable path is a failure.
bad=0
for path in "$HOOK_DIR/job-started.sh" "$HOOK_DIR" "$RUNNER_DIR" "$RUNNER_DIR/.env" "$RUNNER_DIR/bin" "$UNIT"; do
  if sudo -u "$USER_NAME" test -w "$path"; then echo "FAIL: $USER_NAME can write $path" >&2; bad=1; fi
done
grep -qiE '"disableUpdate": *"?true' "$RUNNER_DIR/.runner" || { echo "FAIL: self-update not disabled" >&2; bad=1; }
sudo -u "$USER_NAME" "$HOOK_DIR/job-started.sh" --self-test || bad=1
systemctl is-active --quiet mcpgw-runner.service || { echo "FAIL: service not active" >&2; bad=1; }
[[ $bad -eq 0 ]] && echo "setup OK: runner $RUNNER_NAME ($LABEL) running as $USER_NAME"
exit $bad
