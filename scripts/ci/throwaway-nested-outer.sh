#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# THROWAWAY (E1, never merged): a launcher that calls a launcher that calls cargo, which no static census follows.
set -euo pipefail
exec "$(dirname "$0")/throwaway-nested-inner.sh"
