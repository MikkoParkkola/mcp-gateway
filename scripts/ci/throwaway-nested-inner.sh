#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# THROWAWAY (E1, never merged): the inner launcher: a whole lib test build.
set -euo pipefail
cargo test --lib --all-features --no-run
