#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Throwaway probe command (R8): starts a sleeper that outlives this script and writes its pid (the handshake).
set -eu
sleep 600 </dev/null >/dev/null 2>&1 &
echo "$!" > "$1"
