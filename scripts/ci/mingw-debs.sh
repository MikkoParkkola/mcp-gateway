#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# mingw-debs.sh — the mingw C toolchain of the Feature combinations windows
# target shard, in one place for both workflows that touch its deb cache
# (MIK-8766): the cache key, the download and the install, so the fill and
# the shard cannot drift apart. mingw-debs.yml fills the cache;
# feature-combos.yml installs from it, downloading itself only on a miss.
#
#   key             print the cache key (it names the runner image, so a new
#                   image fetches afresh rather than reuse another base's debs)
#   download <dir>  fetch the debs into <dir>; nothing is installed
#   install <dir>   install the debs in <dir>, never from the mirror
set -euo pipefail

pkg=gcc-mingw-w64-x86-64

case "${1:-}" in
  key)
    echo "mingw-debs-${ImageOS:?}-${ImageVersion:?}-$pkg"
    ;;
  download)
    dir=${2:?usage: mingw-debs.sh download <dir>}
    # Each fetch is bounded and retried, so a stalled mirror connection is
    # retried, not waited out (MIK-8761).
    apt_opts=(-o Acquire::Retries=5 -o Acquire::http::Timeout=60)
    scratch=$(mktemp -d "${RUNNER_TEMP:-/tmp}/mingw-apt.XXXXXX")
    mkdir -p "$scratch/partial" "$dir"
    sudo apt-get "${apt_opts[@]}" update
    sudo apt-get "${apt_opts[@]}" -o Dir::Cache::Archives="$scratch" \
      install -y --download-only --no-install-recommends "$pkg"
    cp "$scratch"/*.deb "$dir"/
    ;;
  install)
    dir=${2:?usage: mingw-debs.sh install <dir>}
    # apt, not a batch dpkg -i: it orders pre-dependencies across the debs.
    # --no-download: a deb the folder lacks fails here, never fetches.
    sudo apt-get install -y --no-install-recommends --no-download "$dir"/*.deb
    x86_64-w64-mingw32-gcc --version
    ;;
  *)
    echo "usage: mingw-debs.sh key | download <dir> | install <dir>" >&2
    exit 2
    ;;
esac
