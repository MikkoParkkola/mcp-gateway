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
#   prefix          print the restore-keys prefix: any image of the same OS
#   download <dir>  fetch the debs into <dir>; nothing is installed
#   install <dir>   install the debs in <dir> with dpkg, which never fetches
set -euo pipefail

pkg=gcc-mingw-w64-x86-64

case "${1:-}" in
  key)
    echo "mingw-debs-${ImageOS:?}-${ImageVersion:?}-$pkg"
    ;;
  prefix)
    # The restore-keys prefix: any earlier image of the same OS. A new runner
    # image misses the exact key until a fill covers it, and the train that
    # lands first on it then fetched 114 MB from a slow mirror (43 min, a
    # cancelled train); the same OS's previous set installs instead.
    echo "mingw-debs-${ImageOS:?}-"
    ;;
  download)
    dir=${2:?usage: mingw-debs.sh download <dir>}
    # Each fetch is bounded and retried, so a stalled mirror connection is
    # retried, not waited out (MIK-8761). A mirror that trickles (43.5 kB/s
    # for 43 min) never trips those timeouts, so each attempt also has a wall
    # clock bound, and a second attempt opens fresh connections.
    apt_opts=(-o Acquire::Retries=5 -o Acquire::http::Timeout=60)
    limit=${MINGW_DOWNLOAD_SECONDS:-600}
    scratch=$(mktemp -d "${RUNNER_TEMP:-/tmp}/mingw-apt.XXXXXX")
    mkdir -p "$scratch/partial" "$dir"
    sudo apt-get "${apt_opts[@]}" update
    ok=""
    for attempt in 1 2; do
      if sudo timeout "$limit" apt-get "${apt_opts[@]}" -o Dir::Cache::Archives="$scratch" \
        install -y --download-only --no-install-recommends "$pkg"; then
        ok=1; break
      fi
      echo "::warning::mingw download attempt $attempt did not finish within ${limit}s (slow mirror?)"
    done
    if [ -z "$ok" ]; then
      echo "::error::mingw packages: the Ubuntu mirror did not deliver them in 2 attempts of ${limit}s; rerun the job" >&2
      exit 1
    fi
    debs=("$scratch"/*.deb)
    if [ ! -e "${debs[0]}" ]; then
      echo "mingw-debs.sh: the download produced no .deb files (is $pkg already installed?)" >&2
      exit 1
    fi
    cp "${debs[@]}" "$dir"/
    ;;
  install)
    dir=${2:?usage: mingw-debs.sh install <dir>}
    debs=("$dir"/*.deb)
    if [ ! -e "${debs[0]}" ]; then
      echo "mingw-debs.sh: no .deb files in $dir" >&2
      exit 1
    fi
    # dpkg -i, not apt: dpkg never fetches, so a cache hit makes no mirror
    # call. apt-get install of local .deb paths resolved them from the index
    # and fetched all 114 MB again (MIK-8766, run 40053233814). One dpkg
    # call unpacks the whole set before configuring any of it, which is safe
    # only while no deb in the set pre-depends on another deb in the set:
    # checked here on every run and logged, not assumed. If that ever
    # changes, fall back to apt, which orders pre-dependencies.
    names=" "
    for d in "${debs[@]}"; do names+="$(dpkg-deb -f "$d" Package) "; done
    inner=""
    for d in "${debs[@]}"; do
      pd=$(dpkg-deb -f "$d" Pre-Depends)
      echo "pre-depends $(dpkg-deb -f "$d" Package): ${pd:-none}"
      # Package names only: drop version constraints and arch qualifiers.
      for n in $(printf '%s' "$pd" | sed -E 's/\([^)]*\)//g; s/:[a-z0-9]+//g; s/[,|]/ /g'); do
        case "$names" in *" $n "*) inner+=" $n" ;; esac
      done
    done
    if [ -n "$inner" ]; then
      echo "::warning::a mingw deb pre-depends on another in the set ($inner): installing with apt, which may fetch from the mirror"
      sudo apt-get install -y --no-install-recommends "${debs[@]}"
    else
      sudo dpkg -i "${debs[@]}"
    fi
    x86_64-w64-mingw32-gcc --version
    ;;
  *)
    echo "usage: mingw-debs.sh key | prefix | download <dir> | install <dir>" >&2
    exit 2
    ;;
esac
