# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Sourced, not run. The one list of text that marks material as private, read
# by the tracked-tree check (check-public-repo-hygiene.sh), the commit-message
# check and the pull-request-body check, so the three cannot drift apart.
#
# Each entry is <id>::<flags>::<extended regex>::<reason>. <flags> is "i" for a
# case-insensitive match or "-" for a case-sensitive one. The regex is POSIX
# ERE, as `grep -E` and `git grep -E` read it: no \b, no lookaround, so a
# boundary is spelled out as a character class.
# shellcheck disable=SC2034  # read by the scripts that source this file
private_content_checks=(
  # The maintainer's other projects are private repositories. Followed by a
  # non-letter so "Hebbian" (the learning rule) is not a hit; the second entry
  # catches the same names opening a CamelCase identifier.
  "private-name::i::(^|[^[:alpha:]])(hebb|botnaut|airlok|raxor|throttla|pithy)([^[:alpha:]]|$)::names a private project"
  "private-name::-::(^|[^[:alpha:]])(Hebb|Botnaut|Airlok|Raxor|Throttla|Pithy)[A-Z]::names a private project"
  "home-path::-::/Users/mikko([^[:alnum:]_-]|$)::is a home-directory path from the maintainer's machine"
  "agent-config::-::(~|\\\$HOME|\\\$\\{HOME\\}|/Users/[^/[:space:]]+)/\\.claude([^.[:alnum:]_-]|$)::is a private agent-configuration directory"
  # 100.64.0.0/10 is shared address space (RFC 6598); on this project it is a
  # private-network host. Any 100.x.y.z is refused and the SSRF code that has
  # to name the range carries an allowlist entry.
  "tailnet-ip::-::(^|[^0-9.])100\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}([^0-9]|$)::is a private-network address"
)

# Fixed strings, matched case-insensitively, that every hit of a check above
# contains. The tree check greps for these first and runs the regexes only on
# the lines they find, so a new check needs its literal core added here.
private_content_prefilter=(
  "hebb" "botnaut" "airlok" "raxor" "throttla" "pithy"
  "/Users/mikko" "/.claude" "100."
)

# A tracker id. Existing ones stay and fade; a change may not add one, in a
# line, a file name, a commit message or a pull-request body.
ticket_id_regex='(^|[^[:alnum:]])MIK-[0-9]+'

# Paths the private companion repository owns. It is cloned at the ignored
# internal/ path of a public checkout; nothing under these is tracked here.
private_path_prefixes=(
  "docs/internal/"
  "docs/competitive/"
  "docs/competitive-intelligence/"
  "docs/positioning/"
  "docs/requirements/"
  "docs/strategy/"
  "tickets/"
)
# Agent instruction files, at any depth.
private_file_names=(
  "CLAUDE.md"
  "AGENTS.md"
)
