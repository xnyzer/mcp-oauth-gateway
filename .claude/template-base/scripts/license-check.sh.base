#!/bin/sh
# License check — judges the licenses of the runtime dependencies against the policy.
#
# Usage:
#   sh scripts/license-check.sh LIST [POLICY]
#
# LIST holds one line per dependency, `package<TAB>license`, as the module's
# `just license-check` writes it (`-` reads standard input). POLICY defaults to
# `license-policy.txt`; its header explains the lines `allow` and `except`.
#
# A package passes when an `except` line names it, or when its license is allowed:
#   - the whole text is an `allow` line, or
#   - a list separated by "; " (how Python packages name several licenses): every name
#     is an `allow` line — names may contain brackets, like "Mozilla Public License 2.0
#     (MPL 2.0)";
#   - an SPDX expression (outer brackets ignored): with OR one alternative is allowed,
#     within an alternative every part joined by AND; nested brackets or WITH clauses
#     pass only as a whole allowed text (fail closed).
#
# Every finding is reported, then a summary. Exit 0 when all packages pass, 1 on a
# finding (a license that is not allowed, an `except` without a reason, an unknown
# policy line, a list line without a tab), 2 when LIST or POLICY cannot be read.
set -eu

if [ $# -lt 1 ] || [ $# -gt 2 ]; then
  echo "usage: sh scripts/license-check.sh LIST [POLICY]" >&2
  exit 2
fi
list=$1
policy=${2:-license-policy.txt}
if [ ! -r "$policy" ]; then
  echo "license-check: policy $policy not found" >&2
  exit 2
fi
if [ "$list" != - ] && [ ! -r "$list" ]; then
  echo "license-check: list $list not found" >&2
  exit 2
fi

awk -v policy="$policy" '
function trim(s) { sub(/^[ \t\r]+/, "", s); sub(/[ \t\r]+$/, "", s); return s }

# Every part of TEXT split at SEP must be an allowed name.
function all_allowed(text, sep,    n, parts, i) {
  n = split(text, parts, sep)
  for (i = 1; i <= n; i++) if (!(trim(parts[i]) in allowed)) return 0
  return 1
}

function passes(lic,    n, alts, i) {
  if (lic in allowed) return 1
  if (index(lic, "; ")) return all_allowed(lic, "; ")
  if (lic ~ /^\(.*\)$/) {
    lic = substr(lic, 2, length(lic) - 2)
    if (lic in allowed) return 1
  }
  if (lic ~ /[()]/ || lic ~ / WITH /) return 0
  n = split(lic, alts, / OR /)
  for (i = 1; i <= n; i++) if (all_allowed(alts[i], " AND ")) return 1
  return 0
}

FILENAME == policy {
  line = trim($0)
  if (line == "" || line ~ /^#/) next
  if ($1 == "allow" && NF >= 2) {
    sub(/^allow[ \t]+/, "", line)
    allowed[line] = 1
    next
  }
  if ($1 == "except" && NF >= 3) { excepted[$2] = 1; next }
  if ($1 == "except") {
    printf "%s:%d: exception without a reason: %s\n", policy, FNR, line
  } else {
    printf "%s:%d: unknown line: %s\n", policy, FNR, line
  }
  bad++
  next
}

{
  if (trim($0) == "") next
  tab = index($0, "\t")
  if (tab == 0) {
    printf "list line %d has no tab: %s\n", FNR, $0
    bad++
    next
  }
  pkg = trim(substr($0, 1, tab - 1))
  lic = trim(substr($0, tab + 1))
  checked++
  if (pkg in excepted) next
  if (!passes(lic)) {
    printf "not allowed: %s (%s)\n", pkg, (lic == "" ? "no license" : lic)
    denied++
  }
}

END {
  printf "license-check: %d package(s) checked, %d not allowed\n", checked, denied
  if (denied > 0) {
    printf "Allow the license in %s or add `except <package> <reason>` there.\n", policy
  }
  exit (bad + denied > 0)
}
' "$policy" "$list"
