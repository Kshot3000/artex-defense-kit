#!/usr/bin/env bash
# =============================================================================
# self-scan.sh — ARTEX Defense Kit SELF-assessment tool
#
# *** SELF-ASSESSMENT ONLY ***
# Run this ONLY against assets you own or are explicitly authorized to test:
#   * your own GitHub account/organization, and
#   * hosts listed in a file YOU supply, containing YOUR OWN hostnames/IPs.
#
# This tool does not discover third-party targets, does not accept target
# ranges, and must not be pointed at anyone else's infrastructure. Probing
# systems you don't own may be illegal and contaminates real investigations.
# If you find an ARTEX console that isn't yours, report it (see REPORTING.md)
# — do not log in to it.
#
# What it does:
#   github <owner>   List <owner>'s public repos and report OPEN GitHub
#                    secret-scanning alerts per repo (count + secret types).
#                    Secret VALUES are never requested in output fields and
#                    never printed.
#   hosts  <file>    For each hostname/IP in <file> (one per line), fetch the
#                    root page on the known ARTEX console ports and check the
#                    HTML <title> against the known console fingerprints, and
#                    (if python3 + mmh3 are available) the favicon against the
#                    known Shodan favicon hash. Prints hits only, plus a
#                    summary line.
#
# Requirements: bash, curl; gh CLI + jq for the github mode; python3 + mmh3
# (optional) for favicon hashing.
#
# Fingerprints (Censys / FBI FLASH-20261113-001):
#   Titles : "ARTEX — Autonomous Penetration Testing Console"
#            "ARTEX — 自主渗透测试控制台"   (Chinese)
#            "자율 침투 테스트 콘솔"          (Korean)
#            "ARTEX Restricted"             (behind basic auth)
#   Ports  : 8787 (default console), 8790, 443, 80; 8788 is the MITM proxy
#   Favicon: Shodan http.favicon.hash -1898746557
# =============================================================================

set -u

FAVICON_HASH_EXPECTED="-1898746557"
CONSOLE_PORTS="8787 8790 443 80"

usage() {
  cat <<'EOF'
Usage:
  self-scan.sh github <owner>     Open secret-scanning alerts for <owner>'s
                                  public repos (counts + secret types only).
  self-scan.sh hosts  <file>      Check YOUR OWN hosts (one hostname/IP per
                                  line in <file>) for exposed ARTEX console
                                  fingerprints (title / favicon hash).
  self-scan.sh --help             This text.

SELF-ASSESSMENT ONLY: run against assets you own or are authorized to test.
EOF
}

# ---------------------------------------------------------------------------
# Mode: github
# ---------------------------------------------------------------------------
cmd_github() {
  local owner="$1"
  command -v gh >/dev/null 2>&1 || { echo "error: gh CLI is required (https://cli.github.com)" >&2; exit 1; }
  command -v jq >/dev/null 2>&1 || { echo "error: jq is required" >&2; exit 1; }
  gh auth status >/dev/null 2>&1 || { echo "error: gh is not authenticated — run 'gh auth login' first" >&2; exit 1; }

  echo "Listing public repos for '${owner}' ..."
  local repos
  repos="$(gh api --paginate "users/${owner}/repos?type=public&per_page=100" --jq '.[].name' 2>/dev/null)"
  if [ -z "${repos}" ]; then
    echo "No public repos found (or the account could not be read)."
    return 0
  fi

  local total=0 with_alerts=0 unavailable=0 total_alerts=0
  local repo alerts count types
  while IFS= read -r repo; do
    [ -n "${repo}" ] || continue
    total=$((total + 1))
    # NOTE: we select ONLY metadata fields (number, state, secret_type).
    # Secret values are never selected and never printed.
    if ! alerts="$(gh api --paginate "repos/${owner}/${repo}/secret-scanning/alerts?state=open&per_page=100" \
                    --jq '.[] | {number, state, secret_type}' 2>/dev/null)"; then
      unavailable=$((unavailable + 1))
      continue
    fi
    if [ -z "${alerts}" ]; then
      continue
    fi
    count="$(printf '%s\n' "${alerts}" | jq -s 'length')"
    types="$(printf '%s\n' "${alerts}" | jq -rs '[group_by(.secret_type)[] | "\(.[0].secret_type) x\(length)"] | join(", ")')"
    echo "  ${owner}/${repo}: ${count} OPEN alert(s): ${types}"
    with_alerts=$((with_alerts + 1))
    total_alerts=$((total_alerts + count))
  done <<EOF
${repos}
EOF

  echo "----"
  echo "Repos checked: ${total} | with open alerts: ${with_alerts} (${total_alerts} alerts) | secret scanning unavailable: ${unavailable}"
  if [ "${with_alerts}" -gt 0 ]; then
    echo "ACTION: treat every open alert as a COMPROMISED credential — revoke and"
    echo "rotate it. Deleting the secret from the repo is NOT remediation"
    echo "(history, forks, and attacker copies remain). See HARDENING.md."
  fi
}

# ---------------------------------------------------------------------------
# Mode: hosts
# ---------------------------------------------------------------------------

# Compute the Shodan-style favicon hash (mmh3 of base64-wrapped favicon bytes)
# for a local file. Returns empty string if python3/mmh3 unavailable.
favicon_hash() {
  local file="$1"
  python3 - "$file" <<'PY' 2>/dev/null
import sys
try:
    import mmh3, base64
except ImportError:
    sys.exit(0)
data = open(sys.argv[1], 'rb').read()
if not data:
    sys.exit(0)
print(mmh3.hash(base64.encodebytes(data)))
PY
}

check_one() {
  # $1 = host, $2 = scheme, $3 = port
  local host="$1" scheme="$2" port="$3"
  local url="${scheme}://${host}:${port}/"
  local body title
  body="$(curl -sk --max-time 8 --connect-timeout 5 \
            -A 'artex-defense-kit-selfscan/1.0' "${url}" 2>/dev/null)" || return 0
  [ -n "${body}" ] || return 0
  title="$(printf '%s' "${body}" | grep -oi '<title[^>]*>[^<]*</title>' | head -1 \
            | sed -e 's/<[^>]*>//g' | tr -d '\r\n' | sed 's/^ *//;s/ *$//')"
  [ -n "${title}" ] || return 0
  # Fingerprint: any known console title. "ARTEX" alone in a title is worth a
  # human look on your own host, so match the full strings plus the bare word.
  case "${title}" in
    *ARTEX*|*자율\ 침투\ 테스트\ 콘솔*)
      echo "HIT  ${url}  title: ${title}"
      ;;
  esac
}

cmd_hosts() {
  local file="$1"
  [ -f "${file}" ] || { echo "error: host list '${file}' not found" >&2; exit 1; }
  command -v curl >/dev/null 2>&1 || { echo "error: curl is required" >&2; exit 1; }

  echo "Checking hosts from '${file}' for ARTEX console fingerprints"
  echo "(ports: ${CONSOLE_PORTS}; title match + favicon hash where available) ..."
  local hits=0 checked=0 host port scheme fav tmp hash
  tmp="$(mktemp)"
  while IFS= read -r host; do
    # Trim whitespace; skip blanks and comments.
    host="$(printf '%s' "${host}" | tr -d '[:space:]')"
    case "${host}" in ''|\#*) continue ;; esac
    checked=$((checked + 1))
    for port in ${CONSOLE_PORTS}; do
      case "${port}" in
        443)  check_one "${host}" https "${port}" ;;
        80)   check_one "${host}" http  "${port}" ;;
        *)    check_one "${host}" http  "${port}"
              check_one "${host}" https "${port}" ;;
      esac
    done
    # Favicon hash check on the default console port (http and https).
    for scheme in http https; do
      fav="${scheme}://${host}:8787/favicon.ico"
      if curl -sk --max-time 8 --connect-timeout 5 -o "${tmp}" "${fav}" 2>/dev/null \
         && [ -s "${tmp}" ]; then
        hash="$(favicon_hash "${tmp}")"
        if [ "${hash}" = "${FAVICON_HASH_EXPECTED}" ]; then
          echo "HIT  ${fav}  favicon hash matches ARTEX console (${hash})"
          hits=$((hits + 1))
        fi
      fi
    done
  done < "${file}"
  rm -f "${tmp}"
  echo "----"
  echo "Hosts checked: ${checked}. Title hits are printed above as they are found;"
  echo "favicon hits counted: ${hits}."
  echo "Reminder: a title HIT on your own host means an ARTEX console is exposed —"
  echo "take it off the internet, then see HARDENING.md and REPORTING.md. If the"
  echo "host isn't yours, do not probe further; report the fingerprint instead."
}

# ---------------------------------------------------------------------------
case "${1:-}" in
  github)
    [ $# -eq 2 ] || { usage >&2; exit 2; }
    cmd_github "$2"
    ;;
  hosts)
    [ $# -eq 2 ] || { usage >&2; exit 2; }
    cmd_hosts "$2"
    ;;
  --help|-h|'')
    usage
    ;;
  *)
    echo "error: unknown command '${1}'" >&2
    usage >&2
    exit 2
    ;;
esac
