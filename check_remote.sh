#!/usr/bin/env bash
#
# QJ Remote Reachability Audit
# ============================
# From YOUR machine (the one running this script), checks whether services like
# Traefik dashboard / cAdvisor / Loki (etc.) are actually reachable over the network.
#
# It does 2 things per server + service:
#   1) TCP connect test (nc)
#   2) HTTP GET test (curl) to a known path, returns HTTP code (or FAIL)
#
# Usage:
#   ./reachability_audit.sh
#   ./reachability_audit.sh -s "sce dat api edge db res ai"
#   ./reachability_audit.sh --ssh-suffix "-qj"     # if you use qj-res-qj aliases
#   ./reachability_audit.sh -o ./reports/reach_$(date +%F).md
#
set -euo pipefail

ALL_SERVERS=("sce" "dat" "api" "edge" "db" "res" "ai")
SERVERS=("${ALL_SERVERS[@]}")
SSH_SUFFIX=""          # set to "-qj" if you want qj-res-qj style
REPORT_DIR="./reports"
REPORT_FILE=""
TS="$(date +"%Y%m%d_%H%M%S")"

# ---- Define what you want to test (name|port|scheme|path|notes)
# scheme: http|https|both  (both = try http then https)
CHECKS=(
  "traefik_dashboard|8080|http|/dashboard/|Traefik dashboard"
  "traefik_api|8080|http|/api/overview|Traefik API (if enabled)"
  "cadvisor_ui|8085|http|/|cAdvisor UI"
  "cadvisor_metrics|8085|http|/metrics|cAdvisor metrics"
  "loki_ready|3100|http|/ready|Loki readiness"
  "loki_metrics|3100|http|/metrics|Loki metrics"
  "backend_health|8000|http|/health|Backend health (adjust path)"
  "frontend_root|8006|http|/|Frontend (direct port)"
  "admin_root|4322|http|/|Admin (direct port)"
)

usage() {
  cat <<EOF
Usage: $0 [options]

Options:
  -s, --servers "srv1 srv2"   Servers to check (default: all)
  --ssh-suffix "-qj"          Use ssh host like qj-res-qj (default: none => qj-res)
  -o, --out PATH              Report path (default: ./reports/reachability_TS.md)
  -h, --help                  Help

Servers: ${ALL_SERVERS[*]}
EOF
  exit 0
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -s|--servers) IFS=' ' read -ra SERVERS <<< "${2:-}"; shift 2 ;;
    --ssh-suffix) SSH_SUFFIX="${2:-}"; shift 2 ;;
    -o|--out) REPORT_FILE="${2:-}"; shift 2 ;;
    -h|--help) usage ;;
    *) echo "Unknown option: $1" >&2; usage ;;
  esac
done

mkdir -p "$REPORT_DIR"
if [[ -z "$REPORT_FILE" ]]; then
  REPORT_FILE="${REPORT_DIR}/reachability_${TS}.md"
fi

ssh_host() {
  local s="$1"
  echo "qj-${s}${SSH_SUFFIX}"
}

# Resolve per-server public IPs (v4 + v6) using SSH to that server
get_ips() {
  local host="$1"
  # Try IPv4 and IPv6 explicitly; if either fails, keep empty.
  local v4 v6
  v4="$(ssh -o ConnectTimeout=10 -o StrictHostKeyChecking=accept-new -T "$host" 'curl -4 -s --max-time 4 ifconfig.me 2>/dev/null || true' || true)"
  v6="$(ssh -o ConnectTimeout=10 -o StrictHostKeyChecking=accept-new -T "$host" 'curl -6 -s --max-time 4 ifconfig.me 2>/dev/null || true' || true)"
  echo "${v4}|${v6}"
}

tcp_check() {
  local ip="$1" port="$2"
  # nc returns 0 if open, non-0 otherwise
  if nc -z -w 2 "$ip" "$port" >/dev/null 2>&1; then
    echo "open"
  else
    echo "closed"
  fi
}

http_check_one() {
  local scheme="$1" ip="$2" port="$3" path="$4"
  # Return: HTTP_CODE (e.g. 200, 401, 403, 404) or FAIL
  # -k for https to ignore cert issues on :port endpoints
  local url="${scheme}://${ip}:${port}${path}"
  local code
  code="$(curl -sS -k --connect-timeout 2 --max-time 4 -o /dev/null -w "%{http_code}" "$url" 2>/dev/null || true)"
  [[ -z "$code" || "$code" == "000" ]] && echo "FAIL" || echo "$code"
}

http_check() {
  local sch="$1" ip="$2" port="$3" path="$4"
  if [[ "$sch" == "both" ]]; then
    local c1 c2
    c1="$(http_check_one "http" "$ip" "$port" "$path")"
    if [[ "$c1" != "FAIL" ]]; then
      echo "http:$c1"
      return
    fi
    c2="$(http_check_one "https" "$ip" "$port" "$path")"
    if [[ "$c2" != "FAIL" ]]; then
      echo "https:$c2"
      return
    fi
    echo "FAIL"
  else
    echo "${sch}:$(http_check_one "$sch" "$ip" "$port" "$path")"
  fi
}

pick_best_ip() {
  local v4="$1" v6="$2"
  # Prefer IPv4 for reachability checks (most networks), fallback to IPv6.
  if [[ -n "${v4:-}" ]]; then echo "$v4"; else echo "$v6"; fi
}

# --- Run checks ---
{
  echo "# QJ Remote Reachability Report"
  echo ""
  echo "**Generated:** $(date "+%Y-%m-%d %H:%M:%S")"
  echo "**Servers checked:** ${SERVERS[*]}"
  echo ""

  echo "## Summary"
  echo ""
  echo "| Server | SSH Host | Target IP | traefik:8080 | cadvisor:8085 | loki:3100 | Notes |"
  echo "|---|---|---|---|---|---|---|"

  # We will also write full detail below.
  declare -A DETAILS=()

  for s in "${SERVERS[@]}"; do
    host="$(ssh_host "$s")"

    # Fetch public IPs
    ips="$(get_ips "$host")"
    v4="${ips%%|*}"
    v6="${ips##*|}"
    target="$(pick_best_ip "$v4" "$v6")"

    if [[ -z "${target:-}" ]]; then
      echo "| $s | $host | (no ip) | ? | ? | ? | ssh ok? ip lookup failed |"
      DETAILS["$s"]="> Failed to resolve public IP via SSH for $host"
      continue
    fi

    # High-level: just check if TCP open on these ports and whether HTTP responds
    # Traefik (8080)
    t_tcp="$(tcp_check "$target" 8080)"
    t_http="$(http_check "http" "$target" 8080 "/api/overview")"
    # cAdvisor (8085)
    c_tcp="$(tcp_check "$target" 8085)"
    c_http="$(http_check "http" "$target" 8085 "/")"
    # Loki (3100)
    l_tcp="$(tcp_check "$target" 3100)"
    l_http="$(http_check "http" "$target" 3100 "/ready")"

    t_cell="${t_tcp}, ${t_http}"
    c_cell="${c_tcp}, ${c_http}"
    l_cell="${l_tcp}, ${l_http}"

    notes=()
    [[ "$t_tcp" == "open" ]] && notes+=("8080 open")
    [[ "$c_tcp" == "open" ]] && notes+=("8085 open")
    [[ "$l_tcp" == "open" ]] && notes+=("3100 open")
    notes_str="$(IFS='; '; echo "${notes[*]:-}")"

    echo "| $s | $host | $target | $t_cell | $c_cell | $l_cell | ${notes_str:-} |"

    # Full per-check details
    out="### Server: $s ($host)\n\n"
    out+="**Public IPs:** v4=${v4:-none}, v6=${v6:-none}\n\n"
    out+="| Check | Port | TCP | HTTP |\n|---|---:|---|---|\n"
    for chk in "${CHECKS[@]}"; do
      IFS='|' read -r name port scheme path note <<<"$chk"
      tcp="$(tcp_check "$target" "$port")"
      http="$(http_check "$scheme" "$target" "$port" "$path")"
      out+="| $name ($note) | $port | $tcp | $http |\n"
    done
    DETAILS["$s"]="$out"
  done

  echo ""
  echo "## Details"
  echo ""
  for s in "${SERVERS[@]}"; do
    printf "%b\n\n" "${DETAILS[$s]:-> No details}\n"
  done

} > "$REPORT_FILE"

echo "Report saved to: $REPORT_FILE"

