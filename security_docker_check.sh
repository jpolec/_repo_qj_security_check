#!/usr/bin/env bash
#
# QJ Exposure Audit
# =================
# Checks each server for:
# - Public listening TCP ports (0.0.0.0 / ::)
# - Docker published ports on host
# - UFW allow-list
# - Flags risky services/ports (Traefik dashboard, cAdvisor, Loki, backend/admin/front, etc.)
#
# Usage:
#   ./exposure_audit.sh
#   ./exposure_audit.sh -s "sce dat api edge db res ai"
#   ./exposure_audit.sh -o ./reports/exposure_$(date +%F).md
#   ./exposure_audit.sh -p   # parallel
#
set -euo pipefail

ALL_SERVERS=("sce" "dat" "api" "edge" "db" "res" "ai")
SERVERS=("${ALL_SERVERS[@]}")
REPORT_DIR="./reports"
TIMESTAMP="$(date +"%Y%m%d_%H%M%S")"
REPORT_FILE=""
PARALLEL=false

# Risky ports to flag (extend freely)
# Feel free to add: 9090 (prometheus), 3000 (grafana), 9000/9001 (minio), etc.
RISK_PORTS_TCP=(8080 8085 3100 8000 8006 4322 9090 3000)

# Ports that are OK to be public (adjust to your policy)
ALLOWED_PUBLIC_TCP=(22 80 443)

usage() {
  cat <<EOF
Usage: $0 [options]

Options:
  -s, --servers "srv1 srv2"   Servers to check (default: all)
  -o, --out PATH              Report path (default: ./reports/exposure_audit_TIMESTAMP.md)
  -p, --parallel              Run checks in parallel
  -h, --help                  Help

Servers: ${ALL_SERVERS[*]}
EOF
  exit 0
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -s|--servers) IFS=' ' read -ra SERVERS <<< "${2:-}"; shift 2 ;;
    -o|--out) REPORT_FILE="${2:-}"; shift 2 ;;
    -p|--parallel) PARALLEL=true; shift ;;
    -h|--help) usage ;;
    *) echo "Unknown option: $1" >&2; usage ;;
  esac
done

mkdir -p "$REPORT_DIR"
if [[ -z "$REPORT_FILE" ]]; then
  REPORT_FILE="${REPORT_DIR}/exposure_audit_${TIMESTAMP}.md"
fi

get_ssh_host() {
  local s="$1"
  # You use patterns like qj-res or qj-res-qj; pick what you want as default.
  # If your non-root user alias is qj-{server}-qj, switch to that here.
  echo "qj-${s}"
}

# Remote script: print machine info + public listeners + ufw allow + docker published ports
REMOTE='
set -euo pipefail

echo "=== HOST ==="
echo "hostname: $(hostname)"
echo "kernel: $(uname -r)"
echo "uptime: $(uptime -p 2>/dev/null || uptime)"
echo "date: $(date -Iseconds)"
echo "ipv4: $(hostname -I 2>/dev/null | awk "{print \$1}" || true)"
echo "ipv6: $(ip -6 addr show scope global 2>/dev/null | awk "/inet6/ {print \$2}" | head -1 || true)"

echo ""
echo "=== UFW ==="
if command -v ufw >/dev/null 2>&1; then
  (sudo -n ufw status verbose 2>/dev/null || ufw status verbose 2>/dev/null || true) | sed "s/\r//g"
else
  echo "ufw: not installed"
fi

echo ""
echo "=== PUBLIC_LISTEN_TCP ==="
# Listeners on 0.0.0.0:* and [::]:* (TCP only), include process if possible
SS_OUT="$(sudo -n ss -lntpH 2>/dev/null || ss -lntpH 2>/dev/null || true)"
# Expected columns: State Recv-Q Send-Q Local:Port Peer:Port users:(...)
echo "$SS_OUT" | awk "
  \$4 ~ /^0\\.0\\.0\\.0:/ || \$4 ~ /^\\[::\\]:/ {
    # Extract port after last :
    lp=\$4; sub(/.*:/, \"\", lp);
    print \$4 \" \" lp \" \" \$6
  }"

echo ""
echo "=== DOCKER_PUBLISHED_PORTS ==="
# Show published ports (host bindings) per container
if command -v docker >/dev/null 2>&1; then
  (docker ps --format "{{.Names}}\t{{.Ports}}" 2>/dev/null || sudo -n docker ps --format "{{.Names}}\t{{.Ports}}" 2>/dev/null || true) \
    | sed "s/\r//g"
else
  echo "docker: not installed"
fi
'

# Helpers
contains_port() {
  local port="$1"; shift
  for p in "$@"; do [[ "$p" == "$port" ]] && return 0; done
  return 1
}

check_one() {
  local server="$1"
  local host; host="$(get_ssh_host "$server")"
  local tmp; tmp="$(mktemp)"

  if printf '%s' "$REMOTE" | ssh -T -o ConnectTimeout=20 -o StrictHostKeyChecking=accept-new "$host" "bash" >"$tmp" 2>&1; then
    echo "$tmp"
  else
    echo "CONNECTION_FAILED" >"$tmp"
    echo "$tmp"
  fi
}

# Run
declare -a results=()
if [[ "$PARALLEL" == "true" ]]; then
  declare -A pids=()
  declare -A files=()
  for s in "${SERVERS[@]}"; do
    {
      f="$(check_one "$s")"
      echo "$f"
    } >"/tmp/exposure_${s}_${TIMESTAMP}.out" &
    pids["$s"]=$!
    files["$s"]="/tmp/exposure_${s}_${TIMESTAMP}.out"
  done
  for s in "${SERVERS[@]}"; do
    wait "${pids[$s]}" || true
    results+=("$(cat "${files[$s]}")")
    rm -f "${files[$s]}"
  done
else
  for s in "${SERVERS[@]}"; do
    results+=("$(check_one "$s")")
  done
fi

# Generate report
{
  echo "# QJ Exposure Audit Report"
  echo ""
  echo "**Generated:** $(date "+%Y-%m-%d %H:%M:%S")"
  echo "**Servers checked:** ${SERVERS[*]}"
  echo ""
  echo "## Summary"
  echo ""
  echo "| Server | SSH Host | Public TCP listeners (non-allowlist) | Risk ports exposed (TCP) | UFW active | Notes |"
  echo "|---|---|---:|---:|---|---|"

  for i in "${!SERVERS[@]}"; do
    s="${SERVERS[$i]}"
    host="$(get_ssh_host "$s")"
    f="${results[$i]}"

    if [[ ! -f "$f" ]] || grep -q "CONNECTION_FAILED" "$f"; then
      echo "| $s | $host | ? | ? | ? | connection failed |"
      continue
    fi

    # UFW active?
    ufw_active="unknown"
    if grep -q "^Status: active" "$f"; then ufw_active="active"; fi
    if grep -q "^Status: inactive" "$f"; then ufw_active="inactive"; fi

    # Parse public listeners (LocalAddr Port Proc)
    mapfile -t listeners < <(awk '/^=== PUBLIC_LISTEN_TCP ===/{flag=1;next}/^===/{flag=0}flag{print}' "$f" | sed '/^\s*$/d' || true)

    # Count non-allowlisted public ports + risk ports
    non_allow=0
    risk_exposed=0
    notes=()

    # Build a set of public ports
    pub_ports=()
    for line in "${listeners[@]}"; do
      # line like: 0.0.0.0:8085 8085 users:(("docker-proxy",pid=...,fd=...))
      port="$(awk '{print $2}' <<<"$line" | tr -d '[:space:]')"
      [[ -z "$port" ]] && continue
      pub_ports+=("$port")
      if ! contains_port "$port" "${ALLOWED_PUBLIC_TCP[@]}"; then
        non_allow=$((non_allow+1))
      fi
      if contains_port "$port" "${RISK_PORTS_TCP[@]}"; then
        risk_exposed=$((risk_exposed+1))
      fi
    done

    # Note: docker publishes ports even if UFW blocks; we still flag.
    if [[ "$non_allow" -gt 0 ]]; then notes+=("public listen != (22/80/443)"); fi
    if [[ "$risk_exposed" -gt 0 ]]; then notes+=("risk ports listening"); fi
    if [[ "$ufw_active" != "active" ]]; then notes+=("ufw not active"); fi

    notes_str="$(IFS='; '; echo "${notes[*]:-}"))"
    echo "| $s | $host | $non_allow | $risk_exposed | $ufw_active | ${notes_str:-} |"
  done

  echo ""
  echo "## Details"
  echo ""

  for i in "${!SERVERS[@]}"; do
    s="${SERVERS[$i]}"
    host="$(get_ssh_host "$s")"
    f="${results[$i]}"

    echo "### Server: ${s} (${host})"
    echo ""

    if [[ ! -f "$f" ]] || grep -q "CONNECTION_FAILED" "$f"; then
      echo "> Connection failed"
      echo ""
      continue
    fi

    echo "#### Host"
    echo '```'
    awk '/^=== HOST ===/{flag=1;next}/^===/{flag=0}flag{print}' "$f"
    echo '```'
    echo ""

    echo "#### UFW"
    echo '```'
    awk '/^=== UFW ===/{flag=1;next}/^===/{flag=0}flag{print}' "$f" | sed -n '1,120p'
    echo '```'
    echo ""

    echo "#### Public TCP listeners (0.0.0.0 / ::)"
    echo '```'
    awk '/^=== PUBLIC_LISTEN_TCP ===/{flag=1;next}/^===/{flag=0}flag{print}' "$f" | sed '/^\s*$/d' || true
    echo '```'
    echo ""

    echo "#### Docker published ports"
    echo '```'
    awk '/^=== DOCKER_PUBLISHED_PORTS ===/{flag=1;next}/^===/{flag=0}flag{print}' "$f" | sed -n '1,200p'
    echo '```'
    echo ""

    echo "---"
    echo ""
  done

} > "$REPORT_FILE"

# Cleanup temp files
for f in "${results[@]}"; do
  [[ -f "$f" ]] && rm -f "$f"
done

echo "Report saved to: $REPORT_FILE"

