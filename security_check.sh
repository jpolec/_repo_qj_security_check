#!/bin/bash
#
# QJ Server Security Check Script
# ================================
# Security audit script for VM servers
#
# Usage:
#   ./security_check.sh [--servers "sce dat api"] [--user qj] [--report /path/to/report]
#
# By default checks all servers: sce, dat, api, edge, db, res, ai
#

set -euo pipefail

# ============================================================================
# Configuration
# ============================================================================

# All available servers
ALL_SERVERS=("sce" "dat" "api" "edge" "db" "res" "ai")

# Default settings
SERVERS=("${ALL_SERVERS[@]}")
SSH_USER=""  # Empty = use qj-{server}, non-empty = use q-{server}-qj
REPORT_DIR="./reports"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
REPORT_FILE=""
VERBOSE=false
PARALLEL=false

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# ============================================================================
# Helper functions
# ============================================================================

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1" >&2
}

log_success() {
    echo -e "${GREEN}[OK]${NC} $1" >&2
}

log_warning() {
    echo -e "${YELLOW}[WARN]${NC} $1" >&2
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
}

log_header() {
    echo "" >&2
    echo -e "${CYAN}------------------------------------------------------------------------------${NC}" >&2
    echo -e "${CYAN}  $1${NC}" >&2
    echo -e "${CYAN}------------------------------------------------------------------------------${NC}" >&2
}

# Helper for uppercase (zsh/bash compatible)
to_upper() {
    echo "$1" | tr '[:lower:]' '[:upper:]'
}

get_ssh_host() {
    local server=$1
    if [[ -z "$SSH_USER" ]]; then
        # Default: root/admin access via qj-{server}
        echo "qj-${server}"
    else
        # Non-admin user qj via qj-{server}-qj
        echo "qj-${server}-qj"
    fi
}

usage() {
    cat << EOF
QJ Server Security Check Script
================================

Usage: $0 [options]

Options:
  -s, --servers "srv1 srv2"  List of servers to check (default: all)
  -u, --user qj              Use qj user (ssh q-{server}-qj) instead of default
  -r, --report PATH          Path to save the report
  -v, --verbose              Verbose mode
  -p, --parallel             Check servers in parallel
  -h, --help                 Show this help

Available servers:
  sce   - Scenario Server
  dat   - Data Server
  api   - API Server
  edge  - Edge Server
  db    - Database Server
  res   - Research Server
  ai    - AI Server

Examples:
  $0                                    # Check all servers
  $0 -s "sce api db"                   # Check only selected
  $0 -u qj                              # Use qj user
  $0 -r /tmp/security_report.md        # Save report to file

EOF
    exit 0
}

# ============================================================================
# Argument parsing
# ============================================================================

while [[ $# -gt 0 ]]; do
    case $1 in
        -s|--servers)
            IFS=' ' read -ra SERVERS <<< "$2"
            shift 2
            ;;
        -u|--user)
            SSH_USER="$2"
            shift 2
            ;;
        -r|--report)
            REPORT_FILE="$2"
            shift 2
            ;;
        -v|--verbose)
            VERBOSE=true
            shift
            ;;
        -p|--parallel)
            PARALLEL=true
            shift
            ;;
        -h|--help)
            usage
            ;;
        *)
            log_error "Unknown option: $1"
            usage
            ;;
    esac
done

# Set default report file if not specified
if [[ -z "$REPORT_FILE" ]]; then
    mkdir -p "$REPORT_DIR"
    REPORT_FILE="${REPORT_DIR}/security_check_${TIMESTAMP}.md"
fi

# ============================================================================
# Remote check script to execute on server
# ============================================================================

REMOTE_CHECK_SCRIPT='
#!/bin/bash

echo "=== SERVER_CHECK_START ==="
echo "hostname: $(hostname)"
echo "date: $(date -Iseconds)"
echo "uptime: $(uptime -p 2>/dev/null || uptime)"
echo "kernel: $(uname -r)"

# ============================================================================
# 1. CHECK PACKAGE UPDATES
# ============================================================================
echo ""
echo "=== SECTION: UPDATES ==="

# Detect package manager
if command -v apt-get &> /dev/null; then
    PKG_MANAGER="apt"
    # Refresh package list (quietly)
    sudo apt-get update -qq 2>/dev/null
    
    # Check available updates
    UPDATES=$(apt-get -s upgrade 2>/dev/null | grep -c "^Inst" || echo "0")
    SECURITY_UPDATES=$(apt-get -s upgrade 2>/dev/null | grep -i security | grep -c "^Inst" || echo "0")
    
    echo "pkg_manager: apt"
    echo "updates_available: $UPDATES"
    echo "security_updates: $SECURITY_UPDATES"
    
    # List packages to update
    if [[ $UPDATES -gt 0 ]]; then
        echo "update_list:"
        apt-get -s upgrade 2>/dev/null | grep "^Inst" | head -20 | sed "s/^/  - /"
    fi
    
elif command -v dnf &> /dev/null; then
    PKG_MANAGER="dnf"
    UPDATES=$(dnf check-update 2>/dev/null | grep -c "^\S" || echo "0")
    SECURITY_UPDATES=$(dnf check-update --security 2>/dev/null | grep -c "^\S" || echo "0")
    
    echo "pkg_manager: dnf"
    echo "updates_available: $UPDATES"
    echo "security_updates: $SECURITY_UPDATES"
    
elif command -v yum &> /dev/null; then
    PKG_MANAGER="yum"
    UPDATES=$(yum check-update 2>/dev/null | grep -c "^\S" || echo "0")
    
    echo "pkg_manager: yum"
    echo "updates_available: $UPDATES"
    echo "security_updates: unknown"
fi

# ============================================================================
# 2. CHECK KERNEL RESTART REQUIREMENT
# ============================================================================
echo ""
echo "=== SECTION: KERNEL ==="

RUNNING_KERNEL=$(uname -r)
echo "running_kernel: $RUNNING_KERNEL"

# Check latest installed kernel
if command -v dpkg &> /dev/null; then
    LATEST_KERNEL=$(dpkg -l | grep -E "^ii.*linux-image-[0-9]" | sort -V | tail -1 | awk "{print \$2}" | sed "s/linux-image-//")
elif command -v rpm &> /dev/null; then
    LATEST_KERNEL=$(rpm -q kernel --last | head -1 | awk "{print \$1}" | sed "s/kernel-//")
fi
echo "latest_kernel: ${LATEST_KERNEL:-unknown}"

# Check if restart is needed
NEEDS_REBOOT="false"
REBOOT_REASON=""

# Method 1: /var/run/reboot-required (Debian/Ubuntu)
if [[ -f /var/run/reboot-required ]]; then
    NEEDS_REBOOT="true"
    REBOOT_REASON="reboot-required file exists"
    if [[ -f /var/run/reboot-required.pkgs ]]; then
        echo "reboot_packages:"
        cat /var/run/reboot-required.pkgs | head -10 | sed "s/^/  - /"
    fi
fi

# Method 2: needrestart (if installed)
if command -v needrestart &> /dev/null; then
    NEEDRESTART_OUTPUT=$(sudo needrestart -b 2>/dev/null || true)
    if echo "$NEEDRESTART_OUTPUT" | grep -q "NEEDRESTART-KSTA: 3"; then
        NEEDS_REBOOT="true"
        REBOOT_REASON="needrestart reports kernel mismatch"
    fi
fi

# Method 3: Kernel version comparison
if [[ -n "$LATEST_KERNEL" && "$RUNNING_KERNEL" != "$LATEST_KERNEL" ]]; then
    if ! echo "$LATEST_KERNEL" | grep -q "$RUNNING_KERNEL"; then
        NEEDS_REBOOT="true"
        REBOOT_REASON="kernel version mismatch: running=$RUNNING_KERNEL, installed=$LATEST_KERNEL"
    fi
fi

echo "needs_reboot: $NEEDS_REBOOT"
echo "reboot_reason: ${REBOOT_REASON:-none}"

# Check services needing restart
if command -v needrestart &> /dev/null; then
    echo "services_need_restart:"
    sudo needrestart -b 2>/dev/null | grep "NEEDRESTART-SVC" | awk -F: "{print \"  - \" \$2}" | head -10
fi

# ============================================================================
# 3. CHECK FOR INTRUSION SIGNS
# ============================================================================
echo ""
echo "=== SECTION: SECURITY ==="

# 3.1 Failed SSH logins
echo "ssh_failed_logins:"
FAILED_SSH=$(grep -c "Failed password" /var/log/auth.log 2>/dev/null || journalctl -u ssh --since "24 hours ago" 2>/dev/null | grep -c "Failed password" || echo "0")
echo "  last_24h: $FAILED_SSH"

# Top IPs with failed logins
echo "  top_attackers:"
if [[ -f /var/log/auth.log ]]; then
    grep "Failed password" /var/log/auth.log 2>/dev/null | \
        grep -oE "[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+" | \
        sort | uniq -c | sort -rn | head -5 | \
        awk "{print \"    - ip: \" \$2 \", attempts: \" \$1}"
fi

# 3.2 Check active SSH sessions
echo "active_ssh_sessions:"
who | grep -v "^$" | while read line; do
    echo "  - $line"
done

# 3.3 Check recent root logins
echo "recent_root_logins:"
last root 2>/dev/null | head -5 | grep -v "^$" | while read line; do
    echo "  - $line"
done

# 3.4 New users (last 7 days)
echo "new_users_7d:"
for user in $(awk -F: "\$3 >= 1000 && \$3 < 65534 {print \$1}" /etc/passwd); do
    home_dir=$(getent passwd "$user" | cut -d: -f6)
    if [[ -d "$home_dir" ]]; then
        creation=$(stat -c %Y "$home_dir" 2>/dev/null || echo 0)
        seven_days_ago=$(date -d "7 days ago" +%s 2>/dev/null || echo 0)
        if [[ $creation -gt $seven_days_ago ]]; then
            echo "  - $user (created: $(date -d @$creation +%Y-%m-%d))"
        fi
    fi
done

# 3.5 Check suspicious processes
echo "suspicious_processes:"
echo "  listening_ports:"
ss -tulpn 2>/dev/null | grep LISTEN | awk "{print \"    - \" \$5 \" (\" \$7 \")\"}" | head -15

# 3.6 SUID files modified in last 7 days
echo "recently_modified_suid:"
find /usr -perm -4000 -mtime -7 2>/dev/null | head -10 | while read file; do
    echo "  - $file"
done

# 3.7 Check crontabs
echo "crontab_entries:"
echo "  system:"
for f in /etc/crontab /etc/cron.d/*; do
    if [[ -f "$f" ]]; then
        grep -v "^#" "$f" 2>/dev/null | grep -v "^$" | head -5 | while read line; do
            echo "    - $line"
        done
    fi
done
echo "  root:"
sudo crontab -l 2>/dev/null | grep -v "^#" | grep -v "^$" | head -5 | while read line; do
    echo "    - $line"
done

# 3.8 Check SSH authorized keys
echo "ssh_authorized_keys:"
for user_home in /root /home/*; do
    if [[ -f "$user_home/.ssh/authorized_keys" ]]; then
        user=$(basename "$user_home")
        count=$(wc -l < "$user_home/.ssh/authorized_keys" 2>/dev/null || echo 0)
        echo "  - user: $user, keys: $count"
    fi
done

# 3.9 Check failed sudo attempts
echo "failed_sudo_attempts:"
FAILED_SUDO=$(grep -c "authentication failure" /var/log/auth.log 2>/dev/null || echo "0")
echo "  count: $FAILED_SUDO"

# 3.10 Check firewall
echo "firewall_status:"
if command -v ufw &> /dev/null; then
    UFW_STATUS=$(sudo ufw status 2>/dev/null | head -1)
    echo "  ufw: $UFW_STATUS"
fi
if command -v iptables &> /dev/null; then
    IPTABLES_RULES=$(sudo iptables -L -n 2>/dev/null | grep -c "^" || echo "0")
    echo "  iptables_rules: $IPTABLES_RULES"
fi

# 3.11 Check fail2ban status
echo "fail2ban:"
if command -v fail2ban-client &> /dev/null; then
    F2B_STATUS=$(sudo fail2ban-client status 2>/dev/null | head -1 || echo "not running")
    echo "  status: $F2B_STATUS"
    
    # Check sshd jail specifically
    if sudo fail2ban-client status sshd &>/dev/null; then
        BANNED_IPS=$(sudo fail2ban-client status sshd 2>/dev/null | grep "Banned IP" | sed "s/.*Banned IP list://" | tr -d "\\t" || echo "none")
        BANNED_COUNT=$(sudo fail2ban-client status sshd 2>/dev/null | grep "Currently banned" | awk "{print \$NF}" || echo "0")
        TOTAL_BANNED=$(sudo fail2ban-client status sshd 2>/dev/null | grep "Total banned" | awk "{print \$NF}" || echo "0")
        echo "  sshd_jail: active"
        echo "  currently_banned: $BANNED_COUNT"
        echo "  total_banned: $TOTAL_BANNED"
        if [[ -n "$BANNED_IPS" && "$BANNED_IPS" != "none" ]]; then
            echo "  banned_ips: $BANNED_IPS"
        fi
    else
        echo "  sshd_jail: not configured"
    fi
else
    echo "  status: not installed"
fi

# 3.12 Check for rootkits (rkhunter/chkrootkit if available)
echo "rootkit_scanner:"
if command -v rkhunter &> /dev/null; then
    RKHUNTER_LOG="/var/log/rkhunter.log"
    if [[ -f "$RKHUNTER_LOG" ]]; then
        LAST_RUN=$(stat -c %y "$RKHUNTER_LOG" 2>/dev/null | cut -d. -f1 || echo "unknown")
        WARNINGS=$(grep -c "Warning:" "$RKHUNTER_LOG" 2>/dev/null || echo "0")
        echo "  rkhunter: installed"
        echo "  last_run: $LAST_RUN"
        echo "  warnings: $WARNINGS"
    else
        echo "  rkhunter: installed (no logs)"
    fi
elif command -v chkrootkit &> /dev/null; then
    echo "  chkrootkit: installed"
else
    echo "  status: not installed"
fi

# 3.13 Check WireGuard VPN
echo "wireguard:"
if ip link show type wireguard &>/dev/null 2>&1; then
    WG_INTERFACES=$(ip link show type wireguard 2>/dev/null | grep -oP "^\d+: \K[^:@]+" || echo "none")
    echo "  status: active"
    echo "  interfaces: $WG_INTERFACES"
    # Get WireGuard details if available
    if command -v wg &> /dev/null; then
        WG_PEERS=$(sudo wg show all peers 2>/dev/null | wc -l || echo "0")
        echo "  peers: $WG_PEERS"
    fi
elif command -v wg &> /dev/null; then
    echo "  status: installed but not active"
else
    echo "  status: not installed"
fi

# 3.14 Check UFW detailed rules
echo "ufw_details:"
if command -v ufw &> /dev/null; then
    UFW_STATUS=$(sudo ufw status verbose 2>/dev/null | head -1 | awk "{print \$2}" || echo "unknown")
    echo "  status: $UFW_STATUS"
    if [[ "$UFW_STATUS" == "active" ]]; then
        UFW_DEFAULT_IN=$(sudo ufw status verbose 2>/dev/null | grep "Default:" | head -1 | awk "{print \$2}" || echo "unknown")
        UFW_DEFAULT_OUT=$(sudo ufw status verbose 2>/dev/null | grep "Default:" | head -1 | awk "{print \$4}" || echo "unknown")
        echo "  default_incoming: $UFW_DEFAULT_IN"
        echo "  default_outgoing: $UFW_DEFAULT_OUT"
        echo "  rules:"
        sudo ufw status numbered 2>/dev/null | grep -E "^\[" | head -15 | while read line; do
            echo "    - $line"
        done
    fi
else
    echo "  status: not installed"
fi

# 3.15 Check auditd (system auditing)
echo "auditd:"
if command -v auditctl &> /dev/null; then
    if systemctl is-active auditd &>/dev/null; then
        echo "  status: running"
        AUDIT_RULES=$(sudo auditctl -l 2>/dev/null | wc -l || echo "0")
        echo "  rules_loaded: $AUDIT_RULES"
        # Check audit status
        AUDIT_ENABLED=$(sudo auditctl -s 2>/dev/null | grep "enabled" | awk "{print \$2}" || echo "unknown")
        echo "  enabled: $AUDIT_ENABLED"
        # Recent audit log entries (last hour)
        if [[ -f /var/log/audit/audit.log ]]; then
            RECENT_EVENTS=$(sudo ausearch -ts recent 2>/dev/null | grep -c "type=" || echo "0")
            echo "  recent_events: $RECENT_EVENTS"
        fi
    else
        echo "  status: installed but not running"
    fi
else
    echo "  status: not installed"
fi

# ============================================================================
# 4. SYSTEM INFORMATION
# ============================================================================
echo ""
echo "=== SECTION: SYSTEM ==="

# Disk usage
echo "disk_usage:"
df -h / | tail -1 | awk "{print \"  root: \" \$5 \" used (\" \$3 \" of \" \$2 \")\"}"

# Memory
echo "memory_usage:"
free -h | grep Mem | awk "{print \"  ram: \" \$3 \" used of \" \$2}"

# Load
echo "load_average:"
cat /proc/loadavg | awk "{print \"  1m: \" \$1 \", 5m: \" \$2 \", 15m: \" \$3}"

# Last reboot
echo "last_reboot: $(who -b | awk "{print \$3, \$4}")"

# Docker status (if running)
if command -v docker &> /dev/null; then
    echo "docker:"
    DOCKER_RUNNING=$(docker ps -q 2>/dev/null | wc -l || echo "0")
    DOCKER_TOTAL=$(docker ps -aq 2>/dev/null | wc -l || echo "0")
    echo "  running_containers: $DOCKER_RUNNING"
    echo "  total_containers: $DOCKER_TOTAL"
fi

echo ""
echo "=== SERVER_CHECK_END ==="
'

# ============================================================================
# Function to check single server
# ============================================================================

log_verbose() {
    if [[ "$VERBOSE" == "true" ]]; then
        echo -e "${CYAN}  [VERBOSE]${NC} $1" >&2
    fi
}

check_server() {
    local server=$1
    local ssh_host=$(get_ssh_host "$server")
    local output_file=$(mktemp)
    
    log_info "Connecting to server: ${server} (${ssh_host})..."
    log_verbose "SSH command: ssh -o ConnectTimeout=10 -o StrictHostKeyChecking=accept-new $ssh_host"
    
    # Execute remote script
    if printf '%s' "$REMOTE_CHECK_SCRIPT" | ssh -T -o ConnectTimeout=30 -o StrictHostKeyChecking=accept-new "$ssh_host" "bash" > "$output_file" 2>&1; then
        log_success "Server ${server} - check completed"
        
        # Verbose output - show what was checked
        if [[ "$VERBOSE" == "true" ]]; then
            log_verbose "Parsing results..."
            
            local updates=$(grep "^updates_available:" "$output_file" | cut -d: -f2 | tr -d ' ')
            local security=$(grep "^security_updates:" "$output_file" | cut -d: -f2 | tr -d ' ')
            local needs_reboot=$(grep "^needs_reboot:" "$output_file" | cut -d: -f2 | tr -d ' ')
            local failed_ssh=$(grep "last_24h:" "$output_file" | cut -d: -f2 | tr -d ' ')
            local f2b_status=$(grep "^  status:" "$output_file" | head -1 | cut -d: -f2 | tr -d ' ')
            local banned=$(grep "^  currently_banned:" "$output_file" | cut -d: -f2 | tr -d ' ')
            
            log_verbose "  Updates available: ${updates:-0}"
            log_verbose "  Security updates: ${security:-0}"
            log_verbose "  Needs reboot: ${needs_reboot:-false}"
            log_verbose "  Failed SSH (24h): ${failed_ssh:-0}"
            log_verbose "  Fail2ban: ${f2b_status:-unknown}"
            [[ -n "$banned" ]] && log_verbose "  Currently banned IPs: ${banned}"
            
            # Show immediate warnings for critical issues
            if [[ ${security:-0} -gt 0 ]]; then
                log_warning "SECURITY UPDATES: ${security} security updates pending!"
            fi
            if [[ ${updates:-0} -gt 10 ]]; then
                log_warning "UPDATES: ${updates} total updates pending"
            fi
            if [[ "$needs_reboot" == "true" ]]; then
                log_warning "REBOOT REQUIRED: Kernel or services need restart!"
            fi
            if [[ ${failed_ssh:-0} -gt 50 ]]; then
                log_warning "INTRUSION: ${failed_ssh} failed SSH logins in 24h!"
            fi
        fi
        
        echo "$output_file"
    else
        log_error "Server ${server} - connection failed or error occurred"
        if [[ "$VERBOSE" == "true" ]]; then
            log_verbose "Connection error. Check SSH config and keys."
            log_verbose "Try manually: ssh $ssh_host"
            log_verbose "Output file contents:"
            cat "$output_file" | head -20 | while read line; do
                log_verbose "  $line"
            done
        fi
        echo "CONNECTION_FAILED" > "$output_file"
        echo "$output_file"
    fi
}

# ============================================================================
# Function to generate Markdown report
# ============================================================================

generate_report() {
    local all_results=("$@")
    
    cat << EOF
# QJ Server Security Report

**Generated:** $(date "+%Y-%m-%d %H:%M:%S")  
**Servers checked:** ${SERVERS[*]}

---

## Summary

EOF

    local total_updates=0
    local total_security_updates=0
    local servers_need_reboot=0
    local servers_with_issues=0
    local connection_failed=0
    
    # Array for storing actions
    declare -a actions_needed
    
    for i in "${!SERVERS[@]}"; do
        local server="${SERVERS[$i]}"
        local result_file="${all_results[$i]}"
        
        if [[ -f "$result_file" ]] && ! grep -q "CONNECTION_FAILED" "$result_file"; then
            # Parse results
            local updates=$(grep "^updates_available:" "$result_file" | cut -d: -f2 | tr -d ' ')
            local security=$(grep "^security_updates:" "$result_file" | cut -d: -f2 | tr -d ' ')
            local needs_reboot=$(grep "^needs_reboot:" "$result_file" | cut -d: -f2 | tr -d ' ')
            local failed_ssh=$(grep "last_24h:" "$result_file" | cut -d: -f2 | tr -d ' ')
            
            total_updates=$((total_updates + ${updates:-0}))
            total_security_updates=$((total_security_updates + ${security:-0}))
            
            if [[ "$needs_reboot" == "true" ]]; then
                servers_need_reboot=$((servers_need_reboot + 1))
            fi
            
            if [[ ${failed_ssh:-0} -gt 100 ]]; then
                servers_with_issues=$((servers_with_issues + 1))
            fi
        else
            connection_failed=$((connection_failed + 1))
        fi
    done
    
    # Summary table
    cat << EOF
| Metric | Value | Status |
|--------|-------|--------|
| Servers checked | ${#SERVERS[@]} | OK |
| Connection errors | $connection_failed | $(if [[ $connection_failed -gt 0 ]]; then echo "WARN"; else echo "OK"; fi) |
| Pending updates | $total_updates | $(if [[ $total_updates -gt 0 ]]; then echo "WARN"; else echo "OK"; fi) |
| Security updates | $total_security_updates | $(if [[ $total_security_updates -gt 0 ]]; then echo "CRIT"; else echo "OK"; fi) |
| Servers need reboot | $servers_need_reboot | $(if [[ $servers_need_reboot -gt 0 ]]; then echo "WARN"; else echo "OK"; fi) |
| Suspicious activity | $servers_with_issues | $(if [[ $servers_with_issues -gt 0 ]]; then echo "CRIT"; else echo "OK"; fi) |

---

EOF
    
    # Details for each server
    for i in "${!SERVERS[@]}"; do
        local server="${SERVERS[$i]}"
        local result_file="${all_results[$i]}"
        local ssh_host=$(get_ssh_host "$server")
        
        local server_upper=$(to_upper "$server")
        cat << EOF
## Server: ${server_upper}
**Host:** \`${ssh_host}\`

EOF
        
        if [[ -f "$result_file" ]] && ! grep -q "CONNECTION_FAILED" "$result_file"; then
            # Basic info
            local hostname=$(grep "^hostname:" "$result_file" | cut -d: -f2 | tr -d ' ')
            local kernel=$(grep "^kernel:" "$result_file" | cut -d: -f2 | tr -d ' ')
            local uptime=$(grep "^uptime:" "$result_file" | cut -d: -f2-)
            
            cat << EOF
**Hostname:** ${hostname}  
**Kernel:** ${kernel}  
**Uptime:** ${uptime}

EOF
            
            # Updates
            local updates=$(grep "^updates_available:" "$result_file" | cut -d: -f2 | tr -d ' ')
            local security=$(grep "^security_updates:" "$result_file" | cut -d: -f2 | tr -d ' ')
            
            cat << EOF
### Updates

| Type | Count |
|------|-------|
| All | ${updates:-0} |
| Security | ${security:-unknown} |

EOF
            
            if [[ ${updates:-0} -gt 0 ]]; then
                echo "**Packages to update:**"
                echo '```'
                sed -n '/^update_list:/,/^[a-z]/p' "$result_file" | grep "  -" | head -10
                echo '```'
                echo ""
                actions_needed+=("[FIX] ${server}: Install ${updates} updates (${security:-0} security)")
            fi
            
            # Kernel / Reboot
            local needs_reboot=$(grep "^needs_reboot:" "$result_file" | cut -d: -f2 | tr -d ' ')
            local reboot_reason=$(grep "^reboot_reason:" "$result_file" | cut -d: -f2-)
            
            cat << EOF
### Kernel Status

| Status | Value |
|--------|-------|
| Needs reboot | $(if [[ "$needs_reboot" == "true" ]]; then echo "YES"; else echo "NO"; fi) |
| Reason | ${reboot_reason:-none} |

EOF
            
            if [[ "$needs_reboot" == "true" ]]; then
                actions_needed+=("[REBOOT] ${server}: System restart required (${reboot_reason})")
            fi
            
            # Security
            local failed_ssh=$(grep "last_24h:" "$result_file" | cut -d: -f2 | tr -d ' ')
            
            # Get tool installation status
            local f2b_installed=$(sed -n '/^fail2ban:/,/^[a-z]/p' "$result_file" | grep "status:" | head -1 | cut -d: -f2 | tr -d ' ')
            local ufw_installed=$(sed -n '/^ufw_details:/,/^[a-z]/p' "$result_file" | grep "status:" | head -1 | cut -d: -f2 | tr -d ' ')
            local wg_installed=$(sed -n '/^wireguard:/,/^[a-z]/p' "$result_file" | grep "status:" | cut -d: -f2 | tr -d ' ')
            local auditd_installed=$(sed -n '/^auditd:/,/^[a-z]/p' "$result_file" | grep "status:" | cut -d: -f2 | tr -d ' ')
            local rkhunter_installed=$(sed -n '/^rootkit_scanner:/,/^[a-z]/p' "$result_file" | grep -E "rkhunter:|chkrootkit:" | head -1)
            
            # Format statuses
            local f2b_icon="NO" && [[ "$f2b_installed" == *"Number"* || "$f2b_installed" == *"Status"* ]] && f2b_icon="YES"
            local ufw_icon="NO" && [[ "$ufw_installed" == "active" ]] && ufw_icon="YES"
            local wg_icon="NO" && [[ "$wg_installed" == "active" ]] && wg_icon="YES"
            local auditd_icon="NO" && [[ "$auditd_installed" == "running" ]] && auditd_icon="YES"
            local rkhunter_icon="NO" && [[ -n "$rkhunter_installed" ]] && rkhunter_icon="YES"
            
            cat << EOF
### Security Tools Installed

| Tool | Status | Notes |
|------|--------|-------|
| Fail2ban | ${f2b_icon} | $(if [[ "$f2b_icon" == "YES" ]]; then echo "SSH protection active"; else echo "NOT INSTALLED - install with: apt install fail2ban"; fi) |
| UFW Firewall | ${ufw_icon} | $(if [[ "$ufw_icon" == "YES" ]]; then echo "Firewall active"; elif [[ "$ufw_installed" == "notinstalled" ]]; then echo "NOT INSTALLED"; else echo "INACTIVE - enable with: sudo ufw enable"; fi) |
| WireGuard | ${wg_icon} | $(if [[ "$wg_icon" == "YES" ]]; then echo "VPN active"; elif [[ "$wg_installed" == "installedbutnotactive" ]]; then echo "Installed but not active"; else echo "Not installed"; fi) |
| Auditd | ${auditd_icon} | $(if [[ "$auditd_icon" == "YES" ]]; then echo "System auditing active"; elif [[ "$auditd_installed" == "installedbutnotrunning" ]]; then echo "Installed but not running"; else echo "NOT INSTALLED - install with: apt install auditd"; fi) |
| Rootkit Scanner | ${rkhunter_icon} | $(if [[ "$rkhunter_icon" == "YES" ]]; then echo "rkhunter/chkrootkit installed"; else echo "Not installed - install with: apt install rkhunter"; fi) |

### Intrusion Detection

**Failed SSH logins (24h):** ${failed_ssh:-0}

EOF
            
            if [[ ${failed_ssh:-0} -gt 0 ]]; then
                echo "**Top attacking IPs:**"
                echo '```'
                sed -n '/^  top_attackers:/,/^[a-z]/p' "$result_file" | grep "    -" | head -5
                echo '```'
                echo ""
            fi
            
            if [[ ${failed_ssh:-0} -gt 100 ]]; then
                actions_needed+=("[ALERT] ${server}: High number of failed SSH logins (${failed_ssh}) - check fail2ban")
            fi
            
            # Fail2ban status
            local f2b_status=$(grep "^  status:" "$result_file" | head -1 | cut -d: -f2 | tr -d ' ')
            local f2b_banned=$(grep "^  currently_banned:" "$result_file" | cut -d: -f2 | tr -d ' ')
            local f2b_total=$(grep "^  total_banned:" "$result_file" | cut -d: -f2 | tr -d ' ')
            local f2b_jail=$(grep "^  sshd_jail:" "$result_file" | cut -d: -f2 | tr -d ' ')
            
            echo "**Fail2ban:**"
            if [[ "$f2b_status" == *"Number"* ]] || [[ -n "$f2b_jail" ]]; then
                echo "- Status: Running"
                echo "- SSHD jail: ${f2b_jail:-unknown}"
                echo "- Currently banned: ${f2b_banned:-0}"
                echo "- Total banned: ${f2b_total:-0}"
            elif [[ "$f2b_status" == "notinstalled" ]]; then
                echo "- Status: NOT INSTALLED"
                actions_needed+=("[WARN] ${server}: fail2ban not installed - consider installing for SSH protection")
            else
                echo "- Status: ${f2b_status:-unknown}"
            fi
            echo ""
            
            # WireGuard VPN
            local wg_status=$(grep "^  status:" "$result_file" | grep -A1 "wireguard" | tail -1 | cut -d: -f2 | tr -d ' ' 2>/dev/null)
            wg_status=$(sed -n '/^wireguard:/,/^[a-z]/p' "$result_file" | grep "status:" | cut -d: -f2 | tr -d ' ')
            echo "**WireGuard VPN:**"
            if [[ "$wg_status" == "active" ]]; then
                local wg_ifaces=$(sed -n '/^wireguard:/,/^[a-z]/p' "$result_file" | grep "interfaces:" | cut -d: -f2 | tr -d ' ')
                local wg_peers=$(sed -n '/^wireguard:/,/^[a-z]/p' "$result_file" | grep "peers:" | cut -d: -f2 | tr -d ' ')
                echo "- Status: Active"
                echo "- Interfaces: ${wg_ifaces:-none}"
                [[ -n "$wg_peers" ]] && echo "- Peers: $wg_peers"
            elif [[ "$wg_status" == "installedbutnotactive" ]]; then
                echo "- Status: Installed but not active"
            else
                echo "- Status: Not installed"
            fi
            echo ""
            
            # UFW Firewall details
            local ufw_status=$(sed -n '/^ufw_details:/,/^[a-z]/p' "$result_file" | grep "status:" | head -1 | cut -d: -f2 | tr -d ' ')
            echo "**UFW Firewall:**"
            if [[ "$ufw_status" == "active" ]]; then
                local ufw_in=$(sed -n '/^ufw_details:/,/^[a-z]/p' "$result_file" | grep "default_incoming:" | cut -d: -f2 | tr -d ' ')
                local ufw_out=$(sed -n '/^ufw_details:/,/^[a-z]/p' "$result_file" | grep "default_outgoing:" | cut -d: -f2 | tr -d ' ')
                echo "- Status: Active"
                echo "- Default incoming: ${ufw_in:-unknown}"
                echo "- Default outgoing: ${ufw_out:-unknown}"
                echo "- Rules:"
                echo '```'
                sed -n '/^ufw_details:/,/^[a-z_]*:/p' "$result_file" | grep "    -" | head -10 | sed 's/    - //'
                echo '```'
            elif [[ "$ufw_status" == "notinstalled" ]]; then
                echo "- Status: NOT INSTALLED"
                actions_needed+=("[WARN] ${server}: UFW firewall not installed")
            else
                echo "- Status: Inactive"
                actions_needed+=("[WARN] ${server}: UFW firewall is inactive - consider enabling")
            fi
            echo ""
            
            # Auditd
            local auditd_status=$(sed -n '/^auditd:/,/^[a-z]/p' "$result_file" | grep "status:" | cut -d: -f2 | tr -d ' ')
            echo "**Auditd (System Auditing):**"
            if [[ "$auditd_status" == "running" ]]; then
                local audit_rules=$(sed -n '/^auditd:/,/^[a-z]/p' "$result_file" | grep "rules_loaded:" | cut -d: -f2 | tr -d ' ')
                local audit_enabled=$(sed -n '/^auditd:/,/^[a-z]/p' "$result_file" | grep "enabled:" | cut -d: -f2 | tr -d ' ')
                echo "- Status: Running"
                echo "- Rules loaded: ${audit_rules:-0}"
                echo "- Enabled: ${audit_enabled:-unknown}"
            elif [[ "$auditd_status" == "installedbutnotrunning" ]]; then
                echo "- Status: Installed but not running"
                actions_needed+=("[WARN] ${server}: auditd installed but not running")
            else
                echo "- Status: Not installed"
            fi
            echo ""
            
            # Active sessions
            echo "**Active SSH sessions:**"
            echo '```'
            sed -n '/^active_ssh_sessions:/,/^[a-z]/p' "$result_file" | grep "  -" | head -5 || echo "  No active sessions"
            echo '```'
            echo ""
            
            # Listening ports
            echo "**Listening ports:**"
            echo '```'
            sed -n '/^  listening_ports:/,/^[a-z]/p' "$result_file" | grep "    -" | head -10
            echo '```'
            echo ""
            
            # System info
            echo "### System Resources"
            echo ""
            local disk=$(grep "root:" "$result_file" | grep "used" | cut -d: -f2-)
            local memory=$(grep "ram:" "$result_file" | cut -d: -f2-)
            local load=$(grep -A3 "^load_average:" "$result_file" | grep "1m:" | cut -d: -f2-)
            
            cat << EOF
| Resource | Usage |
|----------|-------|
| Disk (/) | ${disk:-unknown} |
| RAM | ${memory:-unknown} |
| Load | ${load:-unknown} |

EOF
            
            # Docker
            if grep -q "^docker:" "$result_file"; then
                local docker_running=$(grep "running_containers:" "$result_file" | cut -d: -f2 | tr -d ' ')
                local docker_total=$(grep "total_containers:" "$result_file" | cut -d: -f2 | tr -d ' ')
                echo "**Docker:** ${docker_running}/${docker_total} containers running"
                echo ""
            fi
            
        else
            cat << EOF
> **WARNING: Failed to connect to this server.**
> 
> Check:
> - Is the server running
> - Is SSH configuration correct
> - Are SSH keys configured

EOF
            actions_needed+=("[CONN] ${server}: Check connection - server unreachable")
        fi
        
        echo "---"
        echo ""
    done
    
    # Actions section
    if [[ ${#actions_needed[@]} -gt 0 ]]; then
        cat << EOF
## Actions Required

EOF
        for action in "${actions_needed[@]}"; do
            echo "- [ ] $action"
        done
        echo ""
    else
        cat << EOF
## Actions Required

All servers are healthy! No critical issues detected.

EOF
    fi
    
    # Recommendations
    cat << EOF
---

## Recommendations

### Regular Tasks
1. **Daily:** Check logs for failed logins
2. **Weekly:** Install security updates
3. **Monthly:** Full configuration and permissions review

### Commands to Execute

**Update all servers:**
\`\`\`bash
# For each server with updates:
ssh qj-{server} "sudo apt update && sudo apt upgrade -y"
\`\`\`

**Restart server (if required):**
\`\`\`bash
ssh qj-{server} "sudo reboot"
\`\`\`

**Check fail2ban:**
\`\`\`bash
ssh qj-{server} "sudo fail2ban-client status sshd"
\`\`\`

---

*Report generated automatically by \`security_check.sh\`*
EOF
}

# ============================================================================
# Main logic
# ============================================================================

main() {
    log_header "QJ Server Security Check"
    log_info "Starting check of ${#SERVERS[@]} servers..."
    log_info "Servers: ${SERVERS[*]}"
    echo ""
    
    # Store results for each server
    declare -a results
    
    if [[ "$PARALLEL" == "true" ]]; then
        log_info "Parallel mode - checking all servers simultaneously..."
        
        # Run all in background
        declare -A pids
        for server in "${SERVERS[@]}"; do
            check_server "$server" &
            pids[$server]=$!
        done
        
        # Wait for all
        for server in "${SERVERS[@]}"; do
            wait ${pids[$server]}
            result=$(check_server "$server")
            results+=("$result")
        done
    else
        for server in "${SERVERS[@]}"; do
            result=$(check_server "$server")
            results+=("$result")
        done
    fi
    
    echo ""
    log_header "Generating Report"
    
    # Generate report
    generate_report "${results[@]}" > "$REPORT_FILE"
    
    log_success "Report saved to: $REPORT_FILE"
    echo ""
    
    # Show summary on console
    log_header "Summary"
    grep -A 20 "## Summary" "$REPORT_FILE" | head -15
    echo ""
    
    # Show actions
    if grep -q "## Actions Required" "$REPORT_FILE"; then
        log_header "Actions Required"
        sed -n '/## Actions Required/,/^---$/p' "$REPORT_FILE" | grep "^\- \[" | head -10
    fi
    
    echo ""
    log_info "Full report: $REPORT_FILE"
    
    # Cleanup
    for result in "${results[@]}"; do
        if [[ -f "$result" ]]; then
            rm -f "$result"
        fi
    done
}

# Run main function
main
