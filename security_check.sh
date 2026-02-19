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
PARALLEL=true
NOTIFY=false

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
  -n, --notify               Send Telegram/Email alerts for critical issues
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
        -n|--notify)
            NOTIFY=true
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
echo ">>> Checking: Package Updates" >&2
echo ""
echo "=== SECTION: UPDATES ==="

# Detect package manager
if command -v apt-get &> /dev/null; then
    PKG_MANAGER="apt"
    # Refresh package list (quietly)
    sudo apt-get update -qq 2>/dev/null
    
    # Check available updates
    UPDATES=$(apt-get -s upgrade 2>/dev/null | grep -c "^Inst" 2>/dev/null | tail -1 | tr -cd '0-9')
    UPDATES=${UPDATES:-0}
    SECURITY_UPDATES=$(apt-get -s upgrade 2>/dev/null | grep -i security | grep -c "^Inst" 2>/dev/null | tail -1 | tr -cd '0-9')
    SECURITY_UPDATES=${SECURITY_UPDATES:-0}
    
    echo "pkg_manager: apt"
    echo "updates_available: $UPDATES"
    echo "security_updates: $SECURITY_UPDATES"
    
    # List packages to update
    if [[ "$UPDATES" -gt 0 ]]; then
        echo "update_list:"
        apt-get -s upgrade 2>/dev/null | grep "^Inst" | head -30 | sed "s/^/  - /"
    fi
    
elif command -v dnf &> /dev/null; then
    PKG_MANAGER="dnf"
    UPDATES=$(dnf check-update 2>/dev/null | grep -c "^\S" 2>/dev/null | tail -1 | tr -cd '0-9')
    UPDATES=${UPDATES:-0}
    SECURITY_UPDATES=$(dnf check-update --security 2>/dev/null | grep -c "^\S" 2>/dev/null | tail -1 | tr -cd '0-9')
    SECURITY_UPDATES=${SECURITY_UPDATES:-0}
    
    echo "pkg_manager: dnf"
    echo "updates_available: $UPDATES"
    echo "security_updates: $SECURITY_UPDATES"
    
elif command -v yum &> /dev/null; then
    PKG_MANAGER="yum"
    UPDATES=$(yum check-update 2>/dev/null | grep -c "^\S" 2>/dev/null | tail -1 | tr -cd '0-9')
    UPDATES=${UPDATES:-0}
    
    echo "pkg_manager: yum"
    echo "updates_available: $UPDATES"
    echo "security_updates: unknown"
fi

# ============================================================================
# 2. CHECK KERNEL RESTART REQUIREMENT
# ============================================================================
echo ">>> Checking: Kernel Status" >&2
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
echo ">>> Checking: Security & Intrusion" >&2
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
echo ">>> Checking: Fail2ban" >&2
echo "fail2ban:"
if command -v fail2ban-client &>/dev/null; then
    # Primary: use systemctl (works without sudo)
    if systemctl is-active --quiet fail2ban 2>/dev/null; then
        echo "  service_running: true"
    else
        echo "  service_running: false"
    fi
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
    echo "  service_running: false"
    echo "  status: not installed"
fi

# 3.12 Check for rootkits (rkhunter/chkrootkit if available)
echo ">>> Checking: Rootkit Scanner" >&2
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
echo ">>> Checking: WireGuard VPN" >&2
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
echo ">>> Checking: UFW Firewall" >&2
echo "ufw_details:"
if command -v ufw &>/dev/null; then
    # Primary: use systemctl (works without sudo)
    if systemctl is-active --quiet ufw 2>/dev/null; then
        echo "  service_running: true"
    else
        echo "  service_running: false"
    fi
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
    echo "  service_running: false"
    echo "  status: not installed"
fi

# 3.15 Check auditd (system auditing)
echo ">>> Checking: Auditd" >&2
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
# 3.16 SSH HARDENING AUDIT
# ============================================================================
echo ">>> Checking: SSH Hardening" >&2
echo ""
echo "=== SECTION: SSH_HARDENING ==="
echo "ssh_hardening:"

SSHD_CONFIG="/etc/ssh/sshd_config"
if [[ -f "$SSHD_CONFIG" ]]; then
    # PermitRootLogin
    ROOT_LOGIN=$(grep -i "^PermitRootLogin" "$SSHD_CONFIG" 2>/dev/null | awk "{print \$2}" || echo "not set")
    echo "  permit_root_login: ${ROOT_LOGIN:-not set}"

    # PasswordAuthentication
    PASS_AUTH=$(grep -i "^PasswordAuthentication" "$SSHD_CONFIG" 2>/dev/null | awk "{print \$2}" || echo "not set")
    echo "  password_auth: ${PASS_AUTH:-not set}"

    # PubkeyAuthentication
    PUBKEY_AUTH=$(grep -i "^PubkeyAuthentication" "$SSHD_CONFIG" 2>/dev/null | awk "{print \$2}" || echo "not set")
    echo "  pubkey_auth: ${PUBKEY_AUTH:-not set}"

    # MaxAuthTries
    MAX_AUTH=$(grep -i "^MaxAuthTries" "$SSHD_CONFIG" 2>/dev/null | awk "{print \$2}" || echo "not set")
    echo "  max_auth_tries: ${MAX_AUTH:-not set}"

    # PermitEmptyPasswords
    EMPTY_PASS=$(grep -i "^PermitEmptyPasswords" "$SSHD_CONFIG" 2>/dev/null | awk "{print \$2}" || echo "not set")
    echo "  permit_empty_passwords: ${EMPTY_PASS:-not set}"

    # X11Forwarding
    X11=$(grep -i "^X11Forwarding" "$SSHD_CONFIG" 2>/dev/null | awk "{print \$2}" || echo "not set")
    echo "  x11_forwarding: ${X11:-not set}"

    # LoginGraceTime
    GRACE=$(grep -i "^LoginGraceTime" "$SSHD_CONFIG" 2>/dev/null | awk "{print \$2}" || echo "not set")
    echo "  login_grace_time: ${GRACE:-not set}"

    # SSH protocol version (older configs)
    PROTO=$(grep -i "^Protocol" "$SSHD_CONFIG" 2>/dev/null | awk "{print \$2}" || echo "2")
    echo "  protocol: ${PROTO}"

    # Ciphers & MACs (weak cipher check)
    WEAK_CIPHERS=$(grep -i "^Ciphers" "$SSHD_CONFIG" 2>/dev/null | grep -ciE "arcfour|3des|blowfish|cast128" || echo "0")
    echo "  weak_ciphers_configured: $WEAK_CIPHERS"
else
    echo "  status: sshd_config not found"
fi

# ============================================================================
# 3.17 UNATTENDED-UPGRADES STATUS
# ============================================================================
echo ">>> Checking: Auto-Updates" >&2
echo ""
echo "=== SECTION: AUTO_UPDATES ==="
echo "unattended_upgrades:"

if dpkg -l unattended-upgrades &>/dev/null 2>&1; then
    echo "  installed: true"
    # Check if enabled
    AUTO_CFG="/etc/apt/apt.conf.d/20auto-upgrades"
    if [[ -f "$AUTO_CFG" ]]; then
        UU_ENABLED=$(grep -i "Unattended-Upgrade" "$AUTO_CFG" 2>/dev/null | grep -c "\"1\"" 2>/dev/null | tail -1 | tr -cd '0-9')
        UU_ENABLED=${UU_ENABLED:-0}
        echo "  enabled: $([ "${UU_ENABLED:-0}" -gt 0 ] && echo true || echo false)"
    else
        echo "  enabled: unknown (no config)"
    fi
    # Last run
    UU_LOG="/var/log/unattended-upgrades/unattended-upgrades.log"
    if [[ -f "$UU_LOG" ]]; then
        LAST_UU=$(stat -c %y "$UU_LOG" 2>/dev/null | cut -d. -f1 || echo "unknown")
        echo "  last_run: $LAST_UU"
    fi
else
    echo "  installed: false"
fi

# ============================================================================
# 3.18 SSL/TLS CERTIFICATE EXPIRY
# ============================================================================
echo ">>> Checking: SSL Certificates" >&2
echo ""
echo "=== SECTION: SSL_CERTS ==="
echo "ssl_certificates:"

# Check certificates on common ports (443, 8443, 8080)
for port in 443 8443; do
    if ss -tlnp | grep -q ":${port} " 2>/dev/null; then
        CERT_INFO=$(echo | timeout 5 openssl s_client -connect 127.0.0.1:${port} -servername localhost 2>/dev/null | openssl x509 -noout -dates -subject 2>/dev/null)
        if [[ -n "$CERT_INFO" ]]; then
            CERT_EXPIRY=$(echo "$CERT_INFO" | grep "notAfter" | cut -d= -f2)
            CERT_SUBJ=$(echo "$CERT_INFO" | grep "subject" | sed "s/subject=//" | tr -d " ")
            echo "  - port: $port"
            echo "    subject: $CERT_SUBJ"
            echo "    expires: $CERT_EXPIRY"
            # Check if expiring within 30 days
            if command -v date &>/dev/null; then
                EXPIRY_EPOCH=$(date -d "$CERT_EXPIRY" +%s 2>/dev/null || echo "0")
                NOW_EPOCH=$(date +%s)
                DAYS_LEFT=$(( (EXPIRY_EPOCH - NOW_EPOCH) / 86400 ))
                echo "    days_remaining: $DAYS_LEFT"
            fi
        fi
    fi
done

# Check Traefik/LetsEncrypt cert files if exist
for CERT_DIR in /etc/letsencrypt/live /opt/traefik/certs; do
    if [[ -d "$CERT_DIR" ]]; then
        for cert in "$CERT_DIR"/*/fullchain.pem "$CERT_DIR"/*.crt; do
            if [[ -f "$cert" ]]; then
                CERT_EXPIRY=$(openssl x509 -in "$cert" -noout -enddate 2>/dev/null | cut -d= -f2)
                CERT_CN=$(openssl x509 -in "$cert" -noout -subject 2>/dev/null | sed "s/.*CN = //" | head -1)
                if [[ -n "$CERT_EXPIRY" ]]; then
                    EXPIRY_EPOCH=$(date -d "$CERT_EXPIRY" +%s 2>/dev/null || echo "0")
                    NOW_EPOCH=$(date +%s)
                    DAYS_LEFT=$(( (EXPIRY_EPOCH - NOW_EPOCH) / 86400 ))
                    echo "  - file: $cert"
                    echo "    cn: ${CERT_CN:-unknown}"
                    echo "    expires: $CERT_EXPIRY"
                    echo "    days_remaining: $DAYS_LEFT"
                fi
            fi
        done
    fi
done

# ============================================================================
# 3.19 DOCKER IMAGE AGE & SECURITY
# ============================================================================
echo ">>> Checking: Docker Security" >&2
echo ""
echo "=== SECTION: DOCKER_SECURITY ==="
echo "docker_security:"

if command -v docker &>/dev/null; then
    # Image age check (flag images older than 90 days)
    echo "  old_images:"
    docker images --format "{{.Repository}}:{{.Tag}} {{.CreatedAt}}" 2>/dev/null | while read img created rest; do
        if [[ "$img" != "<none>:<none>" && -n "$created" ]]; then
            IMG_DATE=$(echo "$created" | cut -d" " -f1)
            IMG_EPOCH=$(date -d "$IMG_DATE" +%s 2>/dev/null || echo "0")
            NOW_EPOCH=$(date +%s)
            AGE_DAYS=$(( (NOW_EPOCH - IMG_EPOCH) / 86400 ))
            if [[ $AGE_DAYS -gt 90 ]]; then
                echo "    - image: $img"
                echo "      age_days: $AGE_DAYS"
            fi
        fi
    done

    # Containers running as root
    echo "  containers_as_root:"
    docker ps -q 2>/dev/null | while read cid; do
        C_USER=$(docker inspect --format "{{.Config.User}}" "$cid" 2>/dev/null)
        C_NAME=$(docker inspect --format "{{.Name}}" "$cid" 2>/dev/null | tr -d "/")
        if [[ -z "$C_USER" || "$C_USER" == "root" || "$C_USER" == "0" ]]; then
            echo "    - $C_NAME (user: ${C_USER:-root})"
        fi
    done

    # Dangling images (waste / potential info leak)
    DANGLING=$(docker images -f "dangling=true" -q 2>/dev/null | wc -l || echo "0")
    echo "  dangling_images: $DANGLING"

    # Containers with host network
    echo "  host_network_containers:"
    docker ps --format "{{.Names}}" --filter "network=host" 2>/dev/null | while read name; do
        echo "    - $name"
    done

    # Privileged containers
    echo "  privileged_containers:"
    docker ps -q 2>/dev/null | while read cid; do
        PRIV=$(docker inspect --format "{{.HostConfig.Privileged}}" "$cid" 2>/dev/null)
        if [[ "$PRIV" == "true" ]]; then
            C_NAME=$(docker inspect --format "{{.Name}}" "$cid" 2>/dev/null | tr -d "/")
            echo "    - $C_NAME"
        fi
    done
else
    echo "  status: docker not available"
fi

# ============================================================================
# 3.20 ZOMBIE / DEFUNCT PROCESSES
# ============================================================================
echo ">>> Checking: Zombie Processes" >&2
echo ""
echo "=== SECTION: ZOMBIES ==="
echo "zombie_processes:"

ZOMBIE_COUNT=$(ps aux | grep -c "[Z]" 2>/dev/null || echo "0")
echo "  count: $ZOMBIE_COUNT"
if [[ $ZOMBIE_COUNT -gt 0 ]]; then
    echo "  list:"
    ps aux | awk "\$8 ~ /Z/ {print \"    - pid: \" \$2 \", ppid: \" \$3 \", cmd: \" \$11}" | head -10
fi

# ============================================================================
# 3.21 OPEN FILE DESCRIPTORS
# ============================================================================
echo ">>> Checking: File Descriptors" >&2
echo ""
echo "=== SECTION: FILE_DESCRIPTORS ==="
echo "file_descriptors:"

FD_MAX=$(cat /proc/sys/fs/file-max 2>/dev/null || echo "unknown")
FD_USED=$(cat /proc/sys/fs/file-nr 2>/dev/null | awk "{print \$1}" || echo "unknown")
echo "  max: $FD_MAX"
echo "  used: $FD_USED"

# Top processes by open FDs
echo "  top_consumers:"
for pid in $(ls /proc 2>/dev/null | grep -E "^[0-9]+$" | head -200); do
    if [[ -d "/proc/$pid/fd" ]]; then
        count=$(ls /proc/$pid/fd 2>/dev/null | wc -l)
        name=$(cat /proc/$pid/comm 2>/dev/null || echo "?")
        echo "$count $pid $name"
    fi
done 2>/dev/null | sort -rn | head -5 | while read cnt pid name; do
    echo "    - process: $name (pid: $pid), open_fds: $cnt"
done

# ============================================================================
# 3.22 DNS RESOLUTION TEST
# ============================================================================
echo ">>> Checking: DNS Resolution" >&2
echo ""
echo "=== SECTION: DNS ==="
echo "dns_resolution:"

# Test internal DNS
for domain in google.com api.quantjourney.cloud data.quantjourney.cloud; do
    RESOLVED=$(timeout 5 host "$domain" 2>/dev/null | head -1 || echo "FAILED")
    if echo "$RESOLVED" | grep -q "has address"; then
        echo "  - domain: $domain"
        echo "    status: ok"
        echo "    ip: $(echo "$RESOLVED" | awk "{print \$NF}")"
    else
        echo "  - domain: $domain"
        echo "    status: FAILED"
    fi
done

# Check /etc/resolv.conf
echo "  nameservers:"
grep "^nameserver" /etc/resolv.conf 2>/dev/null | awk "{print \"    - \" \$2}"

# ============================================================================
# 3.23 DISK I/O WAIT
# ============================================================================
echo ">>> Checking: Disk I/O Wait" >&2
echo ""
echo "=== SECTION: IO_WAIT ==="
echo "io_wait:"

# Get I/O wait from top (1 sample)
IOWAIT=$(top -bn1 2>/dev/null | grep "Cpu" | head -1 | grep -oP "[0-9.]+(?=\s*wa)" || echo "unknown")
echo "  cpu_iowait_pct: ${IOWAIT:-unknown}"

# iostat if available
if command -v iostat &>/dev/null; then
    echo "  devices:"
    iostat -dx 1 1 2>/dev/null | awk "NR>6 && \$1 != \"\" {print \"    - device: \" \$1 \", util_pct: \" \$NF \", await_ms: \" \$10}" | head -5
fi

# Check for high I/O wait processes
echo "  high_io_processes:"
iotop -bon1 2>/dev/null | head -5 | tail -3 | while read line; do
    echo "    - $line"
done 2>/dev/null || echo "    iotop not available"

# ============================================================================
# 4. SYSTEM INFORMATION
# ============================================================================
echo ">>> Checking: System Resources" >&2
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
    
    # Execute remote script (stdout=data to file, stderr=progress to console)
    # Prefix stderr lines with server name for progress visibility
    if printf '%s' "$REMOTE_CHECK_SCRIPT" | ssh -T -o ConnectTimeout=30 -o StrictHostKeyChecking=accept-new "$ssh_host" "bash" > "$output_file" 2> >(sed "s/^>>> Checking: /[$server] /" >&2); then
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
            
            # Get tool installation status - use service_running field (from systemctl)
            local f2b_running=$(sed -n '/^fail2ban:/,/^[a-z]/p' "$result_file" | grep "service_running:" | cut -d: -f2 | tr -d ' ')
            local ufw_running=$(sed -n '/^ufw_details:/,/^[a-z]/p' "$result_file" | grep "service_running:" | cut -d: -f2 | tr -d ' ')
            local ufw_status_val=$(sed -n '/^ufw_details:/,/^[a-z]/p' "$result_file" | grep "^  status:" | cut -d: -f2 | tr -d ' ')
            local wg_installed=$(sed -n '/^wireguard:/,/^[a-z]/p' "$result_file" | grep "status:" | cut -d: -f2 | tr -d ' ')
            local auditd_installed=$(sed -n '/^auditd:/,/^[a-z]/p' "$result_file" | grep "status:" | cut -d: -f2 | tr -d ' ')
            local rkhunter_installed=$(sed -n '/^rootkit_scanner:/,/^[a-z]/p' "$result_file" | grep -E "rkhunter:|chkrootkit:" | head -1)
            
            # Format statuses - use service_running for reliable detection
            local f2b_icon="NO"
            [[ "$f2b_running" == "true" ]] && f2b_icon="YES"
            local ufw_icon="NO"
            [[ "$ufw_running" == "true" || "$ufw_status_val" == "active" ]] && ufw_icon="YES"
            local wg_icon="NO"
            [[ "$wg_installed" == "active" ]] && wg_icon="YES"
            local auditd_icon="NO"
            [[ "$auditd_installed" == "running" ]] && auditd_icon="YES"
            local rkhunter_icon="NO"
            [[ -n "$rkhunter_installed" ]] && rkhunter_icon="YES"
            
            cat << EOF
### Security Tools Installed

| Tool | Status | Notes |
|------|--------|-------|
| Fail2ban | ${f2b_icon} | $(if [[ "$f2b_icon" == "YES" ]]; then echo "SSH protection active"; else echo "NOT INSTALLED - install with: apt install fail2ban"; fi) |
| UFW Firewall | ${ufw_icon} | $(if [[ "$ufw_icon" == "YES" ]]; then echo "Firewall active"; elif [[ "$ufw_status_val" == "notinstalled" ]]; then echo "NOT INSTALLED"; else echo "INACTIVE - enable with: sudo ufw enable"; fi) |
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
            local ufw_status=$(sed -n '/^ufw_details:/,/^[a-z]/p' "$result_file" | grep "^  status:" | cut -d: -f2 | tr -d ' ')
            local ufw_svc=$(sed -n '/^ufw_details:/,/^[a-z]/p' "$result_file" | grep "service_running:" | cut -d: -f2 | tr -d ' ')
            echo "**UFW Firewall:**"
            if [[ "$ufw_status" == "active" || "$ufw_svc" == "true" ]]; then
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
            
            # ---- NEW HARDENING SECTIONS ----
            
            # SSH Hardening
            if grep -q "^ssh_hardening:" "$result_file"; then
                echo "### SSH Hardening"
                echo ""
                # Safe value reader — disables strict mode for parsing
                _ssh_val() {
                    local val
                    val=$(set +euo pipefail; sed -n '/^ssh_hardening:/,/^[a-z]/p' "$1" 2>/dev/null | grep "$2" 2>/dev/null | cut -d: -f2 2>/dev/null | tr -d ' ' 2>/dev/null) || true
                    # Clean "notset" (from remote "not set" after tr -d ' ')
                    if [[ -z "$val" || "$val" == "notset" ]]; then echo ""; else echo "$val"; fi
                }
                local ssh_root; ssh_root=$(_ssh_val "$result_file" "permit_root_login:")
                local ssh_pass; ssh_pass=$(_ssh_val "$result_file" "password_auth:")
                local ssh_pubkey; ssh_pubkey=$(_ssh_val "$result_file" "pubkey_auth:")
                local ssh_max; ssh_max=$(_ssh_val "$result_file" "max_auth_tries:")
                local ssh_empty; ssh_empty=$(_ssh_val "$result_file" "permit_empty_passwords:")
                local ssh_x11; ssh_x11=$(_ssh_val "$result_file" "x11_forwarding:")

                local _sr="${ssh_root:-}" _sp="${ssh_pass:-}" _spk="${ssh_pubkey:-}" _sm="${ssh_max:-}" _se="${ssh_empty:-}" _sx="${ssh_x11:-}"

                echo "| Setting | Value | Recommendation |"
                echo "|---------|-------|----------------|"
                echo "| PermitRootLogin | ${_sr:-N/A} | $(if [[ "$_sr" == "no" || "$_sr" == "prohibit-password" ]]; then echo "✅ OK"; else echo "⚠️ Set to no or prohibit-password"; fi) |"
                echo "| PasswordAuthentication | ${_sp:-N/A} | $(if [[ "$_sp" == "no" ]]; then echo "✅ OK"; else echo "⚠️ Set to no (use key auth)"; fi) |"
                echo "| PubkeyAuthentication | ${_spk:-N/A} | $(if [[ "$_spk" == "yes" || -z "$_spk" ]]; then echo "✅ OK"; else echo "⚠️ Set to yes"; fi) |"
                echo "| MaxAuthTries | ${_sm:-N/A} | $(if [[ -n "$_sm" && "$_sm" =~ ^[0-9]+$ && $_sm -le 4 ]]; then echo "✅ OK"; else echo "⚠️ Should be 4 or less"; fi) |"
                echo "| PermitEmptyPasswords | ${_se:-N/A} | $(if [[ "$_se" == "no" || -z "$_se" ]]; then echo "✅ OK"; else echo "🔴 CRITICAL"; fi) |"
                echo "| X11Forwarding | ${_sx:-N/A} | $(if [[ "$_sx" == "no" ]]; then echo "✅ OK"; else echo "⚠️ Set to no on servers"; fi) |"
                echo ""

                if [[ "$_sp" == "yes" ]]; then
                    actions_needed+=("[SSH] ${server}: Password authentication is enabled - consider disabling")
                fi
                if [[ "$_sr" == "yes" ]]; then
                    actions_needed+=("[SSH] ${server}: Root login permitted - high risk")
                fi
            fi

            # Unattended-Upgrades
            if grep -q "^unattended_upgrades:" "$result_file"; then
                local uu_installed=$(sed -n '/^unattended_upgrades:/,/^[a-z]/p' "$result_file" | grep "installed:" | cut -d: -f2 | tr -d ' ')
                local uu_enabled=$(sed -n '/^unattended_upgrades:/,/^[a-z]/p' "$result_file" | grep "enabled:" | cut -d: -f2 | tr -d ' ')
                echo "**Auto-Updates:** $(if [[ "$uu_installed" == "true" ]]; then echo "Installed"; else echo "NOT INSTALLED"; fi) — $(if [[ "$uu_enabled" == "true" ]]; then echo "Enabled ✅"; else echo "⚠️ Not enabled"; fi)"
                echo ""
                if [[ "$uu_installed" != "true" ]]; then
                    actions_needed+=("[AUTO-UPDATE] ${server}: unattended-upgrades not installed")
                elif [[ "$uu_enabled" != "true" ]]; then
                    actions_needed+=("[AUTO-UPDATE] ${server}: unattended-upgrades not enabled")
                fi
            fi

            # SSL Certificates
            if grep -q "^ssl_certificates:" "$result_file"; then
                local ssl_data=$(sed -n '/^ssl_certificates:/,/^[a-z_]*[^:]*:/p' "$result_file" | grep -c "port:\|file:")
                if [[ ${ssl_data:-0} -gt 0 ]]; then
                    echo "### SSL Certificates"
                    echo ""
                    echo "| Port/File | CN | Expires | Days Left |"
                    echo "|-----------|-------|---------|-----------|"
                    # Parse port-based certs
                    sed -n '/^ssl_certificates:/,/^[a-z_]*[^:]*:/p' "$result_file" | while IFS= read -r line; do
                        if echo "$line" | grep -q "port:"; then port=$(echo "$line" | cut -d: -f2 | tr -d ' '); fi
                        if echo "$line" | grep -q "subject:"; then subj=$(echo "$line" | cut -d: -f2- | tr -d ' '); fi
                        if echo "$line" | grep -q "days_remaining:"; then
                            days=$(echo "$line" | cut -d: -f2 | tr -d ' ')
                            status="✅"
                            [[ ${days:-0} -lt 30 ]] && status="⚠️"
                            [[ ${days:-0} -lt 7 ]] && status="🔴"
                            echo "| :${port:-?} | ${subj:-?} | — | ${days} ${status} |"
                        fi
                    done
                    echo ""
                fi
            fi

            # Docker Security
            if grep -q "^docker_security:" "$result_file"; then
                local old_images=$(sed -n '/^docker_security:/,/^[a-z_]*[^:]*:/p' "$result_file" | grep -c "image:")
                local root_containers=$(sed -n '/^docker_security:/,/^[a-z_]*[^:]*:/p' "$result_file" | sed -n '/containers_as_root/,/dangling/p' | grep -c "    -")
                local dangling=$(sed -n '/^docker_security:/,/^[a-z_]*[^:]*:/p' "$result_file" | grep "dangling_images:" | cut -d: -f2 | tr -d ' ')
                local priv_containers=$(sed -n '/^docker_security:/,/^[a-z_]*[^:]*:/p' "$result_file" | sed -n '/privileged_containers/,/^[a-z]/p' | grep -c "    -")
                
                if [[ ${old_images:-0} -gt 0 || ${root_containers:-0} -gt 0 || ${dangling:-0} -gt 0 || ${priv_containers:-0} -gt 0 ]]; then
                    echo "### Docker Security"
                    echo ""
                    echo "| Check | Count | Status |"
                    echo "|-------|-------|--------|"
                    echo "| Old images (>90d) | ${old_images:-0} | $(if [[ ${old_images:-0} -gt 0 ]]; then echo "⚠️"; else echo "✅"; fi) |"
                    echo "| Root containers | ${root_containers:-0} | $(if [[ ${root_containers:-0} -gt 0 ]]; then echo "⚠️"; else echo "✅"; fi) |"
                    echo "| Dangling images | ${dangling:-0} | $(if [[ ${dangling:-0} -gt 3 ]]; then echo "⚠️"; else echo "✅"; fi) |"
                    echo "| Privileged | ${priv_containers:-0} | $(if [[ ${priv_containers:-0} -gt 0 ]]; then echo "🔴"; else echo "✅"; fi) |"
                    echo ""
                    if [[ ${priv_containers:-0} -gt 0 ]]; then
                        actions_needed+=("[DOCKER] ${server}: ${priv_containers} privileged container(s) detected")
                    fi
                fi
            fi

            # Zombies
            if grep -q "^zombie_processes:" "$result_file"; then
                local zombies=$(sed -n '/^zombie_processes:/,/^[a-z]/p' "$result_file" | grep "count:" | cut -d: -f2 | tr -d ' ')
                if [[ ${zombies:-0} -gt 0 ]]; then
                    echo "**Zombie processes:** ${zombies} ⚠️"
                    echo ""
                    actions_needed+=("[ZOMBIE] ${server}: ${zombies} zombie processes detected")
                fi
            fi

            # File Descriptors
            if grep -q "^file_descriptors:" "$result_file"; then
                local fd_used=$(sed -n '/^file_descriptors:/,/^[a-z]/p' "$result_file" | grep "used:" | cut -d: -f2 | tr -d ' ')
                local fd_max=$(sed -n '/^file_descriptors:/,/^[a-z]/p' "$result_file" | grep "max:" | cut -d: -f2 | tr -d ' ')
                if [[ -n "$fd_used" && -n "$fd_max" && "$fd_used" != "unknown" && "$fd_max" != "unknown" ]]; then
                    local fd_pct=$((fd_used * 100 / fd_max))
                    if [[ $fd_pct -gt 80 ]]; then
                        echo "**File descriptors:** ${fd_used}/${fd_max} (${fd_pct}%) ⚠️"
                        echo ""
                        actions_needed+=("[FD] ${server}: File descriptors at ${fd_pct}%")
                    fi
                fi
            fi

            # DNS
            if grep -q "^dns_resolution:" "$result_file"; then
                local dns_fail=$(sed -n '/^dns_resolution:/,/^[a-z_]*[^:]*:/p' "$result_file" | grep "status: FAILED" | wc -l)
                if [[ ${dns_fail:-0} -gt 0 ]]; then
                    echo "**DNS:** ${dns_fail} resolution failure(s) ⚠️"
                    sed -n '/^dns_resolution:/,/^[a-z_]*[^:]*:/p' "$result_file" | grep -B1 "FAILED" | grep "domain:" | while read line; do
                        echo "  - $line"
                    done
                    echo ""
                    actions_needed+=("[DNS] ${server}: DNS resolution failures detected")
                fi
            fi

            # I/O Wait
            if grep -q "^io_wait:" "$result_file"; then
                local iowait=$(sed -n '/^io_wait:/,/^[a-z]/p' "$result_file" | grep "cpu_iowait_pct:" | cut -d: -f2 | tr -d ' ')
                if [[ -n "$iowait" && "$iowait" != "unknown" ]]; then
                    local iowait_int=${iowait%.*}
                    if [[ ${iowait_int:-0} -gt 20 ]]; then
                        echo "**I/O Wait:** ${iowait}% ⚠️ (high disk latency)"
                        echo ""
                        actions_needed+=("[IO] ${server}: High I/O wait at ${iowait}%")
                    fi
                fi
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
        log_info "Parallel mode — checking all servers simultaneously..."
        
        # Each background job writes its result file path to a collector file
        declare -A pids
        declare -A result_collectors
        for server in "${SERVERS[@]}"; do
            local collector=$(mktemp)
            result_collectors[$server]="$collector"
            ( check_server "$server" > "$collector" ) &
            pids[$server]=$!
        done
        
        # Wait for all and collect results
        for server in "${SERVERS[@]}"; do
            wait "${pids[$server]}" 2>/dev/null || true
            local result_path
            result_path=$(cat "${result_collectors[$server]}" 2>/dev/null | tail -1)
            if [[ -n "$result_path" && -f "$result_path" ]]; then
                results+=("$result_path")
            fi
            rm -f "${result_collectors[$server]}"
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
    
    # Send notifications if enabled
    if [[ "$NOTIFY" == "true" ]]; then
        local script_dir
        script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
        if [[ -x "${script_dir}/notify.sh" ]]; then
            log_info "Checking for critical issues to notify..."
            "${script_dir}/notify.sh" --report "$REPORT_FILE" || true
        else
            log_warning "notify.sh not found - skipping notifications"
        fi
    fi
    
    # Cleanup
    for result in "${results[@]}"; do
        if [[ -f "$result" ]]; then
            rm -f "$result"
        fi
    done
}

# Run main function
main
