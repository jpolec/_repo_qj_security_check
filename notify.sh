#!/bin/bash
#
# QJ Security Check - Notification Script
# =======================================
# Sends alerts via Telegram and/or Email when critical issues are found.
#
# Usage:
#   ./notify.sh --report /path/to/report.md
#   ./notify.sh --message "Custom alert message"
#   ./notify.sh --test  # Test notifications
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_FILE="${SCRIPT_DIR}/config.env"
QJ_DATA_SECRETS="${SCRIPT_DIR}/../_repo_qj_data/telegram/secrets.yaml"

# Load configuration from local config.env
if [[ -f "$CONFIG_FILE" ]]; then
    source "$CONFIG_FILE"
fi

# Fallback: Try to load from _repo_qj_data/telegram/secrets.yaml
if [[ -z "${TELEGRAM_BOT_TOKEN:-}" && -f "$QJ_DATA_SECRETS" ]]; then
    # Parse YAML with python (more reliable)
    if command -v python3 &>/dev/null; then
        eval $(python3 -c "
import yaml
try:
    with open('$QJ_DATA_SECRETS') as f:
        d = yaml.safe_load(f)
    tg = d.get('alerts', {}).get('telegram', {})
    if tg.get('token'):
        print(f'TELEGRAM_BOT_TOKEN=\"{tg[\"token\"]}\"')
    if tg.get('chat_id'):
        print(f'TELEGRAM_CHAT_ID=\"{tg[\"chat_id\"]}\"')
except: pass
" 2>/dev/null || true)
        if [[ -n "$TELEGRAM_BOT_TOKEN" ]]; then
            echo "[INFO] Loaded Telegram credentials from _repo_qj_data" >&2
        fi
    fi
fi

# Defaults (can be overridden in config.env)
TELEGRAM_BOT_TOKEN="${TELEGRAM_BOT_TOKEN:-}"
TELEGRAM_CHAT_ID="${TELEGRAM_CHAT_ID:-}"
EMAIL_TO="${EMAIL_TO:-}"
EMAIL_FROM="${EMAIL_FROM:-jakub@quantjourney.cloud}"  # Must match verified Mailtrap sender
SMTP_SERVER="${SMTP_SERVER:-localhost}"
NOTIFY_ON_CRITICAL="${NOTIFY_ON_CRITICAL:-true}"
NOTIFY_ON_WARNING="${NOTIFY_ON_WARNING:-false}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# ============================================================================
# Helper Functions
# ============================================================================

log_info() { echo -e "${GREEN}[INFO]${NC} $1" >&2; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1" >&2; }
log_error() { echo -e "${RED}[ERROR]${NC} $1" >&2; }

usage() {
    cat << EOF
QJ Security Check - Notification Script
========================================

Usage: $0 [options]

Options:
  --report PATH      Parse report and send alerts for critical issues
  --message TEXT     Send custom message
  --test             Send test notification to verify setup
  --telegram-only    Only use Telegram
  --email-only       Only use Email
  -h, --help         Show this help

Configuration:
  Create config.env with:
    TELEGRAM_BOT_TOKEN=your_bot_token
    TELEGRAM_CHAT_ID=your_chat_id
    EMAIL_TO=your@email.com

Examples:
  $0 --test                              # Test notification
  $0 --report ./reports/latest.md        # Alert on report issues
  $0 --message "Server down!"            # Custom alert

EOF
    exit 0
}

# ============================================================================
# Telegram Functions
# ============================================================================

send_telegram() {
    local message="$1"
    local parse_mode="${2:-HTML}"
    
    if [[ -z "$TELEGRAM_BOT_TOKEN" || -z "$TELEGRAM_CHAT_ID" ]]; then
        log_warn "Telegram not configured (missing TELEGRAM_BOT_TOKEN or TELEGRAM_CHAT_ID)"
        return 1
    fi
    
    # For HTML mode, we need to escape &, <, > but preserve our formatting tags
    # Simpler approach: just send with proper encoding via JSON
    local response
    response=$(curl -s -X POST "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage" \
        -H "Content-Type: application/json" \
        -d "$(cat <<EOF
{
  "chat_id": "${TELEGRAM_CHAT_ID}",
  "text": $(echo "$message" | python3 -c 'import json,sys; print(json.dumps(sys.stdin.read()))'),
  "parse_mode": "${parse_mode}",
  "disable_web_page_preview": true
}
EOF
)" 2>&1)
    
    if echo "$response" | grep -q '"ok":true'; then
        log_info "Telegram message sent successfully"
        return 0
    else
        log_error "Telegram send failed: $response"
        return 1
    fi
}

# ============================================================================
# Email Functions
# ============================================================================

send_email() {
    local subject="$1"
    local body="$2"
    
    if [[ -z "$EMAIL_TO" ]]; then
        log_warn "Email not configured (missing EMAIL_TO)"
        return 1
    fi
    
    # Try Mailtrap API first (via Python) - this actually sends emails!
    local mailtrap_token="${MAILTRAP_API_TOKEN:-}"
    
    # Load from qj_data secrets if not set
    if [[ -z "$mailtrap_token" && -f "$QJ_DATA_SECRETS" ]]; then
        mailtrap_token=$(python3 -c "
import yaml
try:
    with open('$QJ_DATA_SECRETS') as f:
        d = yaml.safe_load(f)
    print(d.get('alerts', {}).get('email', {}).get('api_token', ''))
except: pass
" 2>/dev/null || true)
    fi
    
    if [[ -n "$mailtrap_token" ]] && command -v python3 &>/dev/null; then
        local result
        result=$(MAILTRAP_TOKEN="$mailtrap_token" EMAIL_TO_ADDR="$EMAIL_TO" EMAIL_FROM_ADDR="$EMAIL_FROM" EMAIL_SUBJECT="$subject" EMAIL_BODY="$body" python3 -c '
import os
import requests

token = os.environ["MAILTRAP_TOKEN"]
to_addr = os.environ["EMAIL_TO_ADDR"]
from_addr = os.environ["EMAIL_FROM_ADDR"]
subject = os.environ["EMAIL_SUBJECT"]
body = os.environ["EMAIL_BODY"]

resp = requests.post(
    "https://send.api.mailtrap.io/api/send",
    headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
    json={
        "from": {"email": from_addr, "name": "QJ Security"},
        "to": [{"email": to_addr}],
        "subject": subject,
        "text": body,
        "category": "QJ Security Alert"
    },
    timeout=10
)
print("OK" if resp.status_code < 300 else f"FAIL: {resp.text}")
' 2>&1)
        
        if [[ "$result" == "OK" ]]; then
            log_info "Email sent via Mailtrap API to $EMAIL_TO"
            return 0
        else
            log_warn "Mailtrap failed: $result"
        fi
    fi
    
    # Fallback to local mail (won't work on macOS without relay)
    if command -v mail &>/dev/null; then
        echo "$body" | mail -s "$subject" "$EMAIL_TO"
        log_info "Email queued via mail command (may not deliver on macOS)"
        return 0
    elif command -v sendmail &>/dev/null; then
        {
            echo "To: $EMAIL_TO"
            echo "From: $EMAIL_FROM"
            echo "Subject: $subject"
            echo "Content-Type: text/plain; charset=UTF-8"
            echo ""
            echo "$body"
        } | sendmail -t
        log_info "Email sent via sendmail"
        return 0
    elif command -v msmtp &>/dev/null; then
        {
            echo "To: $EMAIL_TO"
            echo "From: $EMAIL_FROM"
            echo "Subject: $subject"
            echo ""
            echo "$body"
        } | msmtp "$EMAIL_TO"
        log_info "Email sent via msmtp"
        return 0
    elif command -v curl &>/dev/null && [[ -n "${SMTP_SERVER:-}" ]]; then
        # Use curl with SMTP (requires proper SMTP server)
        log_warn "Email via curl/SMTP not yet implemented"
        return 1
    else
        log_error "No email sending method available (install mailutils, sendmail, or msmtp)"
        return 1
    fi
}

# ============================================================================
# Report Parser
# ============================================================================

parse_report() {
    local report_file="$1"
    
    if [[ ! -f "$report_file" ]]; then
        log_error "Report file not found: $report_file"
        return 1
    fi
    
    local critical_count=0
    local warning_count=0
    local connection_failed=0
    local issues=()
    
    # Parse "Actions Required" section
    local in_actions=false
    while IFS= read -r line; do
        if [[ "$line" =~ ^##.*Actions\ Required ]]; then
            in_actions=true
            continue
        fi
        if [[ "$in_actions" == true ]]; then
            if [[ "$line" =~ ^## ]]; then
                break
            fi
            if [[ "$line" =~ ^\-\ \[.\].*\[CRIT\] || "$line" =~ ^\-\ \[.\].*\[ALERT\] ]]; then
                ((critical_count++))
                issues+=("🔴 ${line#*] }")
            elif [[ "$line" =~ ^\-\ \[.\].*\[REBOOT\] ]]; then
                ((warning_count++))
                issues+=("🟠 ${line#*] }")
            elif [[ "$line" =~ ^\-\ \[.\].*\[FIX\] ]]; then
                ((warning_count++))
                issues+=("🟡 ${line#*] }")
            elif [[ "$line" =~ ^\-\ \[.\].*\[CONN\] ]]; then
                ((critical_count++))
                ((connection_failed++))
                issues+=("🔴 ${line#*] }")
            fi
        fi
    done < "$report_file"
    
    # Extract summary info
    local servers_checked
    servers_checked=$(grep -oP "Servers checked:\*\*\s*\K.*" "$report_file" 2>/dev/null || echo "unknown")
    
    local security_updates
    security_updates=$(grep -oP "Security updates\s*\|\s*\K\d+" "$report_file" 2>/dev/null | head -1 || echo "0")
    
    local score
    score=$(grep -oP "Score.*?\|\s*\K\d+" "$report_file" 2>/dev/null | head -1 || echo "?")
    
    # Determine if we should alert
    local should_alert=false
    if [[ "$NOTIFY_ON_CRITICAL" == "true" && $critical_count -gt 0 ]]; then
        should_alert=true
    fi
    if [[ "$NOTIFY_ON_WARNING" == "true" && $warning_count -gt 0 ]]; then
        should_alert=true
    fi
    
    if [[ "$should_alert" == "false" ]]; then
        log_info "No critical issues found, no alert sent"
        echo "OK"
        return 0
    fi
    
    # Build message
    local timestamp
    timestamp=$(date "+%Y-%m-%d %H:%M")
    
    local severity_emoji="🟡"
    local severity_text="WARNING"
    if [[ $critical_count -gt 0 ]]; then
        severity_emoji="🚨"
        severity_text="CRITICAL"
    fi
    
    local message="${severity_emoji} <b>QJ Security Alert</b> ${severity_emoji}
    
<b>Time:</b> ${timestamp}
<b>Servers:</b> ${servers_checked}
<b>Score:</b> ${score}/100

<b>Issues Found:</b>
• Critical: ${critical_count}
• Warnings: ${warning_count}
"

    if [[ ${#issues[@]} -gt 0 ]]; then
        message+="
<b>Details:</b>"
        for issue in "${issues[@]:0:10}"; do  # Limit to 10 items
            message+="
${issue}"
        done
        if [[ ${#issues[@]} -gt 10 ]]; then
            message+="
... and $((${#issues[@]} - 10)) more"
        fi
    fi
    
    message+="

<i>Check full report for details.</i>"

    # Output for logging
    echo "ALERT: ${critical_count} critical, ${warning_count} warnings"
    echo "$message"
    
    # Return values for caller
    echo "CRITICAL_COUNT=$critical_count"
    echo "WARNING_COUNT=$warning_count"
}

# ============================================================================
# Main Alert Function
# ============================================================================

send_alert() {
    local message="$1"
    local subject="${2:-QJ Security Alert}"
    local use_telegram="${3:-true}"
    local use_email="${4:-true}"
    
    local success=false
    
    if [[ "$use_telegram" == "true" ]]; then
        if send_telegram "$message"; then
            success=true
        fi
    fi
    
    if [[ "$use_email" == "true" ]]; then
        # Strip HTML tags for email
        local email_body
        email_body=$(echo "$message" | sed 's/<[^>]*>//g')
        if send_email "$subject" "$email_body"; then
            success=true
        fi
    fi
    
    if [[ "$success" == "true" ]]; then
        return 0
    else
        return 1
    fi
}

# ============================================================================
# Test Function
# ============================================================================

test_notifications() {
    log_info "Testing notification delivery..."
    
    local test_message="🧪 <b>QJ Security Check - Test Alert</b>

This is a test message to verify notification delivery.

<b>Time:</b> $(date '+%Y-%m-%d %H:%M:%S')
<b>Host:</b> $(hostname)

If you received this, notifications are working! ✅"

    echo ""
    echo "Configuration:"
    echo "  TELEGRAM_BOT_TOKEN: ${TELEGRAM_BOT_TOKEN:+[SET]}${TELEGRAM_BOT_TOKEN:-[NOT SET]}"
    echo "  TELEGRAM_CHAT_ID: ${TELEGRAM_CHAT_ID:-[NOT SET]}"
    echo "  EMAIL_TO: ${EMAIL_TO:-[NOT SET]}"
    echo ""
    
    local telegram_ok=false
    local email_ok=false
    
    if [[ -n "$TELEGRAM_BOT_TOKEN" && -n "$TELEGRAM_CHAT_ID" ]]; then
        echo "Testing Telegram..."
        if send_telegram "$test_message"; then
            telegram_ok=true
            echo -e "${GREEN}✓ Telegram: OK${NC}"
        else
            echo -e "${RED}✗ Telegram: FAILED${NC}"
        fi
    else
        echo -e "${YELLOW}⊘ Telegram: Not configured${NC}"
    fi
    
    if [[ -n "$EMAIL_TO" ]]; then
        echo "Testing Email..."
        local email_body
        email_body=$(echo "$test_message" | sed 's/<[^>]*>//g')
        if send_email "QJ Security Check - Test" "$email_body"; then
            email_ok=true
            echo -e "${GREEN}✓ Email: OK${NC}"
        else
            echo -e "${RED}✗ Email: FAILED${NC}"
        fi
    else
        echo -e "${YELLOW}⊘ Email: Not configured${NC}"
    fi
    
    echo ""
    if [[ "$telegram_ok" == "true" || "$email_ok" == "true" ]]; then
        log_info "Test completed - at least one channel working"
        return 0
    else
        log_error "Test failed - no notification channels working"
        return 1
    fi
}

# ============================================================================
# Main
# ============================================================================

main() {
    local report_file=""
    local custom_message=""
    local do_test=false
    local telegram_only=false
    local email_only=false
    
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --report)
                report_file="$2"
                shift 2
                ;;
            --message)
                custom_message="$2"
                shift 2
                ;;
            --test)
                do_test=true
                shift
                ;;
            --telegram-only)
                telegram_only=true
                shift
                ;;
            --email-only)
                email_only=true
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
    
    # Determine which channels to use
    local use_telegram=true
    local use_email=true
    
    if [[ "$telegram_only" == "true" ]]; then
        use_email=false
    fi
    if [[ "$email_only" == "true" ]]; then
        use_telegram=false
    fi
    
    # Execute requested action
    if [[ "$do_test" == "true" ]]; then
        test_notifications
        exit $?
    fi
    
    if [[ -n "$report_file" ]]; then
        local parsed
        parsed=$(parse_report "$report_file")
        
        if [[ "$parsed" == "OK" ]]; then
            exit 0
        fi
        
        # Extract message (everything after first line)
        local alert_message
        alert_message=$(echo "$parsed" | tail -n +2 | head -n -2)
        
        if [[ -n "$alert_message" ]]; then
            send_alert "$alert_message" "QJ Security Alert" "$use_telegram" "$use_email"
        fi
        exit 0
    fi
    
    if [[ -n "$custom_message" ]]; then
        local formatted="🔔 <b>QJ Security Alert</b>

<b>Time:</b> $(date '+%Y-%m-%d %H:%M')

${custom_message}"
        send_alert "$formatted" "QJ Security Alert" "$use_telegram" "$use_email"
        exit 0
    fi
    
    # No action specified
    usage
}

main "$@"
