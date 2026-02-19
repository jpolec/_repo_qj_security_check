#!/bin/bash
#
# QJ Security Check - Cron Installer
# ===================================
# Sets up automated hourly security checks with notifications.
#
# Usage:
#   ./install_cron.sh          # Install hourly cron
#   ./install_cron.sh --remove # Remove cron job
#   ./install_cron.sh --status # Check current status
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_FILE="${SCRIPT_DIR}/config.env"
CRON_MARKER="# QJ-SECURITY-CHECK"

# Load config if exists
if [[ -f "$CONFIG_FILE" ]]; then
    source "$CONFIG_FILE"
fi

# Defaults
CRON_SCHEDULE="${CRON_SCHEDULE:-0 * * * *}"
LOG_DIR="${LOG_DIR:-${SCRIPT_DIR}/logs}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[OK]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

usage() {
    cat << EOF
QJ Security Check - Cron Installer
===================================

Usage: $0 [options]

Options:
  --install         Install hourly cron job (default)
  --remove          Remove cron job
  --status          Show current cron status
  --schedule EXPR   Custom cron schedule (default: "0 * * * *")
  -h, --help        Show this help

Examples:
  $0                          # Install with default (hourly)
  $0 --schedule "*/30 * * * *"  # Every 30 minutes
  $0 --schedule "0 */4 * * *"   # Every 4 hours
  $0 --remove                 # Remove cron job

EOF
    exit 0
}

check_prerequisites() {
    log_info "Checking prerequisites..."
    
    local errors=0
    
    # Check if security_check.sh exists and is executable
    if [[ ! -x "${SCRIPT_DIR}/security_check.sh" ]]; then
        log_error "security_check.sh not found or not executable"
        ((errors++))
    fi
    
    # Check if notify.sh exists
    if [[ ! -x "${SCRIPT_DIR}/notify.sh" ]]; then
        log_warn "notify.sh not found - installing without notifications"
    fi
    
    # Check if config exists
    if [[ ! -f "$CONFIG_FILE" ]]; then
        log_warn "config.env not found - using defaults"
        log_info "Copy config.env.example to config.env to customize settings"
    fi
    
    # Check crontab access
    if ! crontab -l &>/dev/null; then
        log_warn "No existing crontab - will create new one"
    fi
    
    return $errors
}

get_cron_line() {
    local notify_flag=""
    if [[ -x "${SCRIPT_DIR}/notify.sh" && -f "$CONFIG_FILE" ]]; then
        notify_flag="--notify"
    fi
    
    echo "${CRON_SCHEDULE} cd ${SCRIPT_DIR} && ./security_check.sh -p ${notify_flag} >> ${LOG_DIR}/cron.log 2>&1 ${CRON_MARKER}"
}

install_cron() {
    log_info "Installing cron job..."
    
    # Create log directory
    mkdir -p "$LOG_DIR"
    
    # Get current crontab (or empty if none)
    local current_cron
    current_cron=$(crontab -l 2>/dev/null || echo "")
    
    # Check if already installed
    if echo "$current_cron" | grep -q "$CRON_MARKER"; then
        log_warn "Cron job already exists - updating..."
        # Remove old entry
        current_cron=$(echo "$current_cron" | grep -v "$CRON_MARKER")
    fi
    
    # Add new cron line
    local new_cron_line
    new_cron_line=$(get_cron_line)
    
    # Install new crontab
    {
        echo "$current_cron"
        echo ""
        echo "$new_cron_line"
    } | grep -v "^$" | crontab -
    
    log_success "Cron job installed!"
    echo ""
    echo "Schedule: ${CRON_SCHEDULE}"
    echo "Command:  ${new_cron_line}"
    echo "Log file: ${LOG_DIR}/cron.log"
    echo ""
    
    # Show next run time
    if command -v cronexpr &>/dev/null; then
        log_info "Next run: $(cronexpr "${CRON_SCHEDULE}")"
    fi
    
    log_info "To test immediately: ./security_check.sh -p --notify"
    log_info "To check logs: tail -f ${LOG_DIR}/cron.log"
}

remove_cron() {
    log_info "Removing cron job..."
    
    local current_cron
    current_cron=$(crontab -l 2>/dev/null || echo "")
    
    if ! echo "$current_cron" | grep -q "$CRON_MARKER"; then
        log_warn "No QJ Security Check cron job found"
        return 0
    fi
    
    # Remove our line
    echo "$current_cron" | grep -v "$CRON_MARKER" | crontab -
    
    log_success "Cron job removed"
}

show_status() {
    echo "QJ Security Check - Cron Status"
    echo "================================"
    echo ""
    
    local current_cron
    current_cron=$(crontab -l 2>/dev/null || echo "")
    
    if echo "$current_cron" | grep -q "$CRON_MARKER"; then
        echo -e "Status: ${GREEN}INSTALLED${NC}"
        echo ""
        echo "Current cron entry:"
        echo "$current_cron" | grep "$CRON_MARKER"
        echo ""
        
        # Show recent logs
        if [[ -f "${LOG_DIR}/cron.log" ]]; then
            echo "Recent log entries:"
            tail -5 "${LOG_DIR}/cron.log" 2>/dev/null || echo "  (no logs yet)"
            echo ""
            echo "Log file: ${LOG_DIR}/cron.log"
        fi
    else
        echo -e "Status: ${YELLOW}NOT INSTALLED${NC}"
        echo ""
        echo "Run '$0 --install' to set up scheduled checks"
    fi
    
    echo ""
    
    # Show config status
    echo "Configuration:"
    if [[ -f "$CONFIG_FILE" ]]; then
        echo -e "  config.env: ${GREEN}Found${NC}"
        source "$CONFIG_FILE"
        echo "  TELEGRAM: ${TELEGRAM_BOT_TOKEN:+Configured}${TELEGRAM_BOT_TOKEN:-Not set}"
        echo "  EMAIL: ${EMAIL_TO:-Not set}"
    else
        echo -e "  config.env: ${YELLOW}Not found${NC}"
        echo "  Run: cp config.env.example config.env"
    fi
}

# ============================================================================
# Main
# ============================================================================

main() {
    local action="install"
    
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --install)
                action="install"
                shift
                ;;
            --remove)
                action="remove"
                shift
                ;;
            --status)
                action="status"
                shift
                ;;
            --schedule)
                CRON_SCHEDULE="$2"
                shift 2
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
    
    case "$action" in
        install)
            check_prerequisites
            install_cron
            ;;
        remove)
            remove_cron
            ;;
        status)
            show_status
            ;;
    esac
}

main "$@"
