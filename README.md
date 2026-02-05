# QJ Server Security Check

Automated security auditing tool for QJ infrastructure. Checks multiple servers for updates, intrusion signs, and security configuration.

## Quick Start

```bash
# Check all servers
./security_check.sh

# Check specific server with verbose output
./security_check.sh -s sce -v

# Check multiple servers
./security_check.sh -s "sce edge db" -v

# Parallel mode (faster for many servers)
./security_check.sh -p -v
```

## What It Checks

| Category | Checks |
|----------|--------|
| **Updates** | Pending packages, security updates |
| **Kernel** | Reboot required, version mismatch |
| **Intrusion** | Failed SSH logins, active sessions, new users, SUID files |
| **Protection** | Fail2ban status, banned IPs, UFW rules |
| **Network** | WireGuard VPN, listening ports |
| **System** | Disk, RAM, load, Docker status |
| **Auditing** | Auditd status, rkhunter |

## Options

```
-s, --servers "srv1 srv2"  Servers to check (default: all)
-u, --user qj              Use qj user instead of default
-r, --report PATH          Custom report path
-v, --verbose              Show detailed output + immediate warnings
-p, --parallel             Check servers simultaneously
-h, --help                 Show help
```

## Available Servers

| Alias | Description |
|-------|-------------|
| sce | Scenario Server |
| dat | Data Server |
| api | API Server |
| edge | Edge/Proxy Server |
| db | Database Server |
| res | Research Server |
| ai | AI Server |

## Output

- **Terminal**: Summary table + Actions Required
- **Report**: Markdown file in `./reports/security_check_YYYYMMDD_HHMMSS.md`

### Example Output

```
[OK] Server sce - check completed
  [VERBOSE]   Updates available: 0
  [VERBOSE]   Security updates: 0
  [VERBOSE]   Fail2ban: Status Running
  [VERBOSE]   Currently banned IPs: 3
[WARN] REBOOT REQUIRED: Kernel or services need restart!

## Summary
| Metric | Value | Status |
|--------|-------|--------|
| Servers checked | 3 | OK |
| Pending updates | 15 | WARN |
| Security updates | 5 | CRIT |

## Actions Required
- [ ] [FIX] dat: Install 15 updates (5 security)
- [ ] [REBOOT] edge: System restart required
```

## Prerequisites

### Local Machine
- SSH access to all servers via `~/.ssh/config`
- SSH keys configured (no password prompts)

### Remote Servers
- User with sudo NOPASSWD for required commands:
```bash
# /etc/sudoers.d/security-check
jp ALL=(ALL) NOPASSWD: /usr/bin/apt-get, /usr/sbin/ufw, /usr/bin/fail2ban-client, /usr/sbin/iptables, /usr/sbin/needrestart, /usr/bin/wg, /usr/sbin/auditctl, /usr/sbin/ausearch
```

Or full NOPASSWD:
```bash
jp ALL=(ALL) NOPASSWD: ALL
```

## Cron Setup (Automated)

```bash
# Run twice daily at 8:00 and 20:00
0 8,20 * * * /path/to/security_check.sh -p > /dev/null 2>&1
```

## Files

```
├── security_check.sh    # Main script
├── SECURITY.md          # Security documentation & recommendations
├── README.md            # This file
└── reports/             # Generated reports
    └── security_check_*.md
```

## See Also

- [SECURITY.md](SECURITY.md) - Full security guide, hardening recommendations, Wazuh setup

---

*QJ Infrastructure Security Tools*
