# QJ Security Check — Tool Description

## 🎯 Mission Statement

**QJ Security Check** is a comprehensive automated security auditing tool for server infrastructure. It combines deep system analysis with an elegant dashboard, providing real-time visibility into the security posture of your entire server fleet.

---

## 💡 Value Proposition

### For DevOps/SysAdmins
- **Time savings**: One script instead of manually logging into each server
- **Consistency**: Same checklist across all servers
- **History**: Markdown reports as audit trail
- **Parallel execution**: Check 7 servers in seconds instead of minutes

### For Security Teams
- **Visibility**: Dashboard shows entire infrastructure status on one page
- **Actionable insights**: "Actions Required" list prioritizes what to fix
- **Compliance-ready**: Reports document security state over time
- **Proactive monitoring**: Detects issues before they become incidents

### For Management
- **Security Score**: Single number (0-100) showing security health
- **Executive summary**: Quick overview without technical details
- **Trend tracking**: Report history shows whether we're improving

---

## 🔧 What We Check

### 1. System Updates
| Check | Purpose | Alert When |
|-------|---------|------------|
| Pending packages | Available updates | >10 packages |
| Security updates | Critical patches | >0 |
| Kernel restart | Requires reboot | Yes |
| needrestart services | Services needing restart | >0 |

### 2. Intrusion Detection
| Check | Purpose | Alert When |
|-------|---------|------------|
| Failed SSH logins (24h) | Brute-force attempts | >50 |
| Active SSH sessions | Who is logged in | Always show |
| New users (7d) | Unauthorized accounts | New users found |
| SUID files (7d) | Privilege escalation | Modified |
| Failed sudo attempts | Lateral movement | >10 |
| Zombie processes | System health | >0 |

### 3. Security Tools
| Tool | Purpose | Check |
|------|---------|-------|
| **Fail2ban** | Auto-ban attackers | Running, banned IPs count |
| **UFW Firewall** | Network filtering | Active, default deny |
| **WireGuard VPN** | Secure tunnels | Active, peers count |
| **Auditd** | System auditing | Running, rules loaded |
| **Rootkit scanner** | Malware detection | Installed, warnings |

### 4. SSH Hardening
| Setting | Recommended | Risk |
|---------|-------------|------|
| PermitRootLogin | no | Direct root access |
| PasswordAuthentication | no | Brute-force vector |
| MaxAuthTries | 3-5 | Slow down attacks |
| PermitEmptyPasswords | no | Zero-click access |
| X11Forwarding | no | Attack surface |

### 5. Docker Security
| Check | Risk | Alert |
|-------|------|-------|
| Containers as root | Privilege escalation | List them |
| Host network mode | Network exposure | Flag |
| Privileged containers | Full host access | Critical |
| Dangling images | Info leak, clutter | Count |
| Image age (>90d) | Unpatched vulns | List |

### 6. Network Exposure
| Check | Purpose |
|-------|---------|
| Public listeners (0.0.0.0) | What's open to the world |
| Docker published ports | What Docker exposes |
| UFW allow rules | What firewall allows |
| Risk ports (8080, 3100...) | Dashboard/admin exposure |

### 7. System Resources
| Metric | Critical When |
|--------|---------------|
| Disk usage | >90% |
| RAM usage | >90% |
| Load average | >CPU count |
| I/O wait | >30% |
| File descriptors | Near limit |

### 8. Certificates & DNS
| Check | Alert When |
|-------|------------|
| SSL cert expiry | <30 days |
| DNS resolution | Failed |
| Nameservers | Unreachable |

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        LOCAL MACHINE                            │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────────┐   │
│  │ security_    │    │ server.py    │    │ dashboard.html   │   │
│  │ check.sh     │───▶│ (Flask API)  │◀───│ (Web UI)         │   │
│  └──────────────┘    └──────────────┘    └──────────────────┘   │
│         │                   │                                    │
│         │                   ▼                                    │
│         │            ./reports/*.md                              │
│         ▼                                                       │
│  ┌──────────────┐                                               │
│  │  SSH + Key   │                                               │
│  │  Auth        │                                               │
│  └──────────────┘                                               │
└─────────┬───────────────────────────────────────────────────────┘
          │
          │  SSH (parallel or sequential)
          ▼
┌─────────────────────────────────────────────────────────────────┐
│                     REMOTE SERVERS                              │
│  ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌─────────┐            │
│  │ qj-sce  │  │ qj-dat  │  │ qj-api  │  │ qj-edge │  ...       │
│  │ (VM)    │  │ (VM)    │  │ (VM)    │  │ (VM)    │            │
│  └─────────┘  └─────────┘  └─────────┘  └─────────┘            │
│       │            │            │            │                  │
│       └────────────┴────────────┴────────────┘                  │
│                         │                                        │
│                   Embedded bash                                  │
│                   script execution                               │
│                   (no agent needed)                              │
└─────────────────────────────────────────────────────────────────┘
```

## 🛠️ Components

| File | Description |
|------|-------------|
| `security_check.sh` | Main audit script (~1500 LOC bash) |
| `check_remote.sh` | Service reachability test (TCP/HTTP) |
| `security_docker_check.sh` | Docker port exposure audit |
| `server.py` | Flask API + report parser |
| `web/dashboard.html` | Premium dark-mode dashboard |
| `reports/*.md` | Report history (Git tracked) |
| `notify.sh` | Bash notification script (Telegram/Email) |
| `notify_py.py` | Python notification script (uses qj_data creds) |
| `setup_telegram.py` | Interactive Telegram bot setup wizard |
| `install_cron.sh` | Automated cron job installer |
| `config.env` | Configuration (tokens, emails, thresholds) |

---

## 🚀 Usage

### CLI (Quick)
```bash
# All servers (parallel)
./security_check.sh -p -v

# Specific servers
./security_check.sh -s "sce edge db" -v

# With custom SSH user
./security_check.sh -u qj -s "sce"

# With notifications on critical issues
./security_check.sh -p --notify
```

### Web Dashboard
```bash
python server.py --port 5050
# Open http://localhost:5050
```

### Scheduled (cron) - Hourly with Alerts
```bash
# Install hourly cron job with notifications
./install_cron.sh

# Or manually add to crontab:
0 * * * * cd /path/to/repo && ./security_check.sh -p --notify >> ./logs/cron.log 2>&1
```

---

## 📊 Output

### 1. Terminal (real-time)
```
[INFO] Checking server: sce
[OK] Server sce - check completed
  [VERBOSE] Updates available: 3
  [VERBOSE] Security updates: 0
  [VERBOSE] Fail2ban: Running, 5 IPs banned
[WARN] REBOOT REQUIRED: Kernel mismatch
```

### 2. Markdown Report
- Persisted in `./reports/security_check_YYYYMMDD_HHMMSS.md`
- Per-server breakdown
- Summary table
- Actions Required checklist

### 3. JSON API (dashboard)
```json
{
  "score": 85,
  "servers": [...],
  "actions": [
    {"text": "[FIX] sce: Install 3 updates", "severity": "warning"}
  ]
}
```

### 4. Web Dashboard
- Security Score gauge
- Server cards with status
- Expand for details
- Live scan execution
- Report history browser

### 5. Notifications (Telegram/Email)
- Critical alerts sent immediately
- Summary of issues with severity
- Direct link to full report

---

## 🔐 Security of the Tool Itself

| Concern | Mitigation |
|---------|------------|
| SSH keys | Use dedicated readonly user where possible |
| Sudo | Minimal NOPASSWD for specific commands |
| Local dashboard | Bind to localhost only by default |
| Reports | No passwords/secrets in output |
| Git | Reports in `.gitignore` (optional) |
| Tokens | Keep in config.env (not in git) |

---

## 📈 Success Metrics

1. **Mean Time To Detection (MTTD)**: Time from issue occurrence to detection
   - Target: <1h for critical issues (hourly cron)
   
2. **Coverage**: % of servers in infrastructure being monitored
   - Target: 100%
   
3. **False Positive Rate**: How many alerts are false alarms
   - Target: <5%

4. **Action Completion Rate**: How many detected issues get fixed
   - Target: >90% within SLA

---

## 🏆 Why This Works

1. **Agentless**: No installation required on servers
2. **Bash**: Works everywhere, zero dependencies on remote
3. **Parallel**: 7 servers in seconds
4. **Single source of truth**: One script, one dashboard
5. **Markdown reports**: Human-readable + Git-friendly
6. **Extensible**: Easy to add new checks

---

## 🌟 Unique Selling Points

| Feature | Why It Matters |
|---------|----------------|
| **Zero agents** | No need to maintain agents on 7+ servers |
| **Embedded script** | Entire check in one SSH, zero temporary files |
| **Premium dashboard** | No terminal parsing, everything with a click |
| **Security score** | Single number for management reporting |
| **Historical reports** | Compliance and audit trail out of the box |
| **Instant alerts** | Telegram/Email notifications for critical issues |

---

*Built by QJ Team for QJ Infrastructure*
