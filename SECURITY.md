# QJ Infrastructure Security Guide

## Current Security Stack

### ✅ Implemented

| Component | Status | Servers | Description |
|-----------|--------|---------|-------------|
| **Fail2ban** | Active | sce, edge, db | Automatic IP banning after failed login attempts |
| **UFW Firewall** | Active | sce, edge, db | Default deny incoming, allow outgoing |
| **WireGuard VPN** | Active | sce | Secure inter-server communication |
| **SSH Key Auth** | Active | All | Password authentication disabled |
| **Auditd** | Pending | None | System call auditing for forensics |

### Firewall Rules (Standard)

```bash
# Default policies
sudo ufw default deny incoming
sudo ufw default allow outgoing

# SSH access
sudo ufw allow 22/tcp comment "SSH"

# Web traffic (edge servers only)
sudo ufw allow 80/tcp comment "HTTP"
sudo ufw allow 443/tcp comment "HTTPS"

# Enable firewall
sudo ufw enable
```

---

## Security Monitoring

### Automated Checks (security_check.sh)

The script performs the following checks on each server:

| Check | Description | Alert Threshold |
|-------|-------------|-----------------|
| Package Updates | Pending apt updates | >10 updates |
| Security Updates | Critical security patches | >0 |
| Kernel Restart | Kernel version mismatch | true |
| Failed SSH Logins | Brute force attempts (24h) | >50 attempts |
| Active SSH Sessions | Currently logged in users | Informational |
| Fail2ban Status | Service running, banned IPs | Not running |
| UFW Firewall | Active with deny incoming | Inactive |
| WireGuard VPN | Tunnel status and peers | Not active |
| Auditd | System auditing daemon | Not installed |
| SUID Files | Recently modified setuid binaries | Modified in 7 days |
| Crontab Entries | Scheduled tasks review | Informational |
| SSH Authorized Keys | Key management review | Informational |
| Listening Ports | Open network services | Informational |
| System Resources | Disk, RAM, CPU load | >90% disk |
| Docker Status | Running containers | Informational |

### Recommended Schedule

| Frequency | Action | Tool |
|-----------|--------|------|
| Real-time | Intrusion blocking | Fail2ban |
| Every 4 hours | Security audit | security_check.sh (cron) |
| Daily | Log review | Manual / automated |
| Weekly | Full update cycle | apt upgrade |
| Monthly | Access review | SSH keys, users |

---

## Server-Specific Configuration

### Edge Server (qj-edge)
- **Role**: Public-facing reverse proxy (Traefik)
- **Ports**: 22, 80, 443
- **Extra security**: Rate limiting, Cloudflare proxy

### Database Server (qj-db)
- **Role**: PostgreSQL database
- **Ports**: 22 only (DB via internal network)
- **Extra security**: No public DB port, WireGuard only

### Application Servers (qj-sce, qj-dat, qj-res, qj-api)
- **Role**: Docker application hosts
- **Ports**: 22 only
- **Extra security**: Internal access via WireGuard

---

## Recommended Enhancements

### Priority 1: Quick Wins

#### 1.1 Install Auditd (System Auditing)
```bash
# On each server
sudo apt install -y auditd audispd-plugins
sudo systemctl enable --now auditd

# Verify
sudo auditctl -s
```

**Benefits**: Forensics capability, compliance logging, file integrity monitoring.

#### 1.2 Enable UFW on All Servers
```bash
# Check status
sudo ufw status

# If inactive, enable with proper rules first
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow 22/tcp
sudo ufw enable
```

#### 1.3 Automatic Security Updates
```bash
# Install unattended-upgrades
sudo apt install -y unattended-upgrades apt-listchanges

# Enable automatic security updates
sudo dpkg-reconfigure -plow unattended-upgrades
```

### Priority 2: Enhanced Monitoring

#### 2.1 Centralized Logging (Recommended: Loki + Grafana)

For 7 servers, a lightweight stack:

```yaml
# docker-compose.yml on monitoring server
services:
  loki:
    image: grafana/loki:latest
    ports:
      - "3100:3100"
    
  grafana:
    image: grafana/grafana:latest
    ports:
      - "3000:3000"
```

Install Promtail agent on each server to ship logs.

#### 2.2 Wazuh (Full SIEM Solution)

**What it provides:**
- Real-time log analysis
- Intrusion detection (HIDS)
- File integrity monitoring
- Vulnerability detection
- Compliance dashboards (PCI-DSS, GDPR)
- Centralized management

**When to consider:**
- 20+ servers
- Compliance requirements
- Dedicated security team
- Need for real-time alerting

**Installation:**
```bash
# Manager (central server)
curl -sO https://packages.wazuh.com/4.7/wazuh-install.sh
sudo bash wazuh-install.sh -a

# Agents (each server)
curl -sO https://packages.wazuh.com/4.7/wazuh-agent-4.7.0-1.x86_64.deb
sudo dpkg -i wazuh-agent-4.7.0-1.x86_64.deb
```

**Resource requirements:**
- Manager: 4GB RAM, 50GB disk minimum
- Dashboard: 4GB RAM additional
- Agents: ~100MB RAM each

### Priority 3: Advanced Hardening

#### 3.1 SSH Hardening
```bash
# /etc/ssh/sshd_config additions
PermitRootLogin no
PasswordAuthentication no
MaxAuthTries 3
ClientAliveInterval 300
ClientAliveCountMax 2
AllowUsers jp qj
```

#### 3.2 Kernel Hardening (sysctl)
```bash
# /etc/sysctl.d/99-security.conf
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
kernel.randomize_va_space = 2
```

#### 3.3 Rootkit Detection
```bash
# Install rkhunter
sudo apt install -y rkhunter

# Initial scan
sudo rkhunter --update
sudo rkhunter --propupd
sudo rkhunter --check --sk

# Add to cron (weekly)
echo "0 3 * * 0 root /usr/bin/rkhunter --check --sk" | sudo tee /etc/cron.d/rkhunter
```

---

## Incident Response Checklist

### If Intrusion Suspected

1. **Don't panic** - Document everything
2. **Isolate** - Disconnect server from network if active attack
3. **Preserve** - Take disk snapshot before any changes
4. **Investigate**:
   ```bash
   # Check recent logins
   last -20
   lastb -20
   
   # Check running processes
   ps auxf
   
   # Check network connections
   ss -tulpn
   netstat -anlp
   
   # Check recent file changes
   find /etc -mtime -1 -type f
   find /var/www -mtime -1 -type f
   
   # Check crontabs
   for user in $(cut -f1 -d: /etc/passwd); do crontab -u $user -l 2>/dev/null; done
   
   # Check auth logs
   grep "Accepted\|Failed" /var/log/auth.log | tail -50
   ```
5. **Remediate** - Remove access, patch vulnerabilities
6. **Report** - Document timeline and actions taken
7. **Harden** - Implement additional controls

---

## Security Contacts

| Role | Contact |
|------|---------|
| Infrastructure Lead | [Your email] |
| Security Alerts | [Slack channel / email] |

---

## Changelog

| Date | Change |
|------|--------|
| 2026-02-05 | Initial security documentation |
| 2026-02-05 | Added security_check.sh automated monitoring |
| 2026-02-05 | Documented fail2ban, UFW, WireGuard status |

---

*Last updated: 2026-02-05*
