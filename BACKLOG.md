# QJ Security Check — Backlog

Proposals to evolve the tool into a world-class security auditing platform.

---

## 📋 Priority Legend

| Tag | Description | Timeline |
|-----|-------------|----------|
| 🔴 P0 | Critical - do ASAP | This week |
| 🟠 P1 | High - significantly increases value | This month |
| 🟡 P2 | Medium - nice to have | This quarter |
| 🟢 P3 | Low - future considerations | Someday |

---

## 🔴 P0 — Critical / Quick Wins

### 1. ✅ Notifications & Alerting (IMPLEMENTED)
**Problem**: You have to manually run the check and look at results.

**Solution**:
- [x] Telegram bot integration (instant alerts)
- [x] Email alerts for CRITICAL issues
- [ ] Slack webhook integration
- [ ] Discord webhook (alternative)
- [ ] PagerDuty/OpsGenie integration for on-call

**Effort**: 2-4h | **Impact**: High

---

### 2. ✅ Scheduled Execution (IMPLEMENTED)
**Problem**: You don't see what changed since last run.

**Solution**:
- [x] Cron setup script with auto-installation
- [ ] Diff mode: `--diff` shows only changes vs previous report
- [ ] Alert only on NEW issues (don't repeat old ones)

**Effort**: 4-8h | **Impact**: High

---

### 3. Configuration File
**Problem**: Hardcoded server list, ports, thresholds.

**Solution**:
```yaml
# config.yaml
servers:
  - name: sce
    host: qj-sce
    critical: true  # 24/7 monitoring
  - name: dev
    host: qj-dev
    critical: false

thresholds:
  updates_warn: 10
  updates_crit: 20
  security_updates_crit: 1
  ssh_failed_warn: 50
  ssh_failed_crit: 200
  disk_warn: 80
  disk_crit: 90

notifications:
  telegram_token: ${TELEGRAM_BOT_TOKEN}
  telegram_chat_id: ${TELEGRAM_CHAT_ID}
  email: security@company.com
```

**Effort**: 4-6h | **Impact**: Medium

---

## 🟠 P1 — High Priority

### 4. CVE/Vulnerability Scanning
**Problem**: We know there are updates, but don't know which are critical CVEs.

**Solution**:
- [ ] Integration with `apt-cache policy` + Ubuntu Security Notices
- [ ] Parse CVE IDs from package changelogs
- [ ] CVSS score display in report
- [ ] Trivy scan for Docker images (CVEs in containers)

```bash
# Trivy scan example
trivy image --severity HIGH,CRITICAL myapp:latest
```

**Effort**: 1-2 days | **Impact**: Very High

---

### 5. Compliance Frameworks
**Problem**: We don't know if we meet industry standards.

**Solution**:
- [ ] CIS Benchmark checks (Linux hardening)
- [ ] PCI-DSS relevant controls (for payment processing)
- [ ] SOC 2 controls mapping
- [ ] Compliance score per framework

**Example output**:
```
## CIS Benchmark (Ubuntu 22.04)
| Control | Description | Status |
|---------|-------------|--------|
| 1.1.1 | Ensure /tmp is separate partition | ❌ FAIL |
| 5.2.1 | Ensure SSH PermitRootLogin disabled | ✅ PASS |
| 5.2.2 | Ensure SSH PasswordAuth disabled | ✅ PASS |
```

**Effort**: 2-3 days | **Impact**: Very High (enterprise customers)

---

### 6. Trend Analysis & History Dashboard
**Problem**: You see current state, but not the trend.

**Solution**:
- [ ] SQLite database instead of just markdown
- [ ] Charts in dashboard: score over time
- [ ] "Security posture improved by 15% this month"
- [ ] Per-server trend lines

**Effort**: 2-3 days | **Impact**: High

---

### 7. Secret/Credential Scanning
**Problem**: We might have credential leaks in files.

**Solution**:
- [ ] Scan `.env`, config files for AWS keys, passwords
- [ ] Trufflehog/gitleaks integration
- [ ] Check for hardcoded credentials in Docker env vars

```bash
# Check example
docker inspect --format '{{json .Config.Env}}' container_name | \
  grep -iE 'password|secret|key|token'
```

**Effort**: 1 day | **Impact**: High

---

### 8. Network Segmentation Audit
**Problem**: We don't know if servers can communicate with each other (lateral movement risk).

**Solution**:
- [ ] Matrix test: which server can connect to which
- [ ] Detect unexpected connectivity (db server → internet?)
- [ ] WireGuard topology visualization

**Output**:
```
## Network Matrix
        | sce | dat | api | edge | db |
--------|-----|-----|-----|------|-----|
sce     |  -  | ✅  | ✅  |  ❌  | ❌  |
edge    | ❌  | ❌  | ❌  |  -   | ❌  |
db      | ✅  | ❌  | ❌  |  ❌  |  -  |
```

**Effort**: 1-2 days | **Impact**: High

---

## 🟡 P2 — Medium Priority

### 9. Kubernetes Support
**Problem**: Some workloads will move to K8s.

**Solution**:
- [ ] kubectl integration (pod security policies)
- [ ] RBAC audit (who has access to what)
- [ ] Network policies review
- [ ] Secrets encryption status
- [ ] Pod Security Standards checks

**Effort**: 3-5 days | **Impact**: High (future-proofing)

---

### 10. Cloud Provider Integration
**Problem**: We have resources in AWS/GCP/Azure.

**Solution**:
- [ ] AWS: IAM audit, Security Groups, S3 bucket policies
- [ ] GCP: IAM, Firewall rules, Storage permissions
- [ ] Azure: NSG, RBAC, Storage
- [ ] Prowler/ScoutSuite integration

**Effort**: 3-5 days per cloud | **Impact**: Medium-High

---

### 11. API Security Testing
**Problem**: We don't test security of our API endpoints.

**Solution**:
- [ ] OWASP ZAP passive scan integration
- [ ] Rate limiting tests
- [ ] Authentication bypass attempts
- [ ] SQL injection detection (safe payloads)
- [ ] CORS misconfiguration check

**Effort**: 2-3 days | **Impact**: Medium

---

### 12. Log Analysis & Anomaly Detection
**Problem**: We have logs, but don't analyze them systematically.

**Solution**:
- [ ] Pattern matching on auth.log (unusual times, locations)
- [ ] ML-based anomaly detection (baseline → alert on deviation)
- [ ] Correlation: failed SSH + successful login = compromised?
- [ ] Loki/Grafana integration

**Effort**: 3-5 days | **Impact**: High

---

### 13. Backup Verification
**Problem**: Backups exist, but do they work?

**Solution**:
- [ ] Check backup timestamps (last successful)
- [ ] Verify backup size (not empty/corrupted)
- [ ] Test restore capability (read sample file)
- [ ] Off-site backup verification

**Effort**: 1-2 days | **Impact**: Medium

---

### 14. Performance Baseline & Comparison
**Problem**: We don't know what's "normal" for our servers.

**Solution**:
- [ ] Auto-learn baseline (CPU, RAM, connections over 30 days)
- [ ] Alert when >2 standard deviations
- [ ] "This server normally has 50 connections, now has 500"

**Effort**: 2-3 days | **Impact**: Medium

---

### 15. Interactive Remediation
**Problem**: We found an issue, but fixing it requires manual SSH.

**Solution**:
- [ ] One-click "Fix" buttons in dashboard
- [ ] `./security_check.sh --fix updates` - auto-apply safe fixes
- [ ] Dry-run mode: show what would be fixed
- [ ] Audit log of fixes applied

**Effort**: 2-3 days | **Impact**: Very High (productivity)

---

## 🟢 P3 — Future / Wishlist

### 16. Agent Mode (Optional)
**Problem**: SSH polling doesn't give real-time visibility.

**Solution**:
- [ ] Lightweight agent (optional) on servers
- [ ] Push model instead of pull
- [ ] Real-time alerts (intrusion detected NOW)
- [ ] 100ms latency instead of minutes

**Effort**: 1-2 weeks | **Impact**: Medium (most cases don't need real-time)

---

### 17. SBOM (Software Bill of Materials)
**Problem**: We don't know exactly what's installed.

**Solution**:
- [ ] Generate SBOM per server
- [ ] Compare SBOM vs known vulnerabilities
- [ ] "You have log4j 2.14 installed" alerts

**Effort**: 2-3 days | **Impact**: Medium

---

### 18. Chaos Engineering Integration
**Problem**: We don't know how security tools will behave under stress.

**Solution**:
- [ ] Brute-force attack simulation (does fail2ban react?)
- [ ] Network disruption test (does VPN reconnect?)
- [ ] Resource exhaustion test

**Effort**: 1-2 weeks | **Impact**: Low (nice to have)

---

### 19. Multi-tenancy / White-label
**Problem**: We want to offer this as a service to other teams.

**Solution**:
- [ ] Auth system (login/roles)
- [ ] Per-customer dashboards
- [ ] Isolated reports
- [ ] Branding customization

**Effort**: 2-4 weeks | **Impact**: Low (business expansion)

---

### 20. AI-Powered Insights
**Problem**: Too much data, not enough conclusions.

**Solution**:
- [ ] LLM summary: "Your biggest risk this week is..."
- [ ] Auto-prioritization based on context
- [ ] Natural language queries: "Which servers have outdated SSL?"
- [ ] Predicted risk score (what happens if we don't patch?)

**Effort**: 1-2 weeks | **Impact**: Medium (cool factor)

---

## 📊 Roadmap Suggestion

### Phase 1: Foundation (Next 2 weeks)
1. ✅ Telegram/Email notifications
2. ✅ Cron scheduling
3. Config file (yaml)

### Phase 2: Enterprise-Ready (Next month)
4. CVE scanning
5. CIS Benchmark checks
6. Trend analysis dashboard

### Phase 3: Advanced (Next quarter)
7. Secret scanning
8. Network segmentation audit
9. Interactive remediation
10. Kubernetes support

### Phase 4: Platform (Future)
11. Cloud provider integration
12. API security testing
13. AI insights

---

## 🏁 Success Metrics

| Metric | Current | Target | How to Measure |
|--------|---------|--------|----------------|
| Check coverage | ~20 checks | 50+ checks | Count sections |
| Time to detect | 1h (cron) | <5min (agent) | Incident postmortem |
| False positive rate | Unknown | <5% | Track manual dismissals |
| Integration count | 2 (Telegram, Email) | 5+ | Count webhooks |
| Compliance frameworks | 0 | 3 (CIS, PCI, SOC2) | Count implemented |

---

## 💰 Effort vs Impact Matrix

```
                    HIGH IMPACT
                        │
     CVE Scanning  ◄────┼────► Notifications ✅
     Compliance         │        Config file
                        │
LOW EFFORT ─────────────┼─────────────── HIGH EFFORT
                        │
     Trend dashboard    │      Kubernetes
     Secret scanning    │      Cloud integration
                        │
                    LOW IMPACT
```

**Recommendation**: Start with upper-left quadrant (high impact, low effort).

---

## 🚧 Technical Debt

| Item | Severity | Fix |
|------|----------|-----|
| Hardcoded server list | Medium | Move to config.yaml |
| No tests | High | Add bats tests for bash |
| Dashboard inline CSS | Low | Extract to CSS file |
| No error handling in parser | Medium | Add try/except blocks |
| Mixed bash/zsh syntax | Low | Standardize on bash |

---

## 📝 Notes

- Each feature should have its own branch and PR
- Before merge: test on staging first
- Document breaking changes in CHANGELOG.md
- Feature flags for experimental stuff

---

*Last updated: February 2026*
*Maintained by: QJ Security Team*
