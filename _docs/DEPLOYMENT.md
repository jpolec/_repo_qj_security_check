# Deployment Guide - _repo_qj_security_check

**Last Updated:** 2026-02-05  
**Target:** Production

---

## Quick Deploy

```bash
# Deploy to production
./deploy.sh vm4

# Deploy with rebuild and start
./deploy.sh --start --rebuild vm4
```

---

## Deployment Configuration



---

## Deployment Steps

### 1. Prerequisites
- [ ] SSH access configured to Hetzner VMs
- [ ] Docker and Docker Compose installed on target VM
- [ ] Environment variables configured (.env file)

### 2. First-time Setup
```bash
# SSH to server
ssh [hostname]

# Clone/setup project
# [Add your setup commands here]
```

### 3. Regular Deployment
```bash
# From local machine
./deploy.sh --start vm4
```

### 4. Verify Deployment
```bash
# Check service status
ssh [hostname] "docker ps"

# Check logs
ssh [hostname] "docker logs -f [container-name]"
```

---

## Rollback Procedure

[Document how to rollback failed deployment]

---

## Troubleshooting

### Issue: Deployment fails
**Solution:** [Add common solutions]

### Issue: Service won't start
**Solution:** [Add common solutions]

---

## Related Documentation
- [Architecture Overview](_docs/ARCHITECTURE.md)
- [Onboarding Guide](_docs/ONBOARDING.md)
