#!/usr/bin/env python3
"""
QJ Security Check - Notification Service
=========================================
Sends alerts via Telegram and Email.
Inherits credentials from _repo_qj_data/telegram/secrets.yaml or local config.

Usage:
    python notify_py.py --test
    python notify_py.py --report ./reports/latest.md
    python notify_py.py --message "Server down!"
"""

import os
import re
import sys
import argparse
import asyncio
from pathlib import Path
from datetime import datetime
from typing import Optional, Dict, Any

# Try to import httpx, fallback to requests
try:
    import httpx
    USE_HTTPX = True
except ImportError:
    import requests
    USE_HTTPX = False


class SecurityNotifier:
    """Notification service for security alerts."""
    
    def __init__(self):
        self.config = self._load_config()
        
        # Telegram
        tg = self.config.get("telegram", {})
        self.telegram_token = tg.get("token", "")
        self.telegram_chat_id = str(tg.get("chat_id", ""))
        
        # Email (Mailtrap)
        email = self.config.get("email", {})
        self.email_enabled = email.get("enabled", False)
        self.email_api_token = email.get("api_token", "")
        self.email_to = email.get("admin_email", "") or email.get("to", "")
        self.email_from = email.get("from_email", "security@quantjourney.io")
        self.email_from_name = email.get("from_name", "QJ Security")
    
    def _load_config(self) -> Dict[str, Any]:
        """Load config from multiple sources with priority."""
        config: Dict[str, Any] = {"telegram": {}, "email": {}}
        
        # Priority 1: Local config.env
        local_config = Path(__file__).parent / "config.env"
        if local_config.exists():
            self._parse_env_file(local_config, config)
        
        # Priority 2: _repo_qj_data/telegram/secrets.yaml
        qj_data_secrets = Path(__file__).parent.parent / "_repo_qj_data" / "telegram" / "secrets.yaml"
        if qj_data_secrets.exists():
            self._parse_yaml_secrets(qj_data_secrets, config)
        
        # Priority 3: Environment variables (highest priority)
        if os.getenv("TELEGRAM_BOT_TOKEN"):
            config["telegram"]["token"] = os.getenv("TELEGRAM_BOT_TOKEN")
        if os.getenv("TELEGRAM_CHAT_ID"):
            config["telegram"]["chat_id"] = os.getenv("TELEGRAM_CHAT_ID")
        if os.getenv("EMAIL_TO"):
            config["email"]["admin_email"] = os.getenv("EMAIL_TO")
        
        return config
    
    def _parse_env_file(self, path: Path, config: Dict):
        """Parse shell-style config.env file."""
        try:
            with open(path) as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#") and "=" in line:
                        key, _, value = line.partition("=")
                        key = key.strip()
                        value = value.strip().strip('"').strip("'")
                        
                        if key == "TELEGRAM_BOT_TOKEN" and value:
                            config["telegram"]["token"] = value
                        elif key == "TELEGRAM_CHAT_ID" and value:
                            config["telegram"]["chat_id"] = value
                        elif key == "EMAIL_TO" and value:
                            config["email"]["admin_email"] = value
                        elif key == "EMAIL_API_TOKEN" and value:
                            config["email"]["api_token"] = value
        except Exception as e:
            print(f"Warning: Could not parse {path}: {e}", file=sys.stderr)
    
    def _parse_yaml_secrets(self, path: Path, config: Dict):
        """Parse secrets.yaml from qj_data."""
        try:
            import yaml
            with open(path) as f:
                data = yaml.safe_load(f)
            
            alerts = data.get("alerts", {})
            
            # Don't override if already set from local config
            if not config["telegram"].get("token"):
                tg = alerts.get("telegram", {})
                if tg.get("token"):
                    config["telegram"]["token"] = tg["token"]
                if tg.get("chat_id"):
                    config["telegram"]["chat_id"] = str(tg["chat_id"])
            
            if not config["email"].get("api_token"):
                email = alerts.get("email", {})
                if email.get("api_token"):
                    config["email"]["api_token"] = str(email["api_token"])
                if email.get("admin_email"):
                    config["email"]["admin_email"] = email["admin_email"]
                if email.get("from_email"):
                    config["email"]["from_email"] = email["from_email"]
                config["email"]["enabled"] = email.get("enabled", False)
                
        except ImportError:
            print("Warning: PyYAML not installed, cannot read secrets.yaml", file=sys.stderr)
        except Exception as e:
            print(f"Warning: Could not parse {path}: {e}", file=sys.stderr)
    
    def is_telegram_configured(self) -> bool:
        return bool(self.telegram_token and self.telegram_chat_id)
    
    def is_email_configured(self) -> bool:
        return bool(self.email_api_token and self.email_to)
    
    async def send_telegram(self, message: str, parse_mode: str = "HTML") -> bool:
        """Send Telegram message."""
        if not self.is_telegram_configured():
            print("Telegram not configured", file=sys.stderr)
            return False
        
        url = f"https://api.telegram.org/bot{self.telegram_token}/sendMessage"
        payload = {
            "chat_id": self.telegram_chat_id,
            "text": message,
            "parse_mode": parse_mode,
            "disable_web_page_preview": True
        }
        
        try:
            if USE_HTTPX:
                async with httpx.AsyncClient(timeout=10.0) as client:
                    resp = await client.post(url, json=payload)
                    success = resp.status_code < 300
            else:
                resp = requests.post(url, json=payload, timeout=10)
                success = resp.status_code < 300
            
            if success:
                print("✓ Telegram message sent")
                return True
            else:
                print(f"✗ Telegram error: {resp.text}", file=sys.stderr)
                return False
                
        except Exception as e:
            print(f"✗ Telegram failed: {e}", file=sys.stderr)
            return False
    
    async def send_email(self, subject: str, body: str) -> bool:
        """Send email via Mailtrap API."""
        if not self.is_email_configured():
            print("Email not configured", file=sys.stderr)
            return False
        
        url = "https://send.api.mailtrap.io/api/send"
        headers = {
            "Authorization": f"Bearer {self.email_api_token}",
            "Content-Type": "application/json"
        }
        payload = {
            "from": {"email": self.email_from, "name": self.email_from_name},
            "to": [{"email": self.email_to}],
            "subject": subject,
            "html": body,
            "text": re.sub(r'<[^>]+>', '', body),
            "category": "QJ Security Alert"
        }
        
        try:
            if USE_HTTPX:
                async with httpx.AsyncClient(timeout=10.0) as client:
                    resp = await client.post(url, json=payload, headers=headers)
                    success = resp.status_code < 300
            else:
                resp = requests.post(url, json=payload, headers=headers, timeout=10)
                success = resp.status_code < 300
            
            if success:
                print(f"✓ Email sent to {self.email_to}")
                return True
            else:
                print(f"✗ Email error: {resp.text}", file=sys.stderr)
                return False
                
        except Exception as e:
            print(f"✗ Email failed: {e}", file=sys.stderr)
            return False
    
    async def alert(self, title: str, details: str = "", severity: str = "warning") -> bool:
        """Send alert via all configured channels."""
        import socket
        
        hostname = socket.gethostname()
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        emoji = {"critical": "🚨", "warning": "⚠️", "info": "ℹ️"}.get(severity, "🔔")
        
        # Telegram message (HTML)
        tg_msg = f"""{emoji} <b>QJ Security Alert</b>

<b>{title}</b>

{details}

<code>Host: {hostname}
Time: {timestamp}</code>"""
        
        # Email message (HTML)
        email_body = f"""
<h2>{emoji} QJ Security Alert</h2>
<h3>{title}</h3>
<div>{details.replace(chr(10), '<br>')}</div>
<hr>
<small>Host: {hostname} | Time: {timestamp}</small>
"""
        
        tasks = []
        if self.is_telegram_configured():
            tasks.append(self.send_telegram(tg_msg))
        if self.is_email_configured():
            tasks.append(self.send_email(f"[Security] {title}", email_body))
        
        if not tasks:
            print("No notification channels configured!", file=sys.stderr)
            return False
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        return any(r is True for r in results)


def parse_report(report_path: str) -> tuple[int, int, str]:
    """Parse security report and extract issues."""
    critical = 0
    warnings = 0
    issues = []
    
    with open(report_path) as f:
        content = f.read()
    
    # Parse Actions Required section
    in_actions = False
    for line in content.split('\n'):
        if '## Actions Required' in line:
            in_actions = True
            continue
        if in_actions:
            if line.startswith('## ') or line.startswith('---'):
                break
            if '[CRIT]' in line or '[ALERT]' in line or '[CONN]' in line:
                critical += 1
                issues.append(f"🔴 {line.split('] ', 1)[-1].strip()}")
            elif '[REBOOT]' in line or '[FIX]' in line or '[WARN]' in line:
                warnings += 1
                issues.append(f"🟡 {line.split('] ', 1)[-1].strip()}")
    
    details = '\n'.join(issues[:10])
    if len(issues) > 10:
        details += f"\n... and {len(issues) - 10} more"
    
    return critical, warnings, details


async def main():
    parser = argparse.ArgumentParser(description="QJ Security Check Notifications")
    parser.add_argument("--test", action="store_true", help="Send test notification")
    parser.add_argument("--report", type=str, help="Parse report and alert on issues")
    parser.add_argument("--message", type=str, help="Send custom message")
    parser.add_argument("--telegram-only", action="store_true")
    parser.add_argument("--email-only", action="store_true")
    args = parser.parse_args()
    
    notifier = SecurityNotifier()
    
    # Show config status
    print("Configuration:")
    print(f"  Telegram: {'✓ Configured' if notifier.is_telegram_configured() else '✗ Not configured'}")
    print(f"  Email: {'✓ Configured' if notifier.is_email_configured() else '✗ Not configured'}")
    print()
    
    if args.test:
        print("Sending test notification...")
        await notifier.alert(
            "Test Alert",
            "This is a test message to verify notification delivery.\n\nIf you received this, notifications are working! ✅",
            "info"
        )
        
    elif args.report:
        critical, warnings, details = parse_report(args.report)
        
        if critical == 0 and warnings == 0:
            print("No critical issues found, no alert sent.")
            return
        
        severity = "critical" if critical > 0 else "warning"
        title = f"{critical} Critical, {warnings} Warning issues found"
        
        await notifier.alert(title, details, severity)
        
    elif args.message:
        await notifier.alert("Custom Alert", args.message, "info")
        
    else:
        parser.print_help()


if __name__ == "__main__":
    asyncio.run(main())
