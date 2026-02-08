#!/usr/bin/env python3
"""
QJ Security Check — Web Dashboard
==================================
Local Flask server (port 5000) that runs security check scripts
and presents results as a premium HTML dashboard.

Usage:
    python server.py              # Start on port 5050
    python server.py --port 5050  # Custom port
"""

import os
import re
import json
import subprocess
import threading
import time
import argparse
from datetime import datetime
from pathlib import Path

from flask import Flask, jsonify, request, send_from_directory

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
BASE_DIR = Path(__file__).resolve().parent
REPORTS_DIR = BASE_DIR / "reports"
SCRIPTS = {
    "security":     BASE_DIR / "security_check.sh",
    "reachability": BASE_DIR / "check_remote.sh",
    "exposure":     BASE_DIR / "security_docker_check.sh",
}

app = Flask(__name__, static_folder=str(BASE_DIR / "web"), static_url_path="/static")

# In-memory state for active scans
_scan_lock = threading.Lock()
_active_scan = {"running": False, "type": None, "started": None, "log": []}
_scan_proc = None  # track subprocess for stop
_last_results = {}

# ---------------------------------------------------------------------------
# Report parser — turns the markdown reports into structured JSON
# ---------------------------------------------------------------------------

def parse_security_report(md_text: str) -> dict:
    """Parse a security_check markdown report into structured data."""
    result = {
        "generated": "",
        "servers_checked": [],
        "summary": {},
        "servers": [],
        "actions": [],
        "score": 100,
    }

    # Extract generated date
    m = re.search(r"\*\*Generated:\*\*\s*(.+)", md_text)
    if m:
        result["generated"] = m.group(1).strip()

    # Extract servers checked
    m = re.search(r"\*\*Servers checked:\*\*\s*(.+)", md_text)
    if m:
        result["servers_checked"] = m.group(1).strip().split()

    # Parse summary table
    summary_match = re.search(
        r"\|\s*Metric\s*\|\s*Value\s*\|\s*Status\s*\|.*?\n\|[-\s|]+\n(.*?)(?=\n---|\n##)",
        md_text, re.DOTALL
    )
    if summary_match:
        for row in summary_match.group(1).strip().split("\n"):
            cols = [c.strip() for c in row.split("|") if c.strip()]
            if len(cols) >= 3:
                key = cols[0].lower().replace(" ", "_")
                result["summary"][key] = {"value": cols[1], "status": cols[2]}

    # Parse per-server sections
    server_blocks = re.split(r"## Server:\s*", md_text)[1:]
    for block in server_blocks:
        srv = parse_server_block(block)
        if srv:
            result["servers"].append(srv)

    # Parse actions
    actions_match = re.search(r"## Actions Required\n\n(.*?)(?=\n---|\n##|$)", md_text, re.DOTALL)
    if actions_match:
        for line in actions_match.group(1).strip().split("\n"):
            line = line.strip()
            if line.startswith("- ["):
                # Strip "- [ ] " or "- [x] " prefix
                action = re.sub(r'^- \[[ x]\]\s*', '', line)
                severity = "info"
                if "[REBOOT]" in action:
                    severity = "warning"
                elif "[CRIT]" in action or "[ALERT]" in action:
                    severity = "critical"
                elif "[FIX]" in action:
                    severity = "warning"
                elif "[CONN]" in action:
                    severity = "critical"
                elif "[WARN]" in action:
                    severity = "warning"
                result["actions"].append({"text": action, "severity": severity})

    # Compute score
    result["score"] = compute_score(result)
    return result


def parse_server_block(block: str) -> dict | None:
    """Parse a single server block from the report."""
    lines = block.strip().split("\n")
    if not lines:
        return None

    name = lines[0].strip()
    srv = {
        "name": name,
        "host": "",
        "hostname": "",
        "kernel": "",
        "uptime": "",
        "connected": True,
        "updates": {"all": "0", "security": "0"},
        "update_list": [],
        "needs_reboot": False,
        "reboot_reason": "",
        "tools": {},
        "failed_ssh_24h": "0",
        "fail2ban": {},
        "wireguard": {},
        "ufw": {},
        "auditd": {},
        "sessions": [],
        "ports": [],
        "resources": {},
        "docker": "",
        "severity": "ok",
    }

    text = "\n".join(lines)

    # Check connection failure
    if "Failed to connect" in text or "WARNING" in text[:200]:
        srv["connected"] = False
        srv["severity"] = "critical"
        return srv

    # Host
    m = re.search(r"\*\*Host:\*\*\s*`([^`]+)`", text)
    if m: srv["host"] = m.group(1)

    m = re.search(r"\*\*Hostname:\*\*\s*(\S+)", text)
    if m: srv["hostname"] = m.group(1)

    m = re.search(r"\*\*Kernel:\*\*\s*(\S+)", text)
    if m: srv["kernel"] = m.group(1)

    m = re.search(r"\*\*Uptime:\*\*\s*(.+)", text)
    if m: srv["uptime"] = m.group(1).strip()

    # Updates
    updates_match = re.search(r"\|\s*All\s*\|\s*(\d+)\s*\|", text)
    if updates_match: srv["updates"]["all"] = updates_match.group(1)

    sec_match = re.search(r"\|\s*Security\s*\|\s*(\S+)\s*\|", text)
    if sec_match: srv["updates"]["security"] = sec_match.group(1)

    # Reboot
    reboot_match = re.search(r"\|\s*Needs reboot\s*\|\s*(YES|NO)\s*\|", text)
    if reboot_match: srv["needs_reboot"] = reboot_match.group(1) == "YES"

    reason_match = re.search(r"\|\s*Reason\s*\|\s*(.+?)\s*\|", text)
    if reason_match: srv["reboot_reason"] = reason_match.group(1).strip()

    # Update list (packages to update)
    update_list_match = re.search(r"\*\*Packages to update:\*\*\n```\n(.*?)```", text, re.DOTALL)
    if update_list_match:
        for line in update_list_match.group(1).strip().split("\n"):
            line = line.strip().lstrip("- ").strip()
            if line:
                srv["update_list"].append(line)

    # Security tools
    tool_pattern = r"\|\s*(Fail2ban|UFW Firewall|WireGuard|Auditd|Rootkit Scanner)\s*\|\s*(YES|NO)\s*\|\s*(.+?)\s*\|"
    for m in re.finditer(tool_pattern, text):
        srv["tools"][m.group(1)] = {"installed": m.group(2) == "YES", "notes": m.group(3).strip()}

    # Failed SSH
    m = re.search(r"\*\*Failed SSH logins \(24h\):\*\*\s*(\d+)", text)
    if m: srv["failed_ssh_24h"] = m.group(1)

    # Fail2ban details
    f2b_section = re.search(r"\*\*Fail2ban:\*\*\n((?:- .+\n?)+)", text)
    if f2b_section:
        for line in f2b_section.group(1).split("\n"):
            line = line.strip().lstrip("- ")
            if ":" in line:
                k, v = line.split(":", 1)
                srv["fail2ban"][k.strip().lower().replace(" ", "_")] = v.strip()

    # Resources
    res_match = re.search(r"\|\s*Disk \(/\)\s*\|\s*(.+?)\s*\|", text)
    if res_match: srv["resources"]["disk"] = res_match.group(1).strip()

    ram_match = re.search(r"\|\s*RAM\s*\|\s*(.+?)\s*\|", text)
    if ram_match: srv["resources"]["ram"] = ram_match.group(1).strip()

    load_match = re.search(r"\|\s*Load\s*\|\s*(.+?)\s*\|", text)
    if load_match: srv["resources"]["load"] = load_match.group(1).strip()

    # Docker
    docker_match = re.search(r"\*\*Docker:\*\*\s*(.+)", text)
    if docker_match: srv["docker"] = docker_match.group(1).strip()

    # Ports (from listening ports code block)
    ports_match = re.search(r"\*\*Listening ports:\*\*\n```\n(.*?)```", text, re.DOTALL)
    if ports_match:
        for line in ports_match.group(1).strip().split("\n"):
            line = line.strip().lstrip("- ").strip()
            if line:
                srv["ports"].append(line)

    # Compute severity
    srv["severity"] = compute_server_severity(srv)
    return srv


def _safe_int(val: str, default: int = 0) -> int:
    """Safely parse a string to int, returning default for non-numeric values."""
    try:
        return int(val)
    except (ValueError, TypeError):
        return default


def compute_server_severity(srv: dict) -> str:
    """Compute severity level for a server: ok, warning, critical."""
    if not srv["connected"]:
        return "critical"

    score = 0
    if _safe_int(srv["updates"].get("security", "0") or "0") > 0:
        score += 3
    if _safe_int(srv["updates"].get("all", "0") or "0") > 10:
        score += 1
    if srv["needs_reboot"]:
        score += 1
    if _safe_int(srv["failed_ssh_24h"] or "0") > 100:
        score += 3
    # Check tools
    for tool_name, tool_info in srv.get("tools", {}).items():
        if tool_name in ("Fail2ban", "UFW Firewall") and not tool_info.get("installed"):
            score += 2

    # SSH hardening penalties from report
    # (parsed from SSH Hardening table in markdown)

    # Disk usage
    disk = srv.get("resources", {}).get("disk", "")
    disk_pct_match = re.search(r"(\d+)%", disk)
    if disk_pct_match and int(disk_pct_match.group(1)) > 90:
        score += 2

    if score >= 3:
        return "critical"
    elif score >= 1:
        return "warning"
    return "ok"


def compute_score(report: dict) -> int:
    """Compute overall security score 0-100."""
    score = 100
    for srv in report.get("servers", []):
        if not srv["connected"]:
            score -= 15
            continue
        if _safe_int(srv["updates"].get("security", "0") or "0") > 0:
            score -= 10
        if _safe_int(srv["updates"].get("all", "0") or "0") > 5:
            score -= 3
        if srv["needs_reboot"]:
            score -= 5
        if _safe_int(srv["failed_ssh_24h"] or "0") > 100:
            score -= 10
        for tn, ti in srv.get("tools", {}).items():
            if tn in ("Fail2ban", "UFW Firewall") and not ti.get("installed"):
                score -= 8
    return max(0, min(100, score))


# ---------------------------------------------------------------------------
# Report listing
# ---------------------------------------------------------------------------

def list_reports() -> list[dict]:
    """List all reports sorted by date descending."""
    reports = []
    if not REPORTS_DIR.exists():
        return reports
    for f in sorted(REPORTS_DIR.iterdir(), reverse=True):
        if f.suffix == ".md" and f.is_file():
            # Detect type from filename
            rtype = "security"
            if "exposure" in f.name:
                rtype = "exposure"
            elif "reachability" in f.name:
                rtype = "reachability"
            reports.append({
                "filename": f.name,
                "type": rtype,
                "size": f.stat().st_size,
                "modified": datetime.fromtimestamp(f.stat().st_mtime).isoformat(),
            })
    return reports


# ---------------------------------------------------------------------------
# Scan execution
# ---------------------------------------------------------------------------

def run_scan(scan_type: str, servers: list[str] | None = None):
    """Run a scan script in background thread."""
    global _active_scan, _last_results

    script = SCRIPTS.get(scan_type)
    if not script or not script.exists():
        return {"error": f"Script not found for scan type: {scan_type}"}

    with _scan_lock:
        if _active_scan["running"]:
            return {"error": "A scan is already running", "type": _active_scan["type"]}
        _active_scan = {"running": True, "type": scan_type, "started": time.time(), "log": []}

    def _do_scan():
        global _active_scan, _last_results, _scan_proc
        try:
            cmd = ["bash", str(script)]
            if servers and scan_type == "security":
                cmd.extend(["-s", " ".join(servers)])

            _ansi_re = re.compile(r'\x1b\[[0-9;]*m')
            proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, bufsize=1, cwd=str(BASE_DIR),
                preexec_fn=os.setsid,
            )
            _scan_proc = proc
            for line in iter(proc.stdout.readline, ''):
                if line:
                    clean = _ansi_re.sub('', line.rstrip('\n'))
                    _active_scan["log"].append(clean)
            proc.wait(timeout=600)
            _active_scan["log"].append(f"--- Finished (exit {proc.returncode}) ---")

            # Find the latest report
            reps = list_reports()
            type_reps = [r for r in reps if r["type"] == scan_type]
            print(f"[DEBUG] Found {len(type_reps)} reports for type '{scan_type}'")
            if type_reps:
                latest = REPORTS_DIR / type_reps[0]["filename"]
                print(f"[DEBUG] Loading report: {latest}")
                md_text = latest.read_text(encoding="utf-8", errors="replace")
                if scan_type == "security":
                    parsed = parse_security_report(md_text)
                    print(f"[DEBUG] Parsed: score={parsed.get('score')}, servers={len(parsed.get('servers', []))}")
                    _last_results[scan_type] = parsed
                else:
                    _last_results[scan_type] = {"raw_markdown": md_text, "generated": type_reps[0]["modified"]}
                _last_results[scan_type]["report_file"] = type_reps[0]["filename"]
            else:
                print(f"[DEBUG] No reports found for type '{scan_type}'")

        except subprocess.TimeoutExpired:
            _active_scan["log"].append("ERROR: Scan timed out after 10 minutes")
        except Exception as e:
            _active_scan["log"].append(f"ERROR: {e}")
        finally:
            _active_scan["running"] = False
            _scan_proc = None

    t = threading.Thread(target=_do_scan, daemon=True)
    t.start()
    return {"started": True, "type": scan_type}


# ---------------------------------------------------------------------------
# Flask routes
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    """Serve the dashboard HTML."""
    return send_from_directory(str(BASE_DIR / "web"), "dashboard.html")

@app.route("/api/status")
def api_status():
    return jsonify({
        "status": "ok",
        "scan_running": _active_scan["running"],
        "scan_type": _active_scan.get("type"),
        "scan_started": _active_scan.get("started"),
    })

@app.route("/api/scan", methods=["POST"])
def api_scan():
    data = request.get_json(silent=True) or {}
    scan_type = data.get("type", "security")
    servers = data.get("servers")
    result = run_scan(scan_type, servers)
    return jsonify(result)

@app.route("/api/scan/stop", methods=["POST"])
def api_scan_stop():
    global _scan_proc, _active_scan
    if not _active_scan["running"]:
        return jsonify({"error": "No scan running"})
    proc = _scan_proc
    if proc:
        import signal, os
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
        except (ProcessLookupError, OSError):
            try:
                proc.kill()
            except Exception:
                pass
    _active_scan["log"].append("--- STOPPED by user ---")
    _active_scan["running"] = False
    _scan_proc = None
    return jsonify({"stopped": True})

@app.route("/api/scan/status")
def api_scan_status():
    log = _active_scan.get("log", [])
    # Return last 100 log lines for live display
    since = int(request.args.get("since", 0))
    return jsonify({
        "running": _active_scan["running"],
        "type": _active_scan.get("type"),
        "started": _active_scan.get("started"),
        "log_lines": len(log),
        "log": log[since:][-100:],
    })

@app.route("/api/results")
def api_results():
    scan_type = request.args.get("type", "security")
    if scan_type in _last_results:
        return jsonify(_last_results[scan_type])
    return jsonify({"error": "No results yet. Run a scan first."})

@app.route("/api/reports")
def api_reports():
    return jsonify(list_reports())

@app.route("/api/reports/folder")
def api_reports_folder():
    """List all files in the reports directory with details."""
    if not REPORTS_DIR.exists():
        return jsonify({"files": [], "path": str(REPORTS_DIR)})
    files = []
    for f in sorted(REPORTS_DIR.iterdir(), reverse=True):
        if f.is_file():
            st = f.stat()
            files.append({
                "name": f.name,
                "size": st.st_size,
                "modified": datetime.fromtimestamp(st.st_mtime).strftime("%Y-%m-%d %H:%M"),
                "ext": f.suffix,
            })
    return jsonify({"files": files, "path": str(REPORTS_DIR)})

@app.route("/api/reports/<filename>")
def api_report_detail(filename):
    """Return parsed report or raw markdown."""
    filepath = REPORTS_DIR / filename
    if not filepath.exists() or not filepath.is_file():
        return jsonify({"error": "Report not found"}), 404

    md_text = filepath.read_text(encoding="utf-8", errors="replace")

    if "security_check" in filename:
        return jsonify(parse_security_report(md_text))
    else:
        return jsonify({"raw_markdown": md_text})

@app.route("/api/latest")
def api_latest():
    """Load and parse the latest security report without running a scan."""
    reps = list_reports()
    sec_reps = [r for r in reps if r["type"] == "security"]
    if not sec_reps:
        return jsonify({"error": "No security reports found"})

    latest = REPORTS_DIR / sec_reps[0]["filename"]
    md_text = latest.read_text(encoding="utf-8", errors="replace")
    parsed = parse_security_report(md_text)
    parsed["report_file"] = sec_reps[0]["filename"]
    _last_results["security"] = parsed
    return jsonify(parsed)




@app.route("/api/shell", methods=["POST"])
def api_shell():
    """Execute a shell command in the project directory."""
    data = request.get_json(silent=True) or {}
    cmd = data.get("command", "").strip()
    if not cmd:
        return jsonify({"error": "No command provided"})
    # If bare SSH (no command), append a default command to avoid interactive hang
    import shlex
    parts = cmd.split()
    if parts and parts[0] == 'ssh' and '"' not in cmd and "'" not in cmd:
        # bare: ssh host -> ssh host "hostname && uptime && df -h"
        if len(parts) == 2:
            cmd = f'{cmd} "hostname && uptime && df -h"'
    timeout = 60 if 'ssh' in cmd else 30
    try:
        proc = subprocess.run(
            cmd, shell=True, capture_output=True, text=True,
            timeout=timeout, cwd=str(BASE_DIR),
        )
        return jsonify({
            "stdout": proc.stdout[-8000:] if proc.stdout else "",
            "stderr": proc.stderr[-4000:] if proc.stderr else "",
            "returncode": proc.returncode,
        })
    except subprocess.TimeoutExpired:
        return jsonify({"error": f"Command timed out ({timeout}s)", "stdout": "", "stderr": "", "returncode": -1})
    except Exception as e:
        return jsonify({"error": str(e), "stdout": "", "stderr": "", "returncode": -1})


# ---------------------------------------------------------------------------

# Main
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="QJ Security Check Dashboard")
    parser.add_argument("--port", type=int, default=5050, help="Port (default: 5050)")
    parser.add_argument("--host", default="127.0.0.1", help="Host (default: 127.0.0.1)")
    parser.add_argument("--debug", action="store_true", help="Debug mode")
    args = parser.parse_args()

    # Ensure web directory exists
    (BASE_DIR / "web").mkdir(exist_ok=True)

    print(f"\n{'='*60}")
    print(f"  QJ Security Check Dashboard")
    print(f"  http://{args.host}:{args.port}")
    print(f"{'='*60}\n")

    app.run(host=args.host, port=args.port, debug=args.debug)
