# scanner/external_tools.py
"""
External tool wrappers — Nikto removed.
"""
import subprocess
import json
import logging

import config

log = logging.getLogger(__name__)


def _run(cmd, timeout):
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return proc.stdout or "", proc.stderr or "", proc.returncode
    except FileNotFoundError:
        return "", f"Executable not found: {cmd[0]}", -1
    except subprocess.TimeoutExpired:
        return "", f"Timed out after {timeout}s", -1
    except Exception as e:
        log.exception("[external_tools] failed: %s", cmd)
        return "", str(e), -1


def run_nuclei(target, mode):
    if not config.NUCLEI_PATH:
        return {"error": "Nuclei not found. Install from projectdiscovery."}
    templates = {
        "basic": ["-tags", "exposure,misconfig"],
        "cve": ["-tags", "cve"],
        "full": [],
    }.get(mode, [])
    cmd = [config.NUCLEI_PATH, "-u", target, "-json", "-silent"] + templates
    out, err, rc = _run(cmd, timeout=config.SCAN_TIMEOUT_NUCLEI)

    findings = []
    for line in out.strip().splitlines():
        try:
            findings.append(json.loads(line))
        except json.JSONDecodeError:
            continue

    summary = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
    for f in findings:
        sev = f.get("info", {}).get("severity", "info").capitalize()
        if sev in summary:
            summary[sev] += 1
    if rc != 0 and not findings:
        return {"error": err.strip()[:300]}
    return {"findings": findings, "summary": summary}


def run_whatweb(target):
    if not config.WHATWEB_PATH:
        return {"error": "WhatWeb not found. Install Ruby then `gem install whatweb`."}
    cmd = ["ruby", config.WHATWEB_PATH, target, "--color=never"]
    out, err, rc = _run(cmd, timeout=config.SCAN_TIMEOUT_WHATWEB)
    return {"output": out, "stderr": err}