# scanner/web_scanner.py
"""
Website and Network scanning module.
"""

import os
import re
import json
import logging
import subprocess

import config

log = logging.getLogger(__name__)
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}")


def run_custom_command(command_string: str, target: str = "", timeout: int = None) -> dict:
    if not command_string or not command_string.strip():
        return {"error": "No command provided."}

    command_string = command_string.strip()
    first_token = command_string.split(maxsplit=1)[0].lower()
    first_token_basename = os.path.basename(first_token).lower()
    if first_token_basename.endswith(".exe"):
        first_token_basename = first_token_basename[:-4]

    if not any(first_token_basename.startswith(p) or first_token.startswith(p) for p in config.ALLOWED_COMMAND_PREFIXES):
        return {"error": f"Command prefix '{first_token}' is not allowed."}

    if timeout is None:
        timeout = config.SCAN_TIMEOUT_SQLMAP 

    log.info("[custom] running: %s", command_string)

    if "sqlmap" in command_string.lower():
        # Force SQLMap to run without asking questions and flush old cache
        if "--batch" not in command_string:
            command_string += " --batch"
        if "--disable-coloring" not in command_string:
            command_string += " --disable-coloring"
        if "--flush-session" not in command_string:
            command_string += " --flush-session"

    env = os.environ.copy()
    env["PYTHONUNBUFFERED"] = "1"

    try:
        process = subprocess.Popen(
            command_string,
            shell=True,
            stdin=subprocess.DEVNULL,  # Prevents hanging on prompts
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding='utf-8',
            errors='replace',
            env=env
        )

        output_lines = []
        try:
            for line in iter(process.stdout.readline, ''):
                output_lines.append(line)
                print(f"[SCANNER] {line.strip()}")
            
            process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            process.kill()
            output_lines.append("\n[!] Command timed out.")
        
        combined = "".join(output_lines).strip()
        rc = process.returncode

    except Exception as e:
        log.exception("[custom] execution failed")
        return {"error": f"Failed to execute command: {e}"}

    if not combined and rc != 0:
        combined = f"Command exited with code {rc} but produced no output."

    findings = _parse_command_findings(command_string, combined, "", rc)

    return {
        "command": command_string,
        "target": target,
        "return_code": rc,
        "raw_output": combined[-8000:] if len(combined) > 8000 else combined,
        "findings": findings,
        "CVE Vulnerabilities": sorted(set(CVE_RE.findall(combined))),
    }


def _parse_command_findings(command: str, stdout: str, stderr: str, rc: int) -> list:
    text = (stdout + "\n" + stderr).lower()
    findings = []
    idx = 1

    def add(title, severity, description, impact, remediation):
        nonlocal idx
        findings.append({
            "id": f"CMD-{idx:03d}", "title": title, "severity": severity,
            "description": description[:1500], "impact": impact, "remediation": remediation,
        })
        idx += 1

    cmd_lower = command.lower()

    if "sqlmap" in cmd_lower:
        # SQLMap outputs different phrases when it finds a vuln
        if "is vulnerable" in text or "appears to be" in text or "sqlmap identified" in text:
            add("SQL Injection Confirmed", "Critical", _extract_snippet(stdout, ("vulnerable", "injectable", "appears to be")), 
                "Application is vulnerable to SQL injection.", "Use parameterized queries.")
        elif "not injectable" in text:
            add("SQLMap: No Injection Found", "Informational", "No injectable parameters found.", "No action required.", "N/A")
        else:
            add("SQLMap Execution Output", "Low", _extract_snippet(stdout, ("error", "critical", "start")), 
                "Review the raw output for details.", "Check target reachability and command syntax.")

    elif "dalfox" in cmd_lower:
        if "[v]" in text or "vulnerable" in text:
            add("Reflected XSS Confirmed", "High", _extract_snippet(stdout, ("[v]", "vulnerable")), 
                "Reflected XSS found.", "HTML-encode all reflected output.")
        elif "no vulnerability" in text:
            add("Dalfox: No XSS Found", "Informational", "No reflected XSS found.", "No action required.", "N/A")

    elif "nuclei" in cmd_lower:
        severities = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for sev in severities:
            severities[sev] = len(re.findall(rf"\[{sev}\]", text))
        total = sum(severities.values())
        if total > 0:
            worst = "Critical" if severities["critical"] else ("High" if severities["high"] else ("Medium" if severities["medium"] else "Low"))
            add(f"Nuclei: {total} Finding(s)", worst, _extract_snippet(stdout, ('[critical]', '[high]')), 
                "Nuclei matched templates.", "Review raw output.")
        else:
            add("Nuclei: No Findings", "Informational", "No matches found.", "No action required.", "N/A")

    elif "nmap" in cmd_lower:
        open_ports = re.findall(r"(\d+)/(?:tcp|udp)\s+open\s+(\S+)", text)
        if open_ports:
            lines = "\n".join(f"{port}/{svc}" for port, svc in open_ports[:50])
            add(f"Nmap: {len(open_ports)} Open Port(s)", "Medium", lines, 
                "Open ports increase attack surface.", "Close unnecessary services.")
        else:
            add("Nmap: Scan Complete", "Informational", _extract_snippet(stdout, ("nmap scan report", "host is up")), 
                "No notable open ports.", "N/A")

    elif "whatweb" in cmd_lower:
        if rc == 0 and stdout.strip():
            add("WhatWeb: Fingerprint", "Informational", stdout.strip()[:1500], 
                "Technology stack identified.", "Suppress version headers.")
        else:
            add("WhatWeb: No Response", "Low", _extract_snippet(stdout, ("error",)), "Could not fingerprint.", "Check target.")

    if not findings:
        if rc == 0 and stdout.strip():
            add("Command Output", "Informational", stdout.strip()[:1500], "Completed successfully.", "Review manually.")
        else:
            err_msg = stderr.strip() or stdout.strip() or f"Command exited non-zero ({rc}) with no output."
            add("Command Failed", "Low", err_msg[:1500], "Command did not complete successfully.", "Check syntax and tool installation.")

    return findings


def _extract_snippet(text: str, keywords: tuple, max_lines: int = 20) -> str:
    lines = text.splitlines()
    matches = [line.strip() for line in lines if any(k in line.lower() for k in keywords)]
    return "\n".join(matches[:max_lines]) if matches else text[:1500]


# --- Legacy helpers ---
def normalize_url(target):
    target = (target or "").strip()
    if not re.match(r"^https?://", target, re.IGNORECASE): target = "http://" + target
    return f"{target}", target.replace("http://", "").replace("https://", "").split("/")[0]

def _run(cmd, timeout=300):
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return proc.stdout or "", proc.stderr or "", proc.returncode
    except Exception as e:
        return "", str(e), -1

def _whois_scan(target):
    try: import whois as pythonwhois
    except ImportError: return {"error": "python-whois missing."}
    _, domain = normalize_url(target)
    try:
        w = pythonwhois.whois(domain)
        return {"domain_name": str(w.get("domain_name")), "registrar": str(w.get("registrar"))}
    except Exception as e: return {"error": str(e)}

def _dns_enum(target):
    _, domain = normalize_url(target)
    if config.DNSENUM_PATH and os.path.exists(config.DNSENUM_PATH) and config.PERL_PATH:
        cmd = [config.PERL_PATH, config.DNSENUM_PATH, domain]
        out, err, rc = _run(cmd, timeout=config.SCAN_TIMEOUT_DNSENUM)
        if out.strip(): return {"dnsenum_output": out.strip()[:4000]}
    return {"error": "dnsenum failed."}

def _tech_detect(target):
    base, _ = normalize_url(target)
    try:
        import requests
        r = requests.get(base, timeout=15)
        tech = []
        if r.headers.get("Server"): tech.append(f"Server: {r.headers['Server']}")
        return {"status_code": r.status_code, "technologies": tech or ["None"]}
    except Exception as e: return {"error": str(e)}

_NUCLEI_TAGS = {"basic": ["-tags", "exposure,misconfig"], "cves":  ["-tags", "cve"], "full":  []}

def _nuclei(target, mode):
    base, _ = normalize_url(target)
    if not config.NUCLEI_PATH: return {"error": "Nuclei not found."}
    cmd = [config.NUCLEI_PATH, "-u", base, "-jsonl", "-silent"] + _NUCLEI_TAGS.get(mode, [])
    out, err, rc = _run(cmd, timeout=config.SCAN_TIMEOUT_NUCLEI)
    findings = []
    for line in out.strip().splitlines():
        try: findings.append(json.loads(line))
        except: pass
    return {"findings": findings, "CVE Vulnerabilities": sorted(set(CVE_RE.findall(json.dumps(findings))))}

def web_scan(target, scan_type):
    try: target = config.validate_web_target(target)
    except Exception as e: return {"error": str(e)}
    if scan_type == "full_recon":
        return {"whois": _whois_scan(target), "dns": _dns_enum(target), "tech_detect": _tech_detect(target), "nuclei_basic": _nuclei(target, "basic")}
    return {"error": "Use custom command mode."}