# config.py
"""
Central configuration for VulnScan Pro — command-mode architecture.
"""

import os
import re
import shutil
import platform
import ipaddress
from urllib.parse import urlparse

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

# ---------------------------------------------------------------------------
# Secrets
# ---------------------------------------------------------------------------
SECRET_KEY = os.environ.get("SECRET_KEY", "")
if not SECRET_KEY:
    import warnings
    SECRET_KEY = "dev-insecure-change-me"
    warnings.warn(
        "[config] SECRET_KEY not set — using insecure dev fallback. "
        "Set SECRET_KEY in your .env before deploying.",
        RuntimeWarning,
    )

DEBUG = os.environ.get("FLASK_DEBUG", "0") == "1"
HOST = os.environ.get("FLASK_HOST", "127.0.0.1")
PORT = int(os.environ.get("FLASK_PORT", "5000"))


# ---------------------------------------------------------------------------
# Tool discovery helper
# ---------------------------------------------------------------------------
def _resolve_tool(env_var: str, exe_name: str, platform_defaults: dict) -> str | None:
    val = os.environ.get(env_var)
    if val and os.path.exists(val):
        return val
    found = shutil.which(exe_name)
    if found:
        return found
    sysname = platform.system().lower()
    for candidate in platform_defaults.get(sysname, []):
        if candidate and os.path.exists(candidate):
            return candidate
    return None


# ---------------------------------------------------------------------------
# Tool paths
# ---------------------------------------------------------------------------
NMAP_PATH = _resolve_tool("NMAP_PATH", "nmap", {
    "windows": [r"C:\Program Files (x86)\Nmap\nmap.exe", r"C:\Program Files\Nmap\nmap.exe"],
    "linux":   ["/usr/bin/nmap", "/usr/local/bin/nmap"],
})

NUCLEI_PATH = _resolve_tool("NUCLEI_PATH", "nuclei", {
    "windows": [r"C:\Users\<username>\go\bin\nuclei.exe", r"C:\Users\Public\go\bin\nuclei.exe"],
    "linux":   ["/usr/local/bin/nuclei", "/usr/bin/nuclei"],
})

WHATWEB_PATH = _resolve_tool("WHATWEB_PATH", "whatweb", {
    "windows": [r"C:\Tools\WhatWeb\whatweb", r"C:\Ruby40-x64\bin\whatweb"],
    "linux":   ["/usr/bin/whatweb", "/usr/local/bin/whatweb"],
})

DNSENUM_PATH = _resolve_tool("DNSENUM_PATH", "dnsenum", {
    "windows": [r"C:\\Tools\\dnsenum\dnsenum.pl"],
    "linux":   ["/usr/bin/dnsenum"],
})

DALFOX_PATH = _resolve_tool("DALFOX_PATH", "dalfox", {
    "windows": [r"C:\ProgramData\chocolatey\bin\dalfox.exe", r"C:\Tools\dalfox\dalfox.exe"],
    "linux":   ["/usr/local/bin/dalfox", "/usr/bin/dalfox"],
})

SQLMAP_PATH = os.environ.get("SQLMAP_PATH", r"C:\\Tools\\sqlmap\sqlmap.py")

PYTHON_PATH = _resolve_tool("PYTHON_PATH", "python", {
    "windows": [r"C:\Python315\python.exe", r"C:\Python312\python.exe", r"C:\Python311\python.exe"],
    "linux":   ["/usr/bin/python3"],
})

RUBY_PATH = _resolve_tool("RUBY_PATH", "ruby", {"windows": [r"C:\Ruby40-x64\bin\ruby.exe"], "linux": ["/usr/bin/ruby"]})
PERL_PATH = _resolve_tool("PERL_PATH", "perl", {"windows": [r"C:\Strawberry\perl\bin\perl.exe"], "linux": ["/usr/bin/perl"]})


# ---------------------------------------------------------------------------
# Command whitelist
# ---------------------------------------------------------------------------
# 'python' is required to run sqlmap.py directly. 'perl' is required for dnsenum.pl.
ALLOWED_COMMAND_PREFIXES = (
    "nmap",
    "nuclei",
    "whatweb",
    "dnsenum",
    "sqlmap",
    "dalfox",
    "python",
    "perl",
    "ruby"
)


# ---------------------------------------------------------------------------
# Target validation
# ---------------------------------------------------------------------------
_HOSTNAME_RE = re.compile(r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63}(?<!-))*$")
MAX_CIDR_PREFIX_NETWORK = 24

class TargetValidationError(ValueError):
    pass

def validate_network_target(target: str) -> str:
    if not target or not isinstance(target, str):
        raise TargetValidationError("Target is required.")
    target = target.strip()
    if "/" in target:
        try:
            net = ipaddress.ip_network(target, strict=False)
        except ValueError:
            raise TargetValidationError(f"Invalid CIDR: {target}")
        if net.prefixlen < MAX_CIDR_PREFIX_NETWORK:
            raise TargetValidationError(f"CIDR /{net.prefixlen} is too large; max /{MAX_CIDR_PREFIX_NETWORK}.")
        return str(net)
    try:
        ipaddress.ip_address(target)
        return target
    except ValueError:
        pass
    if _HOSTNAME_RE.match(target):
        return target
    raise TargetValidationError(f"Invalid network target: {target}")

def validate_web_target(target: str) -> str:
    if not target or not isinstance(target, str):
        raise TargetValidationError("Target is required.")
    target = target.strip()
    if not re.match(r"^https?://", target, re.IGNORECASE):
        candidate = "http://" + target
    else:
        candidate = target
    parsed = urlparse(candidate)
    if parsed.scheme not in ("http", "https"):
        raise TargetValidationError(f"Only http/https allowed, got: {parsed.scheme}")
    if not parsed.hostname:
        raise TargetValidationError(f"Missing hostname in: {target}")
    if not _HOSTNAME_RE.match(parsed.hostname) and not _is_ip(parsed.hostname):
        raise TargetValidationError(f"Invalid hostname: {parsed.hostname}")
    return candidate

def _is_ip(s: str) -> bool:
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# Database & Settings
# ---------------------------------------------------------------------------
DB_PATH = os.environ.get("VULNSCAN_DB", "database.db")
ALLOWED_PROVIDERS = {"groq", "openai", "anthropic", "mistral", "deepseek"}

SCAN_TIMEOUT_NMAP = int(os.environ.get("SCAN_TIMEOUT_NMAP", "900"))
SCAN_TIMEOUT_NUCLEI = int(os.environ.get("SCAN_TIMEOUT_NUCLEI", "600"))
SCAN_TIMEOUT_WHATWEB = int(os.environ.get("SCAN_TIMEOUT_WHATWEB", "180"))
SCAN_TIMEOUT_DNSENUM = int(os.environ.get("SCAN_TIMEOUT_DNSENUM", "120"))
SCAN_TIMEOUT_DALFOX = int(os.environ.get("SCAN_TIMEOUT_DALFOX", "300"))
SCAN_TIMEOUT_SQLMAP = int(os.environ.get("SCAN_TIMEOUT_SQLMAP", "600"))


def print_tool_status():
    tools = {
        "Nmap": NMAP_PATH, "Nuclei": NUCLEI_PATH, "WhatWeb": WHATWEB_PATH,
        "dnsenum": DNSENUM_PATH, "Ruby": RUBY_PATH, "Perl": PERL_PATH,
        "Dalfox": DALFOX_PATH, "SQLMap": SQLMAP_PATH if os.path.exists(SQLMAP_PATH) else None,
    }
    for name, path in tools.items():
        status = "OK" if path else "MISSING"
        print(f"[config] {name:<8}: {status:<7} {path or '(not found)'}")
    print(f"[config] Providers: {sorted(ALLOWED_PROVIDERS)}")
    print(f"[config] Allowed commands: {sorted(ALLOWED_COMMAND_PREFIXES)}")

if __name__ == "__main__":
    print_tool_status()