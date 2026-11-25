# scripts/test_all_scans.py
"""
Smoke-test every scan type against a set of targets.
Does NOT save to the database — pure tool verification.

Fast scans only. The following are commented out because they are
slow, need admin rights, or require a specific target:
  udp_scan, os_scan, ping_scan, vuln_scan, vulners,
  smb_enum, smb_vuln, ssl_audit, http_enum,
  nuclei_full, nuclei_kev, nuclei_wordpress, nuclei_graphql

Test those manually through the UI one at a time.
"""
import sys, os, traceback
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from scanner import network_scan, web_scan

LOCAL      = "127.0.0.1"
DVWA_IP    = "192.168.0.77"
DVWA       = f"http://{DVWA_IP}"
LOCAL_HTTP = "http://127.0.0.1:8000"
EXT        = "example.com"

NETWORK_TESTS = [
    ("tcp_basic",    LOCAL),
    ("tcp_full",     LOCAL),
    ("version_scan", LOCAL),
    ("aggressive",   LOCAL),
    # ("udp_scan",     LOCAL),        # 5-15 min, UDP timeouts
    # ("os_scan",      LOCAL),        # needs Administrator
    # ("ping_scan",    "192.168.1.0/24"),
    # ("http_enum",    DVWA_IP),
    # ("smb_enum",     DVWA_IP),
    # ("smb_vuln",     DVWA_IP),
    # ("ssl_audit",    DVWA_IP),
    # ("vuln_scan",    DVWA_IP),      # 3-5 min
    # ("vulners",      DVWA_IP),      # 2-3 min
]

WEB_TESTS = [
    ("whois_web",          EXT),
    ("dnsenum_private",    EXT),
    ("dns_brute_web",      EXT),
    ("subdomain_scan",     EXT),
    ("tech_detect",        LOCAL_HTTP),
    ("waf_detect",         LOCAL_HTTP),
    ("whatweb_passive",    DVWA),
    ("whatweb_aggressive", DVWA),
    ("dir_scan",           LOCAL_HTTP),
    ("xss_scan",           DVWA),
    ("sql_injection_scan", DVWA),
    ("nuclei_basic",       DVWA),
    ("nuclei_panels",      DVWA),
    ("nuclei_cves",        DVWA),
    # ("nuclei_full",        DVWA),   # 3-10 min
    # ("nuclei_kev",         DVWA),
    # ("nuclei_wordpress",   DVWA),
    # ("nuclei_graphql",     DVWA),
    # ("crawl_xss",          LOCAL_HTTP),
    # ("crawl_sqli",         LOCAL_HTTP),
]


def classify(result):
    if not isinstance(result, dict):
        return "❌ NOT A DICT"
    if "error" in result and len(result) == 1:
        return f"❌ ERROR: {result['error'][:120]}"
    if any(k in result for k in ("findings", "vulnerable", "output", "paths",
                                  "subdomains", "dnsenum_output", "technologies",
                                  "waf_detected", "CVE Vulnerabilities", "A",
                                  "registrar")):
        return "✅ OK"
    if any(isinstance(v, dict) and "state" in v for v in result.values()):
        return "✅ OK (hosts)"
    return "✅ OK (data)"


print("=" * 70)
print("NETWORK SCANS (fast subset)")
print("=" * 70)
for scan_type, target in NETWORK_TESTS:
    print(f"\n→ {scan_type} → {target}")
    try:
        result = network_scan(target, scan_type)
        print(f"  {classify(result)}")
    except KeyboardInterrupt:
        print("  ⏸️ INTERRUPTED (Ctrl+C) — not a bug, re-run without hitting Ctrl+C")
        break
    except Exception as e:
        print(f"  ❌ EXCEPTION: {e}")

print("\n" + "=" * 70)
print("WEB SCANS (fast subset)")
print("=" * 70)
for scan_type, target in WEB_TESTS:
    print(f"\n→ {scan_type} → {target}")
    try:
        result = web_scan(target, scan_type)
        print(f"  {classify(result)}")
    except KeyboardInterrupt:
        print("  ⏸️ INTERRUPTED (Ctrl+C)")
        break
    except Exception as e:
        print(f"  ❌ EXCEPTION: {e}")