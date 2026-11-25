# scanner/network_scanner.py
import nmap
import re
import logging

import config

log = logging.getLogger(__name__)


def extract_cves(text):
    cves = re.findall(r"CVE-\d{4}-\d+", text)
    return list(set(cves))


def network_scan(target, scan_type, custom_script=None):
    """
    Perform network scanning using predefined Nmap scan profiles.
    All profiles use -sT (TCP Connect) for Windows compatibility.
    """
    # C6 / H5 — validate target before touching Nmap
    try:
        target = config.validate_network_target(target)
    except config.TargetValidationError as e:
        return {"error": f"Invalid target: {e}"}

    # C1 — fail clearly if Nmap isn't found
    if not config.NMAP_PATH:
        return {"error": "Nmap not found. Install Nmap and set NMAP_PATH or add to PATH."}

    scan_profiles = {
        "tcp_basic": "-sT -Pn -v",
        "tcp_full": "-sT -Pn -v",
        "version_scan": "-sT -sV -Pn -v",
        "aggressive": "-sT -sV -Pn -v -A",
        "udp_scan": "-sU -Pn",
        "ping_scan": "-PE -sn",
        "os_scan": "-O -Pn",
        "whois": "--script whois -Pn",
        "dns_brute": "--script=dns-brute -Pn",
        "http_enum": "-sT -sV -Pn -p 80,443,8080,8443 --script http-enum",
        "smb_enum": "-sT -sV -Pn -p 445 --script smb-enum-shares,smb-enum-users",
        "vuln_scan": "-sT -sV -Pn --script vuln",
        "vuln_full": "-sT -sV -Pn --script vuln",
        "vulners": "-sT -sV -Pn --script vulners",
        "smb_vuln": "-sT -sV -Pn -p 445 --script smb-vuln-*",
        "ssl_audit": "-sT -sV -Pn -p 443,8443 --script ssl-*",
        "decoy_syn": "-sT -Pn -D RND:12",
        "anonymous_full": "-sT -f -A -Pn --proxies http://127.0.0.1",
        "proxy_scan": "-sT -Pn --proxies socks4://127.0.0.1:9050",
        "tor_scan": "-sT -f -Pn --proxies socks4://127.0.0.1:9050",
        "vpn_scan": "-sT -A -Pn",
    }

    if scan_type == "nse_custom" and custom_script:
        # H6 — reject shell metachars in custom NSE script name
        if not re.match(r"^[A-Za-z0-9_.,\-*]+$", custom_script):
            return {"error": "Invalid NSE script name (letters, digits, _ . , - * only)."}
        arguments = f"-sT -sV -Pn --script={custom_script}"
    else:
        arguments = scan_profiles.get(scan_type, "-sT -Pn -v")

    # H5 — enforce host timeout so a /24 can't run forever
    arguments += f" --host-timeout {config.SCAN_TIMEOUT_NMAP}s"

    result = {}
    try:
        scanner = nmap.PortScanner(nmap_search_path=[config.NMAP_PATH])
        log.info("[NMAP] Scanning %s with args: %s", target, arguments)
        scanner.scan(target, arguments=arguments)

        for host in scanner.all_hosts():
            result[host] = {
                "state": scanner[host].state(),
                "protocols": {},
                "scripts": {},
            }
            for proto in scanner[host].all_protocols():
                result[host]["protocols"][proto] = []
                for port in scanner[host][proto].keys():
                    port_data = scanner[host][proto][port]
                    version_info = (
                        port_data.get("version")
                        or port_data.get("extrainfo")
                        or (port_data.get("cpe")[0] if port_data.get("cpe") else "")
                    )
                    result[host]["protocols"][proto].append({
                        "port": port,
                        "state": port_data.get("state", ""),
                        "service": port_data.get("name", ""),
                        "product": port_data.get("product", ""),
                        "version": version_info,
                    })

            if "hostscript" in scanner[host]:
                for script in scanner[host]["hostscript"]:
                    result[host]["scripts"][script["id"]] = script["output"]

        if not scanner.all_hosts():
            result["error"] = (
                "No hosts responded. The target may be offline, "
                "or try a different scan profile."
            )
        else:
            result["CVE Vulnerabilities"] = extract_cves(str(result))

    except nmap.PortScannerError as e:
        result["error"] = f"Nmap error: {e}"
    except Exception as e:
        log.exception("[NMAP] scan failed")
        result["error"] = str(e)

    return result