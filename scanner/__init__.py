"""
scanner package
===============

Exposes the two top-level scan entry points used by ``app.py``:

    from scanner import network_scan, web_scan

Both functions accept ``(target, scan_type)`` and return a ``dict`` of
results. Any exception inside a scan is caught and returned as
``{"error": "..."}`` so a single failing tool never crashes the Flask app.

Submodules
----------
network_scanner : Nmap-based network scanning (``network_scan``)
web_scanner     : HTTP / DNS / tool-based website scanning (``web_scan``)
"""

__version__ = "2.0.0"
__author__ = "VulnScan Pro"

# ---------------------------------------------------------------------------
# Re-exports
# ---------------------------------------------------------------------------
# Import lazily so a missing optional dependency (python-whois, dnspython,
# python-nmap, etc.) produces a clear per-scan error instead of killing
# `import scanner` at startup.
# ---------------------------------------------------------------------------

_network_scan = None
_web_scan = None


def _load_network():
    global _network_scan
    if _network_scan is None:
        from .network_scanner import network_scan as _fn
        _network_scan = _fn
    return _network_scan


def _load_web():
    global _web_scan
    if _web_scan is None:
        from .web_scanner import web_scan as _fn
        _web_scan = _fn
    return _web_scan


def network_scan(target, scan_type):
    """Run a network scan. See ``scanner.network_scanner.network_scan``."""
    try:
        return _load_network()(target, scan_type)
    except ImportError as e:
        return {"error": f"network_scanner unavailable: {e}"}


def web_scan(target, scan_type):
    """Run a website scan. See ``scanner.web_scanner.web_scan``."""
    try:
        return _load_web()(target, scan_type)
    except ImportError as e:
        return {"error": f"web_scanner unavailable: {e}"}


__all__ = ["network_scan", "web_scan", "__version__"]