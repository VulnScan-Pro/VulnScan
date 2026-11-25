# cve_enrichment.py
"""
CVE Enrichment Module.
Fetches CVSS from NVD and EPSS from FIRST.org, caches in SQLite.

Fixes:
  H3 — no silent except; failures logged
  M8 — timestamps compared as UTC epoch, not strings
"""

import sqlite3
import json
import logging
import time
from datetime import datetime, timezone

import requests

import config

log = logging.getLogger(__name__)

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EPSS_API = "https://api.first.org/data/v1/epss"
CACHE_TTL_SECONDS = 30 * 24 * 3600   # 30 days
REQUEST_TIMEOUT = 10


def init_cache_table():
    conn = sqlite3.connect(config.DB_PATH)
    try:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS cve_cache (
                cve_id TEXT PRIMARY KEY,
                cvss_score REAL,
                cvss_severity TEXT,
                cvss_vector TEXT,
                epss_score REAL,
                epss_percentile REAL,
                description TEXT,
                published_date TEXT,
                references_json TEXT,
                fetched_epoch INTEGER DEFAULT 0
            )
        """)
        conn.commit()
    finally:
        conn.close()


def _now_epoch() -> int:
    return int(datetime.now(timezone.utc).timestamp())


def _is_cache_fresh(cve_id: str) -> bool:
    """M8 fix — compare integer epochs, not strings."""
    conn = sqlite3.connect(config.DB_PATH)
    try:
        row = conn.execute(
            "SELECT fetched_epoch FROM cve_cache WHERE cve_id=?", (cve_id,)
        ).fetchone()
    finally:
        conn.close()
    if not row:
        return False
    fetched = row[0] or 0
    return (_now_epoch() - fetched) < CACHE_TTL_SECONDS


def _get_cached_cve(cve_id: str):
    conn = sqlite3.connect(config.DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        row = conn.execute(
            "SELECT * FROM cve_cache WHERE cve_id=?", (cve_id,)
        ).fetchone()
    finally:
        conn.close()
    if not row:
        return None
    return {
        "cve_id": row["cve_id"],
        "cvss_score": row["cvss_score"],
        "cvss_severity": row["cvss_severity"],
        "cvss_vector": row["cvss_vector"],
        "epss_score": row["epss_score"],
        "epss_percentile": row["epss_percentile"],
        "description": row["description"],
        "published_date": row["published_date"],
        "references": json.loads(row["references_json"]) if row["references_json"] else [],
    }


def _save_cve_to_cache(cve_data):
    conn = sqlite3.connect(config.DB_PATH)
    try:
        conn.execute("""
            INSERT OR REPLACE INTO cve_cache
            (cve_id, cvss_score, cvss_severity, cvss_vector,
             epss_score, epss_percentile, description, published_date,
             references_json, fetched_epoch)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            cve_data.get("cve_id"),
            cve_data.get("cvss_score"),
            cve_data.get("cvss_severity"),
            cve_data.get("cvss_vector"),
            cve_data.get("epss_score"),
            cve_data.get("epss_percentile"),
            cve_data.get("description", ""),
            cve_data.get("published_date", ""),
            json.dumps(cve_data.get("references", [])),
            _now_epoch(),
        ))
        conn.commit()
    finally:
        conn.close()


def fetch_nvd_data(cve_id):
    try:
        r = requests.get(
            f"{NVD_API}?cveId={cve_id}",
            headers={"User-Agent": "VulnScanPro/1.0"},
            timeout=REQUEST_TIMEOUT,
        )
        if r.status_code != 200:
            log.warning("[nvd] %s returned %s", cve_id, r.status_code)
            return None
        data = r.json()
        if not data.get("vulnerabilities"):
            return None
        vuln = data["vulnerabilities"][0]["cve"]
        metrics = vuln.get("metrics", {})

        cvss_score = cvss_severity = cvss_vector = None
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if metrics.get(key):
                m = metrics[key][0]
                cvss_score = m["cvssData"].get("baseScore")
                cvss_severity = m["cvssData"].get("baseSeverity") or m.get("baseSeverity")
                cvss_vector = m["cvssData"].get("vectorString")
                break

        description = ""
        for d in vuln.get("descriptions", []):
            if d.get("lang") == "en":
                description = d.get("value", "")
                break

        references = [
            {"url": ref.get("url"), "source": ref.get("source", "")}
            for ref in vuln.get("references", [])[:5]
        ]
        return {
            "cvss_score": cvss_score,
            "cvss_severity": cvss_severity,
            "cvss_vector": cvss_vector,
            "description": description[:500],
            "published_date": vuln.get("published", ""),
            "references": references,
        }
    except requests.exceptions.Timeout:
        log.warning("[nvd] timeout for %s", cve_id)
        return None
    except Exception as e:
        log.warning("[nvd] error for %s: %s", cve_id, e)
        return None


def fetch_epss_data(cve_id):
    try:
        r = requests.get(f"{EPSS_API}?cve={cve_id}", timeout=REQUEST_TIMEOUT)
        if r.status_code != 200:
            return None
        data = r.json()
        if not data.get("data"):
            return None
        e = data["data"][0]
        return {
            "epss_score": float(e.get("epss", 0)),
            "epss_percentile": float(e.get("percentile", 0)),
        }
    except requests.exceptions.Timeout:
        log.warning("[epss] timeout for %s", cve_id)
        return None
    except Exception as e:
        log.warning("[epss] error for %s: %s", cve_id, e)
        return None


def enrich_cve(cve_id, force_refresh=False):
    cve_id = cve_id.upper().strip()
    if not force_refresh and _is_cache_fresh(cve_id):
        cached = _get_cached_cve(cve_id)
        if cached:
            return cached

    nvd = fetch_nvd_data(cve_id)
    epss = fetch_epss_data(cve_id)

    data = {
        "cve_id": cve_id,
        "cvss_score": nvd.get("cvss_score") if nvd else None,
        "cvss_severity": nvd.get("cvss_severity") if nvd else None,
        "cvss_vector": nvd.get("cvss_vector") if nvd else None,
        "description": nvd.get("description", "") if nvd else "",
        "published_date": nvd.get("published_date", "") if nvd else "",
        "references": nvd.get("references", []) if nvd else [],
        "epss_score": epss.get("epss_score") if epss else None,
        "epss_percentile": epss.get("epss_percentile") if epss else None,
    }
    if data["cvss_score"] or data["epss_score"]:
        _save_cve_to_cache(data)
    return data


def enrich_cves_bulk(cve_list, delay=0.7):
    results = {}
    total = len(cve_list)
    for idx, cve in enumerate(cve_list):
        cve_clean = cve.upper().strip()
        log.info("[enrich] %d/%d %s", idx + 1, total, cve_clean)
        try:
            results[cve_clean] = enrich_cve(cve_clean)
        except Exception as e:
            log.exception("[enrich] failed for %s", cve_clean)
            results[cve_clean] = {
                "cve_id": cve_clean, "cvss_score": None, "cvss_severity": None,
                "cvss_vector": None, "epss_score": None, "epss_percentile": None,
                "description": "", "published_date": "", "references": [],
            }
        if idx < total - 1:
            time.sleep(delay)
    return results


def get_enriched_cve(cve_id):
    return _get_cached_cve(cve_id.upper().strip())


def get_all_cached_cves(cve_list):
    return {c.upper().strip(): get_enriched_cve(c) for c in cve_list}


init_cache_table()