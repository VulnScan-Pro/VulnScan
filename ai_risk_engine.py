# ai_risk_engine.py
import json
import re
import sqlite3
import logging
from contextlib import contextmanager
from datetime import datetime

import config

log = logging.getLogger(__name__)

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}")
ENGINE_VERSION = "2024-11-05-strict"


def extract_actionable_cves(result: dict) -> set:
    cves: set = set()
    if isinstance(result, dict):
        for c in result.get("CVE Vulnerabilities", []) or []:
            if isinstance(c, str) and CVE_RE.fullmatch(c.strip()):
                cves.add(c.strip())
    return cves


class AIRiskEngine:
    def __init__(self, db_path=None):
        self.db_path = db_path or config.DB_PATH

    @contextmanager
    def _conn(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        finally:
            conn.close()

    def is_score_stale(self, scan_id):
        with self._conn() as conn:
            cols = [c[1] for c in conn.execute("PRAGMA table_info(ai_risk_scores)")]
            if "engine_version" not in cols:
                return True
            row = conn.execute(
                "SELECT engine_version FROM ai_risk_scores WHERE scan_id=?",
                (scan_id,),
            ).fetchone()
            if not row:
                return True
            return (row["engine_version"] or "") != ENGINE_VERSION

    def calculate_risk_score(self, scan_id):
        with self._conn() as conn:
            row = conn.execute(
                "SELECT result, scan_category FROM scan_history WHERE id=?",
                (scan_id,),
            ).fetchone()
        if not row:
            return None
        result = json.loads(row["result"] or "{}")
        category = row["scan_category"]

        # 1. CVE Component
        cves = extract_actionable_cves(result)
        cve_score = min(len(cves) / 10.0, 1.0)

        # 2. Parsed Findings Component (New)
        findings = result.get("findings", [])
        critical_count = sum(1 for f in findings if f.get("severity") == "Critical")
        high_count = sum(1 for f in findings if f.get("severity") == "High")
        medium_count = sum(1 for f in findings if f.get("severity") == "Medium")
        
        findings_penalty = 0.0
        if critical_count > 0:
            findings_penalty += 0.60
        if high_count > 0:
            findings_penalty += 0.40
        if medium_count > 0:
            findings_penalty += 0.20
            
        has_actionable_finding = (critical_count + high_count + medium_count) > 0

        # 3. Web vulnerability flags (legacy)
        web_hits = 0
        if isinstance(result, dict):
            if result.get("XSS Vulnerable") is True: web_hits += 1
            if result.get("SQL Injection Vulnerable") is True: web_hits += 1
            for key in ("xss_scan", "sql_injection_scan"):
                sub = result.get(key)
                if isinstance(sub, dict) and sub.get("vulnerable") is True:
                    web_hits += 1
        web_score = min(web_hits / 3.0, 1.0)

        # 4. Base Score Calculation
        if category == "website":
            base = (web_score * 0.45 + cve_score * 0.35 + findings_penalty + 0.10)
        else:
            base = (findings_penalty + cve_score * 0.45 + 0.05)

        base = max(0.0, min(base, 1.0))

        exploitation_probability = round((cve_score * 0.7 + web_score * 0.3) * 100, 1)
        threat_intel_score = round(cve_score * 100, 1)
        attack_surface_score = round(max(web_score, findings_penalty) * 100, 1)
        risk_score = int(round(base * 1000, 0))

        # 5. Risk Level
        if risk_score >= 750:
            level = "Critical"
        elif risk_score >= 500:
            level = "High"
        elif risk_score >= 250:
            level = "Medium"
        else:
            level = "Low"

        # Guard clauses
        if level in ("Critical", "High") and not has_actionable_finding and not cves:
            level = "Medium"

        zero_findings = (
            not cves and not has_actionable_finding and 
            web_hits == 0 and findings_penalty == 0
        )
        if zero_findings:
            level = "Low"

        impact_map = {
            "Critical": "Immediate exploitation likely. Potential full system compromise.",
            "High": "Significant exposure. Attackers could gain unauthorized access.",
            "Medium": "Notable gaps. Requires chained attacks.",
            "Low": "Low exposure. Standard hardening recommended.",
        }

        return {
            "risk_score": risk_score,
            "risk_level": level,
            "business_impact": impact_map[level],
            "asset_criticality": 60.0,
            "exploitation_probability": exploitation_probability,
            "threat_intel_score": threat_intel_score,
            "attack_surface_score": attack_surface_score,
            "components": {
                "cve_score": round(cve_score * 100, 1),
                "findings_penalty": round(findings_penalty * 100, 1),
                "business_context": round(base * 100, 1),
            },
        }

    def save_risk_score(self, scan_id, risk_data):
        with self._conn() as conn:
            cols = [c[1] for c in conn.execute("PRAGMA table_info(ai_risk_scores)")]
            if "engine_version" not in cols:
                conn.execute("ALTER TABLE ai_risk_scores ADD COLUMN engine_version TEXT DEFAULT ''")
            conn.execute("DELETE FROM ai_risk_scores WHERE scan_id=?", (scan_id,))
            conn.execute("""
                INSERT INTO ai_risk_scores
                    (scan_id, risk_score, risk_level, business_impact,
                     asset_criticality, exploitation_probability,
                     threat_intel_score, attack_surface_score, engine_version)
                VALUES (?,?,?,?,?,?,?,?,?)
            """, (
                scan_id, risk_data["risk_score"], risk_data["risk_level"],
                risk_data["business_impact"], risk_data["asset_criticality"],
                risk_data["exploitation_probability"], risk_data["threat_intel_score"],
                risk_data["attack_surface_score"], ENGINE_VERSION,
            ))
            conn.execute("""
                INSERT INTO risk_history (scan_id, risk_score, risk_level, date)
                VALUES (?,?,?,?)
            """, (
                scan_id, risk_data["risk_score"], risk_data["risk_level"],
                datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            ))
            conn.commit()

    def get_remediation_recommendations(self, scan_id, risk_data):
        level = (risk_data or {}).get("risk_level", "Low")
        recs = []
        if level in ("Critical", "High"):
            recs.append({
                "priority": "CRITICAL" if level == "Critical" else "HIGH",
                "action": "Patch the identified vulnerabilities immediately.",
                "timeline": "Within 48 hours",
                "steps": ["Review the raw scan output.", "Apply vendor patches.", "Re-scan to verify."],
            })
        return recs

    def get_risk_trending(self, scan_id):
        with self._conn() as conn:
            rows = conn.execute("SELECT scan_id, risk_score, risk_level, date FROM risk_history ORDER BY date DESC LIMIT 20").fetchall()
        return [dict(r) for r in rows]

    def generate_nlp_context(self, scan_id, result):
        return []