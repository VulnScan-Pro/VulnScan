# app.py
"""
VulnScan Pro Flask application — custom-command mode.
"""

import io
import json
import csv
import sqlite3
import logging

from flask import (
    Flask, render_template, request, redirect, session, jsonify,
    flash, send_file, Response, abort,
)

import config
from scanner.web_scanner import run_custom_command, web_scan
from ai_risk_engine import AIRiskEngine, extract_actionable_cves
from ai_providers import (
    save_api_key, get_api_key, get_masked_keys, delete_api_key,
    set_active_provider, get_active_provider, get_ai_provider,
)
from cve_enrichment import enrich_cves_bulk, get_enriched_cve

try:
    from weasyprint import HTML
    WEASYPRINT_AVAILABLE = True
    WEASYPRINT_ERROR = None
except Exception as e:
    WEASYPRINT_AVAILABLE = False
    WEASYPRINT_ERROR = str(e)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
log = logging.getLogger("app")

app = Flask(__name__)
app.secret_key = config.SECRET_KEY
ai_engine = AIRiskEngine()

MAX_CHAT_SCAN_CHARS = 20000


# ---------------------------------------------------------------------------
# DB helper
# ---------------------------------------------------------------------------
def get_db():
    conn = sqlite3.connect(config.DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def ensure_database_schema():
    conn = get_db()
    try:
        cur = conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS scan_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_name TEXT, target TEXT, scan_category TEXT, scan_type TEXT,
                result TEXT, severity TEXT, status TEXT, progress INTEGER,
                qod TEXT, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS ai_risk_scores (
                id INTEGER PRIMARY KEY AUTOINCREMENT, scan_id INTEGER UNIQUE,
                risk_score REAL DEFAULT 0, risk_level TEXT DEFAULT 'Low',
                business_impact TEXT DEFAULT '', asset_criticality REAL DEFAULT 0,
                exploitation_probability REAL DEFAULT 0, threat_intel_score REAL DEFAULT 0,
                attack_surface_score REAL DEFAULT 0, engine_version TEXT DEFAULT ''
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS risk_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT, scan_id INTEGER,
                risk_score REAL, risk_level TEXT, date TEXT
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS ai_findings_context (
                id INTEGER PRIMARY KEY AUTOINCREMENT, scan_id INTEGER, context TEXT
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS cve_watchlist (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                cve_id TEXT UNIQUE, added_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS scan_chats (
                id INTEGER PRIMARY KEY AUTOINCREMENT, scan_id INTEGER,
                role TEXT, content TEXT, timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        cur.execute("PRAGMA table_info(ai_risk_scores)")
        cols = [c[1] for c in cur.fetchall()]
        if "attack_surface_score" not in cols:
            cur.execute("ALTER TABLE ai_risk_scores ADD COLUMN attack_surface_score REAL DEFAULT 0")
        if "engine_version" not in cols:
            cur.execute("ALTER TABLE ai_risk_scores ADD COLUMN engine_version TEXT DEFAULT ''")
        cur.execute("DELETE FROM scan_chats WHERE scan_id NOT IN (SELECT id FROM scan_history)")
        conn.commit()
        log.info("[schema] database OK")
    except Exception:
        log.exception("[schema] migration failed")
        raise
    finally:
        conn.close()


ensure_database_schema()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def save_scan(scan_name, target, category, scan_type, result, qod):
    conn = get_db()
    try:
        text = json.dumps(result).lower()
        if any(x in text for x in ("cve", "vulnerab", "xss", "sql injection", "exploit")):
            severity = "High"
        elif any(x in text for x in ("open", "port", "detected")):
            severity = "Medium"
        else:
            severity = "Low"
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO scan_history
                (scan_name, target, scan_category, scan_type, result,
                 severity, status, progress, qod)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (scan_name, target, category, scan_type, json.dumps(result),
              severity, "Completed", 100, qod))
        conn.commit()
        return cur.lastrowid
    finally:
        conn.close()


def get_history():
    conn = get_db()
    try:
        rows = conn.execute("""
            SELECT sh.id, sh.scan_name, sh.target, sh.scan_category, sh.scan_type,
                   COALESCE(ars.risk_level, sh.severity) AS severity,
                   sh.status, sh.progress, sh.qod, sh.created_at,
                   COALESCE(ars.risk_score, 0) AS ai_risk_score
            FROM scan_history sh
            LEFT JOIN ai_risk_scores ars ON sh.id = ars.scan_id
            ORDER BY sh.id DESC
        """).fetchall()
    finally:
        conn.close()
    return rows


def normalize_severity(sev_str):
    if not sev_str:
        return "Medium"
    s = sev_str.strip().lower()
    for token in ("critical", "high", "medium", "low", "info"):
        if token in s:
            return token.capitalize() if token != "info" else "Informational"
    return "Medium"


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------
@app.route("/")
def index():
    return redirect("/dashboard")


@app.route("/dashboard", methods=["GET", "POST"])
def dashboard():
    if request.method == "POST":
        scan_name = request.form.get("scan_name", "").strip()
        scan_type = request.form.get("scan_type")   # e.g. "nmap", "nuclei"
        command   = request.form.get("command", "").strip()
        target    = request.form.get("target", "").strip()

        if not scan_name or not command:
            flash("Scan name and command are required", "error")
            return redirect("/dashboard")

        category = "network" if command.lower().startswith("nmap") else "website"
        
        result = None
        scan_id = None

        try:
            timeout = config.SCAN_TIMEOUT_SQLMAP if "sqlmap" in command.lower() else (
                config.SCAN_TIMEOUT_NUCLEI if "nuclei" in command.lower() else 600
            )
            result = run_custom_command(command, target=target, timeout=timeout)
        except Exception:
            log.exception("[dashboard] command execution failed")
            flash("Command execution failed — see server logs", "error")
            return redirect("/dashboard")

        if isinstance(result, dict) and "error" in result and "findings" not in result:
            flash(f"Scan failed: {result['error']}", "error")
            return redirect("/dashboard")

        scan_id = save_scan(scan_name, target or "(none)", category, scan_type, result, "N/A")

        if scan_id and result:
            try:
                cves = extract_actionable_cves(result)
                if cves:
                    enrich_cves_bulk(sorted(cves), delay=0.7)
            except Exception:
                log.exception("[dashboard] CVE enrichment failed")
            try:
                risk = ai_engine.calculate_risk_score(scan_id)
                if risk:
                    ai_engine.save_risk_score(scan_id, risk)
            except Exception:
                log.exception("[dashboard] risk scoring failed")

        return redirect("/dashboard")

    history = get_history()
    conn = get_db()
    try:
        watchlist = conn.execute("SELECT * FROM cve_watchlist ORDER BY added_date DESC").fetchall()
    finally:
        conn.close()
    return render_template(
        "index.html", history=history,
        active_provider=get_active_provider(), watchlist=watchlist,
        allowed_prefixes=sorted(config.ALLOWED_COMMAND_PREFIXES),
    )


# ---------------------------------------------------------------------------
# Guide & Settings
# ---------------------------------------------------------------------------
@app.route("/guide")
def guide():
    return render_template("guide.html", active_provider=get_active_provider())

@app.route("/settings")
def settings():
    return render_template(
        "settings.html",
        masked_keys=get_masked_keys(),
        active_provider=get_active_provider(),
        configured={p: bool(get_api_key(p)) for p in config.ALLOWED_PROVIDERS},
    )

@app.route("/settings/save_key", methods=["POST"])
def save_key_route():
    provider = request.form.get("provider")
    api_key = request.form.get("api_key", "").strip()
    if provider not in config.ALLOWED_PROVIDERS or not api_key:
        flash("Provider and API key are required", "error")
        return redirect("/settings")
    try:
        save_api_key(provider, api_key)
        if not get_active_provider():
            set_active_provider(provider)
        flash(f"{provider.upper()} key saved", "success")
    except Exception:
        log.exception("[settings] save_key")
        flash("Failed to save API key", "error")
    return redirect("/settings")


@app.route("/settings/set_active", methods=["POST"])
def set_active_route():
    data = request.get_json(silent=True) or {}
    provider = data.get("provider")
    if provider not in config.ALLOWED_PROVIDERS or not get_api_key(provider):
        return jsonify({"success": False, "error": "Invalid provider"}), 400
    set_active_provider(provider)
    return jsonify({"success": True})


@app.route("/settings/delete_key/<provider>", methods=["POST"])
def delete_key_route(provider):
    if provider not in config.ALLOWED_PROVIDERS:
        abort(400)
    delete_api_key(provider)
    flash(f"{provider.upper()} key deleted", "success")
    return redirect("/settings")


# ---------------------------------------------------------------------------
# Watchlist / Email / Chat
# ---------------------------------------------------------------------------
@app.route("/api/watchlist/add", methods=["POST"])
def add_watchlist():
    data = request.get_json(silent=True) or {}
    cve_id = data.get("cve_id", "").strip().upper()
    if not cve_id.startswith("CVE-"):
        return jsonify({"error": "Invalid CVE format"}), 400
    conn = get_db()
    try:
        conn.execute("INSERT OR IGNORE INTO cve_watchlist (cve_id) VALUES (?)", (cve_id,))
        conn.commit()
    finally:
        conn.close()
    return jsonify({"success": True})


@app.route("/api/watchlist/remove/<cve_id>", methods=["POST"])
def remove_watchlist(cve_id):
    conn = get_db()
    try:
        conn.execute("DELETE FROM cve_watchlist WHERE cve_id=?", (cve_id,))
        conn.commit()
    finally:
        conn.close()
    return jsonify({"success": True})


@app.route("/api/email_security", methods=["POST"])
def email_security():
    target = (request.get_json(silent=True) or {}).get("target", "").strip()
    if not target:
        return jsonify({"error": "Target required"}), 400
    try:
        import dns.resolver
    except ImportError:
        return jsonify({"error": "Missing 'dnspython'. Run: pip install dnspython"}), 500
    try:
        canonical = config.validate_web_target(target)
    except config.TargetValidationError as e:
        return jsonify({"error": str(e)}), 400
    from urllib.parse import urlparse
    domain = urlparse(canonical).hostname

    results = {"spf": "None", "dmarc": "None", "dkim": "None"}
    try:
        try:
            for rdata in dns.resolver.resolve(domain, "TXT"):
                if "v=spf1" in str(rdata):
                    results["spf"] = str(rdata)
        except Exception:
            pass
        try:
            for rdata in dns.resolver.resolve(f"_dmarc.{domain}", "TXT"):
                if "v=DMARC1" in str(rdata):
                    results["dmarc"] = str(rdata)
        except Exception:
            pass
        for sel in ("default", "google", "selector1"):
            try:
                dns.resolver.resolve(f"{sel}._domainkey.{domain}", "TXT")
                results["dkim"] = f"Found at selector: {sel}"
                break
            except Exception:
                continue
        return jsonify({"success": True, "data": results})
    except Exception as e:
        log.exception("[email_security]")
        return jsonify({"error": str(e)}), 500


@app.route("/api/chat/<int:scan_id>", methods=["POST"])
def chat_with_scan(scan_id):
    body = request.get_json(silent=True) or {}
    user_msg = (body.get("message") or "").strip()
    if not user_msg:
        return jsonify({"error": "Message required"}), 400
    conn = get_db()
    try:
        row = conn.execute("SELECT result FROM scan_history WHERE id=?", (scan_id,)).fetchone()
    finally:
        conn.close()
    if not row:
        return jsonify({"error": "Scan not found"}), 404
    provider_name = get_active_provider()
    ai_provider = get_ai_provider()
    if not ai_provider:
        return jsonify({"error": "No AI provider configured. Go to Settings."}), 400
    scan_data = row["result"] or ""
    if len(scan_data) > MAX_CHAT_SCAN_CHARS:
        scan_data = scan_data[:MAX_CHAT_SCAN_CHARS] + "\n\n... [truncated]"
    system_prompt = (
        f"You are a helpful cybersecurity assistant running on {provider_name.upper()}. "
        "Answer based ONLY on the scan data provided."
    )
    prompt = f"Scan JSON:\n\n{scan_data}\n\nQuestion: {user_msg}"
    try:
        response_text = str(ai_provider.generate(system_prompt=system_prompt, user_prompt=prompt, max_tokens=1000))
    except Exception as e:
        log.exception("[chat]")
        return jsonify({"error": f"AI Error: {e}"}), 500
    conn = get_db()
    try:
        conn.execute("INSERT INTO scan_chats (scan_id, role, content) VALUES (?, ?, ?)", (scan_id, "user", user_msg))
        conn.execute("INSERT INTO scan_chats (scan_id, role, content) VALUES (?, ?, ?)", (scan_id, "assistant", response_text))
        conn.commit()
    finally:
        conn.close()
    return jsonify({"success": True, "response": response_text})


# ---------------------------------------------------------------------------
# View scan
# ---------------------------------------------------------------------------
@app.route("/view_scan/<int:scan_id>")
def view_scan(scan_id):
    try:
        if ai_engine.is_score_stale(scan_id):
            fresh = ai_engine.calculate_risk_score(scan_id)
            if fresh:
                ai_engine.save_risk_score(scan_id, fresh)
    except Exception:
        log.exception("[view_scan] risk recalc")

    conn = get_db()
    try:
        row = conn.execute("""
            SELECT sh.result, sh.scan_name, sh.scan_category, sh.scan_type,
                   COALESCE(ars.risk_score, 0) AS risk_score,
                   COALESCE(ars.risk_level, sh.severity) AS risk_level,
                   COALESCE(ars.business_impact, 'Not analyzed') AS business_impact,
                   COALESCE(ars.asset_criticality, 0) AS asset_criticality,
                   COALESCE(ars.exploitation_probability, 0) AS exploitation_probability,
                   COALESCE(ars.threat_intel_score, 0) AS threat_intel_score
            FROM scan_history sh
            LEFT JOIN ai_risk_scores ars ON sh.id = ars.scan_id
            WHERE sh.id=?
        """, (scan_id,)).fetchone()
        chats = conn.execute("SELECT * FROM scan_chats WHERE scan_id=? ORDER BY id ASC", (scan_id,)).fetchall()
    finally:
        conn.close()
    if not row:
        abort(404)

    result = json.loads(row["result"])
    cves = sorted(extract_actionable_cves(result))
    enriched_cves = [{"cve_id": c, "data": get_enriched_cve(c)} for c in cves[:20]]

    findings_list = result.get("findings", [])
    chart_data = {"scan_category": row["scan_category"], "cve_count": len(cves)}

    return render_template(
        "scan_result.html", result=result, scan_name=row["scan_name"],
        chart_data=chart_data, scan_id=scan_id, risk_score=row["risk_score"],
        risk_level=row["risk_level"], business_impact=row["business_impact"],
        asset_criticality=row["asset_criticality"],
        exploitation_probability=row["exploitation_probability"],
        threat_intel_score=row["threat_intel_score"],
        active_provider=get_active_provider(),
        enriched_cves=enriched_cves, chats=chats, findings_list=findings_list,
    )


# ---------------------------------------------------------------------------
# Exports, PDF, Delete, Compare
# ---------------------------------------------------------------------------
@app.route("/export/json/<int:scan_id>")
def export_json(scan_id):
    conn = get_db()
    try:
        row = conn.execute("SELECT result FROM scan_history WHERE id=?", (scan_id,)).fetchone()
    finally:
        conn.close()
    if not row:
        abort(404)
    return Response(row["result"], mimetype="application/json",
                    headers={"Content-Disposition": f"attachment;filename=scan_{scan_id}.json"})

@app.route("/export/csv/<int:scan_id>")
def export_csv(scan_id):
    conn = get_db()
    try:
        row = conn.execute("SELECT result FROM scan_history WHERE id=?", (scan_id,)).fetchone()
    finally:
        conn.close()
    if not row:
        abort(404)
    result = json.loads(row["result"])
    output = io.StringIO()
    w = csv.writer(output)
    w.writerow(["Key", "Value"])
    for k, v in result.items():
        w.writerow([k, str(v)])
    return Response(output.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition": f"attachment;filename=scan_{scan_id}.csv"})

@app.route("/download_report/<int:scan_id>")
def download_report(scan_id):
    if not WEASYPRINT_AVAILABLE:
        return f"PDF generation unavailable: {WEASYPRINT_ERROR}", 500, {"Content-Type": "text/plain"}
    conn = get_db()
    try:
        row = conn.execute("""
            SELECT sh.result, sh.scan_name, sh.scan_type, sh.scan_category,
                   sh.qod, sh.created_at, sh.target,
                   COALESCE(ars.risk_score, 0) AS risk_score,
                   COALESCE(ars.risk_level, sh.severity) AS risk_level,
                   COALESCE(ars.business_impact, '') AS business_impact,
                   COALESCE(ars.asset_criticality, 0) AS asset_criticality,
                   COALESCE(ars.exploitation_probability, 0) AS exploitation_prob,
                   COALESCE(ars.threat_intel_score, 0) AS threat_intel_score
            FROM scan_history sh
            LEFT JOIN ai_risk_scores ars ON sh.id = ars.scan_id
            WHERE sh.id=?
        """, (scan_id,)).fetchone()
    finally:
        conn.close()
    if not row:
        abort(404)
    result = json.loads(row["result"])
    cves = sorted(extract_actionable_cves(result))
    findings_list = result.get("findings", [])
    severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Informational": 0}
    for f in findings_list:
        sev = f.get("severity", "Low")
        severity_counts[sev if sev in severity_counts else "Informational"] += 1
    executive_summary = f"<p>Command-based scan of {row['target']}.</p>"
    strengths_weaknesses = "<ul><li>Review findings above.</li></ul>"
    template = ("report.html", f"Report_{row['scan_name']}.pdf")
    try:
        html_content = render_template(
            template[0],
            scan_name=row["scan_name"], scan_type=row["scan_type"],
            scan_category=row["scan_category"], qod=row["qod"],
            date=row["created_at"], target=row["target"], result=result,
            risk_score=row["risk_score"], risk_level=row["risk_level"],
            business_impact=row["business_impact"],
            asset_criticality=row["asset_criticality"],
            exploitation_prob=row["exploitation_prob"],
            threat_intel_score=row["threat_intel_score"],
            recommendations=[], nlp_context=[],
            executive_summary=executive_summary,
            strengths_weaknesses=strengths_weaknesses,
            findings_list=findings_list, severity_counts=severity_counts,
            report_type=request.args.get("type", "full"),
        )
        pdf = HTML(string=html_content).write_pdf()
        return send_file(io.BytesIO(pdf), mimetype="application/pdf",
                         as_attachment=False, download_name=template[1])
    except Exception as e:
        log.exception("[pdf]")
        return f"PDF generation failed: {e}", 500, {"Content-Type": "text/plain"}

@app.route("/api/ai_risk_analysis/<int:scan_id>")
def ai_risk_analysis(scan_id):
    try:
        risk = ai_engine.calculate_risk_score(scan_id)
        if not risk:
            return jsonify({"error": "Scan not found"}), 404
        ai_engine.save_risk_score(scan_id, risk)
        return jsonify({
            "success": True, "risk_data": risk,
            "recommendations": ai_engine.get_remediation_recommendations(scan_id, risk),
            "trending": ai_engine.get_risk_trending(scan_id),
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/delete_scan/<int:scan_id>", methods=["POST"])
def delete_scan(scan_id):
    conn = get_db()
    try:
        conn.execute("DELETE FROM scan_history WHERE id=?", (scan_id,))
        conn.execute("DELETE FROM ai_risk_scores WHERE scan_id=?", (scan_id,))
        conn.execute("DELETE FROM scan_chats WHERE scan_id=?", (scan_id,))
        conn.commit()
    finally:
        conn.close()
    return jsonify({"success": True})

@app.route("/delete_all_scans", methods=["POST"])
def delete_all_scans():
    conn = get_db()
    try:
        for t in ("scan_history", "ai_risk_scores", "scan_chats", "risk_history"):
            conn.execute(f"DELETE FROM {t}")
        conn.commit()
    finally:
        conn.close()
    return jsonify({"success": True})

@app.route("/compare")
@app.route("/compare/<int:scan_a>/<int:scan_b>")
def compare(scan_a=0, scan_b=0):
    history = get_history()
    if not scan_a or not scan_b:
        return render_template("compare.html", history=history, comparison=None)
    def _load(scan_id):
        conn = get_db()
        try:
            return conn.execute("""
                SELECT sh.id, sh.scan_name, sh.target, sh.scan_type, sh.created_at, sh.result,
                       COALESCE(ars.risk_score, 0) AS risk_score,
                       COALESCE(ars.risk_level, sh.severity) AS risk_level
                FROM scan_history sh
                LEFT JOIN ai_risk_scores ars ON sh.id = ars.scan_id
                WHERE sh.id=?
            """, (scan_id,)).fetchone()
        finally:
            conn.close()
    a = _load(scan_a); b = _load(scan_b)
    if not a or not b:
        flash("One or both scans not found", "error")
        return redirect("/compare")
    set_a = extract_actionable_cves(json.loads(a["result"]))
    set_b = extract_actionable_cves(json.loads(b["result"]))
    comparison = {
        "scan_a": {"id": a["id"], "name": a["scan_name"], "date": a["created_at"],
                   "target": a["target"], "type": a["scan_type"],
                   "risk_score": a["risk_score"], "risk_level": a["risk_level"],
                   "cve_count": len(set_a)},
        "scan_b": {"id": b["id"], "name": b["scan_name"], "date": b["created_at"],
                   "target": b["target"], "type": b["scan_type"],
                   "risk_score": b["risk_score"], "risk_level": b["risk_level"],
                   "cve_count": len(set_b)},
        "risk_delta": (b["risk_score"] or 0) - (a["risk_score"] or 0),
        "new_vulns": sorted(set_b - set_a),
        "fixed_vulns": sorted(set_a - set_b),
        "persistent_vulns": sorted(set_a & set_b),
        "enriched_new": {c: get_enriched_cve(c) for c in (set_b - set_a)},
    }
    return render_template("compare.html", history=history, comparison=comparison)


@app.errorhandler(404)
def not_found(_):
    return "Not found", 404


@app.errorhandler(500)
def internal_error(_):
    return "Internal Server Error", 500


if __name__ == "__main__":
    app.run(host=config.HOST, port=config.PORT, debug=config.DEBUG)