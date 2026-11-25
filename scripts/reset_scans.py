# scripts/reset_scans.py
import sys, os, sqlite3

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
import config

conn = sqlite3.connect(config.DB_PATH)
try:
    for t in ("scan_history", "ai_risk_scores", "risk_history",
              "ai_findings_context", "scan_chats", "cve_watchlist"):
        conn.execute(f"DELETE FROM {t}")
    conn.commit()
finally:
    conn.close()

print("✔ All scans, scores, history, chats, and watchlist cleared")
print("  (API keys preserved)")