# scripts/reset_scores.py
import sys, os, sqlite3

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
import config

conn = sqlite3.connect(config.DB_PATH)
try:
    conn.execute("DELETE FROM ai_risk_scores")
    conn.execute("DELETE FROM risk_history")
    conn.commit()
finally:
    conn.close()

print("Cleared stale scores. Re-open any scan to recompute.")