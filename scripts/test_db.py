# scripts/test_db.py
import sys, os, sqlite3

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
import config

conn = sqlite3.connect(config.DB_PATH)
cur = conn.cursor()

cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
tables = [r[0] for r in cur.fetchall()]
print("Tables:", tables)

orphans = cur.execute(
    "SELECT COUNT(*) FROM ai_risk_scores "
    "WHERE scan_id NOT IN (SELECT id FROM scan_history)"
).fetchone()[0]
print("Orphan risk rows:", orphans)

scan_count = cur.execute("SELECT COUNT(*) FROM scan_history").fetchone()[0]
score_count = cur.execute("SELECT COUNT(*) FROM ai_risk_scores").fetchone()[0]
hist_count = cur.execute("SELECT COUNT(*) FROM risk_history").fetchone()[0]
print(f"Scans: {scan_count} | Scores: {score_count} | History: {hist_count}")

conn.close()