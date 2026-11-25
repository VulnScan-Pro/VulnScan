# scripts/db_check.py
import sys, os, json, sqlite3

# Allow imports from project root regardless of cwd
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
import config

DB = config.DB_PATH

if not os.path.exists(DB):
    print(f"[!] {DB} does not exist — Flask will create it on first run")
    sys.exit(0)

conn = sqlite3.connect(DB)
cur = conn.cursor()

print("=== Database health check ===\n")

required = [
    "scan_history", "ai_risk_scores", "risk_history",
    "ai_findings_context", "cve_watchlist", "scan_chats",
]
cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
present = {r[0] for r in cur.fetchall()}
missing = [t for t in required if t not in present]
print(f"  Tables present: {sorted(present)}")
print(f"  ✔ All required tables present" if not missing
      else f"  ⚠ Missing: {missing} (Flask will create them on next run)")

orphans = cur.execute(
    "SELECT COUNT(*) FROM ai_risk_scores WHERE scan_id NOT IN (SELECT id FROM scan_history)"
).fetchone()[0]
if orphans:
    print(f"  ⚠ {orphans} orphan risk row(s) — cleaning")
    cur.execute("DELETE FROM ai_risk_scores WHERE scan_id NOT IN (SELECT id FROM scan_history)")
    conn.commit()
else:
    print("  ✔ No orphan risk scores")

no_score = cur.execute(
    "SELECT COUNT(*) FROM scan_history sh "
    "LEFT JOIN ai_risk_scores ars ON sh.id = ars.scan_id "
    "WHERE ars.scan_id IS NULL"
).fetchone()[0]
print(f"  ⚠ {no_score} scan(s) without risk score" if no_score
      else "  ✔ Every scan has a risk score")

cur.execute("PRAGMA table_info(ai_risk_scores)")
cols = [c[1] for c in cur.fetchall()]
if "engine_version" in cols:
    try:
        from ai_risk_engine import ENGINE_VERSION
        stale = cur.execute(
            "SELECT COUNT(*) FROM ai_risk_scores "
            "WHERE engine_version != ? OR engine_version IS NULL",
            (ENGINE_VERSION,)
        ).fetchone()[0]
        print(f"  engine_version present (current = {ENGINE_VERSION})")
        print(f"  ⚠ {stale} stale score(s)" if stale else "  ✔ All scores current")
    except ImportError:
        print("  engine_version present (could not import ENGINE_VERSION)")
else:
    print("  ⚠ engine_version column missing — Flask adds it on next run")

bad_json = 0
for scan_id, result in cur.execute("SELECT id, result FROM scan_history").fetchall():
    try:
        json.loads(result or "{}")
    except json.JSONDecodeError:
        bad_json += 1
        print(f"  ⚠ Scan #{scan_id} has invalid JSON")
if not bad_json:
    print("  ✔ All scan results are valid JSON")

conn.close()
print("\n=== Done ===")