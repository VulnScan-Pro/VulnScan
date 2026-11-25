# scripts/test_scores.py
import sys, os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import ai_risk_engine

engine = ai_risk_engine.AIRiskEngine()
print(f"{'Scan':<6}{'Score':<7}{'Level':<10}{'CVE':<6}{'Web':<6}{'Actionable':<12}{'Info':<6}{'Ports':<6}")
print("-" * 65)

# Edit these IDs to match your DB
for scan_id in (20, 18, 12, 11, 2):
    r = engine.calculate_risk_score(scan_id)
    if not r:
        print(f"{scan_id:<6}(not found)")
        continue
    comps = r["components"]
    print(f"{scan_id:<6}{r['risk_score']:<7}{r['risk_level']:<10}"
          f"{comps['cve_score']:<6}{comps['attack_surface']:<6}"
          f"{'—':<12}{comps.get('business_context', 0):<6}")