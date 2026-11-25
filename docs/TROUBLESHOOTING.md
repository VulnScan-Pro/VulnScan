# VulnScan Pro — Troubleshooting

Fix common issues before opening a GitHub issue. Most "errors" fall into one of the categories below.

---

## A. External Tool Errors

### `whatweb is not recognized as an internal or external command`
**Cause:** WhatWeb is a Ruby script and is not in your Windows PATH.
**Fix:** Use the full path with the `ruby` prefix in the command box:
```text
ruby C:\Users\YOURNAME\Downloads\whatweb\whatweb "http://target.com" --color=never
```

### `ruby executable not found` when running WhatWeb scan
Ruby is not on PATH.
**Fix A — Reinstall Ruby** with *Add Ruby executables to your PATH* checked.
**Fix B — Set `RUBY_PATH` in `.env`:**
```text
RUBY_PATH=C:\Ruby40-x64\bin\ruby.exe
```
Verify:
```text
ruby --version
```

### `nmap program was not found in path`
- Nmap not installed, or not on PATH.
- Install Nmap and ensure **Npcap** was installed during setup.
- Set `NMAP_PATH` in `.env`:
```text
NMAP_PATH=C:\Program Files (x86)\Nmap\nmap.exe
```
Verify:
```text
nmap --version
```

### Nmap returns `{"state": "down"}` for all hosts
Either Nmap is not working, or the target blocks ICMP. Try the `tcp_basic` profile which uses `-Pn` (skip ping).
If that still fails, test Nmap directly:
```text
nmap -sT -Pn example.com
```

### Nuclei scan says "templates not found" / all-zero severity
Templates were never installed.
```text
nuclei -update-templates
```
Verify:
```text
nuclei -version
```

### `Nuclei execution failed ... nuclei not found`
Either Nuclei isn't installed, or it's not on PATH.
- Install: `go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest`
- Default binary path: `C:\Users\<username>\go\bin\nuclei.exe`
- Add that folder to PATH, then reopen the terminal.
- Or set `NUCLEI_PATH` in `.env`.

### `dnsenum` returns nothing / errors
- Confirm Perl works: `perl --version`
- Confirm `dnsenum.pl` exists: `Test-Path C:\Tools\dnsenum\dnsenum.pl`
- Run it manually: `perl C:\Tools\dnsenum\dnsenum.pl --help`
If `--help` works, the app will work too once `DNSENUM_PATH` in `.env` points to it.

---

## B. Python / Library Errors

### `Missing 'dnspython' library`
```text
pip install dnspython
```

### `PDF generation unavailable: cannot load library 'libgobject-2.0-0'`
GTK3 Runtime is not installed. WeasyPrint needs it to render PDFs.
- Download: https://github.com/tschoonj/GTK-for-Windows-Runtime-Environment-Installer/releases
- Run the installer with default options, then **restart** your terminal.

### `WeasyPrint` fails with `OSError` / `DLL load failed`
Same fix as above — install GTK3 Runtime.
If you have GTK3 installed but it still fails, ensure the GTK `bin` folder is on PATH:
```text
# Usually C:\Program Files\GTK3-Runtime Win64\bin
```
Then open a new terminal and test:
```text
python -c "from weasyprint import HTML; print('OK')"
```

### `ModuleNotFoundError: No module named 'flask'` (or any other library)
Python packages not installed in the active interpreter.
```text
cd C:\Users\<username>\Desktop\vulnscan-pro
pip install -r requirements.txt
```
If using a virtual environment, activate it first:
```text
.\.venv\Scripts\Activate.ps1
```

---

## C. Runtime / Server Errors

### Port 5000 already in use
Find and kill the process:
```text
Get-NetTCPConnection -LocalPort 5000 | Select-Object OwningProcess
Stop-Process -Id <PID>
```
Or change the port in `.env`:
```text
FLASK_PORT=5001
```
Then visit `http://127.0.0.1:5001`.

### `config.py` prints `MISSING` for a tool
Open `.env`, fix that tool's `*_PATH` line, save, then re-run:
```text
python config.py
```
Do not edit `scanner\*.py` directly — the config reader only looks at `.env`.

### `sqlite3.OperationalError: database is locked`
A previous Flask process is still running. Kill all Python processes:
```text
Get-Process python* | Stop-Process -Force
```
Then restart: `python app.py`.
WAL mode (already enabled) prevents this in normal use — if it recurs, check that you aren't running two `python app.py` windows simultaneously.

### Database corrupted / missing tables
```text
python scripts\db_check.py
```
If it reports problems:
```text
# Wipe the DB (all scans & API keys lost)
del database.db
python app.py     # recreates schema on first run
```

### Chat with scan says "No AI provider configured"
You haven't saved an API key, or none is active.
1. Open http://127.0.0.1:5000 → **Configuration**
2. Paste a key → **Save**
3. Click **Activate** next to that provider
4. Reload the scan page → chat should work
If the key is saved but the provider errors:
- Verify the key is still valid on the provider's dashboard
- Check the terminal running `python app.py` — the full error is logged there

---

## D. Scan-Specific Oddities

### Scan Result shows "No vulnerabilities detected" (100/Low) but I know it's vulnerable
**Cause:** The tool returned zero findings.
**Fix:** 
*   For **SQLMap**, you must provide a URL with a parameter (e.g., `?id=1`) or use `--forms --crawl=2`.
*   For **Nuclei**, ensure templates are updated (`nuclei -update-templates`).
*   Check the **Raw Output** section in the scan results to see exactly what the tool printed.

### SQLMap runs but finishes in 1 second with no output
**Cause:** SQLMap on Windows hangs or fails silently when run via Python's `subprocess` without STDIN redirection.
**Fix:** 
1. Ensure your command in the UI includes `--batch`.
2. Verify `web_scanner.py` is using `stdin=subprocess.DEVNULL` when running the command.

### "Command prefix 'python' is not allowed"
**Cause:** Your `config.py` whitelist does not include `python`, but you are trying to run `python sqlmap.py ...`.
**Fix:** Ensure `ALLOWED_COMMAND_PREFIXES` in `config.py` includes `"python"`.

### Scan completes but zero findings
For external targets:
- Target may genuinely have no matching findings in the Nuclei template set you ran.
- Try the **Full Reconnaissance** or **Nuclei Full Scan** profile to test all templates.
- Verify internet access from the machine running the scan.
For local targets:
- Nmap needs to reach the host — test `ping <target>` first, then `nmap -sT -Pn <target>`.

### Enrichment hangs / CVEs stuck at "N/A"
NVD's public API has aggressive rate limits (5 requests per 30 seconds without an API key). Enriching many CVEs can take minutes. The app caches results for 30 days, so the first scan of a CVE is slow, subsequent scans are instant.
If enrichment never completes:
- Check internet: `Invoke-WebRequest https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2021-44228`
- If it hangs on your network, set `SCAN_TIMEOUT_NMAP` low enough that the scan itself doesn't stall

### AI report is empty / very short
Two possibilities:
1. **No provider active** — see "Chat with scan says No AI provider configured" above.
2. **Provider rate limit** — most free tiers throttle. Wait, or switch to another provider in Settings.
The app falls back to a heuristic summary if the AI call fails; you'll still get a valid PDF, just without the narrative sections.

---

## E. When All Else Fails

1. Run `python config.py` and confirm every tool says `OK`.
2. Run `python scripts\db_check.py` and confirm the DB is healthy.
3. Run `python app.py` and **look at the terminal output** — errors are logged with full tracebacks.
4. Open an issue at `https://github.com/<your-username>/vulnscan-pro/issues` and paste:
   - The `python config.py` output
   - The last 20 lines of the Flask terminal
   - The scan type and target (redact if sensitive)

---

## F. Reset Options (data-level)

### Wipe all scans, scores, history, chats, and watchlist
```text
cd C:\Users\<username>\Desktop\vulnscan-pro
python scripts\reset_scans.py
```
Preserves your saved API keys.

### Wipe only risk scores (force recompute)
```text
python scripts\reset_scores.py
```
Every scan's risk score will be recalculated the next time you open it.

### Wipe API keys only
Via the dashboard: **Configuration** → click **Delete Key** next to each provider.
Or in SQL (advanced):
```text
python -c "import sqlite3; c=sqlite3.connect('database.db'); c.execute('DELETE FROM api_keys'); c.execute('DELETE FROM active_provider'); c.commit(); print('done')"
```

---

## G. Full Uninstall

### 1. Remove the project folder
```text
cd C:\Users\<username>\Desktop
Remove-Item -Recurse -Force vulnscan-pro
```
This deletes `.env`, `database.db`, all code, and all templates. Nothing else remains from the app itself.

### 2. Remove Python packages (optional)
If you installed these packages *only* for VulnScan Pro and want them gone:
```text
pip uninstall -y flask flask-session requests python-dotenv python-nmap python-whois dnspython beautifulsoup4 weasyprint groq openai anthropic cryptography
```
If you used a virtual environment (`.venv` folder inside the project), that was already deleted in step 1 — no further action needed.

### 3. Remove external tools (optional)
Only remove these if you do not use them elsewhere. All are legitimate, standalone tools.
- Uninstall via Settings → Apps: Nmap, Ruby+Devkit, Strawberry Perl, Go, GTK3 Runtime.
- Delete cloned tool folders:
```text
Remove-Item -Recurse -Force C:\Tools\whatweb
Remove-Item -Recurse -Force C:\Tools\sqlmap
Remove-Item -Recurse -Force C:\Tools\dnsenum
```
- Remove Nuclei binary (installed via Go):
```text
Remove-Item C:\Users\<username>\go\bin\nuclei.exe
```
- Nuclei templates cache:
```text
Remove-Item -Recurse -Force C:\Users\<username>\nuclei-templates
Remove-Item -Recurse -Force $env:USERPROFILE\.local\nuclei
```

### 4. Remove environment variables (optional)
If you added `C:\Users\<username>\go\bin` or `C:\Ruby40-x64\bin` to PATH *only* for this project and no longer need them:
1. `Win+R` → `sysdm.cpl` → **Advanced** → **Environment Variables**
2. Under **User variables** → select **Path** → **Edit**
3. Remove the entries → **OK**

### 5. Verify nothing is left running
```text
Get-Process python*, nuclei*, nmap*, perl*, ruby* -ErrorAction SilentlyContinue
```
If any show up:
```text
Get-Process python*, nuclei*, nmap*, perl*, ruby* -ErrorAction SilentlyContinue | Stop-Process -Force
```

### 6. Verify the database is gone
The database lives inside the project folder and was deleted with step 1. Confirm:
```text
Test-Path C:\Users\<username>\Desktop\vulnscan-pro\database.db
```
Should print `False`.

---

## H. Common Scenarios (Quick Reference)

| Goal | Action |
|---|---|
| **Keep app, clear all scans and chats** | `python scripts\reset_scans.py` |
| **Keep scans, recompute all risk scores** | `python scripts\reset_scores.py` |
| **Remove one AI provider's key** | Dashboard → Configuration → **Delete Key** next to that provider |
| **Remove all AI keys** | `python -c "import sqlite3; c=sqlite3.connect('database.db'); c.execute('DELETE FROM api_keys'); c.execute('DELETE FROM active_provider'); c.commit(); print('done')"` |
| **Start with a completely empty DB (keep code & tools)** | `del database.db*` then `python app.py` |
| **Move the project to another folder** | Move `vulnscan-pro\`, then `python config.py` to re-verify tool paths |
| **Move the project to another machine** | Clone the repo again, recreate `.env`, reinstall tools per `SETUP.md`, run `python config.py` |
| **Remove app, keep Nmap/Nuclei/etc. installed** | Section G.1 only |
| **Remove everything (app + tools + data)** | Sections G.1 → G.5 in order |
| **Change the port the app listens on** | Add `FLASK_PORT=5001` to `.env`, restart |
| **Change the database location** | Add `VULNSCAN_DB=D:\path\to\db.sqlite` to `.env` |
| **Check what tools were found** | `python config.py` |
| **Check DB health** | `python scripts\db_check.py` |
| **Update Nuclei templates** | `nuclei -update-templates` |
| **Update WhatWeb** | `cd C:\Tools\whatweb && git pull` |
| **Update the project itself** | `git pull` in the project root, then `pip install -r requirements.txt` |

---

## I. What Not To Do

These actions will break your installation or corrupt the database. Avoid them.

| Don't | Why | Do instead |
|---|---|---|
| Edit `scanner\*.py` to change tool paths | Bypasses `config.py`; changes are lost on `git pull` | Edit `.env` |
| Commit `.env` to git | Leaks API keys and machine-specific paths | `.gitignore` already excludes it |
| Commit `database.db` to git | Leaks scan data and API keys | `.gitignore` already excludes it |
| Run `python app.py` with `FLASK_DEBUG=1` on a public interface | Werkzeug debugger allows remote code execution | Leave `FLASK_DEBUG=0` unless testing locally |
| Delete `config.py` | Every module imports it | It's safe to edit; never delete |
| Run two `python app.py` at once | SQLite lock errors | Close the other terminal first |
| Change `SECRET_KEY` after saving AI keys | Previously saved API keys become undecryptable | Either restore the old key or re-enter all API keys |
| Scan targets you don't own or lack written authorization for | Illegal in most jurisdictions | Only scan your own systems or with explicit permission |

---

**Back to:** [`SETUP.md`](SETUP.md)