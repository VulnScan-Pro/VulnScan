# VulnScan Pro — Setup Guide

Complete installation guide for **Windows 10/11**. Linux/macOS users can follow the same structure but use `apt` / `brew` for system packages.

---

## 1. System Requirements

| Component | Minimum | Recommended |
|---|---|---|
| **OS** | Windows 10 (64-bit) | Windows 11 |
| **RAM** | 4 GB | 8 GB+ |
| **Disk** | 1 GB free | 2 GB free |
| **Python** | 3.10 | 3.12 / 3.13 |
| **Internet** | Required for AI features + CVE enrichment | — |

> **Python 3.15 note:** Python 3.15.x exists and works with this project, but some third-party libraries (WeasyPrint, google-genai, python-nmap) may not yet have fully-compatible releases. **Python 3.12 or 3.13 is the safest choice.** If you hit a pip build error on 3.15, downgrade to 3.12.

---

## 2. Pre-Requisite Tools

Install in the order listed. Each step includes a **verify** command — run it before moving on.

### 2.1 Python 3.10+ (3.12 recommended)

- **Download:** https://www.python.org/downloads/
- During install: check **Add Python to PATH**
- Open a **new** PowerShell and verify:

```text
python --version
```

### 2.2 Upgrade pip

```text
python -m pip install --upgrade pip
```

### 2.3 Nmap

- **Download:** https://nmap.org/download.html
- During install: check **Install Npcap** when prompted
- Default install path: `C:\Program Files (x86)\Nmap\nmap.exe`
- Verify:

```text
nmap --version
```

### 2.4 Go

- **Download:** https://go.dev/dl/
- Install with default options.
- Verify in a new terminal:

```text
go version
```

### 2.5 Nuclei

```text
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
```

- Binary ends up at: `C:\Users\<username>\go\bin\nuclei.exe`
- **Add `C:\Users\<username>\go\bin` to your PATH** (System → Environment Variables → Path → New), then open a new terminal.
- One-time template setup:

```text
nuclei -update-templates
```

- Verify:

```text
nuclei -version
```

### 2.6 Ruby & WhatWeb

- **Download Ruby:** https://rubyinstaller.org/downloads/ (Ruby+Devkit)
- During install: check **Add Ruby executables to your PATH**
- Verify:

```text
ruby --version
```

- Install WhatWeb via RubyGems:

```text
gem install whatweb
```

- If that fails, clone the repo manually:

```text
cd C:\Tools
git clone https://github.com/urbanadventurer/whatweb
```

- Verify (replace the path with your actual install location):

```text
ruby C:\Tools\whatweb\whatweb --version
```

### 2.7 SQLMap

- **Download:** https://github.com/sqlmapproject/sqlmap/archive/refs/heads/master.zip
- Extract the zip to a folder (e.g., `C:\Tools\sqlmap`).
- Ensure `sqlmap.py` is directly inside that folder (e.g., `C:\Tools\sqlmap\sqlmap.py`).

### 2.8 Dalfox

- **Download (Chocolatey):**

```text
choco install dalfox
```

- Or download the binary directly from https://github.com/hahwul/dalfox/releases and add it to your PATH.
- Verify:

```text
dalfox --help
```

### 2.9 Strawberry Perl (for dnsenum)

- **Download:** https://strawberryperl.com/
- During install: check **Add Perl to PATH**
- Verify:

```text
perl --version
```

### 2.10 Dnsenum

- **Download:** https://github.com/fwaeytens/dnsenum
- Extract it to a folder (e.g., `C:\Tools\dnsenum`).
- Verify:

```text
perl C:\Tools\dnsenum\dnsenum.pl --help
```

### 2.11 GTK3 Runtime (required by WeasyPrint for PDF export)

- **Download:** https://github.com/tschoonj/GTK-for-Windows-Runtime-Environment-Installer/releases
- Run the installer with default options.
- Without this, PDF report generation returns *"PDF generation failed"*.

---

## 3. Install the Project

### 3.1 Clone the repository

```text
cd C:\Users\<username>\Desktop
git clone https://github.com/<your-username>/vulnscan-pro.git
cd vulnscan-pro
```

### 3.2 Install Python packages

```text
pip install -r requirements.txt
```

*(Optional: If you want PDF generation, also run `pip install -r requirements-report.txt`)*

### 3.3 Generate your `SECRET_KEY`

Run this in PowerShell to generate a strong random key:

```text
python -c "import secrets; print(secrets.token_hex(32))"
```

Copy the output — a 64-character hex string.

### 3.4 Create your `.env`

```text
copy .env.example .env
notepad .env
```

Edit `.env` — replace `YOURNAME` with your actual Windows username, paste your `SECRET_KEY`, and adjust any tool path that differs:

```ini
SECRET_KEY=PASTE_YOUR_GENERATED_KEY_HERE
FLASK_DEBUG=0

NMAP_PATH=C:\Program Files (x86)\Nmap\nmap.exe
NUCLEI_PATH=C:\Users\YOURNAME\go\bin\nuclei.exe
WHATWEB_PATH=C:\Tools\whatweb\whatweb
DNSENUM_PATH=C:\Tools\dnsenum\dnsenum.pl
RUBY_PATH=C:\Ruby40-x64\bin\ruby.exe
PERL_PATH=C:\Strawberry\perl\bin\perl.exe
SQLMAP_PATH=C:\Tools\sqlmap\sqlmap.py
DALFOX_PATH=C:\ProgramData\chocolatey\bin\dalfox.exe
```

> **Do not edit `scanner/*.py` directly.** All tool paths are read from `.env` via `config.py`. Hardcoding paths in the `.py` files breaks portability.

### 3.5 Verify tool discovery

```text
python config.py
```

Expected output — every line should say `OK`, and **no `RuntimeWarning: SECRET_KEY not set`** should appear:

```text
[config] Nmap    : OK      C:\Program Files (x86)\Nmap\nmap.exe
[config] Nuclei  : OK      C:\Users\YOURNAME\go\bin\nuclei.exe
[config] WhatWeb : OK      C:\Tools\whatweb\whatweb
[config] dnsenum : OK      C:\Tools\dnsenum\dnsenum.pl
[config] Ruby    : OK      C:\Ruby40-x64\bin\ruby.exe
[config] Perl    : OK      C:\Strawberry\perl\bin\perl.exe
[config] Dalfox  : OK      C:\ProgramData\chocolatey\bin\dalfox.exe
[config] SQLMap  : OK      C:\Tools\sqlmap\sqlmap.py
```

If any line says `MISSING`, fix that `.env` entry and re-run `python config.py` before proceeding.

### 3.6 Verify database schema

```text
python scripts\db_check.py
```

Expected: `All required tables present`, `No orphan risk scores`.

---

## 4. Run the Application

Every time you want to start the scanner:

```text
cd C:\Users\<username>\Desktop\vulnscan-pro
python app.py
```

You should see:

```text
[INFO] app: [schema] database OK
 * Running on http://127.0.0.1:5000
```

Open **http://127.0.0.1:5000** in your browser.

To stop: `Ctrl+C` in the terminal.

---

## 5. Configure an AI Provider (optional)

At least one API key is needed for: risk narrative, chat-with-scan, and full AI reports.

1. Start the app (`python app.py`).
2. Open http://127.0.0.1:5000 → click **Configuration** (bottom-left).
3. Paste your key next to the desired provider → **Save** → **Activate**.

Keys are stored **encrypted** in `database.db` (`api_keys` table).

---

## 6. Folder Layout Reference

```text
vulnscan-pro\
├── .env                 ← your secrets & tool paths (gitignored)
├── .env.example         ← template (committed)
├── .gitignore
├── app.py
├── config.py            ← central config, reads .env
├── ai_providers.py
├── ai_risk_engine.py
├── cve_enrichment.py
├── requirements.txt
├── requirements-report.txt
├── database.db          ← auto-created
├── scanner\
│   ├── __init__.py
│   └── web_scanner.py
├── templates\
│   ├── index.html
│   ├── settings.html
│   ├── scan_result.html
│   ├── guide.html
│   └── report.html
├── scripts\
│   └── db_check.py
└── docs\
    ├── SETUP.md          ← this file
    └── TROUBLESHOOTING.md
```

---

## 7. Legal Notice

Only scan systems you own or have **explicit written authorization** to test. Unauthorized scanning is illegal in most jurisdictions. The dashboard enforces a consent checkbox before each scan — it does not substitute for legal authorization.