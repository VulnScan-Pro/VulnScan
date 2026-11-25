# VulnScan Pro

A self-hosted, command-driven vulnerability scanner with AI-powered API-integrated guidance and risk analysis. Combines Nmap, Nuclei, SQLMap, Dalfox, and WhatWeb into a unified dashboard.

> ⚠️ **Disclaimer:** This tool is for educational purposes and authorized security testing only. Do not scan targets you do not own or have permission to test.

## Features
- **Network Scanning:** Full Nmap integration (TCP/UDP, Vuln Scripts, OS detection).
- **Web Scanning:** SQLMap (SQLi), Dalfox (XSS), Nuclei (CVEs/Misconfigs), WhatWeb (Fingerprinting).
- **AI Risk Engine:** Deterministic scoring (0-1000) with NVD/EPSS enrichment.
- **AI Chat:** Ask questions about your scan results using Groq, OpenAI, Anthropic, Mistral, or DeepSeek.
- **PDF Reports:** Generate executive summaries and detailed findings.

## Prerequisites
- **Python 3.10+**
- **Nmap:** [Download here](https://nmap.org/download.html)
- **Nuclei:** `go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest`
- **SQLMap:** Download and extract to `C:\Tools\sqlmap`
- **Dalfox:** `choco install dalfox` (Windows) or `go install github.com/hahwul/dalfox/v2@latest`
- **WhatWeb:** Requires Ruby. `gem install whatweb` or clone the repo.
- **GTK3 Runtime** (Windows only, for PDF generation): [Download here](https://github.com/tschoonj/GTK-for-Windows-Runtime-Environment-Installer/releases)

## Installation
1. Clone the repository:
   ```bash
   git clone https://github.com/YOURUSERNAME/VulnScan-Pro.git
   cd VulnScan-Pro