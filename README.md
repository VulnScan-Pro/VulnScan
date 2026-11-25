<p>
  <img src="https://github.com/user-attachments/assets/4dbdf8bc-abb2-433e-a560-019e64fc33c9" alt="Screenshot 2026-11-05 183246" width="390">
  <img src="https://github.com/user-attachments/assets/38c337d6-b6c6-4bd7-8686-5683b2fa6174" alt="Screenshot 2026-11-05 183302" width="390">
</p>
<p>
  <img src="https://github.com/user-attachments/assets/1dbcc471-d724-4776-ba71-7ca21f7f977c" alt="Screenshot 2026-11-05 184005" width="390">
  <img src="https://github.com/user-attachments/assets/092b317e-5b8a-47b3-873d-0dc80b6efe53" alt="Screenshot 2026-11-05 183345" width="390">
</p>
<p>
  <img src="https://github.com/user-attachments/assets/39fb45fe-18fc-4f5b-9ac3-c4d757546c6a" alt="Screenshot 2026-11-05 184202" width="390">
  <img src="https://github.com/user-attachments/assets/34cd68e1-5a90-4aca-855c-aeaae3976808" alt="Screenshot 2026-11-05 184047" width="390">
</p>

# VulnScan Pro

A self-hosted, command-driven vulnerability scanner with AI-powered risk analysis. Combines Nmap, Nuclei, SQLMap, Dalfox, and WhatWeb into a unified dashboard.

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
   ```
2. Install Python dependencies:
   ```bash
   pip install -r requirements.txt
   ```
   *(Optional)* If you want to generate PDF reports, install the extra dependencies:
   ```bash
   pip install -r requirements-report.txt
   ```
3. Configure your environment:
   Copy `.env.example` to `.env` and edit the paths to match your system:
   ```bash
   copy .env.example .env
   notepad .env
   ```
4. Verify tool paths:
   ```bash
   python config.py
   ```
5. Run the application:
   ```bash
   python app.py
   ```
6. Open your browser to `http://127.0.0.1:5000`.

## Linux / macOS Notes
This project was built and tested on Windows, but it fully supports Linux and macOS. 
Because the command builder in the UI defaults to Windows paths, you must manually adjust the commands in the interface:
- **Windows:** `python C:\Tools\sqlmap\sqlmap.py -u "..."`
- **Linux/macOS:** Just use the tool name directly: `sqlmap -u "..."` or `dalfox url "..."`
Ensure your tools are installed in your PATH (e.g., `/usr/bin/` or `/usr/local/bin/`).

## Configuration
The `.env` file is where you configure:
- **SECRET_KEY:** Generate one with `python -c "import secrets; print(secrets.token_hex(32))"`
- **Tool Paths:** Absolute paths to Nmap, SQLMap, Dalfox, WhatWeb, etc.
- **API Keys:** You can set these in the UI (Configuration page) instead of the `.env` for better security.

## Aim & Uniqueness
Unlike traditional scanners that require separate CLI tools, VulnScan Pro provides a **single web interface** for orchestrating multiple industry-standard tools. The unique **deterministic risk engine** translates raw scan output into a normalized score (0-1000), making it easy to prioritize findings. The built-in AI chat allows you to ask contextual questions about your scan data, turning raw output into actionable intelligence.

## Platform Support
- **Windows:** Fully tested and supported.
- **Linux (Kali/Ubuntu):** Fully supported (see Linux/macOS Notes above).
- **macOS:** Should work with Homebrew-installed tools (Nmap, Ruby, Python).

## Team & Credits
| Name | Role | Contribution |
| :--- | :--- | :--- |
| **Vishwajit Vegda** | Team Lead | Scanning Modules & Backend Implementation |
| **Jainish Patel** | Developer | AI & API Key Integration |
| **Shubh Contractor** | Developer | Frontend UI/UX & Styling |
| **Samarth Patel** | Developer | Data Enrichment & Risk Engine |

## License
This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

