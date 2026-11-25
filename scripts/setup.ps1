# scripts/setup.ps1
# One-shot helper for VulnScan Pro on Windows.
# Run from the project root as Administrator:
#   powershell -ExecutionPolicy Bypass -File scripts\setup.ps1
#
# It does NOT install system tools (Python/Go/Ruby/Perl/Nmap/GTK3).
# Install those per docs/SETUP.md §2 first.

$ErrorActionPreference = "Stop"

Write-Host ""
Write-Host "=== VulnScan Pro — Setup Helper ===" -ForegroundColor Cyan
Write-Host ""

# --- 1. Python packages ---
Write-Host "[1/4] Installing Python packages from requirements.txt..." -ForegroundColor Yellow
try {
    python -m pip install --upgrade pip | Out-Null
    pip install -r requirements.txt
    Write-Host "  Python packages installed." -ForegroundColor Green
} catch {
    Write-Host "  FAILED: $_" -ForegroundColor Red
    Write-Host "  Check that Python is installed and on PATH, then re-run." -ForegroundColor Red
}

# --- 2. Perl module for dnsenum ---
Write-Host ""
Write-Host "[2/4] Installing Perl module XML::Writer (required by dnsenum)..." -ForegroundColor Yellow
$perl = (Get-Command perl -ErrorAction SilentlyContinue).Source
if (-not $perl) {
    Write-Host "  SKIPPED: perl.exe not on PATH." -ForegroundColor DarkYellow
    Write-Host "  Install Strawberry Perl (docs/SETUP.md §2.8) if you want dnsenum." -ForegroundColor DarkYellow
} else {
    & $perl -MCPAN -e "install XML::Writer" 2>&1 | Out-Null
    Write-Host "  XML::Writer installed for: $perl" -ForegroundColor Green
}

# --- 3. WhatWeb Ruby gems ---
Write-Host ""
Write-Host "[3/4] Installing WhatWeb Ruby dependencies..." -ForegroundColor Yellow
$whatwebDir = Read-Host "  Enter full path to your WhatWeb folder (e.g. C:\Users\you\Downloads\whatweb)"
if (Test-Path "$whatwebDir\Gemfile") {
    Push-Location $whatwebDir
    $ruby = (Get-Command ruby -ErrorAction SilentlyContinue).Source
    if ($ruby) {
        $bundle = Join-Path (Split-Path $ruby) "bundle"
        if (Test-Path $bundle) {
            & $bundle install
            Write-Host "  WhatWeb gems installed." -ForegroundColor Green
        } else {
            Write-Host "  Bundler not found next to ruby.exe. Run: gem install bundler" -ForegroundColor Red
        }
    } else {
        Write-Host "  SKIPPED: ruby.exe not on PATH. Install Ruby (docs/SETUP.md §2.6)." -ForegroundColor Red
    }
    Pop-Location
} else {
    Write-Host "  SKIPPED: Gemfile not found in $whatwebDir" -ForegroundColor Red
}

# --- 4. Nuclei templates ---
Write-Host ""
Write-Host "[4/4] Updating Nuclei templates (one-time)..." -ForegroundColor Yellow
$nuclei = (Get-Command nuclei -ErrorAction SilentlyContinue).Source
if ($nuclei) {
    & $nuclei -update-templates
    Write-Host "  Nuclei templates updated." -ForegroundColor Green
} else {
    Write-Host "  SKIPPED: nuclei.exe not on PATH." -ForegroundColor DarkYellow
    Write-Host "  Add C:\Users\<you>\go\bin to PATH, then re-run." -ForegroundColor DarkYellow
}

Write-Host ""
Write-Host "=== Setup helper complete ===" -ForegroundColor Cyan
Write-Host ""
Write-Host "Next steps:" -ForegroundColor Cyan
Write-Host "  1. Copy .env.example to .env and fill in your paths (docs/SETUP.md §3.4)"
Write-Host "  2. Verify with: python config.py"
Write-Host "  3. Verify DB with: python scripts\db_check.py"
Write-Host "  4. Run: python app.py"
Write-Host ""