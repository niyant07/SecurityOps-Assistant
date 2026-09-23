# SecurityOps Assistant — PowerShell installer for Windows.
#
# Installs Python dependencies in a local .venv virtual environment and provides
# run options. Safe to re-run.
#
# Usage:
#   .\scripts\install.ps1          # install everything, print run instructions
#   .\scripts\install.ps1 -Run     # install and launch immediately

[CmdletBinding()]
param (
    [switch]$Run
)

$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectRoot = Resolve-Path "$ScriptDir\.."
Set-Location $ProjectRoot

Write-Host "[install] SecurityOps Assistant Windows Setup" -ForegroundColor Cyan

# 1. Locate Python 3.12+
$PythonBin = Get-Command python3, python -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Source -First 1

if (-not $PythonBin) {
    Write-Error "[install] No python interpreter found. Please install Python 3.12+ and add it to PATH."
    exit 1
}

Write-Host "[install] Using Python: $PythonBin" -ForegroundColor Green

# 2. Create Virtual Environment
if (-not (Test-Path ".venv")) {
    Write-Host "[install] Creating virtual environment in .venv..." -ForegroundColor Cyan
    & $PythonBin -m venv .venv
} else {
    Write-Host "[install] Reusing existing .venv" -ForegroundColor Green
}

$VenvPython = "$ProjectRoot\.venv\Scripts\python.exe"

# 3. Install Requirements
Write-Host "[install] Upgrading pip and installing requirements..." -ForegroundColor Cyan
& $VenvPython -m pip install --upgrade pip --quiet
& $VenvPython -m pip install -r requirements.txt

Write-Host "[install] Setup complete!" -ForegroundColor Green
Write-Host ""
Write-Host "To run SecurityOps Assistant on Windows:" -ForegroundColor Yellow
Write-Host "  .\.venv\Scripts\activate" -ForegroundColor Yellow
Write-Host "  python -m securityops" -ForegroundColor Yellow
Write-Host ""

if ($Run) {
    Write-Host "[install] Launching SecurityOps Assistant..." -ForegroundColor Cyan
    & $VenvPython -m securityops
}
