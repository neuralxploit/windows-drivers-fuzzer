# GitHub Setup Script for Ladybug Fuzzer
# Run this in PowerShell

$ErrorActionPreference = "Stop"

Write-Host "=== Ladybug Fuzzer GitHub Setup ===" -ForegroundColor Cyan

# Check if git is installed
if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
    Write-Host "ERROR: Git is not installed or not in PATH" -ForegroundColor Red
    Write-Host "Install from: https://git-scm.com/download/win" -ForegroundColor Yellow
    exit 1
}

# Navigate to project directory
Set-Location "C:\Users\const\Desktop\Tools\Fuzzing\windriver_fuzzer_rs"

# Initialize git if not already
if (-not (Test-Path ".git")) {
    Write-Host "Initializing git repository..." -ForegroundColor Green
    git init
}

# Add all files
Write-Host "Adding files to git..." -ForegroundColor Green
git add .

# Show status
Write-Host "`nFiles to be committed:" -ForegroundColor Yellow
git status --short

# Commit
Write-Host "`nCreating initial commit..." -ForegroundColor Green
git commit -m "Initial commit: Windows kernel driver fuzzer

- Coverage-guided Windows driver fuzzer (Ladybug)
- AFL-style mutation engine with 15+ strategies
- IOCTL discovery and probing
- Ghidra analysis scripts for driver decompilation
- Crash triage and exploit pattern detection
- Python tools for analysis"

Write-Host "`n=== Next Steps ===" -ForegroundColor Cyan
Write-Host "1. Create repo on GitHub: https://github.com/new" -ForegroundColor White
Write-Host "   Name: ladybug-fuzzer" -ForegroundColor White
Write-Host "   Description: Coverage-guided Windows kernel driver fuzzer" -ForegroundColor White
Write-Host ""
Write-Host "2. After creating, run:" -ForegroundColor White
Write-Host "   git remote add origin https://github.com/neuralxploit/ladybug-fuzzer.git" -ForegroundColor Gray
Write-Host "   git branch -M main" -ForegroundColor Gray
Write-Host "   git push -u origin main" -ForegroundColor Gray
Write-Host ""
Write-Host "If you need to login, Git will prompt for credentials." -ForegroundColor Yellow