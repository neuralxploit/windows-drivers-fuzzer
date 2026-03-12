# Complete GitHub Setup Script
# Run in PowerShell: .\push_to_github.ps1

param(
    [string]$RepoName = "windows-drivers-fuzzer"
)

$ErrorActionPreference = "Stop"

Write-Host "=== Windows Drivers Fuzzer - GitHub Setup ===" -ForegroundColor Cyan
Write-Host ""

# Check for required tools
$missing = @()
if (-not (Get-Command git -ErrorAction SilentlyContinue)) { $missing += "git" }
if (-not (Get-Command gh -ErrorAction SilentlyContinue)) { $missing += "gh (GitHub CLI)" }

if ($missing.Count -gt 0) {
    Write-Host "Missing required tools:" -ForegroundColor Red
    foreach ($tool in $missing) {
        Write-Host "  - $tool" -ForegroundColor Red
    }
    Write-Host ""
    Write-Host "Install GitHub CLI from: https://cli.github.com/" -ForegroundColor Yellow
    exit 1
}

# Navigate to project
$projectPath = "C:\Users\const\Desktop\Tools\Fuzzing\windriver_fuzzer_rs"
Set-Location $projectPath
Write-Host "Working directory: $projectPath" -ForegroundColor Gray

# Check if gh is authenticated
Write-Host "`nChecking GitHub authentication..." -ForegroundColor Yellow
$authStatus = gh auth status 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Host "Not logged in to GitHub. Starting login..." -ForegroundColor Yellow
    gh auth login
    if ($LASTEXITCODE -ne 0) {
        Write-Host "GitHub login failed. Please run 'gh auth login' manually." -ForegroundColor Red
        exit 1
    }
}
Write-Host "GitHub authentication OK!" -ForegroundColor Green

# Initialize git if needed
if (-not (Test-Path ".git")) {
    Write-Host "`nInitializing git repository..." -ForegroundColor Green
    git init
}

# Add all files
Write-Host "Adding files to staging..." -ForegroundColor Green
git add .

# Commit
Write-Host "Creating commit..." -ForegroundColor Green
git commit -m "Initial commit: Windows kernel driver fuzzer

- Coverage-guided fuzzer written in Rust (Ladybug)
- AFL-style mutation engine with 15+ strategies
- IOCTL discovery and probing for drivers
- Ghidra analysis scripts for driver decompilation
- Crash triage and exploit pattern detection
- Python tools for vulnerability analysis
- Support for ahcache, AFD, RTCore64, and more drivers"

# Create GitHub repo
Write-Host "`nCreating GitHub repository: $RepoName" -ForegroundColor Green
gh repo create $RepoName --public --description "Coverage-guided Windows kernel driver fuzzer written in Rust" --source=. --remote=origin --push

if ($LASTEXITCODE -eq 0) {
    Write-Host "`n=== SUCCESS ===" -ForegroundColor Green
    Write-Host "Repository created: https://github.com/neuralxploit/$RepoName" -ForegroundColor Cyan
} else {
    Write-Host "`nRepo may already exist. Trying to push..." -ForegroundColor Yellow
    git remote add origin "https://github.com/neuralxploit/$RepoName.git" 2>$null
    git branch -M main
    git push -u origin main
    Write-Host "Pushed to: https://github.com/neuralxploit/$RepoName" -ForegroundColor Cyan
}

Write-Host "`nDone!" -ForegroundColor Green