# LADYBUG Driver Analyzer - All-in-One Script
# Usage: .\analyze_driver.ps1 C:\path\to\driver.sys
#        .\analyze_driver.ps1 .\HWiNFO_x64_214.sys
#        .\analyze_driver.ps1 driver.sys

param(
    [Parameter(Mandatory=$true)]
    [string]$DriverInput
)

$ErrorActionPreference = "Stop"

# Paths
$GhidraPath = "C:\Users\const\Downloads\ghidra_12.0_PUBLIC_20251205\ghidra_12.0_PUBLIC\support\analyzeHeadless.bat"
$ProjectDir = "C:\Users\const\Desktop\Tools\Fuzzing\ghidra_projects"
$ScriptDir = "C:\Users\const\Desktop\Tools\Fuzzing\windriver_fuzzer_rs\scripts"
$OutputDir = "C:\Users\const\Desktop\Tools\Fuzzing\vm_fuzzing"

# Resolve driver path - accept any path
if (Test-Path $DriverInput) {
    # User provided a valid path (absolute or relative)
    $DriverPath = (Resolve-Path $DriverInput).Path
} else {
    Write-Host ""
    Write-Host "[!] Driver not found: $DriverInput" -ForegroundColor Red
    Write-Host ""
    Write-Host "[*] Usage examples:" -ForegroundColor Yellow
    Write-Host "    .\analyze_driver.ps1 .\driver.sys" -ForegroundColor White
    Write-Host "    .\analyze_driver.ps1 C:\path\to\driver.sys" -ForegroundColor White
    Write-Host "    .\analyze_driver.ps1 HWiNFO_x64_214.sys" -ForegroundColor White
    exit 1
}

# Extract driver name from path (without .sys)
$DriverName = [System.IO.Path]::GetFileNameWithoutExtension($DriverPath)

Write-Host ""
Write-Host "╔════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║     🐞 LADYBUG DRIVER ANALYZER - All-in-One               ║" -ForegroundColor Cyan  
Write-Host "╚════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

Write-Host "[*] Driver: $DriverPath" -ForegroundColor Green
Write-Host ""

# Step 1: Run Ghidra
Write-Host "════════════════════════════════════════════════════════════" -ForegroundColor DarkGray
Write-Host "[1/2] 🔍 Running Ghidra analysis (this takes ~2 minutes)..." -ForegroundColor Yellow
Write-Host "════════════════════════════════════════════════════════════" -ForegroundColor DarkGray

& $GhidraPath $ProjectDir "TempAnalysis" -import $DriverPath -scriptPath $ScriptDir -postScript analyze_ioctls_v2.java -deleteProject 2>&1 | ForEach-Object {
    if ($_ -match "IOCTLs|RESULTS|Total|Scanned") {
        Write-Host "    $_" -ForegroundColor Gray
    }
}

# Check output exists
$GhidraOutput = Join-Path $ScriptDir "${DriverName}_ghidra_v2.json"
if (-not (Test-Path $GhidraOutput)) {
    Write-Host "[!] Ghidra output not found: $GhidraOutput" -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "[+] Ghidra output: $GhidraOutput" -ForegroundColor Green
Write-Host ""

# Step 2: Convert to Ladybug format
Write-Host "════════════════════════════════════════════════════════════" -ForegroundColor DarkGray
Write-Host "[2/2] 📊 Converting and sorting IOCTLs..." -ForegroundColor Yellow
Write-Host "════════════════════════════════════════════════════════════" -ForegroundColor DarkGray

python "$ScriptDir\convert_ioctls.py" $DriverName

Write-Host ""
Write-Host "╔════════════════════════════════════════════════════════════╗" -ForegroundColor Green
Write-Host "║                    ✅ DONE!                                ║" -ForegroundColor Green
Write-Host "╚════════════════════════════════════════════════════════════╝" -ForegroundColor Green
Write-Host ""
Write-Host "📁 Output files in: $OutputDir" -ForegroundColor Cyan
Write-Host ""
Write-Host "🚀 To fuzz, run:" -ForegroundColor Yellow
Write-Host "   .\ladybug.exe --device `"\\.\$DriverName`" --analysis ${DriverName}_analysis.json" -ForegroundColor White
Write-Host ""
Write-Host "🔥 For high-risk IOCTLs only:" -ForegroundColor Yellow
Write-Host "   .\ladybug.exe --device `"\\.\$DriverName`" --analysis ${DriverName}_high_risk.json" -ForegroundColor White
Write-Host ""
