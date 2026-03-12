@echo off
REM Batch analyze drivers with Ghidra headless mode
REM Usage: batch_analyze.bat C:\drivers\*.sys

setlocal enabledelayedexpansion

REM === CONFIGURATION ===
set GHIDRA_HOME=C:\ghidra
set PROJECT_DIR=C:\ghidra_projects
set SCRIPT_PATH=%~dp0
set OUTPUT_DIR=%~dp0..\analysis_results

REM Create output directory
if not exist "%OUTPUT_DIR%" mkdir "%OUTPUT_DIR%"

echo ========================================
echo   LADYBUG BATCH DRIVER ANALYZER
echo   Using Ghidra Headless Mode
echo ========================================
echo.

REM Check if Ghidra exists
if not exist "%GHIDRA_HOME%\support\analyzeHeadless.bat" (
    echo [!] Ghidra not found at %GHIDRA_HOME%
    echo [!] Please set GHIDRA_HOME in this script
    exit /b 1
)

REM Process each driver
set COUNT=0
for %%F in (%*) do (
    set /a COUNT+=1
    echo.
    echo [!COUNT!] Analyzing: %%~nxF
    echo ----------------------------------------
    
    REM Run Ghidra headless analysis
    "%GHIDRA_HOME%\support\analyzeHeadless.bat" ^
        "%PROJECT_DIR%" "Analysis_%%~nF" ^
        -import "%%F" ^
        -scriptPath "%SCRIPT_PATH%" ^
        -postScript analyze_driver.py ^
        -deleteProject ^
        -log "%OUTPUT_DIR%\%%~nF_log.txt"
    
    REM Move results to output dir
    if exist "%%~dpF%%~nF_analysis.json" (
        move "%%~dpF%%~nF_analysis.json" "%OUTPUT_DIR%\" >nul
        echo [+] Saved: %%~nF_analysis.json
    )
)

echo.
echo ========================================
echo   COMPLETE - Analyzed %COUNT% drivers
echo   Results in: %OUTPUT_DIR%
echo ========================================

REM List results
echo.
echo Results:
dir /b "%OUTPUT_DIR%\*_analysis.json" 2>nul

endlocal
