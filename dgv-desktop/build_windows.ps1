# build_windows.ps1
# Run this from Windows PowerShell (NOT WSL) inside the dgv-desktop folder.
# Rebuilds only-gate in WSL, then builds the Tauri Windows installer.
#
# Usage (from Windows PowerShell):
#   Set-Location \\wsl.localhost\Ubuntu\home\vdmo\pir\only-engine\dgv\dgv-desktop
#   .\build_windows.ps1

$ErrorActionPreference = "Stop"

Write-Host "=== Step 1: Build only-gate in WSL ===" -ForegroundColor Cyan
wsl bash -c "source ~/.cargo/env && cd /home/vdmo/pir/only-engine && cargo build -p only-gate"
if ($LASTEXITCODE -ne 0)
{ Write-Error "only-gate build failed."; exit 1 
}
Write-Host "[OK] only-gate binary ready at /home/vdmo/pir/only-engine/target/debug/only-gate" -ForegroundColor Green

Write-Host ""
Write-Host "=== Step 2: npm install (if needed) ===" -ForegroundColor Cyan
if (-not (Test-Path ".\node_modules"))
{
    npm install
    if ($LASTEXITCODE -ne 0)
    { Write-Error "npm install failed."; exit 1 
    }
}
Write-Host "[OK] node_modules present" -ForegroundColor Green

Write-Host ""
Write-Host "=== Step 3: Build Tauri Windows app ===" -ForegroundColor Cyan
npx tauri build
if ($LASTEXITCODE -ne 0)
{ Write-Error "Tauri build failed."; exit 1 
}

Write-Host ""
Write-Host "=== BUILD COMPLETE ===" -ForegroundColor Green
Write-Host "Installer: src-tauri\target\release\bundle\nsis\dgv-desktop_0.1.0_x64-setup.exe" -ForegroundColor Yellow
