@echo off
:: REBUILD.bat — double-click from Windows Explorer to rebuild dgv-desktop
:: Requires: Windows Rust toolchain, Node.js, @tauri-apps/cli in node_modules

echo ==========================================================
echo  DGV Desktop Rebuild
echo  Rebuilding only-gate (WSL) + Tauri Windows app
echo ==========================================================
echo.

:: Step 1: Build only-gate inside WSL
echo [1/3] Building only-gate in WSL...
wsl bash -c "source ~/.cargo/env && cd /home/vdmo/pir/only-engine && cargo build -p only-gate"
if %ERRORLEVEL% neq 0 (
    echo ERROR: only-gate build failed.
    pause
    exit /b 1
)
echo [OK] only-gate ready.
echo.

:: Step 2: npm install if node_modules is missing
if not exist "%~dp0node_modules" (
    echo [2/3] Running npm install...
    pushd "%~dp0"
    call npm install
    if %ERRORLEVEL% neq 0 (
        echo ERROR: npm install failed.
        popd
        pause
        exit /b 1
    )
    popd
    echo [OK] node_modules installed.
) else (
    echo [2/3] node_modules present, skipping install.
)
echo.

:: Step 3: Build Tauri Windows app
echo [3/3] Building Tauri Windows app...
pushd "%~dp0"
call npx tauri build
if %ERRORLEVEL% neq 0 (
    echo ERROR: Tauri build failed. Check output above.
    popd
    pause
    exit /b 1
)
popd

echo.
echo ==========================================================
echo  BUILD COMPLETE
echo  Installer: src-tauri\target\release\bundle\nsis\
echo ==========================================================
pause
