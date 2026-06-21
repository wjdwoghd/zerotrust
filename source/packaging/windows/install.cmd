@echo off
chcp 65001 >nul
setlocal EnableExtensions

set "INSTALL_DIR=%LOCALAPPDATA%\ZeroTrustDemo"
set "STAGING_DIR=%LOCALAPPDATA%\ZeroTrustDemo.installing"
set "LOCK_DIR=%LOCALAPPDATA%\ZeroTrustDemo.install.lock"
set "HELPER=%~dp0install_helpers.ps1"
set "QUIET=0"
if /i "%~1"=="/quiet" set "QUIET=1"

if "%QUIET%"=="0" if exist "%~dp0install_progress.ps1" (
    powershell -NoProfile -ExecutionPolicy Bypass -STA -File "%~dp0install_progress.ps1" -Payload "%~dp0payload.zip"
    exit /b %ERRORLEVEL%
)

powershell -NoProfile -ExecutionPolicy Bypass -Command "$p=Join-Path $env:LOCALAPPDATA 'ZeroTrustDemo.install.lock'; if (Test-Path -LiteralPath $p) { $age=(Get-Date)-(Get-Item -LiteralPath $p).CreationTime; if ($age.TotalHours -ge 2) { Remove-Item -LiteralPath $p -Recurse -Force -ErrorAction SilentlyContinue } }" >nul 2>nul
mkdir "%LOCK_DIR%" >nul 2>nul
if errorlevel 1 (
    call :popup "ZeroTrust Setup" "ZeroTrust Demo 설치가 이미 진행 중입니다. 완료될 때까지 기다린 뒤 한 번만 실행하세요." 0
    exit /b 1
)

call :popup "ZeroTrust Setup" "ZeroTrust Demo 설치를 시작합니다. 완료 메시지가 뜰 때까지 설치 파일을 다시 실행하지 마세요." 5
call :install
set "EXIT_CODE=%ERRORLEVEL%"

if not "%EXIT_CODE%"=="0" (
    if exist "%STAGING_DIR%" rmdir /s /q "%STAGING_DIR%" >nul 2>nul
    rmdir "%LOCK_DIR%" >nul 2>nul
    call :popup "ZeroTrust Setup" "설치가 실패했습니다. 실행 중인 ZeroTrust 창을 닫고 설치 파일을 한 번만 다시 실행하세요." 0
    exit /b %EXIT_CODE%
)

rmdir "%LOCK_DIR%" >nul 2>nul
call :popup "ZeroTrust Setup" "ZeroTrust Demo 설치가 완료되었습니다. 바탕화면의 ZeroTrust 바로가기를 실행하세요." 0
exit /b 0

:install
echo [ZeroTrust Setup] Installing to "%INSTALL_DIR%"

echo [ZeroTrust Setup] Step 1/6: stopping existing server if present...
if exist "%INSTALL_DIR%\runtime\python\python.exe" (
    if exist "%INSTALL_DIR%\zt_demo_ctl.py" (
        "%INSTALL_DIR%\runtime\python\python.exe" "%INSTALL_DIR%\zt_demo_ctl.py" stop >nul 2>nul
    ) else if exist "%INSTALL_DIR%\stop_zerotrust.bat" (
        call "%INSTALL_DIR%\stop_zerotrust.bat" /quiet >nul 2>nul
    )
) else if exist "%INSTALL_DIR%\stop_zerotrust.bat" (
    call "%INSTALL_DIR%\stop_zerotrust.bat" /quiet >nul 2>nul
)
if exist "%HELPER%" (
    powershell -NoProfile -ExecutionPolicy Bypass -File "%HELPER%" -Action stop -InstallDir "%INSTALL_DIR%" >nul 2>nul
)

echo [ZeroTrust Setup] Step 2/6: preparing staging directory...
if exist "%STAGING_DIR%" (
    rmdir /s /q "%STAGING_DIR%" >nul 2>nul
)
mkdir "%STAGING_DIR%"
if errorlevel 1 (
    echo [ZeroTrust Setup] Failed to create staging directory.
    exit /b 1
)

echo [ZeroTrust Setup] Step 3/6: extracting payload...
powershell -NoProfile -ExecutionPolicy Bypass -Command "Expand-Archive -LiteralPath '%~dp0payload.zip' -DestinationPath '%STAGING_DIR%' -Force"
if errorlevel 1 (
    echo [ZeroTrust Setup] Failed to extract payload.
    exit /b 1
)

echo [ZeroTrust Setup] Step 4/6: validating required files...
for %%F in (
    "zt_demo_ctl.py"
    "zt_control_gui.pyw"
    "server.py"
    "config.py"
    "runtime\python\python.exe"
    "runtime\postgres\bin\postgres.exe"
) do (
    if not exist "%STAGING_DIR%\%%~F" (
        echo [ZeroTrust Setup] Missing required file: %%~F
        exit /b 1
    )
)

echo [ZeroTrust Setup] Step 5/6: replacing existing installation...
if exist "%HELPER%" (
    powershell -NoProfile -ExecutionPolicy Bypass -File "%HELPER%" -Action replace -InstallDir "%INSTALL_DIR%" -StagingDir "%STAGING_DIR%"
    if errorlevel 1 (
        exit /b 1
    )
) else (
    if exist "%INSTALL_DIR%" (
        rmdir /s /q "%INSTALL_DIR%" >nul 2>nul
        if exist "%INSTALL_DIR%" (
            timeout /t 2 /nobreak >nul
            rmdir /s /q "%INSTALL_DIR%" >nul 2>nul
        )
    )
    if exist "%INSTALL_DIR%" (
        echo [ZeroTrust Setup] Failed to replace existing install directory.
        exit /b 1
    )

    move "%STAGING_DIR%" "%INSTALL_DIR%" >nul
    if errorlevel 1 (
        echo [ZeroTrust Setup] Failed to move staging directory into place.
        exit /b 1
    )
)
if not exist "%INSTALL_DIR%" (
    echo [ZeroTrust Setup] Failed to replace existing install directory.
    exit /b 1
)

echo [ZeroTrust Setup] Step 6/6: creating shortcuts...
"%INSTALL_DIR%\runtime\python\python.exe" "%INSTALL_DIR%\zt_demo_ctl.py" shortcuts
if errorlevel 1 (
    echo [ZeroTrust Setup] Shortcut creation failed.
    exit /b 1
)

echo.
echo [ZeroTrust Setup] Installation complete.
echo Desktop shortcuts were created:
echo   - ZeroTrust
echo   - ZeroTrust 제어
echo   - ZeroTrust 토큰 기기
echo.
echo Use "ZeroTrust" to start the server and open the web system.
echo Use "ZeroTrust 제어" to reset or stop the system.
exit /b 0

:popup
if "%QUIET%"=="1" exit /b 0
set "POPUP_TITLE=%~1"
set "POPUP_MESSAGE=%~2"
set "POPUP_TIMEOUT=%~3"
if "%POPUP_TIMEOUT%"=="" set "POPUP_TIMEOUT=0"
powershell -NoProfile -ExecutionPolicy Bypass -Command "$ws=New-Object -ComObject WScript.Shell; $null=$ws.Popup('%POPUP_MESSAGE%', [int]'%POPUP_TIMEOUT%', '%POPUP_TITLE%', 64)" >nul 2>nul
exit /b 0
