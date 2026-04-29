@echo off
setlocal enabledelayedexpansion

REM ===================================================================
REM TrivyScan Update Script for Windows (Pure Batch)
REM This script updates both Trivy and TrivyScan to latest versions
REM ===================================================================

title TrivyScan Update

REM Colors (Windows 10+)
set "GREEN=[92m"
set "YELLOW=[93m"
set "RED=[91m"
set "BLUE=[94m"
set "NC=[0m"

REM Configuration
set "INSTALL_DIR=%ProgramFiles%\TrivyScan"
set "TRIVY_DIR=%ProgramFiles%\Trivy"
set "TRIVY_REPO=aquasecurity/trivy"
set "TRIVYSCAN_REPO=anhnmt/trivyscan"

echo ===============================================================
echo            TrivyScan Update Script
echo ===============================================================
echo.

REM Check for administrator privileges
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo %RED%ERROR: Administrator privileges required%NC%
    echo.
    echo Please right-click this file and select "Run as Administrator"
    echo.
    pause
    exit /b 1
)

echo %GREEN%[OK] Running with Administrator privileges%NC%
echo.

REM Detect architecture
if "%PROCESSOR_ARCHITECTURE%"=="AMD64" (
    set "ARCH=amd64"
    set "ARCH_TRIVY=64bit"
) else if "%PROCESSOR_ARCHITECTURE%"=="ARM64" (
    set "ARCH=arm64"
    set "ARCH_TRIVY=ARM64"
) else (
    echo %RED%ERROR: Unsupported architecture: %PROCESSOR_ARCHITECTURE%%NC%
    pause
    exit /b 1
)

echo System Information:
echo   OS: Windows
echo   Architecture: %ARCH%
echo   TrivyScan Directory: %INSTALL_DIR%
echo   Trivy Directory: %TRIVY_DIR%
echo.

set "TRIVY_UPDATED=0"
set "TRIVYSCAN_UPDATED=0"

REM ===================================================================
REM Step 1: Update Trivy
REM ===================================================================
echo ---------------------------------------------------------------
echo Step 1: Updating Trivy...
echo ---------------------------------------------------------------
echo.

echo Fetching latest Trivy version...
call :get_latest_version "%TRIVY_REPO%" LATEST_TRIVY
if "!LATEST_TRIVY!"=="" (
    echo %RED%ERROR: Failed to fetch latest Trivy version%NC%
    goto skip_trivy
)
echo %GREEN%[OK] Latest Trivy version: v!LATEST_TRIVY!%NC%

REM Get current version
where trivy >nul 2>&1
if %errorLevel% equ 0 (
    for /f "tokens=2 delims= " %%v in ('trivy --version 2^>nul ^| findstr /i "Version"') do set "CURRENT_TRIVY=%%v"
    if "!CURRENT_TRIVY!"=="" (
        for /f "tokens=1" %%v in ('trivy --version 2^>nul') do (
            set "line=%%v"
            set "CURRENT_TRIVY=!line:v=!"
        )
    )
    if not "!CURRENT_TRIVY!"=="" (
        echo   Current installed: v!CURRENT_TRIVY!
        if "!CURRENT_TRIVY!"=="!LATEST_TRIVY!" (
            echo %GREEN%[OK] Trivy is already up to date!%NC%
            goto skip_trivy
        )
    )
)

REM Update Trivy
echo.
echo %BLUE%Updating Trivy...%NC%

REM Check for Chocolatey first
where choco >nul 2>&1
if %errorLevel% equ 0 (
    echo %BLUE%Using Chocolatey to update Trivy...%NC%
    choco upgrade trivy -y
    if %errorLevel% equ 0 (
        echo %GREEN%[OK] Trivy updated successfully via Chocolatey!%NC%
        set "TRIVY_UPDATED=1"
        goto skip_trivy
    ) else (
        echo %YELLOW%[WARN] Chocolatey update failed, trying manual update...%NC%
    )
)

REM Manual update
set "TRIVY_URL=https://github.com/!TRIVY_REPO!/releases/download/v!LATEST_TRIVY!/trivy_!LATEST_TRIVY!_Windows-!ARCH_TRIVY!.zip"
set "TEMP_ZIP=%TEMP%\trivy_update.zip"
set "TEMP_DIR=%TEMP%\trivy_update"

echo Downloading from: !TRIVY_URL!
call :download_file "!TRIVY_URL!" "!TEMP_ZIP!"
if %errorLevel% neq 0 (
    echo %RED%ERROR: Failed to download Trivy%NC%
    goto skip_trivy
)

echo Extracting...
call :extract_zip "!TEMP_ZIP!" "!TEMP_DIR!"
if %errorLevel% neq 0 (
    echo %RED%ERROR: Failed to extract Trivy%NC%
    goto skip_trivy
)

echo Installing Trivy to !TRIVY_DIR!...
if not exist "!TRIVY_DIR!" mkdir "!TRIVY_DIR!"
copy /Y "!TEMP_DIR!\trivy.exe" "!TRIVY_DIR!\trivy.exe" >nul
if %errorLevel% neq 0 (
    echo %RED%ERROR: Failed to copy Trivy binary%NC%
    goto skip_trivy
)

REM Cleanup
del /F /Q "!TEMP_ZIP!" 2>nul
rmdir /S /Q "!TEMP_DIR!" 2>nul

echo %GREEN%[OK] Trivy updated successfully!%NC%
set "TRIVY_UPDATED=1"

:skip_trivy
echo.

REM ===================================================================
REM Step 2: Update TrivyScan
REM ===================================================================
echo ---------------------------------------------------------------
echo Step 2: Updating TrivyScan...
echo ---------------------------------------------------------------
echo.

echo Fetching latest TrivyScan version...
call :get_latest_version "%TRIVYSCAN_REPO%" LATEST_TRIVYSCAN
if "!LATEST_TRIVYSCAN!"=="" (
    echo %RED%ERROR: Failed to fetch latest TrivyScan version%NC%
    goto skip_trivyscan
)
echo %GREEN%[OK] Latest TrivyScan version: v!LATEST_TRIVYSCAN!%NC%

REM Get current version
where trivyscan >nul 2>&1
if %errorLevel% equ 0 (
    for /f "tokens=3" %%v in ('trivyscan --version 2^>nul') do set "CURRENT_TRIVYSCAN=%%v"
    if "!CURRENT_TRIVYSCAN!"=="" (
        for /f "tokens=1" %%v in ('trivyscan --version 2^>nul') do (
            set "line=%%v"
            set "CURRENT_TRIVYSCAN=!line:v=!"
        )
    )
    if not "!CURRENT_TRIVYSCAN!"=="" (
        echo   Current installed: v!CURRENT_TRIVYSCAN!
        if "!CURRENT_TRIVYSCAN!"=="!LATEST_TRIVYSCAN!" (
            echo %GREEN%[OK] TrivyScan is already up to date!%NC%
            goto skip_trivyscan
        )
    )
)

REM Update TrivyScan
echo.
echo %BLUE%Updating TrivyScan...%NC%

set "TRIVYSCAN_URL=https://github.com/!TRIVYSCAN_REPO!/releases/download/v!LATEST_TRIVYSCAN!/trivyscan_!LATEST_TRIVYSCAN!_windows_!ARCH!.zip"
set "TEMP_ZIP=%TEMP%\trivyscan_update.zip"
set "TEMP_DIR=%TEMP%\trivyscan_update"

echo Downloading from: !TRIVYSCAN_URL!
call :download_file "!TRIVYSCAN_URL!" "!TEMP_ZIP!"
if %errorLevel% neq 0 (
    echo %RED%ERROR: Failed to download TrivyScan%NC%
    goto skip_trivyscan
)

echo Extracting...
call :extract_zip "!TEMP_ZIP!" "!TEMP_DIR!"
if %errorLevel% neq 0 (
    echo %RED%ERROR: Failed to extract TrivyScan%NC%
    goto skip_trivyscan
)

echo Installing TrivyScan to !INSTALL_DIR!...
if not exist "!INSTALL_DIR!" mkdir "!INSTALL_DIR!"
copy /Y "!TEMP_DIR!\trivyscan.exe" "!INSTALL_DIR!\trivyscan.exe" >nul
if %errorLevel% neq 0 (
    echo %RED%ERROR: Failed to copy TrivyScan binary%NC%
    goto skip_trivyscan
)

REM Cleanup
del /F /Q "!TEMP_ZIP!" 2>nul
rmdir /S /Q "!TEMP_DIR!" 2>nul

echo %GREEN%[OK] TrivyScan updated successfully!%NC%
set "TRIVYSCAN_UPDATED=1"

:skip_trivyscan
echo.

REM ===================================================================
REM Step 3: Verify updates
REM ===================================================================
echo ---------------------------------------------------------------
echo Step 3: Verifying updates...
echo ---------------------------------------------------------------
echo.

REM Refresh PATH
call :refresh_path

where trivy >nul 2>&1
if %errorLevel% equ 0 (
    echo Trivy version:
    trivy --version
    echo.
)

where trivyscan >nul 2>&1
if %errorLevel% equ 0 (
    echo TrivyScan version:
    trivyscan --version
    echo.
)

REM ===================================================================
REM Update Summary
REM ===================================================================
echo ===============================================================
echo              Update Summary
echo ===============================================================
echo.

if %TRIVY_UPDATED% equ 1 (
    echo %GREEN%[OK] Trivy updated successfully%NC%
) else (
    echo %YELLOW%[WARN] Trivy update skipped or failed%NC%
)

if %TRIVYSCAN_UPDATED% equ 1 (
    echo %GREEN%[OK] TrivyScan updated successfully%NC%
) else (
    echo %YELLOW%[WARN] TrivyScan update skipped or failed%NC%
)

echo.
echo ===============================================================
echo.

if %TRIVY_UPDATED% equ 1 (
    echo Update completed! 
    echo.
) else if %TRIVYSCAN_UPDATED% equ 1 (
    echo Update completed! 
    echo.
) else (
    echo No updates were performed.
    echo.
)

pause
exit /b 0

REM ===================================================================
REM Functions
REM ===================================================================

:get_latest_version
REM Get latest version from GitHub API
REM Args: %1 = repo (e.g. "aquasecurity/trivy"), %2 = return variable name
setlocal
set "repo=%~1"
set "temp_file=%TEMP%\github_api_response.txt"

REM Try using curl (Windows 10 1803+)
where curl >nul 2>&1
if %errorLevel% equ 0 (
    curl -s "https://api.github.com/repos/%repo%/releases/latest" -o "%temp_file%" 2>nul
    if exist "%temp_file%" (
        for /f "tokens=2 delims=:," %%a in ('findstr /i "tag_name" "%temp_file%"') do (
            set "version=%%a"
            set "version=!version: =!"
            set "version=!version:"=!"
            set "version=!version:v=!"
            del /F /Q "%temp_file%" 2>nul
            endlocal & set "%~2=%version%"
            exit /b 0
        )
    )
)

REM Fallback: try using PowerShell
where powershell >nul 2>&1
if %errorLevel% equ 0 (
    for /f "usebackq delims=" %%v in (`powershell -NoProfile -Command "(Invoke-RestMethod 'https://api.github.com/repos/%repo%/releases/latest').tag_name -replace '^v',''" 2^>nul`) do (
        endlocal & set "%~2=%%v"
        exit /b 0
    )
)

REM Failed to get version
endlocal & set "%~2="
exit /b 1

:download_file
REM Download file using curl or PowerShell
REM Args: %1 = URL, %2 = output file
setlocal
set "url=%~1"
set "output=%~2"

REM Try using curl first (Windows 10 1803+)
where curl >nul 2>&1
if %errorLevel% equ 0 (
    echo Downloading with curl...
    curl -L "%url%" -o "%output%" --progress-bar
    if %errorLevel% equ 0 (
        endlocal
        exit /b 0
    )
)

REM Fallback to PowerShell
where powershell >nul 2>&1
if %errorLevel% equ 0 (
    echo Downloading with PowerShell...
    powershell -NoProfile -Command "& {[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; Invoke-WebRequest -Uri '%url%' -OutFile '%output%' -UseBasicParsing}" 2>nul
    if %errorLevel% equ 0 (
        endlocal
        exit /b 0
    )
)

endlocal
exit /b 1

:extract_zip
REM Extract ZIP file
REM Args: %1 = zip file, %2 = destination
setlocal
set "zipfile=%~1"
set "destination=%~2"

REM Use PowerShell to extract
where powershell >nul 2>&1
if %errorLevel% equ 0 (
    if exist "%destination%" rmdir /S /Q "%destination%" 2>nul
    powershell -NoProfile -Command "Expand-Archive -Path '%zipfile%' -DestinationPath '%destination%' -Force" 2>nul
    if %errorLevel% equ 0 (
        endlocal
        exit /b 0
    )
)

REM Fallback: try using tar (Windows 10 1803+)
where tar >nul 2>&1
if %errorLevel% equ 0 (
    if exist "%destination%" rmdir /S /Q "%destination%" 2>nul
    mkdir "%destination%"
    tar -xf "%zipfile%" -C "%destination%"
    if %errorLevel% equ 0 (
        endlocal
        exit /b 0
    )
)

endlocal
exit /b 1

:refresh_path
REM Refresh PATH in current session
for /f "tokens=2*" %%a in ('reg query "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v Path 2^>nul') do set "PATH=%%b"
exit /b 0
