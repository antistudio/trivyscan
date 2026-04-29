@echo off
setlocal enabledelayedexpansion

REM ===================================================================
REM TrivyScan Installation Script for Windows (Pure Batch)
REM This script installs both TrivyScan and Trivy (if not present)
REM ===================================================================

title TrivyScan Installation

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
echo            TrivyScan Installation Script
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

REM ===================================================================
REM Step 1: Check and install Trivy
REM ===================================================================
echo ---------------------------------------------------------------
echo Step 1: Checking Trivy installation...
echo ---------------------------------------------------------------
echo.

where trivy >nul 2>&1
if %errorLevel% equ 0 (
    echo %GREEN%[OK] Trivy is already installed%NC%
    trivy --version
) else (
    echo %YELLOW%[WARN] Trivy not found. Installing Trivy...%NC%
    echo.
    
    REM Check for Chocolatey
    where choco >nul 2>&1
    if %errorLevel% equ 0 (
        echo %BLUE%Using Chocolatey to install Trivy...%NC%
        choco install trivy -y
        if %errorLevel% equ 0 (
            echo %GREEN%[OK] Trivy installed successfully via Chocolatey!%NC%
            goto trivy_installed
        ) else (
            echo %YELLOW%[WARN] Chocolatey installation failed, trying manual installation...%NC%
        )
    )
    
    REM Manual installation
    echo %BLUE%Installing Trivy manually...%NC%
    echo.
    
    REM Get latest Trivy version
    echo Fetching latest Trivy version from GitHub...
    call :get_latest_version "%TRIVY_REPO%" TRIVY_VERSION
    if "!TRIVY_VERSION!"=="" (
        echo %YELLOW%[WARN] Failed to fetch latest version, using fallback: v0.58.1%NC%
        set "TRIVY_VERSION=0.58.1"
    ) else (
        echo %GREEN%[OK] Latest Trivy version: v!TRIVY_VERSION!%NC%
    )
    echo.
    
    set "TRIVY_URL=https://github.com/!TRIVY_REPO!/releases/download/v!TRIVY_VERSION!/trivy_!TRIVY_VERSION!_Windows-!ARCH_TRIVY!.zip"
    set "TEMP_ZIP=%TEMP%\trivy_install.zip"
    set "TEMP_DIR=%TEMP%\trivy_install"
    
    echo Downloading from: !TRIVY_URL!
    call :download_file "!TRIVY_URL!" "!TEMP_ZIP!"
    if %errorLevel% neq 0 (
        echo %RED%ERROR: Failed to download Trivy%NC%
        pause
        exit /b 1
    )
    
    echo Extracting...
    call :extract_zip "!TEMP_ZIP!" "!TEMP_DIR!"
    if %errorLevel% neq 0 (
        echo %RED%ERROR: Failed to extract Trivy%NC%
        pause
        exit /b 1
    )
    
    echo Installing Trivy to !TRIVY_DIR!...
    if not exist "!TRIVY_DIR!" mkdir "!TRIVY_DIR!"
    copy /Y "!TEMP_DIR!\trivy.exe" "!TRIVY_DIR!\trivy.exe" >nul
    if %errorLevel% neq 0 (
        echo %RED%ERROR: Failed to copy Trivy binary%NC%
        pause
        exit /b 1
    )
    
    REM Cleanup
    del /F /Q "!TEMP_ZIP!" 2>nul
    rmdir /S /Q "!TEMP_DIR!" 2>nul
    
    REM Add to PATH
    call :add_to_path "!TRIVY_DIR!"
    
    echo %GREEN%[OK] Trivy installed successfully!%NC%
)

:trivy_installed
echo.

REM ===================================================================
REM Step 2: Install TrivyScan
REM ===================================================================
echo ---------------------------------------------------------------
echo Step 2: Installing TrivyScan...
echo ---------------------------------------------------------------
echo.

REM Find TrivyScan binary in current directory
set "TRIVYSCAN_SOURCE="
if exist "%~dp0trivyscan.exe" (
    set "TRIVYSCAN_SOURCE=%~dp0trivyscan.exe"
) else if exist "%~dp0trivyscan_windows_%ARCH%.exe" (
    set "TRIVYSCAN_SOURCE=%~dp0trivyscan_windows_%ARCH%.exe"
) else (
    echo %RED%ERROR: TrivyScan binary not found in current directory%NC%
    echo Expected: trivyscan.exe or trivyscan_windows_%ARCH%.exe
    pause
    exit /b 1
)

echo Source: !TRIVYSCAN_SOURCE!
echo Target: %INSTALL_DIR%\trivyscan.exe
echo.

if not exist "%INSTALL_DIR%" mkdir "%INSTALL_DIR%"
copy /Y "!TRIVYSCAN_SOURCE!" "%INSTALL_DIR%\trivyscan.exe" >nul
if %errorLevel% neq 0 (
    echo %RED%ERROR: Failed to copy TrivyScan binary%NC%
    pause
    exit /b 1
)

REM Add to PATH
call :add_to_path "%INSTALL_DIR%"

echo %GREEN%[OK] TrivyScan installed successfully!%NC%
echo.

REM ===================================================================
REM Step 3: Verify installation
REM ===================================================================
echo ---------------------------------------------------------------
echo Step 3: Verifying installation...
echo ---------------------------------------------------------------
echo.

REM Refresh PATH for current session
call :refresh_path

where trivy >nul 2>&1
if %errorLevel% neq 0 (
    echo %YELLOW%[WARN] Trivy not found in PATH. Please restart your terminal.%NC%
) else (
    echo Trivy version:
    trivy --version
)
echo.

where trivyscan >nul 2>&1
if %errorLevel% neq 0 (
    echo %YELLOW%[WARN] TrivyScan not found in PATH. Please restart your terminal.%NC%
) else (
    echo TrivyScan version:
    trivyscan --version
)
echo.

REM ===================================================================
REM Installation Complete
REM ===================================================================
echo ===============================================================
echo              Installation Complete!
echo ===============================================================
echo.
echo IMPORTANT: Please restart your Command Prompt or PowerShell
echo            for PATH changes to take effect.
echo.
echo You can then use:
echo   trivyscan --help
echo   trivyscan -i image.tar -o reports\
echo.
echo Happy scanning! 
echo.
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

:add_to_path
REM Add directory to system PATH if not already present
REM Args: %1 = directory to add
setlocal
set "dir_to_add=%~1"

REM Get current PATH
for /f "tokens=2*" %%a in ('reg query "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v Path 2^>nul') do set "current_path=%%b"

REM Check if already in PATH
echo !current_path! | findstr /i /c:"!dir_to_add!" >nul
if %errorLevel% equ 0 (
    echo %GREEN%[OK] Already in PATH%NC%
    endlocal
    exit /b 0
)

REM Add to PATH
echo Adding !dir_to_add! to system PATH...
set "new_path=!current_path!;!dir_to_add!"
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v Path /t REG_EXPAND_SZ /d "!new_path!" /f >nul 2>&1
if %errorLevel% equ 0 (
    echo %GREEN%[OK] Added to PATH%NC%
) else (
    echo %YELLOW%[WARN] Failed to add to PATH automatically%NC%
)

endlocal
exit /b 0

:refresh_path
REM Refresh PATH in current session
for /f "tokens=2*" %%a in ('reg query "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v Path 2^>nul') do set "PATH=%%b"
exit /b 0

