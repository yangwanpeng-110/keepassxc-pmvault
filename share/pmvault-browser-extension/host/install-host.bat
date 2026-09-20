@echo off
setlocal enableextensions
rem ===========================================================================
rem PmVault Browser Bridge - register the KeePassXC-compatible native messaging
rem host (keepassxc-proxy.exe) for Google Chrome and Microsoft Edge (current user).
rem
rem Usage:
rem   install-host.bat                          (auto-detect proxy next to this folder)
rem   install-host.bat "C:\path\keepassxc-proxy.exe"
rem ===========================================================================

set "HOSTNAME=org.keepassxc.keepassxc_browser"
set "EXTID=efcjblaacddijgiakoocgkhdmihlgpfp"
set "PROXY=%~1"

if "%PROXY%"=="" if exist "%~dp0..\keepassxc-proxy.exe" set "PROXY=%~dp0..\keepassxc-proxy.exe"
if "%PROXY%"=="" if exist "%~dp0keepassxc-proxy.exe" set "PROXY=%~dp0keepassxc-proxy.exe"

if not exist "%PROXY%" (
  echo [PmVault] keepassxc-proxy.exe was not found.
  echo.
  echo Pass its full path as an argument, e.g.:
  echo   install-host.bat "C:\Users\you\Desktop\PmVault-windows-x64\keepassxc-proxy.exe"
  echo.
  pause
  exit /b 1
)

set "TARGETDIR=%LOCALAPPDATA%\PmVault\host"
if not exist "%TARGETDIR%" mkdir "%TARGETDIR%"
set "MANIFEST=%TARGETDIR%\%HOSTNAME%.json"

rem Double backslashes for valid JSON.
set "JSONPATH=%PROXY:\=\\%"

> "%MANIFEST%" echo {
>>"%MANIFEST%" echo   "name": "%HOSTNAME%",
>>"%MANIFEST%" echo   "description": "PmVault native messaging host (keepassxc-proxy)",
>>"%MANIFEST%" echo   "path": "%JSONPATH%",
>>"%MANIFEST%" echo   "type": "stdio",
>>"%MANIFEST%" echo   "allowed_origins": [
>>"%MANIFEST%" echo     "chrome-extension://%EXTID%/"
>>"%MANIFEST%" echo   ]
>>"%MANIFEST%" echo }

reg add "HKCU\Software\Google\Chrome\NativeMessagingHosts\%HOSTNAME%" /ve /t REG_SZ /d "%MANIFEST%" /f >nul
reg add "HKCU\Software\Microsoft\Edge\NativeMessagingHosts\%HOSTNAME%" /ve /t REG_SZ /d "%MANIFEST%" /f >nul
rem Chromium and other Chromium-based browsers
reg add "HKCU\Software\Chromium\NativeMessagingHosts\%HOSTNAME%" /ve /t REG_SZ /d "%MANIFEST%" /f >nul

echo.
echo [PmVault] Native messaging host registered for Chrome / Edge / Chromium.
echo Manifest: %MANIFEST%
echo Proxy:    %PROXY%
echo Extension ID (must match the loaded unpacked extension): %EXTID%
echo.
echo Next: open PmVault desktop, enable Settings ^> Browser Integration ^> Chrome/Edge,
echo then load this folder as an unpacked extension and click "Connect".
echo.
pause
endlocal
