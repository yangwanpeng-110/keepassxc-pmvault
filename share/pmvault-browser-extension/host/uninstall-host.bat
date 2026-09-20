@echo off
setlocal
set "HOSTNAME=org.keepassxc.keepassxc_browser"
reg delete "HKCU\Software\Google\Chrome\NativeMessagingHosts\%HOSTNAME%" /f >nul 2>nul
reg delete "HKCU\Software\Microsoft\Edge\NativeMessagingHosts\%HOSTNAME%" /f >nul 2>nul
reg delete "HKCU\Software\Chromium\NativeMessagingHosts\%HOSTNAME%" /f >nul 2>nul
if exist "%LOCALAPPDATA%\PmVault\host\%HOSTNAME%.json" del /q "%LOCALAPPDATA%\PmVault\host\%HOSTNAME%.json"
echo [PmVault] Native messaging host registration removed for Chrome / Edge / Chromium.
pause
endlocal
