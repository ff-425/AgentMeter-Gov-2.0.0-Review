@echo off
setlocal
chcp 65001 >nul
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0installer\install.ps1"
set "AGENTMETER_EXIT=%ERRORLEVEL%"
echo.
if not "%AGENTMETER_EXIT%"=="0" echo 安装未完成，请保留本窗口中的错误信息。
pause
exit /b %AGENTMETER_EXIT%
