@echo off
cd /d "%~dp0"
:loop
node server.js
echo Server stopped. Restarting in 3 seconds... (close this window to quit)
timeout /t 3 >nul
goto loop
