@echo off
rem Starts crosspost guard on Windows: loads settings from .env if there is one,
rem then runs the bot. Used for starting it automatically when you log in.
cd /d "%~dp0"
title Crosspost guard
if exist .env (
  for /f "usebackq eol=# tokens=1,* delims==" %%a in (".env") do set "%%a=%%b"
)
".venv\Scripts\python.exe" bot.py
echo.
echo The bot has stopped. Press any key to close this window.
pause >nul
