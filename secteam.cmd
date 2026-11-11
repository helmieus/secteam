@echo off
rem Pelancar secteam - tak perlu aktifkan venv secara manual.
set "PATH=%LOCALAPPDATA%\Programs\Ollama;%PATH%"
set "PYTHONIOENCODING=utf-8"
cd /d "%~dp0"
"%~dp0.venv\Scripts\secteam.exe" %*
