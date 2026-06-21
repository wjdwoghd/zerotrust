@echo off
chcp 65001 >nul
cd /d "%~dp0"
start "" "%~dp0runtime\python\pythonw.exe" "%~dp0zt_demo_ctl.py" start
