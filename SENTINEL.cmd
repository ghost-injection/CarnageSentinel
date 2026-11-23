@echo off
REM CARNAGE SENTINEL — silent launcher. No console window, no popups.
setlocal
set "PY=%LOCALAPPDATA%\Programs\Python\Python312\pythonw.exe"
if not exist "%PY%" set "PY=%LOCALAPPDATA%\Programs\Python\Python314\pythonw.exe"
if not exist "%PY%" set "PY=pythonw.exe"
start "" "%PY%" "%~dp0sentinel.py"
endlocal
