@echo off
REM One-time setup for QSafe on Windows
cd /d "%~dp0"
where py >nul 2>nul && (set PY=py) || (set PY=python)
%PY% -m venv .venv || goto :err
.venv\Scripts\python -m pip install --upgrade pip
.venv\Scripts\pip install -r requirements.txt || goto :err
.venv\Scripts\python qsafe.py selftest || goto :err
.venv\Scripts\python make_demo_app.py
echo.
echo Setup complete. Open a terminal here and run:  .venv\Scripts\activate
echo Then try:  python qsafe.py scan demo_vulnerable_app
pause
exit /b 0
:err
echo Setup failed - make sure Python 3.9+ is installed from python.org
pause
exit /b 1
