@echo off
setlocal
cd /d "%~dp0"
chcp 65001 >nul

echo ============================================
echo   Mi Band Cloud Health Dashboard
echo ============================================
echo.

set "PY="
where python >nul 2>nul
if %errorlevel%==0 (
  set "PY=python"
) else (
  where py >nul 2>nul
  if %errorlevel%==0 (
    set "PY=py -3"
  ) else (
    echo [ERROR] Python not found. Please install Python 3.9+ from https://www.python.org
    echo [ERROR] and check "Add Python to PATH" during installation.
    pause
    exit /b 1
  )
)

if not exist "vendor\flask" (
  echo [WARN] Local dependencies (vendor) missing. Trying pip install (online needed once) ...
  %PY% -m pip install flask requests -i https://pypi.tuna.tsinghua.edu.cn/simple --timeout 60 --retries 5 --quiet
  if %errorlevel% neq 0 (
    %PY% -m pip install flask requests -i https://mirrors.aliyun.com/pypi/simple/ --timeout 60 --retries 5 --quiet
  )
  if %errorlevel% neq 0 (
    %PY% -m pip install flask requests --timeout 60 --retries 5 --quiet
  )
  if %errorlevel% neq 0 (
    echo [ERROR] Failed to install dependencies. Check network and run:
    echo   %PY% -m pip install flask requests
    pause
    exit /b 1
  )
)

echo Starting local server ...
echo.
echo   Open browser: http://127.0.0.1:8000
echo   Keep this window open while using. Press Ctrl+C to stop.
echo.
%PY% app.py
pause
