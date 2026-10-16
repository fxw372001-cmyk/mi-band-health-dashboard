@echo off
setlocal
cd /d "%~dp0"
chcp 65001 >nul

echo ============================================
echo   MiBandHealth Client Builder
echo ============================================

python build.py %*
pause
