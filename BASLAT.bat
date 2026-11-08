@echo off
chcp 65001 >nul
title SaytYoxla Skaner
cd /d "%~dp0"

echo ========================================
echo    SaytYoxla Skaner baslatilir...
echo ========================================
echo.

REM --- Python-u tap (proven full path, sonra py launcher) ---
set "PYEXE=C:\Users\%USERNAME%\AppData\Local\Programs\Python\Python312\python.exe"
if not exist "%PYEXE%" set "PYEXE=py"

echo [1/3] Kitabxanalar yoxlanilir / qurasdirilir...
"%PYEXE%" -m pip install -r requirements.txt
echo.

echo [2/3] Brauzer 3 saniyeye acilacaq: http://127.0.0.1:5000
start "" cmd /c "timeout /t 3 >nul & start http://127.0.0.1:5000"
echo.

echo [3/3] Server islyir. Dayandirmaq ucun bu pencerede Ctrl+C.
echo ----------------------------------------
"%PYEXE%" app.py

echo.
echo Server dayandi. Cixmaq ucun bir dugmeye bas...
pause >nul
