@echo off
REM Mole kaldirici. Cift tikla ya da sag tik > Yonetici olarak calistir.
REM Servisi durdurur, kaldirir ve iz birakmaz. Internet normal akmaya devam eder.
title Mole - Kaldirma
cd /d "%~dp0"

net session >nul 2>&1
if %errorlevel% neq 0 (
  echo Yonetici izni isteniyor...
  powershell -NoProfile -Command "Start-Process -Verb RunAs -FilePath '%~f0'"
  exit /b
)

echo ============================================================
echo   Mole - kaldiriliyor
echo ============================================================
echo.

if not exist "%~dp0mole.exe" (
  echo HATA: mole.exe bu klasorde bulunamadi.
  echo.
  pause
  exit /b 1
)

"%~dp0mole.exe" uninstall
echo.
echo Bitti. Bu pencereyi kapatabilirsin.
echo.
pause
