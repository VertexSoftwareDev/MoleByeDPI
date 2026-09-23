@echo off
REM Mole kurucu. Cift tikla ya da sag tik > Yonetici olarak calistir.
REM Kendini yonetici yapar, hatti olcer, calisan ayari servis olarak kurar,
REM ve her adimi bu pencerede gosterir. ASCII metin: her konsolda dogru gorunur.
title Mole - Kurulum
cd /d "%~dp0"

REM --- Yonetici degilsek UAC ile kendini yeniden baslat ---
net session >nul 2>&1
if %errorlevel% neq 0 (
  echo Yonetici izni isteniyor...
  powershell -NoProfile -Command "Start-Process -Verb RunAs -FilePath '%~f0'"
  exit /b
)

echo ============================================================
echo   Mole - yerel erisim engeli asma araci
echo   Kurulum basliyor. Her adim asagida gosterilecek.
echo ============================================================
echo.

if not exist "%~dp0mole.exe" (
  echo HATA: mole.exe bu klasorde bulunamadi.
  echo Bu dosyayi mole.exe ile ayni klasorde calistirin.
  echo.
  pause
  exit /b 1
)

echo [1/2] Ortam kontrol ediliyor ^(yonetici, surucu, antivirus^)...
echo ------------------------------------------------------------
"%~dp0mole.exe" doctor
echo.
echo [2/2] Hattin olculuyor ve calisan ayar kuruluyor...
echo ------------------------------------------------------------
"%~dp0mole.exe" install --auto
set RESULT=%errorlevel%
echo.

if "%RESULT%"=="0" (
  echo ============================================================
  echo   Kurulum tamamlandi. Mole arka planda calisiyor ve
  echo   bilgisayar her acildiginda kendiliginden baslayacak.
  echo   Kendini onarir; durursa internetin kesilmez ^(fail-open^).
  echo.
  echo   Mole kendini Program Files'a kurdu; bu klasoru silebilirsin.
  echo   Kaldirmak istersen: Ayarlar ^> Uygulamalar ^> Mole,
  echo   ya da bu klasordeki uninstall.cmd.
  echo ============================================================
) else (
  echo ============================================================
  echo   Kurulum tamamlanamadi. Yukaridaki mesajlara bak.
  echo   Sik sebep: bir antivirus kalkani ^(Avast vb.^) suruculu
  echo   araclari engeller. O kalkana WinDivert istisnasi ekle
  echo   ya da kalkani gecici kapat, sonra tekrar dene.
  echo ============================================================
)
echo.
pause
