@echo off
rem One-click build of CrunchlockGUI.exe and crunchlock.exe (and the installer if
rem Inno Setup 6 is installed). Uses the exact package versions of the official
rem release builds, in a fresh private environment, then self-tests the result.
rem Needs Python from python.org (3.12 recommended; tick "Add python.exe to PATH").
setlocal
cd /d "%~dp0.."

set "PY="
py -3.12 --version >/dev/null 2>/dev/null && set "PY=py -3.12"
if not defined PY py -3 --version >/dev/null 2>/dev/null && set "PY=py -3"
if not defined PY python --version >/dev/null 2>/dev/null && set "PY=python"
if not defined PY (
  echo Python was not found. Install Python 3.12 from https://www.python.org/downloads/
  echo and tick "Add python.exe to PATH" during setup, then run this again.
  goto :fail
)
echo Using:
%PY% --version

echo [1/4] Creating a fresh private Python environment in .venv ...
if exist .venv rmdir /s /q .venv
if exist .venv (
  echo Could not delete the old .venv folder. Close any program using it and try again.
  goto :fail
)
%PY% -m venv .venv || goto :fail

echo [2/4] Installing the exact package versions used for the official release ...
.venv\Scripts\python.exe -m pip install --upgrade pip || goto :fail
.venv\Scripts\python.exe -m pip install -r packaging\requirements-build.txt || goto :fail
.venv\Scripts\python.exe -m pip install --no-deps . || goto :fail

echo [3/4] Building and self-testing the programs (takes a few minutes) ...
if exist build rmdir /s /q build
if exist dist rmdir /s /q dist
.venv\Scripts\python.exe packaging\build.py || goto :fail

echo [4/4] Installer ...
set "ISCC=%ProgramFiles(x86)%\Inno Setup 6\ISCC.exe"
for /f %%v in ('.venv\Scripts\python.exe -c "import crunchlock; print(crunchlock.__version__)"') do set "VER=%%v"
if exist "%ISCC%" (
  "%ISCC%" /Q "/DAppVersion=%VER%" "/DDistDir=%CD%\dist" "/DIconFile=%CD%\build\icons\crunchlock.ico" packaging\windows\crunchlock.iss || goto :fail
) else (
  echo Skipped: install Inno Setup 6 from https://jrsoftware.org to also get an installer.
)

echo.
echo Done! Your programs are in the "dist" folder:
echo   CrunchlockGUI.exe  - the desktop app (double-click it)
echo   crunchlock.exe     - the command-line tool
if exist "%ISCC%" echo   Crunchlock-Setup-%VER%.exe - the installer
start "" "%CD%\dist"
pause
exit /b 0

:fail
echo.
echo Build failed - see the messages above. If a self-test failed, please copy
echo everything from "Self-test" downwards and report it.
pause
exit /b 1
