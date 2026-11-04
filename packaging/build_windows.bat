@echo off
rem One-click build of CrunchlockGUI.exe and crunchlock.exe on Windows.
rem Needs Python 3.10+ from python.org (tick "Add python.exe to PATH").
setlocal
cd /d "%~dp0.."

where py >nul 2>nul && (set "PY=py -3") || (set "PY=python")
%PY% --version >nul 2>nul || (
  echo Python was not found. Install it from https://www.python.org/downloads/
  echo and tick "Add python.exe to PATH" during setup, then run this again.
  goto :fail
)

echo [1/3] Creating a private Python environment in .venv ...
if not exist .venv\Scripts\python.exe %PY% -m venv .venv || goto :fail

echo [2/3] Installing crunchlock and PyInstaller ...
.venv\Scripts\python.exe -m pip install --upgrade pip || goto :fail
.venv\Scripts\python.exe -m pip install . pyinstaller pillow || goto :fail

echo [3/3] Building the executables (takes a minute or two) ...
.venv\Scripts\python.exe packaging\build.py || goto :fail

set "ISCC=%ProgramFiles(x86)%\Inno Setup 6\ISCC.exe"
for /f %%v in ('.venv\Scripts\python.exe -c "import crunchlock; print(crunchlock.__version__)"') do set "VER=%%v"
if exist "%ISCC%" (
  echo Building the installer with Inno Setup ...
  "%ISCC%" /Q "/DAppVersion=%VER%" "/DDistDir=%CD%\dist" "/DIconFile=%CD%\build\icons\crunchlock.ico" packaging\windows\crunchlock.iss || goto :fail
) else (
  echo Tip: install Inno Setup 6 from https://jrsoftware.org to also get an installer.
)

echo.
echo Done! Your programs are in the "dist" folder:
echo   CrunchlockGUI.exe  - the desktop app (double-click it)
echo   crunchlock.exe     - the command-line tool
if exist "%ISCC%" echo   Crunchlock-Setup-*.exe - installer (Start menu, right-click menu, .clk files)
start "" "%CD%\dist"
pause
exit /b 0

:fail
echo.
echo Build failed - see the messages above.
pause
exit /b 1
