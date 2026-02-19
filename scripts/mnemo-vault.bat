\
@echo off
setlocal enabledelayedexpansion

set "SCRIPT_DIR=%~dp0"
set "PROJECT_DIR=%SCRIPT_DIR%.."

where poetry >nul 2>nul
if %errorlevel%==0 (
  for /f "delims=" %%i in ('poetry -C "%PROJECT_DIR%" env info -e 2^>nul') do set "VENV_BIN=%%i"
  if defined VENV_BIN (
    "%VENV_BIN%" -m mnemo_vault.cli %*
    exit /b %errorlevel%
  )
)

where mnemo-vault >nul 2>nul
if %errorlevel%==0 (
  mnemo-vault %*
  exit /b %errorlevel%
)

echo ERROR: poetry virtualenv not found and mnemo-vault not in PATH. 1>&2
echo Hint: cd "%PROJECT_DIR%" ^& poetry install 1>&2
exit /b 1
