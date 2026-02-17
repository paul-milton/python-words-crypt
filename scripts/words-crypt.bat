\
@echo off
setlocal enabledelayedexpansion

set "SCRIPT_DIR=%~dp0"
set "PROJECT_DIR=%SCRIPT_DIR%.."

where poetry >nul 2>nul
if %errorlevel%==0 (
  poetry -C "%PROJECT_DIR%" run words-crypt %*
  exit /b %errorlevel%
)

where words-crypt >nul 2>nul
if %errorlevel%==0 (
  words-crypt %*
  exit /b %errorlevel%
)

echo ERROR: poetry not found and words-crypt not installed in PATH. 1>&2
echo Hint: run "poetry install" then "poetry run words-crypt ..." 1>&2
exit /b 1
