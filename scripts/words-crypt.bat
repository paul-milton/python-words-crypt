\
@echo off
setlocal enabledelayedexpansion

where poetry >nul 2>nul
if %errorlevel%==0 (
  poetry run words-crypt %*
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
