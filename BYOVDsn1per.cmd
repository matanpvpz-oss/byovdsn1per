@echo off
setlocal
set "SCRIPT=%~dp0BYOVDsn1per.py"

if not exist "%SCRIPT%" (
  echo [BYOVDsn1per] script not found at %SCRIPT%
  exit /b 1
)

where /q python
if %ERRORLEVEL%==0 (
  python "%SCRIPT%" %*
  exit /b %ERRORLEVEL%
)

where /q py
if %ERRORLEVEL%==0 (
  py -3 "%SCRIPT%" %*
  exit /b %ERRORLEVEL%
)

echo [BYOVDsn1per] Python not found on PATH. Install Python 3.10+ and retry.
echo                Get it from https://www.python.org/downloads/
exit /b 1
