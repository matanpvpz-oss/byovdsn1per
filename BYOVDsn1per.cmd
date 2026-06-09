@echo off
REM BYOVDsn1per - portable cmd.exe wrapper.
REM Uses whatever `python` is first on PATH. For non-quick modes you need
REM the idalib bindings shipped with IDA Pro Essential 9.x.

setlocal
set "SCRIPT=%~dp0BYOVDsn1per.py"

if not exist "%SCRIPT%" (
  echo [BYOVDsn1per] script not found at %SCRIPT%
  exit /b 1
)

REM Try `python` first, then `py -3` (the Windows launcher).
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
echo                Get it from https://www.python.org/downloads/  (check "Add to PATH" during install)
exit /b 1
