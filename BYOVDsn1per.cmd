@echo off
REM BYOVDsn1per launcher (cmd.exe wrapper)
REM Pins to Python 3.12 + idalib bundled with IDA Essential 9.3.
REM Filters out the [MCP] auto-start noise lines that idalib's MCP plugin
REM prints on every load (the user's IDA Pro GUI already holds port 13337,
REM so the embedded plugin prints "already in use" then yields harmlessly).

setlocal
set "PY=C:\Users\kj\AppData\Local\Programs\Python\Python312\python.exe"
set "SCRIPT=%~dp0BYOVDsn1per.py"

if not exist "%PY%" (
  echo [BYOVDsn1per] Python 3.12 not found at %PY%
  exit /b 1
)
if not exist "%SCRIPT%" (
  echo [BYOVDsn1per] script not found at %SCRIPT%
  exit /b 1
)

REM Filter [MCP] noise from idalib's auto-loaded MCP plugin. findstr
REM /C: with brackets is unreliable (treats [...] as char class), so
REM filter on "13337" instead -- the port number appears in both noise
REM lines and almost certainly won't appear in legitimate output.
"%PY%" "%SCRIPT%" %* 2>&1 | findstr /V "13337"
exit /b %ERRORLEVEL%
