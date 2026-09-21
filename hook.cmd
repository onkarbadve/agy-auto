@echo off
rem agy-auto PreToolUse hook for Windows.
rem Reads the tool call on stdin, prints {"decision": ...}.
rem Fail-closed: if python cannot start, output json deny.
setlocal
set "DIR=%~dp0"
set "PY=%AGY_AUTO_PYTHON%"
if "%PY%"=="" (
  where python >nul 2>nul && (set "PY=python") || (
    where py >nul 2>nul && (set "PY=py -3") || (
      where python3 >nul 2>nul && (set "PY=python3")
    )
  )
)
if "%PY%"=="" (
  echo {"decision":"deny","reason":"[agy-auto] Python 3.11+ not found on PATH; policy engine cannot run (fail-closed)"}
  exit /b 0
)
"%PY%" "%DIR%engine\main.py"
