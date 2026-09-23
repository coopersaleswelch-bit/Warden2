@echo off
setlocal enabledelayedexpansion
cd /d "%~dp0"
chcp 65001 >nul 2>nul
title Warden 2.0
color 0F

REM ---------------------------------------------------------------------
REM  Refuse to run from a temp folder.
REM
REM  Double-clicking a .bat while still browsing INSIDE a zip makes Windows
REM  copy that one file to a temp folder and run it alone, with none of the
REM  project beside it. The failure that produces is confusing and looks like
REM  a bug in the code, so catch it here and say what actually happened.
REM ---------------------------------------------------------------------
echo "%CD%" | findstr /i "\\Temp\\" >nul
if !errorlevel!==0 goto INZIP
echo "%CD%" | findstr /i ".zip" >nul
if !errorlevel!==0 goto INZIP

REM ---------------------------------------------------------------------
REM  Find a working Python. Tries the three names Windows might have.
REM  "where python" is not enough - the Microsoft Store ships a fake stub
REM  that answers to the name but fails on the first real command, so we
REM  actually run something trivial and check it worked.
REM ---------------------------------------------------------------------

set "PY="

python -c "import sys" >nul 2>nul
if !errorlevel!==0 set "PY=python"

if not defined PY (
  py -3 -c "import sys" >nul 2>nul
  if !errorlevel!==0 set "PY=py -3"
)

if not defined PY (
  python3 -c "import sys" >nul 2>nul
  if !errorlevel!==0 set "PY=python3"
)

if not defined PY goto NOPYTHON

:MENU
cls
echo.
echo   ==========================================================
echo     WARDEN 2.0
echo     Tool contract enforcement for MCP
echo   ==========================================================
echo.
echo     Folder : %CD%
echo     Python : !PY!
echo.
echo   ----------------------------------------------------------
echo.
echo     1   Setup            install what Warden needs (run once)
echo     2   Test             prove the code works
echo     3   Attack demo      the rug-pull, caught
echo     4   Live demo        same attack over a real MCP server
echo     5   Upgrade demo     real updates pass, attacks still do not
echo     6   Real server      run against the official filesystem MCP server
echo     7   Report           open the evidence page in your browser
echo     8   Text summary     same thing, in this window
echo     9   Reset            wipe recorded history, keep the code
echo.
echo    10   Protect          put Warden in front of a Claude Desktop server
echo    11   Unprotect        put a server back exactly as it was
echo    12   Check setup      is this machine ready? changes nothing
echo.
echo     0   Quit
echo.
set "choice="
set /p choice=  Type a number and press Enter:  

if "%choice%"=="1" goto SETUP
if "%choice%"=="2" goto TEST
if "%choice%"=="3" goto DEMO
if "%choice%"=="4" goto LIVE
if "%choice%"=="5" goto DAY3
if "%choice%"=="6" goto DAY4
if "%choice%"=="7" goto REPORT
if "%choice%"=="8" goto SUMMARY
if "%choice%"=="9" goto RESET
if "%choice%"=="10" goto PROTECT
if "%choice%"=="11" goto UNPROTECT
if "%choice%"=="12" goto DOCTOR
if "%choice%"=="0" goto END
goto MENU

:SETUP
cls
echo.
echo   Installing PyYAML, the only thing Warden needs.
echo.
!PY! -m pip install -r requirements.txt
echo.
if !errorlevel!==0 (
  echo   Done. You can go straight to option 2 now.
) else (
  echo   That did not work. Screenshot this window and send it to Claude.
)
echo.
pause
goto MENU

:TEST
cls
echo.
!PY! test_warden.py
echo.
echo   The last line should end in "0 failed".
echo.
pause
goto MENU

:DEMO
cls
echo.
!PY! demo_deadbugz.py
echo.
echo   The important part is STEP 3, where the tool changes and gets caught.
echo.
pause
goto MENU

:LIVE
cls
echo.
echo   This launches a real MCP server, puts Warden in front of it, and
echo   talks to it over the real protocol. Nothing here is faked.
echo.
!PY! demo_live_proxy.py
echo.
pause
goto MENU

:DAY3
cls
echo.
echo   Four sessions against a real server:
echo     - a genuine v1.1.0 release            should be ACCEPTED
echo     - a swap hiding behind the same version should be CAUGHT
echo     - a swap with an honest version bump    should be CAUGHT anyway
echo.
!PY! demo_day3.py
echo.
pause
goto MENU

:DAY4
cls
echo.
echo   Warden against @modelcontextprotocol/server-filesystem - the official
echo   server, written by people who never heard of Warden.
echo.
!PY! demo_day4.py
echo.
pause
goto MENU

:DOCTOR
cls
echo.
!PY! -m warden.doctor
echo.
pause
goto MENU

:PROTECT
cls
echo.
echo   Run option 12 first if you have not already.
echo.
echo   This reads your Claude Desktop settings and lists your MCP servers.
echo   Pick one, and Warden will inspect it, approve its current tools, back
echo   up your settings, and put itself in front of that server.
echo.
!PY! -m warden.install
echo.
pause
goto MENU

:UNPROTECT
cls
echo.
!PY! -m warden.install --list
echo.
set "srv="
set /p srv=  Type the NAME of the server to unprotect (Enter to cancel):  
if not defined srv goto MENU
!PY! -m warden.install --unprotect "!srv!"
echo.
echo   Fully quit Claude Desktop from the system tray, then reopen it.
echo.
pause
goto MENU

:REPORT
cls
echo.
echo   Building the report and opening it in your browser.
echo.
!PY! -m warden.report
echo.
echo   If nothing opened, the file is warden_report.html in this folder.
echo.
pause
goto MENU

:SUMMARY
cls
echo.
!PY! summary.py
echo.
pause
goto MENU

:RESET
cls
echo.
echo   This deletes the recorded decisions and approved contracts.
echo   Your code is untouched. The demos rebuild everything from scratch.
echo.
set "sure="
set /p sure=  Type YES to confirm:  
if /i not "%sure%"=="YES" goto MENU
del /q warden_registry.db warden_audit.db warden_report.html warden_proxy.log 2>nul
echo.
echo   Cleared.
echo.
pause
goto MENU

:INZIP
cls
echo.
echo   ==========================================================
echo     This is running from inside the zip file.
echo   ==========================================================
echo.
echo   Windows copied this one file to a temporary folder and ran it
echo   on its own. The rest of the project is not here, so nothing
echo   would work - and the temp folder gets deleted automatically.
echo.
echo   Current folder:
echo   %CD%
echo.
echo   To fix it:
echo     1. Close this window.
echo     2. Open the zip and find the folder inside it.
echo     3. Right-click that FOLDER and choose Copy.
echo     4. Press the Windows key + D to show your Desktop.
echo     5. Right-click empty space and choose Paste.
echo     6. Open the folder from your Desktop and try again.
echo.
pause
goto END

:NOPYTHON
cls
echo.
echo   ==========================================================
echo     Python is not installed, or Windows cannot find it.
echo   ==========================================================
echo.
echo   Warden needs Python 3.10 or newer.
echo.
echo   1. Go to  https://www.python.org/downloads/
echo   2. Click the big yellow "Download Python" button.
echo   3. Run the installer.
echo   4. IMPORTANT: on the first screen, tick the box that says
echo      "Add python.exe to PATH" before clicking Install.
echo      Almost everyone misses this and then nothing works.
echo   5. Close this window and double-click START WARDEN again.
echo.
pause
start https://www.python.org/downloads/
goto END

:END
endlocal
exit /b 0
