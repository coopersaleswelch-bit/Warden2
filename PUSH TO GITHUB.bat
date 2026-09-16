@echo off
setlocal enabledelayedexpansion
cd /d "%~dp0"
title Warden 2.0 - Push to GitHub
color 0F

set "REPO=https://github.com/coopersaleswelch-bit/Warden2.git"

cls
echo.
echo   ==========================================================
echo     PUSH WARDEN TO GITHUB
echo   ==========================================================
echo.
echo     Folder : %CD%
echo     Repo   : %REPO%
echo.

REM ---------------------------------------------------------------------
REM  1. Is Git installed?
REM ---------------------------------------------------------------------
git --version >nul 2>nul
if not !errorlevel!==0 goto NOGIT

for /f "tokens=*" %%v in ('git --version') do set "GITVER=%%v"
echo     Git    : !GITVER!
echo.

REM ---------------------------------------------------------------------
REM  2. Safety check: .gitignore must be named correctly.
REM     Windows silently appends .txt to extensionless files. That is
REM     exactly how the API key ended up public last time, so this stops
REM     rather than warns.
REM ---------------------------------------------------------------------
if exist ".gitignore.txt" (
  echo     Fixing .gitignore.txt  -^>  .gitignore
  ren ".gitignore.txt" ".gitignore"
)

if not exist ".gitignore" (
  echo.
  echo   STOP. There is no .gitignore in this folder.
  echo   Without it, your local databases would be uploaded to GitHub.
  echo   Send this screenshot to Claude before doing anything else.
  echo.
  pause
  goto END
)

REM ---------------------------------------------------------------------
REM  3. Identity. Git refuses to commit without it.
REM ---------------------------------------------------------------------
set "GITEMAIL="
for /f "tokens=*" %%e in ('git config --global user.email 2^>nul') do set "GITEMAIL=%%e"

if not defined GITEMAIL (
  echo   Git needs to know who you are. This is asked once, ever.
  echo.
  set /p GITEMAIL=  Your GitHub email:  
  if not defined GITEMAIL goto END
  git config --global user.name "Cooper"
  git config --global user.email "!GITEMAIL!"
  echo.
)

echo     Author : !GITEMAIL!
echo.
echo   ----------------------------------------------------------
echo.

REM ---------------------------------------------------------------------
REM  4. Initialise if this folder is not a repo yet.
REM ---------------------------------------------------------------------
if not exist ".git" (
  echo   Setting up version control for this folder...
  git init >nul
  git branch -M main >nul 2>nul
)

REM ---------------------------------------------------------------------
REM  5. Stage, then verify nothing sensitive is about to be uploaded.
REM ---------------------------------------------------------------------
git add .

set "LEAK="
for /f "tokens=*" %%f in ('git diff --cached --name-only 2^>nul') do (
  echo %%f | findstr /i /e ".db" >nul && set "LEAK=%%f"
  echo %%f | findstr /i /e ".env" >nul && set "LEAK=%%f"
  echo %%f | findstr /i /e ".log" >nul && set "LEAK=%%f"
)

if defined LEAK (
  echo.
  echo   STOP - NOTHING HAS BEEN UPLOADED.
  echo.
  echo   A file that should stay private is about to be committed:
  echo       !LEAK!
  echo.
  echo   Unstaging everything now so nothing leaves your machine.
  git reset >nul
  echo   Done. Send this screenshot to Claude.
  echo.
  pause
  goto END
)

echo   Files to upload:
echo.
git diff --cached --name-only
echo.

REM ---------------------------------------------------------------------
REM  6. Commit.
REM ---------------------------------------------------------------------
set "MSG="
set /p MSG=  Describe this save (Enter for default):  
if not defined MSG set "MSG=Warden 2.0 - MCP contract enforcement with inline proxy"

git commit -m "!MSG!" >nul 2>nul
if not !errorlevel!==0 (
  echo.
  echo   Nothing new to commit - your last save is already up to date.
  echo   Pushing anyway in case the upload did not finish last time.
)

REM ---------------------------------------------------------------------
REM  7. Point at the repo. Safe to run repeatedly.
REM ---------------------------------------------------------------------
git remote remove origin >nul 2>nul
git remote add origin "%REPO%"
git branch -M main >nul 2>nul

REM ---------------------------------------------------------------------
REM  8. Push. A sign-in window may appear the first time.
REM ---------------------------------------------------------------------
echo.
echo   Uploading. A GitHub sign-in window may pop up - approve it.
echo.
git push -u origin main

echo.
if !errorlevel!==0 (
  echo   ==========================================================
  echo     DONE. Your code is on GitHub.
  echo     %REPO%
  echo   ==========================================================
  echo.
  echo   From now on, double-click this file any time you want to
  echo   save your progress. It only uploads what changed.
) else (
  echo   The upload did not finish. Screenshot this window and send
  echo   it to Claude - the error text above says why.
)
echo.
pause
goto END

:NOGIT
cls
echo.
echo   ==========================================================
echo     Git is not installed.
echo   ==========================================================
echo.
echo   Git is the tool that uploads your code to GitHub.
echo.
echo   1. The download page will open in your browser.
echo   2. Click the Windows download link.
echo   3. Run the installer.
echo   4. Click Next on every screen. The defaults are correct -
echo      you do not need to change anything.
echo   5. When it finishes, close this window and double-click
echo      this file again.
echo.
pause
start https://git-scm.com/download/win
goto END

:END
endlocal
exit /b 0
