@echo off
setlocal EnableDelayedExpansion
REM Pulls the kmip_pkcs11 component branch into the UI branch.
REM
REM One direction only. The UI branch consumes kmip_pkcs11 (cryptohub_lite
REM imports MetadataStore, the dispatcher and the PKCS#11 shim), so it goes
REM stale as soon as the component branch moves; nothing flows back the other
REM way from here.
REM
REM   sync            merge into the current branch, leave the push to you
REM   sync --push     merge and push, for use from Task Scheduler
REM   sync --check    report how far behind you are, change nothing

set "SOURCE=claude/kmip-specifications-iprzym"
set "TARGET=claude/kmip-specification-iprzym-ui"

cd /d "%~dp0"

set "MODE=merge"
if /i "%~1"=="--push"  set "MODE=push"
if /i "%~1"=="--check" set "MODE=check"

REM ---------------------------------------------------------------- preflight
git rev-parse --is-inside-work-tree >nul 2>&1
if errorlevel 1 (
    echo [ERROR] %~dp0 is not a git repository.
    exit /b 1
)

for /f "delims=" %%b in ('git branch --show-current') do set "CURRENT=%%b"
if not "!CURRENT!"=="%TARGET%" (
    echo [ERROR] On branch '!CURRENT!', expected '%TARGET%'.
    echo         Switch first:  git checkout %TARGET%
    exit /b 1
)

echo [1/3] Fetching origin...
git fetch origin --prune
if errorlevel 1 (
    echo [ERROR] Fetch failed. Check your network or credentials.
    exit /b 1
)

for /f %%n in ('git rev-list --count HEAD..origin/%SOURCE%') do set "BEHIND=%%n"
echo [2/3] %SOURCE% has !BEHIND! commit^(s^) you do not have.

if "!BEHIND!"=="0" (
    echo       Already up to date. Nothing to do.
    exit /b 0
)

git --no-pager log --oneline HEAD..origin/%SOURCE%

if "%MODE%"=="check" exit /b 0

REM A merge over uncommitted work mixes their changes into yours with no way to
REM tell them apart afterwards. Refuse rather than stash silently.
for /f "delims=" %%s in ('git status --porcelain --untracked-files^=no') do (
    echo.
    echo [ERROR] You have uncommitted changes. Commit or stash them first:
    echo             git stash push -m "before sync"
    echo             sync.cmd %*
    echo             git stash pop
    exit /b 1
)

REM ------------------------------------------------------------------- merge
echo [3/3] Merging origin/%SOURCE%...
git merge --no-edit -m "Sync: merge %SOURCE% into %TARGET%" "origin/%SOURCE%"
if errorlevel 1 (
    echo.
    echo [CONFLICT] The branches changed the same lines - most likely under
    echo            kmip_pkcs11\, which both branches modify.
    echo.
    echo            Resolve:   git status          ^(see the conflicted files^)
    echo                       ...edit, then git add ^<file^>
    echo                       git commit
    echo.
    echo            Or back out entirely:  git merge --abort
    exit /b 2
)

echo       Merged cleanly.

if "%MODE%"=="push" (
    echo       Pushing to origin/%TARGET%...
    git push origin %TARGET%
    if errorlevel 1 (
        echo [ERROR] Push failed. The merge is still in your local history.
        exit /b 1
    )
    echo       Pushed.
) else (
    echo       Review it, then:  git push
)

exit /b 0
