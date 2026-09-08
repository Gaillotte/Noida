@echo off
REM Container engine detection for cmd.exe, mirroring engine.sh.
REM
REM The stack runs unchanged on Rancher Desktop and Docker Desktop - the images
REM are plain OCI and the compose file uses nothing vendor-specific. Only the
REM CLI on PATH differs, so this resolves it once rather than each script
REM assuming `docker`.
REM
REM Call it, then use %ENGINE% and %COMPOSE_CMD%:
REM
REM     call "%~dp0engine.cmd" || exit /b 1
REM     %COMPOSE_CMD% -f "%COMPOSE%" up -d
REM
REM Both variables are set in the *caller's* scope, which is why this is a
REM `call`ed script rather than a subroutine and why setlocal is ended with
REM `endlocal &` below - without that, the values would vanish on return.
REM
REM Set CHL_ENGINE=docker or CHL_ENGINE=nerdctl beforehand to force one.

setlocal EnableDelayedExpansion

set "CANDIDATES=docker nerdctl"
if not "%CHL_ENGINE%"=="" set "CANDIDATES=%CHL_ENGINE%"

set "FOUND_ENGINE="
set "FOUND_COMPOSE="
set "FOUND_BUT_DOWN="

for %%E in (%CANDIDATES%) do (
    if not defined FOUND_ENGINE (
        where %%E >nul 2>&1
        if not errorlevel 1 (
            REM Installed is not the same as running. This is the case that
            REM actually bites: the CLI answers, every command fails.
            %%E info >nul 2>&1
            if errorlevel 1 (
                if defined FOUND_BUT_DOWN (
                    set "FOUND_BUT_DOWN=!FOUND_BUT_DOWN!, %%E"
                ) else (
                    set "FOUND_BUT_DOWN=%%E"
                )
            ) else (
                set "FOUND_ENGINE=%%E"
                %%E compose version >nul 2>&1
                if errorlevel 1 (
                    if /i "%%E"=="docker" (
                        where docker-compose >nul 2>&1
                        if not errorlevel 1 set "FOUND_COMPOSE=docker-compose"
                    )
                ) else (
                    set "FOUND_COMPOSE=%%E compose"
                )
            )
        )
    )
)

REM Installed but unreachable is the common case on Rancher Desktop for
REM Windows, and it is repairable - so try, once, rather than making the user
REM run the recovery by hand every time. heal.cmd explains the fault and
REM honours CHL_NO_AUTOHEAL=1.
REM
REM Written with labels rather than a nested if-block on purpose: the retry has
REM to `endlocal` before recursing, and %ERRORLEVEL% inside a parenthesised
REM block is expanded when the block is parsed, so it would carry a stale value.
if defined FOUND_ENGINE goto :have_engine
if not defined FOUND_BUT_DOWN goto :no_engine
if "%CHL_HEALED%"=="1" goto :engine_down

echo [WARN] Found !FOUND_BUT_DOWN!, but it is not running.
call "%~dp0heal.cmd"
if errorlevel 1 goto :heal_failed

REM Healed. Re-run detection from a fresh instance; CHL_HEALED stops it from
REM healing twice, which would loop.
endlocal
set "CHL_HEALED=1"
call "%~dp0engine.cmd"
exit /b %ERRORLEVEL%

:heal_failed
endlocal & exit /b 1

:engine_down
:no_engine
if not defined FOUND_ENGINE (
    if defined FOUND_BUT_DOWN (
        echo [ERROR] Found !FOUND_BUT_DOWN!, but it is not running.
        echo         Start Rancher Desktop ^(or Docker Desktop^) and wait for it to report ready.
        echo         If Rancher is open but the engine is wedged:
        echo             rdctl shutdown ^&^& wsl --shutdown      then relaunch
    ) else (
        echo [ERROR] No container engine found on PATH.
        echo         Install Rancher Desktop ^(recommended^) or Docker Desktop.
        echo         In Rancher Desktop set Container Engine to "moby ^(dockerd^)";
        echo         "containerd" also works and is used through nerdctl.
    )
    endlocal & exit /b 1
)

:have_engine
if not defined FOUND_COMPOSE (
    echo [ERROR] !FOUND_ENGINE! is running but has no compose support.
    echo         Install the compose plugin, or use Rancher Desktop, which bundles it.
    endlocal & exit /b 1
)

REM Hand both values back to the caller.
endlocal & set "ENGINE=%FOUND_ENGINE%" & set "COMPOSE_CMD=%FOUND_COMPOSE%"
exit /b 0
