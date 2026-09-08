@echo off
REM Single entry point for IDEMIA CryptoHub Lite (Windows).
REM
REM Everything that manages the stack lives here, including the volume backup
REM that used to be a separate backup.cmd. One script means one place to learn,
REM one place that resolves the container engine, and no second copy of the
REM project and volume names to fall out of step.
REM
REM   setup                    build, start, and wait until it is serving
REM   setup up                 same
REM   setup start              start without building - after a stop
REM   setup down               stop and remove containers, keep the volumes
REM   setup stop               stop containers, keep them
REM   setup restart [service]  restart everything, or one service
REM   setup status             what is running, with health
REM   setup logs [service]     follow logs
REM   setup test               run the KMIP engine test suite in the container
REM   setup shell [service]    a shell inside a container (default: api)
REM   setup backup [dir]       copy both volumes to dir  (default below)
REM   setup restore [dir]      restore both volumes      (stack must be down)
REM   setup backups [dir]      list what is in the backup folder
REM   setup destroy            remove containers AND volumes - deletes all keys
REM   setup help               this text
REM
REM Mirrors setup.sh; kept as a separate file so it works in cmd.exe without
REM requiring Git Bash or WSL.
setlocal EnableDelayedExpansion

REM Resolved to a full path, not "...\scripts\..\..": the test subcommand passes
REM it to the engine as a bind-mount source, and a relative segment there is
REM rejected on Windows.
for %%I in ("%~dp0..\..") do set "ROOT=%%~fI"
set "COMPOSE=%ROOT%\cryptohub_lite\docker-compose.yml"
set "API_IMAGE=cryptohub-lite/api:dev"
set "PROJECT=cryptohub-lite"
set "BACKUP_DIR=C:\Internal_Idemia\Docker_bkup"

set "CMD=%~1"
if "%CMD%"=="" set "CMD=up"
set "ARG=%~2"

if /i "%CMD%"=="help"   goto :help
if /i "%CMD%"=="--help" goto :help
if /i "%CMD%"=="-h"     goto :help

REM Rancher Desktop and Docker Desktop both work. engine.cmd picks whichever is
REM present and reachable and sets ENGINE and COMPOSE_CMD; it explains what to
REM do when neither is, so no subcommand below has to.
call "%~dp0engine.cmd" || exit /b 1

if /i "%CMD%"=="up"      goto :up
if /i "%CMD%"=="start"   goto :start
if /i "%CMD%"=="down"    goto :down
if /i "%CMD%"=="stop"    goto :stop
if /i "%CMD%"=="restart" goto :restart
if /i "%CMD%"=="status"  goto :status
if /i "%CMD%"=="ps"      goto :status
if /i "%CMD%"=="logs"    goto :logs
if /i "%CMD%"=="test"    goto :test
if /i "%CMD%"=="shell"   goto :shell
if /i "%CMD%"=="backup"  goto :backup
if /i "%CMD%"=="restore" goto :restore
if /i "%CMD%"=="backups" goto :backups
if /i "%CMD%"=="destroy" goto :destroy

echo [ERROR] Unknown command '%CMD%'.
echo.
goto :help

REM ------------------------------------------------------------------- up ----
REM `start` is `up` without the build. Implemented as `up -d --no-build` rather
REM than `compose start`, because `compose start` only revives containers that
REM still exist - after a `down` it fails, which is not what "start everything"
REM should mean. --no-build creates whatever is missing and never compiles.
:start
set "UPFLAGS=--no-build"
echo ==^> Container engine: %ENGINE% ^(compose: %COMPOSE_CMD%^)
echo ==^> Starting existing images ^(no build; use 'setup up' after changing code^)
goto :up_run

:up
set "UPFLAGS="
echo ==^> Container engine: %ENGINE% ^(compose: %COMPOSE_CMD%^)
echo ==^> Building images ^(SoftHSM2 is compiled from source; first run takes a few minutes^)
%COMPOSE_CMD% -f "%COMPOSE%" build || exit /b 1

REM Retried, because on Rancher Desktop for Windows this step intermittently
REM dies with:
REM
REM     Error response from daemon: failed to connect to the backend:
REM     timed out dialing Hyper-V socket
REM
REM That is the host-to-VM channel Rancher's network tunnel runs over
REM (host-switch <-> vm-switch), not anything about this stack, and it is
REM transient - a second attempt normally succeeds. Recent Rancher versions
REM removed the setting that used to disable the tunnel, so it cannot be
REM configured away.
REM
REM Retrying is safe because `up -d` is idempotent: containers already created
REM are left alone and only the missing ones are started, which is why a
REM half-finished attempt does not have to be cleaned up first.
echo ==^> Starting the stack
:up_run
set /a attempt=0
:up_try
set /a attempt+=1
%COMPOSE_CMD% -f "%COMPOSE%" up -d %UPFLAGS% && goto :up_ok
if !attempt! geq 3 (
    echo.
    echo [ERROR] The stack did not start after !attempt! attempts.
    echo         If the message above mentions "timed out dialing Hyper-V socket",
    echo         the engine's host-to-VM channel is wedged rather than busy. Cycle it:
    echo             rdctl shutdown ^&^& wsl --shutdown      then relaunch Rancher Desktop
    exit /b 1
)
echo   attempt !attempt! failed; retrying in 5s ^(see the note in this script^)
ping -n 6 127.0.0.1 >nul
goto :up_try
:up_ok

echo ==^> Waiting for the API to report healthy
set /a tries=0
:wait
curl -fsS http://localhost:8000/api/health >nul 2>&1 && goto :ready
set /a tries+=1
if !tries! geq 60 (
    echo error: API did not become healthy. Inspect: setup logs api
    exit /b 1
)
REM ping as the sleep: timeout fails when stdin is redirected.
ping -n 3 127.0.0.1 >nul
goto :wait

:ready
echo   ok API is serving
echo.
echo   IDEMIA CryptoHub Lite is running on %ENGINE%.
echo.
echo     Portal      http://localhost:8081       admin / admin123
echo     REST API    http://localhost:8000/api/docs
echo     KMIP        localhost:5696
echo     PostgreSQL  not published; reachable only inside the stack
echo.
echo   Change the bootstrap administrator password: click your name -^> My Account.
echo   Back up before you rely on it:  setup backup
echo.
exit /b 0

REM -------------------------------------------------------- stack control ----
:down
%COMPOSE_CMD% -f "%COMPOSE%" down
exit /b %ERRORLEVEL%

:stop
%COMPOSE_CMD% -f "%COMPOSE%" stop
exit /b %ERRORLEVEL%

:restart
%COMPOSE_CMD% -f "%COMPOSE%" restart %ARG%
exit /b %ERRORLEVEL%

:status
%COMPOSE_CMD% -f "%COMPOSE%" ps
exit /b %ERRORLEVEL%

:logs
%COMPOSE_CMD% -f "%COMPOSE%" logs -f --tail 100 %ARG%
exit /b %ERRORLEVEL%

:test
REM A one-off container over the *source tree*, not `exec` into the running
REM api service, and not the copy of the package baked into the image.
REM
REM Two reasons, both learned by getting 8 failures the other way. Six tests
REM read deployment artifacts - deploy/config.example.yaml, the systemd unit,
REM the CI workflow - and Dockerfile.api copies none of those into the runtime
REM image, so they can never pass inside it. And testing the baked copy tests
REM the last build rather than the working tree, which is rarely what is
REM wanted while editing. Mounting the repo fixes both and matches what CI runs.
REM
REM pytest is deliberately absent from the runtime image - it is a test
REM dependency, and the image that ships the API should not carry one - so it
REM is installed into the throwaway container each time.
echo ==^> Running the KMIP engine test suite ^(via %ENGINE%^)
%ENGINE% run --rm --entrypoint sh -e PYTHONPATH=/src -v "%ROOT%":/src -w /src ^
    %API_IMAGE% -c "python -c 'import pytest' 2>/dev/null || pip install --quiet pytest; python -m pytest kmip_pkcs11/tests -q"
exit /b %ERRORLEVEL%

:shell
set "SVC=%ARG%"
if "%SVC%"=="" set "SVC=api"
%COMPOSE_CMD% -f "%COMPOSE%" exec %SVC% sh
exit /b %ERRORLEVEL%

REM ------------------------------------------------------------- backups ----
REM Volumes, not images. Images rebuild from source in minutes; these two
REM cannot be rebuilt from anything:
REM
REM   chl_pgdata  PostgreSQL - user accounts, audit trail, KMIP metadata
REM   chl_tokens  the SoftHSM2 token - the actual key material
REM
REM Saving images instead is what lost the previous environment: `docker save`
REM captures images only, so when the engine went away the keys went with it.
REM
REM The two are one unit. Objects reference key material by CKA_ID and secret
REM blobs are encrypted under a master key on the token, so a database restored
REM beside a different token is not a degraded backup, it is unreadable. Both
REM are therefore always copied and restored together.
:backups
if not "%ARG%"=="" set "BACKUP_DIR=%ARG%"
echo Backups in %BACKUP_DIR%:
dir /b /o-d "%BACKUP_DIR%\chl_*.tgz" 2>nul || echo   ^(none^)
exit /b 0

:backup
if not "%ARG%"=="" set "BACKUP_DIR=%ARG%"
if not exist "%BACKUP_DIR%" mkdir "%BACKUP_DIR%" 2>nul

REM A hot copy of a running PostgreSQL is a torn snapshot, so warn rather than
REM produce an archive that only looks like a backup.
%ENGINE% ps --format "{{.Names}}" | findstr /i "chl-postgres" >nul
if not errorlevel 1 (
    echo [WARN] chl-postgres is running. A copy taken while it writes may not
    echo        restore cleanly. For a dependable backup:
    echo            setup down
    echo            setup backup
    echo.
)

for %%V in (chl_pgdata chl_tokens) do (
    %ENGINE% volume inspect %PROJECT%_%%V >nul 2>&1
    if errorlevel 1 (
        echo [ERROR] Volume %PROJECT%_%%V does not exist. Has the stack ever run?
        echo         Volumes are per-engine: a stack previously run under a
        echo         different engine has its volumes there, not under %ENGINE%.
        exit /b 1
    )
)

echo Writing to %BACKUP_DIR% ... ^(via %ENGINE%^)
for %%V in (chl_pgdata chl_tokens) do (
    %ENGINE% run --rm -v %PROJECT%_%%V:/source:ro -v "%BACKUP_DIR%":/backup alpine ^
        tar czf /backup/%%V.tgz -C /source .
    if errorlevel 1 (
        echo [ERROR] Backup of %%V failed.
        exit /b 1
    )
    for %%F in ("%BACKUP_DIR%\%%V.tgz") do echo   %%V.tgz  %%~zF bytes
)

echo.
echo Done. Restore with:  setup restore
exit /b 0

:restore
if not "%ARG%"=="" set "BACKUP_DIR=%ARG%"
if not exist "%BACKUP_DIR%\chl_pgdata.tgz" (
    echo [ERROR] %BACKUP_DIR%\chl_pgdata.tgz not found.
    exit /b 1
)
REM Restoring into a running stack would have PostgreSQL writing to files being
REM replaced underneath it.
%COMPOSE_CMD% -f "%COMPOSE%" ps --quiet 2>nul | findstr /r "." >nul
if not errorlevel 1 (
    echo [ERROR] The stack is running. Stop it first:
    echo             setup down
    exit /b 1
)
echo Restoring into %PROJECT%_chl_pgdata and %PROJECT%_chl_tokens... ^(via %ENGINE%^)
for %%V in (chl_pgdata chl_tokens) do (
    %ENGINE% volume create %PROJECT%_%%V >nul
    %ENGINE% run --rm -v %PROJECT%_%%V:/target -v "%BACKUP_DIR%":/backup alpine ^
        sh -c "rm -rf /target/* /target/..?* 2>/dev/null; tar xzf /backup/%%V.tgz -C /target"
    if errorlevel 1 (
        echo [ERROR] Restore of %%V failed.
        exit /b 1
    )
    echo   %%V restored
)
echo Done. Bring the stack back up:  setup up
exit /b 0

:destroy
echo This removes the containers AND both volumes.
echo Every key on the token and every account, audit row and KMIP object is
echo deleted, and none of it can be rebuilt from source.
echo.
set /p "CONFIRM=Type DESTROY to confirm: "
if /i not "!CONFIRM!"=="DESTROY" (
    echo Cancelled. Nothing was removed.
    exit /b 1
)
%COMPOSE_CMD% -f "%COMPOSE%" down -v
exit /b %ERRORLEVEL%

REM ---------------------------------------------------------------- help ----
:help
echo IDEMIA CryptoHub Lite - stack management
echo.
echo   setup                    build, start, and wait until it is serving
echo   setup up                 same
echo   setup start              start without building - after a stop
echo   setup down               stop and remove containers, keep the volumes
echo   setup stop               stop containers, keep them
echo   setup restart [service]  restart everything, or one service
echo   setup status             what is running, with health
echo   setup logs [service]     follow logs
echo   setup test               run the KMIP engine test suite in the container
echo   setup shell [service]    a shell inside a container ^(default: api^)
echo.
echo   setup backup [dir]       copy both volumes to dir
echo   setup restore [dir]      restore both volumes ^(stack must be down^)
echo   setup backups [dir]      list what is in the backup folder
echo                            default dir: %BACKUP_DIR%
echo.
echo   setup destroy            remove containers AND volumes - deletes all keys
echo.
echo Works with Rancher Desktop or Docker Desktop; the engine is detected at
echo run time. Force one with:  set CHL_ENGINE=nerdctl
exit /b 0
