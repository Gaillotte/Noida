@echo off
setlocal EnableDelayedExpansion
REM Backs up the two volumes that hold irreplaceable state.
REM
REM Images are NOT backed up, deliberately. They rebuild from source in
REM minutes; these volumes cannot be rebuilt from anything:
REM
REM   chl_pgdata  PostgreSQL - user accounts, audit trail, KMIP metadata
REM   chl_tokens  the SoftHSM2 token - the actual key material
REM
REM Saving images instead of volumes is what lost the previous environment:
REM `docker save` captures images only, so when the engine went away the keys
REM went with it.
REM
REM   backup                 write a timestamped set to the default folder
REM   backup <dir>           write to <dir> instead
REM   backup --restore <dir> restore from a set in <dir>  (stack must be down)
REM   backup --list [dir]    show what is in the backup folder

set "PROJECT=cryptohub-lite"
set "DEST=C:\Internal_Idemia\Docker_bkup"
set "COMPOSE=%~dp0cryptohub_lite\docker-compose.yml"

cd /d "%~dp0"

if /i "%~1"=="--restore" (
    set "MODE=restore"
    if not "%~2"=="" set "DEST=%~2"
) else if /i "%~1"=="--list" (
    set "MODE=list"
    if not "%~2"=="" set "DEST=%~2"
) else (
    set "MODE=backup"
    if not "%~1"=="" set "DEST=%~1"
)

docker info >nul 2>&1
if errorlevel 1 (
    echo [ERROR] No container engine. Start Rancher Desktop, and if the VM is
    echo         wedged:  rdctl shutdown ^&^& wsl --shutdown  then relaunch.
    exit /b 1
)

if not exist "%DEST%" mkdir "%DEST%" 2>nul

if "%MODE%"=="list" (
    echo Backups in %DEST%:
    dir /b /o-d "%DEST%\chl_*.tgz" 2>nul || echo   ^(none^)
    exit /b 0
)

REM ------------------------------------------------------------------ restore
if "%MODE%"=="restore" (
    if not exist "%DEST%\chl_pgdata.tgz" (
        echo [ERROR] %DEST%\chl_pgdata.tgz not found.
        exit /b 1
    )
    REM Restoring into a running stack would have PostgreSQL writing to files
    REM being replaced underneath it.
    docker compose -f "%COMPOSE%" ps --quiet 2>nul | findstr /r "." >nul
    if not errorlevel 1 (
        echo [ERROR] The stack is running. Stop it first:
        echo             docker compose -f "%COMPOSE%" down
        exit /b 1
    )
    echo Restoring into %PROJECT%_chl_pgdata and %PROJECT%_chl_tokens...
    for %%V in (chl_pgdata chl_tokens) do (
        docker volume create %PROJECT%_%%V >nul
        docker run --rm -v %PROJECT%_%%V:/target -v "%DEST%":/backup alpine ^
            sh -c "rm -rf /target/* /target/..?* 2>/dev/null; tar xzf /backup/%%V.tgz -C /target"
        if errorlevel 1 (
            echo [ERROR] Restore of %%V failed.
            exit /b 1
        )
        echo   %%V restored
    )
    echo Done. Bring the stack back up:  docker compose -f "%COMPOSE%" up -d
    exit /b 0
)

REM ------------------------------------------------------------------- backup
REM A hot copy of a running PostgreSQL is a torn snapshot, so warn rather than
REM produce an archive that only looks like a backup.
docker ps --format "{{.Names}}" | findstr /i "chl-postgres" >nul
if not errorlevel 1 (
    echo [WARN] chl-postgres is running. A copy taken while it writes may not
    echo        restore cleanly. For a dependable backup:
    echo            docker compose -f "%COMPOSE%" down
    echo            backup.cmd
    echo.
)

for %%V in (chl_pgdata chl_tokens) do (
    docker volume inspect %PROJECT%_%%V >nul 2>&1
    if errorlevel 1 (
        echo [ERROR] Volume %PROJECT%_%%V does not exist. Has the stack ever run?
        exit /b 1
    )
)

echo Writing to %DEST% ...
for %%V in (chl_pgdata chl_tokens) do (
    docker run --rm -v %PROJECT%_%%V:/source:ro -v "%DEST%":/backup alpine ^
        tar czf /backup/%%V.tgz -C /source .
    if errorlevel 1 (
        echo [ERROR] Backup of %%V failed.
        exit /b 1
    )
    for %%F in ("%DEST%\%%V.tgz") do echo   %%V.tgz  %%~zF bytes
)

echo.
echo Done. Restore with:  backup.cmd --restore
exit /b 0
