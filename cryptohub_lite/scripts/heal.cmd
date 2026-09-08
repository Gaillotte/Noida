@echo off
REM Revive a wedged Rancher Desktop engine.
REM
REM Rancher Desktop on Windows intermittently loses the Hyper-V (AF_VSOCK)
REM channel between the host and the WSL VM. It shows up two ways:
REM
REM   * the CLI answers but every command fails, because
REM     \\.\pipe\docker_engine has no listener - the "Win32 socket proxy"
REM     crash-loops in background.log
REM   * a command dies mid-flight with
REM     "failed to connect to the backend: timed out dialing Hyper-V socket"
REM
REM Both are the same fault in Rancher's network tunnel (host-switch <->
REM vm-switch), not in this stack. Rancher 1.24 removed the setting that used
REM to disable the tunnel, and neither `rdctl set` nor the settings file
REM exposes a replacement, so it cannot be configured away. Restarting the app
REM alone does not clear it; the WSL distribution has to be cycled.
REM
REM This does exactly the documented recovery, so a wedge costs a wait instead
REM of four manual steps. Set CHL_NO_AUTOHEAL=1 to disable it and go back to
REM being told what to run.
REM
REM Exit codes:  0 the engine is up   1 could not revive it
setlocal EnableDelayedExpansion

if "%CHL_NO_AUTOHEAL%"=="1" (
    echo         Automatic recovery is disabled ^(CHL_NO_AUTOHEAL=1^).
    endlocal & exit /b 1
)

REM Only Rancher Desktop is repairable this way. Docker Desktop has its own
REM lifecycle, and shutting down WSL underneath it would be unhelpful.
where rdctl >nul 2>&1
if errorlevel 1 (
    echo         No rdctl on PATH, so this is not Rancher Desktop; start your
    echo         container engine and retry.
    endlocal & exit /b 1
)

REM `wsl --shutdown` stops *every* distribution, not just Rancher's. That is
REM fine on a machine where only Rancher's are registered, and rude otherwise,
REM so check before reaching for it.
set "FOREIGN_DISTRO="
for /f "usebackq skip=1 tokens=1" %%D in (`wsl -l -q 2^>nul`) do (
    set "NAME=%%D"
    if not "!NAME!"=="" (
        echo !NAME! | findstr /i /b "rancher-desktop" >nul || set "FOREIGN_DISTRO=!NAME!"
    )
)

REM Refuse to cycle the VM while containers are running, unless told to.
REM
REM Learned the hard way: healing a *partly* wedged engine - one where the CLI
REM still answers some calls and the stack is up - tore the VM down underneath
REM a running PostgreSQL and a live SoftHSM2 token, and the stack came back
REM against different storage with an empty database and a freshly initialised
REM token. Stopping containers is advertised; silently changing which volumes
REM the engine presents is not, and a key store is the wrong place to find out.
REM
REM So: if anything is still running, stop rather than cycle. The operator can
REM bring the stack down deliberately (setup down), back it up, and retry.
REM Works out the engine itself. engine.cmd only exports ENGINE on success, so
REM by the time it calls here that variable is empty - relying on it made this
REM guard silently no-op and cycle WSL under a live stack, which is the exact
REM accident it exists to prevent.
REM Deliberately not `... | find /c /v ""` to count them. `find` is a Windows
REM builtin *and* a Unix tool, and when this runs from a shell whose PATH puts
REM Git Bash's /usr/bin first, the Unix one wins and starts walking the whole
REM C: drive. Just noting "at least one id was printed" needs no counting tool.
set "RUNNING="
for %%E in (docker nerdctl) do (
    if not defined RUNNING (
        where %%E >nul 2>&1
        if not errorlevel 1 (
            for /f "usebackq delims=" %%C in (`%%E ps -q 2^>nul`) do set "RUNNING=yes"
        )
    )
)

if 1==1 (
    if defined RUNNING (
        echo.
        echo [ERROR] The engine is reachable enough to list running container^(s^),
        echo         so this is a partial wedge, not a dead engine. Cycling WSL now would
        echo         tear the VM down underneath them - which has previously brought the
        echo         stack back against different storage, losing the database and token.
        echo.
        echo         Back up and stop the stack first, then retry:
        echo             setup backup
        echo             setup down
        echo         Or force it anyway with CHL_FORCE_HEAL=1 if you know the volumes
        echo         are expendable.
        if not "%CHL_FORCE_HEAL%"=="1" endlocal & exit /b 1
        echo         CHL_FORCE_HEAL=1 set; continuing anyway.
    )
)

echo ==^> Reviving the container engine ^(Rancher Desktop^)
echo     This is Rancher's Hyper-V socket wedging, a known fault in its network
echo     tunnel. Cycling the VM is the only reliable fix.

echo     [1/4] rdctl shutdown
rdctl shutdown >nul 2>&1

if defined FOREIGN_DISTRO (
    echo     [2/4] skipping 'wsl --shutdown': other distributions are registered
    echo           ^(e.g. !FOREIGN_DISTRO!^) and it would stop those too.
    echo           If the engine does not come back, run it yourself.
) else (
    echo     [2/4] wsl --shutdown
    wsl --shutdown >nul 2>&1
)
REM Give WSL a moment to actually tear the VM down; relaunching into a
REM half-stopped VM is what makes the second attempt fail as well.
ping -n 7 127.0.0.1 >nul

echo     [3/4] relaunching Rancher Desktop
set "RD_EXE=%LOCALAPPDATA%\Programs\Rancher Desktop\Rancher Desktop.exe"
if not exist "%RD_EXE%" set "RD_EXE=%ProgramFiles%\Rancher Desktop\Rancher Desktop.exe"
if not exist "%RD_EXE%" (
    echo           Could not find Rancher Desktop.exe; start it yourself.
    endlocal & exit /b 1
)
start "" "%RD_EXE%"

echo     [4/4] waiting for the engine ^(up to 3 minutes^)
set /a waited=0
:heal_wait
ping -n 11 127.0.0.1 >nul
set /a waited+=10
docker info >nul 2>&1 && goto :heal_ok
nerdctl info >nul 2>&1 && goto :heal_ok
if !waited! geq 180 (
    echo.
    echo [ERROR] The engine did not come back after !waited!s.
    echo         Open Rancher Desktop and check it reports ready. If it keeps
    echo         wedging, the two things worth trying are Preferences -^>
    echo         Application -^> Administrative Access, and an antivirus
    echo         exclusion for %LOCALAPPDATA%\Programs\Rancher Desktop.
    endlocal & exit /b 1
)
echo           ...!waited!s
goto :heal_wait

:heal_ok
echo   ok engine is up after !waited!s
endlocal & exit /b 0
