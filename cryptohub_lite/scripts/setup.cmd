@echo off
REM One-command bootstrap for IDEMIA CryptoHub Lite (Windows).
REM Mirrors setup.sh; kept as a separate file so it works in cmd.exe without
REM requiring Git Bash or WSL.
setlocal

set "ROOT=%~dp0..\.."
set "COMPOSE=%ROOT%\cryptohub_lite\docker-compose.yml"

echo ==^> Checking prerequisites
where docker >nul 2>&1 || (echo error: Docker was not found on PATH. & exit /b 1)
docker info >nul 2>&1 || (echo error: Docker is installed but not running. Start Docker Desktop. & exit /b 1)
echo   ok Docker is available

echo ==^> Building images ^(SoftHSM2 is compiled from source; first run takes a few minutes^)
docker compose -f "%COMPOSE%" build || exit /b 1

echo ==^> Starting the stack
docker compose -f "%COMPOSE%" up -d || exit /b 1

echo ==^> Waiting for the API to report healthy
set /a tries=0
:wait
curl -fsS http://localhost:8000/api/health >nul 2>&1 && goto ready
set /a tries+=1
if %tries% geq 60 (
    echo error: API did not become healthy. Inspect: docker compose -f "%COMPOSE%" logs api
    exit /b 1
)
REM ping as the sleep: timeout fails when stdin is redirected.
ping -n 3 127.0.0.1 >nul
goto wait

:ready
echo   ok API is serving
echo.
echo   IDEMIA CryptoHub Lite is running.
echo.
echo     Portal      http://localhost:8081       admin / admin123
echo     REST API    http://localhost:8000/api/docs
echo     KMIP        localhost:5696
echo     PostgreSQL  localhost:5432              cryptohub / devpass
echo.
echo   Change the bootstrap administrator password: click your name -^> My Account.
echo.
