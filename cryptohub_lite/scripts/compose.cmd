@echo off
REM compose wrapper: resolves the container engine, then forwards everything to
REM it with this project's compose file already selected.
REM
REM     cryptohub_lite\scripts\compose.cmd up -d --build
REM     cryptohub_lite\scripts\compose.cmd logs -f api
REM
REM Exists so that callers which are not shell scripts - VS Code tasks, docs,
REM muscle memory - do not each hardcode `docker compose`, which breaks on a
REM Rancher Desktop set to containerd.
setlocal

call "%~dp0engine.cmd" || exit /b 1
%COMPOSE_CMD% -f "%~dp0..\docker-compose.yml" %*
exit /b %ERRORLEVEL%
