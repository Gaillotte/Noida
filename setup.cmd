@echo off
REM Convenience launcher.
REM
REM Exists because the real script lives under cryptohub_lite\scripts\, and
REM typing "setup.sh" at the repository root in cmd.exe - the obvious thing to
REM try - fails twice over: wrong path, and .sh is not executable by cmd.
REM This makes "setup" work from where people actually are.
"%~dp0cryptohub_lite\scripts\setup.cmd" %*
