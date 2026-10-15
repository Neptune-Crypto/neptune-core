@echo off

REM thin wrapper since she-bang shenanigans don't work on windows
py "%~dp0block_notify_dummy.py" %*
