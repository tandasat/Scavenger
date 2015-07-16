@echo off
RUNDLL32.EXE SETUPAPI.DLL,InstallHinfSection DefaultUninstall 132 %~dp0Scavenger.inf
pause
