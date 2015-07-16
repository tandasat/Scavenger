@echo off
RUNDLL32.EXE SETUPAPI.DLL,InstallHinfSection DefaultInstall 132 %~dp0Scavenger.inf
sc start Scavenger
pause
