@echo off
:: Arrange the x86 folder 
rmdir /s /q _x86
mkdir _x86
move "Win7Release\Scavenger Package"   _x86\Win7Release
move "Win8.1Release\Scavenger Package" _x86\Win8.1Release

:: Arrange the x64 folder
rmdir /s /q _x64
mkdir _x64
move "x64\Win7Release\Scavenger Package"   _x64\Win7Release
move "x64\Win8.1Release\Scavenger Package" _x64\Win8.1Release

:: Arrange the bin_Scavenger folder
rmdir /s /q bin_Scavenger
mkdir bin_Scavenger
move _x86 bin_Scavenger\x86
move _x64 bin_Scavenger\x64
pause
