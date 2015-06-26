del /s *.pdb *.cer
mkdir x86
move Win7Release x86
move Win8.1Release x86
mkdir bin_Scavenger
move x86 bin_Scavenger
move x64 bin_Scavenger
pause
