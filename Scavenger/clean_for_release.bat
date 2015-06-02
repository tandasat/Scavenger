del /s *.pdb *.cer
mkdir x86
move Win7Release x86
move Win8.1Release x86
mkdir bin
move x86 bin
move x64 bin
pause
