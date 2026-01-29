@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2019\BuildTools\VC\Auxiliary\Build\vcvars64.bat"

echo Assembling valid...
ml64 /c demos/asm_license_valid.asm
link /SUBSYSTEM:CONSOLE /ENTRY:start /NODEFAULTLIB /OUT:demos/asm_valid.exe kernel32.lib asm_license_valid.obj

echo.
echo Assembling invalid...
ml64 /c demos/asm_license_invalid.asm
link /SUBSYSTEM:CONSOLE /ENTRY:start /NODEFAULTLIB /OUT:demos/asm_invalid.exe kernel32.lib asm_license_invalid.obj

echo.
echo Done!
dir demos\asm_*.exe
