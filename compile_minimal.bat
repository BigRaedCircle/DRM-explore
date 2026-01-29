@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2019\BuildTools\VC\Auxiliary\Build\vcvars64.bat"

echo Compiling minimal valid (no CRT)...
cl /c /O1 /Zi demos/minimal_license_valid.c
link /SUBSYSTEM:CONSOLE /ENTRY:check_license /NODEFAULTLIB /OUT:demos/minimal_valid.exe kernel32.lib minimal_license_valid.obj

echo.
echo Compiling minimal invalid (no CRT)...
cl /c /O1 /Zi demos/minimal_license_invalid.c
link /SUBSYSTEM:CONSOLE /ENTRY:check_license /NODEFAULTLIB /OUT:demos/minimal_invalid.exe kernel32.lib minimal_license_invalid.obj

echo.
echo Done!
dir demos\minimal_*.exe
