@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2019\BuildTools\VC\Auxiliary\Build\vcvars64.bat"

echo Compiling valid license version...
cl /Od /Zi demos/license_check_valid.c /Fe:demos/license_valid.exe /link /SUBSYSTEM:CONSOLE

echo.
echo Compiling invalid license version...
cl /Od /Zi demos/license_check_invalid.c /Fe:demos/license_invalid.exe /link /SUBSYSTEM:CONSOLE

echo.
echo Done!
dir demos\license_*.exe
