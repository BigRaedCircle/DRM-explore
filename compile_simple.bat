@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2019\BuildTools\VC\Auxiliary\Build\vcvars64.bat"

echo Compiling simple valid...
cl /Od /Zi demos/simple_check_valid.c /Fe:demos/simple_valid.exe /link /SUBSYSTEM:CONSOLE /ENTRY:mainCRTStartup

echo.
echo Compiling simple invalid...
cl /Od /Zi demos/simple_check_invalid.c /Fe:demos/simple_invalid.exe /link /SUBSYSTEM:CONSOLE /ENTRY:mainCRTStartup

echo.
echo Done!
dir demos\simple_*.exe
