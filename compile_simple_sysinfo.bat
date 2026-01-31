@echo off
REM Compile simple_sysinfo.c using MS Build Tools 2019

echo ========================================
echo Compiling simple_sysinfo.c
echo ========================================

REM Setup Visual Studio 2019 Build Tools environment
call "C:\Program Files (x86)\Microsoft Visual Studio\2019\BuildTools\VC\Auxiliary\Build\vcvarsall.bat" x64

REM Compile
echo.
echo Compiling...
cl.exe /nologo /O2 /W3 /Fe:demos\simple_sysinfo.exe demos\simple_sysinfo.c

if %ERRORLEVEL% EQU 0 (
    echo.
    echo ========================================
    echo Compilation successful!
    echo Output: demos\simple_sysinfo.exe
    echo ========================================
    
    REM Clean up intermediate files
    del demos\simple_sysinfo.obj 2>nul
    
    REM Run the program natively
    echo.
    echo ========================================
    echo Running natively:
    echo ========================================
    demos\simple_sysinfo.exe
) else (
    echo.
    echo ========================================
    echo Compilation failed!
    echo ========================================
)
