@echo off
echo Compiling simple_sysinfo_nocrt.c (NO CRT)...

set "MSVC_PATH=C:\Program Files (x86)\Microsoft Visual Studio\2019\BuildTools\VC\Tools\MSVC\14.29.30133"
set "SDK_PATH=C:\Program Files (x86)\Windows Kits\10"
set "SDK_VERSION=10.0.19041.0"

"%MSVC_PATH%\bin\Hostx64\x64\cl.exe" ^
    /nologo ^
    /O2 ^
    /GS- ^
    /Gy ^
    /I"%MSVC_PATH%\include" ^
    /I"%SDK_PATH%\Include\%SDK_VERSION%\ucrt" ^
    /I"%SDK_PATH%\Include\%SDK_VERSION%\um" ^
    /I"%SDK_PATH%\Include\%SDK_VERSION%\shared" ^
    demos\simple_sysinfo_nocrt.c ^
    /link ^
    /NODEFAULTLIB ^
    /SUBSYSTEM:CONSOLE ^
    /ENTRY:mainCRTStartup ^
    /LIBPATH:"%SDK_PATH%\Lib\%SDK_VERSION%\um\x64" ^
    /LIBPATH:"%SDK_PATH%\Lib\%SDK_VERSION%\ucrt\x64" ^
    kernel32.lib ^
    /OUT:demos\simple_sysinfo_nocrt.exe

if %ERRORLEVEL% EQU 0 (
    echo.
    echo Compilation successful!
    echo Output: demos\simple_sysinfo_nocrt.exe
    echo.
    echo Testing native execution:
    echo ========================
    demos\simple_sysinfo_nocrt.exe
) else (
    echo.
    echo Compilation failed!
)
