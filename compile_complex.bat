@echo off
echo Compiling Complex Anti-Tamper Test...

REM Try MSVC first
where cl >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    echo Using MSVC compiler...
    cl /O2 /Fe:demos\complex_antitamper.exe demos\complex_antitamper_simple.c /link /SUBSYSTEM:CONSOLE
    goto :done
)

REM Try MinGW GCC
where gcc >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    echo Using GCC compiler...
    gcc -O2 -o demos\complex_antitamper.exe demos\complex_antitamper_simple.c -lkernel32
    goto :done
)

REM Try TCC (Tiny C Compiler)
where tcc >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    echo Using TCC compiler...
    tcc -o demos\complex_antitamper.exe demos\complex_antitamper_simple.c
    goto :done
)

echo ERROR: No C compiler found!
echo Please install one of: MSVC, MinGW GCC, or TCC
exit /b 1

:done
if exist demos\complex_antitamper.exe (
    echo.
    echo SUCCESS! Compiled: demos\complex_antitamper.exe
    echo.
    echo Running native test...
    echo ========================================
    demos\complex_antitamper.exe
    echo ========================================
) else (
    echo ERROR: Compilation failed!
    exit /b 1
)
