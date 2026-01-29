@echo off
chcp 65001 >nul
echo Проверка сетевых вызовов лаунчера...
echo.

:: 1. Проверяем, какие домены резолвятся при запуске с параметрами
echo [Тест 1] Попытка разрешить домены Ubisoft...
nslookup public-ubiservices.ubi.com 2>nul | find "Address"
nslookup connect.ubisoft.com 2>nul | find "Address"

:: 2. Проверяем, открыт ли порт 443 для Ubisoft
echo.
echo [Тест 2] Проверка порта 443...
powershell -Command "Test-NetConnection public-ubiservices.ubi.com -Port 443 | Select-Object TcpTestSucceeded" 2>nul

:: 3. Проверяем наличие токена в профиле
echo.
echo [Тест 3] Наличие токена авторизации...
if exist "%LocalAppData%\Ubisoft Game Launcher\savedata\*token*" (
    echo   ✓ Токен найден в savedata
) else (
    echo   ✗ Токен ОТСУТСТВУЕТ — критическая ошибка сессии
)

:: 4. Проверяем, видит ли лаунчер Steam
echo.
echo [Тест 4] Контекст Steam...
if defined STEAM_APP_ID (
    echo   STEAM_APP_ID=%STEAM_APP_ID%
) else (
    echo   STEAM_APP_ID НЕ УСТАНОВЛЕН
)
tasklist | findstr /i "steam.exe" >nul && echo   ✓ Steam запущен || echo   ✗ Steam НЕ запущен

pause
