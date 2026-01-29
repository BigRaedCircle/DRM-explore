@echo off
chcp 65001 >nul
title Outlaws Demo Launcher (токен-фикс)

set "GAME_DIR=E:\SteamLibrary\steamapps\common\Star Wars Outlaws Demo"
set "LAUNCHER_DIR=%ProgramFiles(x86)%\Ubisoft\Ubisoft Game Launcher"
set "STEAM_APPID=2619340"

echo [+] Outlaws Demo Launcher — обход бага отсутствия токена
echo ======================================================================

:: 1. Закрываем ВСЁ от Ubisoft
echo [1] Закрываем процессы Ubisoft...
taskkill /f /im UbisoftConnect.exe >nul 2>&1
taskkill /f /im UbisoftGameLauncher.exe >nul 2>&1
taskkill /f /im Outlaws.exe >nul 2>&1
timeout /t 2 /nobreak >nul

:: 2. Очищаем битый кэш демо (оставляем профиль)
echo [2] Очищаем кэш демо-сессии...
del /f /q "%LocalAppData%\Ubisoft Game Launcher\savedata\*.demo.*" 2>nul
del /f /q "%LocalAppData%\Ubisoft Game Launcher\cache\manifests\6203*" 2>nul
del /f /q "%ProgramData%\Ubisoft Game Launcher\cache\*6203*" 2>nul

:: 3. Устанавливаем контекст Steam
echo [3] Устанавливаем контекст Steam...
set STEAM_APP_ID=%STEAM_APPID%
set SteamAppId=%STEAM_APPID%
set SteamGameId=%STEAM_APPID%

:: 4. Запускаем ЧИСТЫЙ лаунчер (без параметров!) — ключевой шаг
echo [4] Запускаем лаунчер БЕЗ параметров для создания токена...
start "" "%LAUNCHER_DIR%\UbisoftConnect.exe"

:: 5. Ждём появления токена (макс. 45 сек)
echo [5] Ожидание появления токена авторизации...
set "token_path=%LocalAppData%\Ubisoft Game Launcher\savedata"
set "wait=0"
:wait_loop
timeout /t 1 /nobreak >nul
if exist "%token_path%\*.token.*" goto token_found
set /a wait+=1
if %wait% gtr 45 goto token_timeout
goto wait_loop

:token_timeout
echo [!] Токен не появился за 45 сек. Пробуем принудительно обновить сессию...
taskkill /f /im UbisoftConnect.exe >nul 2>&1
timeout /t 2 /nobreak >nul
start "" "%LAUNCHER_DIR%\UbisoftConnect.exe"
timeout /t 10 /nobreak >nul

:token_found
echo [✓] Токен авторизации создан!

:: 6. Запускаем игру напрямую (без вызова лаунчера изнутри)
echo [6] Запускаем игру напрямую...
cd /d "%GAME_DIR%"
start "" "Outlaws.exe"

echo ======================================================================
echo [+] Готово! Игра должна запуститься через 10-20 секунд.
echo     Если окно лаунчера показывает "Играть" — нажмите его.
echo ======================================================================
pause
