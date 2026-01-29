@echo off
REM Сохраните как "launch-outlaws-demo.bat" в папке с игрой

REM 1. Закрываем ВСЕ процессы лаунчера
taskkill /f /im UbisoftGameLauncher.exe >nul 2>&1
taskkill /f /im UbisoftConnect.exe >nul 2>&1
timeout /t 2 >nul

REM 2. Запускаем лаунчер НАПРЯМУЮ с параметрами игры
start "" "C:\Program Files (x86)\Ubisoft\Ubisoft Game Launcher\UbisoftGameLauncher.exe" ^
  -upc_uplay_id 6203 ^
  -upc_steam_free_package_id 65707 ^
  -uplay_steam_mode ^
  -upc_game_starter ^
  -steam_appid 2619340

REM 3. Ждём инициализации лаунчера (5 сек)
timeout /t 5 >nul

REM 4. Запускаем игру напрямую (без ожидания лаунчера)
#start "" "E:\SteamLibrary\steamapps\common\Star Wars Outlaws Demo\Outlaws.exe"
#start "" "D:\Games Ubi\Star Wars Outlaws\Outlaws.exe"
