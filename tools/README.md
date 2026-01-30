# WinAPI Stub Generator

Автоматическая генерация заглушек WinAPI из официальных заголовочных файлов Windows SDK.

## Что это?

Вместо ручного написания заглушек для каждой WinAPI функции, мы:
1. Скачиваем официальные .h файлы из Windows SDK
2. Парсим их для извлечения сигнатур функций
3. Автоматически генерируем Python заглушки для эмулятора

## Быстрый старт

```bash
# 1. Скачать/скопировать заголовки Windows SDK
python tools/download_headers.py

# 2. Парсить заголовки и сгенерировать заглушки
python tools/header_parser.py

# 3. Результаты в tools/generated/
```

## Результаты

После запуска генератора получаем:

### 1. Python заглушки (`winapi_stubs_generated.py`)
```python
def _stub_createfilea(self):
    """CreateFileA() - HANDLE WINAPI
    Parameters:
        LPCSTR lpFileName
        DWORD dwDesiredAccess
        DWORD dwShareMode
        ...
    Source: fileapi.h
    """
    lpFileName = self.uc.reg_read(UC_X86_REG_RCX)
    dwDesiredAccess = self.uc.reg_read(UC_X86_REG_RDX)
    # ...
    print(f"[API] CreateFileA()")
    # TODO: Implement stub logic
    self.uc.reg_write(UC_X86_REG_RAX, 0)
    return 0
```

### 2. Документация (`API_REFERENCE.md`)
Полный справочник всех найденных функций с параметрами и источниками.

### 3. JSON данные (`functions.json`)
Структурированные данные для дальнейшей обработки.

## Статистика

**Текущий результат:**
- **436 функций** извлечено из Windows SDK
- **3 DLL** покрыто:
  - `kernel32.dll` - 254 функции
  - `advapi32.dll` - 91 функция
  - `unknown.dll` - 91 функция

### Покрытие по категориям

| Категория | Заголовок | Функций | Статус |
|-----------|-----------|---------|--------|
| **File I/O** | fileapi.h | 97 | ✅ Parsed |
| **Process/Thread** | processthreadsapi.h | 81 | ✅ Parsed |
| **Memory** | memoryapi.h | 28 | ✅ Parsed |
| **Synchronization** | synchapi.h | 49 | ✅ Parsed |
| **Heap** | heapapi.h | 12 | ✅ Parsed |
| **Library Loading** | libloaderapi.h | 30 | ✅ Parsed |
| **Error Handling** | errhandlingapi.h | 18 | ✅ Parsed |
| **Performance** | profileapi.h | 2 | ✅ Parsed |
| **System Info** | sysinfoapi.h | 29 | ✅ Parsed |
| **Registry** | winreg.h | 91 | ✅ Parsed |
| **Graphics** | wingdi.h | 0 | ⚠️ Needs work |

## Архитектура

```
┌─────────────────────────────────────────┐
│  Windows SDK Headers (.h files)         │
│  - fileapi.h                            │
│  - processthreadsapi.h                  │
│  - memoryapi.h                          │
│  - ...                                  │
└─────────────────────────────────────────┘
              ↓
┌─────────────────────────────────────────┐
│  Header Parser (header_parser.py)       │
│  - Regex-based parsing                  │
│  - Function signature extraction        │
│  - Parameter parsing                    │
└─────────────────────────────────────────┘
              ↓
┌─────────────────────────────────────────┐
│  Generated Outputs                      │
│  - Python stubs                         │
│  - Documentation                        │
│  - JSON data                            │
└─────────────────────────────────────────┘
              ↓
┌─────────────────────────────────────────┐
│  Emulator Integration                   │
│  - Import generated stubs               │
│  - Implement critical functions         │
│  - Use "fake but valid" for others      │
└─────────────────────────────────────────┘
```

## Использование сгенерированных заглушек

### Вариант 1: Прямая интеграция
```python
# В src/core/winapi_stubs.py
from tools.generated.winapi_stubs_generated import *

class WinAPIStubs:
    def __init__(self, emulator):
        self.emu = emulator
        self.uc = emulator.uc
        
        # Регистрируем сгенерированные заглушки
        self._register_generated_stubs()
```

### Вариант 2: Выборочная реализация
```python
# Копируем нужные заглушки и реализуем логику
def _stub_createfilea(self):
    """CreateFileA() - создание/открытие файла"""
    lpFileName = self.uc.reg_read(UC_X86_REG_RCX)
    dwDesiredAccess = self.uc.reg_read(UC_X86_REG_RDX)
    
    # Читаем имя файла
    filename = self._read_string(lpFileName)
    print(f"[API] CreateFileA('{filename}')")
    
    # Используем VirtualFileSystem
    handle = self.emu.vfs.open(filename, dwDesiredAccess)
    
    self.uc.reg_write(UC_X86_REG_RAX, handle)
    return handle
```

## Расширение

### Добавление новых заголовков

1. Добавьте в `download_headers.py`:
```python
REQUIRED_HEADERS = {
    'kernel32.dll': [
        # ... существующие ...
        'debugapi.h',  # Новый заголовок
    ],
}
```

2. Запустите:
```bash
python tools/download_headers.py
python tools/header_parser.py
```

### Улучшение парсера

Парсер использует регулярные выражения для извлечения функций. Если нужно поддержать новые форматы:

```python
# В header_parser.py
FUNCTION_PATTERN = re.compile(
    r'(?:WINBASEAPI|НОВЫЙ_ДЕКОРАТОР)\s+'  # Добавьте новый декоратор
    r'(\w+(?:\s+\w+)*?)\s+'
    # ...
)
```

## Преимущества подхода

1. **Автоматизация** - не нужно вручную писать 400+ заглушек
2. **Точность** - сигнатуры берутся из официальных заголовков
3. **Документация** - автоматически генерируется справочник
4. **Обновляемость** - легко добавить новые функции
5. **Консистентность** - единый формат для всех заглушек

## Следующие шаги

1. ✅ Парсинг базовых заголовков (kernel32, advapi32)
2. ⚠️ Улучшение парсера для wingdi.h, winuser.h (большие файлы)
3. ⬜ Добавление user32.dll (GUI функции)
4. ⬜ Добавление ws2_32.dll (Network)
5. ⬜ Автоматическая генерация forward-обёрток (C/C++)
6. ⬜ Интеграция с существующими заглушками в `src/core/winapi_stubs.py`

## Известные ограничения

1. **Сложные макросы** - не парсятся (нужен препроцессор)
2. **Typedef** - не разворачиваются
3. **Вложенные структуры** - упрощаются
4. **Условная компиляция** - игнорируется (#ifdef)

Для большинства случаев это не критично, т.к. нам нужны только сигнатуры функций.

## Лицензия

Заголовочные файлы Windows SDK принадлежат Microsoft и используются в соответствии с лицензией Windows SDK.

Сгенерированные заглушки - часть проекта DRM-explore.
