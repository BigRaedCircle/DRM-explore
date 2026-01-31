# Гибридная архитектура: Эмуляция + Passthrough

## Концепция

Разделяем WinAPI функции на **3 категории** по критичности и возможности проброса:

```
┌─────────────────────────────────────────────────────────────┐
│                    WinAPI Functions                         │
└─────────────────────────────────────────────────────────────┘
                           │
        ┌──────────────────┼──────────────────┐
        │                  │                  │
        ▼                  ▼                  ▼
┌──────────────┐  ┌──────────────┐  ┌──────────────┐
│  EMULATED    │  │ PASSTHROUGH  │  │    STUB      │
│  (Critical)  │  │   (Safe)     │  │ (Non-crit)   │
└──────────────┘  └──────────────┘  └──────────────┘
```

## 1. EMULATED (Критичные) - Полная эмуляция

**Почему эмулируем:**
- Работают с внутренним состоянием эмулятора
- Модифицируют адресное пространство Unicorn
- Требуют контроля над памятью/потоками

**Примеры:**
```python
HeapAlloc()          # Выделяет память В эмуляторе
GetModuleHandleW()   # Возвращает адрес ИЗ эмулятора
GetCurrentThreadId() # Виртуальный thread ID
ExitProcess()        # Останавливает эмуляцию
```

**Список:**
- Память: `HeapAlloc`, `HeapFree`, `VirtualAlloc`, `VirtualFree`
- Модули: `GetModuleHandleW`, `LoadLibraryW`, `GetProcAddress`
- Потоки: `GetCurrentThreadId`, `EnterCriticalSection`
- Время: `GetSystemTimeAsFileTime` (виртуальное)
- Отладка: `IsDebuggerPresent` (всегда FALSE)

## 2. PASSTHROUGH (Безопасные) - Проброс в систему

**Почему пробрасываем:**
- Read-only операции
- Не модифицируют состояние эмулятора
- Возвращают реальные данные системы

**Примеры:**
```python
IsProcessorFeaturePresent() # Реальные CPU features
WriteConsoleW()             # Реальный вывод в консоль
GetACP()                    # Реальная кодовая страница
GetLastError()              # Thread-local, но безопасно
```

**Список:**
- Системная информация: `GetSystemInfo`, `IsProcessorFeaturePresent`
- Консоль: `WriteConsoleW`, `GetStdHandle`, `GetConsoleMode`
- Локализация: `GetACP`, `MultiByteToWideChar`
- Ошибки: `GetLastError`, `SetLastError`

**Преимущества:**
- ✅ Реальные данные CPU/системы
- ✅ Реальный вывод в консоль
- ✅ Меньше кода для эмуляции

## 3. STUB (Некритичные) - Простые заглушки

**Почему заглушаем:**
- Не нужны для консольного режима
- Сложны для эмуляции
- Не влияют на основную логику

**Примеры:**
```python
DialogBoxIndirectParamW() # GUI - не нужен
PrintDlgW()               # Печать - не нужна
CoCreateInstance()        # COM - сложно
RegOpenKeyW()             # Registry - можно заглушить
```

**Список:**
- GUI: `SendMessageW`, `DialogBoxIndirectParamW`, `LoadCursorW`
- Печать: `PrintDlgW`, `StartDocW`, `EndDoc`
- COM: `CoCreateInstance`, `CoInitializeSecurity`
- Registry: `RegOpenKeyW`, `RegQueryValueExW`
- Exception handling: `RtlCaptureContext`, `RtlVirtualUnwind`

## Реализация Passthrough

### Проблема: Маппинг памяти

```
┌─────────────────────────────────────────────────────────────┐
│  Unicorn Memory Space          Real Windows Memory          │
├─────────────────────────────────────────────────────────────┤
│  0x140000000 (PE base)         0x00007FF... (real PE)       │
│  0x1FF000 (stack)              0x00000000... (real stack)   │
│  0x7FFF0000 (stubs)            N/A                          │
└─────────────────────────────────────────────────────────────┘
```

**Решение:**
1. **Для простых функций** (без указателей): прямой вызов
2. **Для функций с указателями**: копируем данные туда-обратно

### Пример: WriteConsoleW (с указателями)

```python
def passthrough_writeconsolew(hybrid, uc):
    # 1. Читаем параметры из регистров Unicorn
    hConsoleOutput = uc.reg_read(UC_X86_REG_RCX)
    lpBuffer = uc.reg_read(UC_X86_REG_RDX)  # Указатель в Unicorn!
    nChars = uc.reg_read(UC_X86_REG_R8)
    
    # 2. КОПИРУЕМ строку из памяти Unicorn в Python
    text = hybrid.read_string_from_memory(lpBuffer, unicode=True)
    
    # 3. Вызываем РЕАЛЬНУЮ WriteConsoleW с РЕАЛЬНЫМ handle
    written = wintypes.DWORD()
    result = kernel32.WriteConsoleW(
        hConsoleOutput,  # Реальный handle
        text,            # Python string
        nChars,
        ctypes.byref(written),
        None
    )
    
    # 4. КОПИРУЕМ результат обратно в память Unicorn
    if lpNumberOfCharsWritten:
        uc.mem_write(lpNumberOfCharsWritten, written.value.to_bytes(4, 'little'))
    
    # 5. Возвращаем результат в RAX
    uc.reg_write(UC_X86_REG_RAX, result)
```

### Пример: IsProcessorFeaturePresent (без указателей)

```python
def passthrough_isprocessorfeaturepresent(uc):
    # 1. Читаем параметр
    feature = uc.reg_read(UC_X86_REG_RCX)
    
    # 2. Вызываем РЕАЛЬНУЮ функцию напрямую
    result = kernel32.IsProcessorFeaturePresent(feature)
    
    # 3. Возвращаем результат
    uc.reg_write(UC_X86_REG_RAX, result)
```

## Преимущества гибридного подхода

### Для CoreInfo:

**До (только эмуляция):**
```
[API] IsProcessorFeaturePresent() -> 0 [STUB]
[API] WriteConsoleW() -> 1 [STUB]
```
❌ Нет реальных CPU features
❌ Нет вывода в консоль

**После (гибрид):**
```
[API] IsProcessorFeaturePresent(AVX) -> 1 [PASSTHROUGH]
[CONSOLE] Coreinfo v4.0 - Dump information...
[CONSOLE] AMD Ryzen 5 3400G...
```
✅ Реальные CPU features
✅ Реальный вывод в консоль

## Ограничения Passthrough

### Что НЕЛЬЗЯ пробрасывать:

1. **Функции с указателями на код**
   - `GetProcAddress()` - вернет адрес из реальной DLL, не из эмулятора
   - `LoadLibraryW()` - загрузит DLL в реальный процесс

2. **Функции, модифицирующие память**
   - `HeapAlloc()` - вернет адрес из реального heap
   - `VirtualAlloc()` - выделит память вне Unicorn

3. **Функции с callbacks**
   - `EnumSystemLocalesW()` - callback должен быть в Unicorn
   - `CreateThread()` - thread будет реальным, не эмулированным

### Решение: Гибридный подход

```python
if func_name == 'GetProcAddress':
    # ЭМУЛИРУЕМ - возвращаем адрес stub из Unicorn
    return emulated_getprocaddress()
    
elif func_name == 'IsProcessorFeaturePresent':
    # ПРОБРАСЫВАЕМ - вызываем реальную функцию
    return passthrough_isprocessorfeaturepresent()
    
elif func_name == 'WriteConsoleW':
    # ГИБРИД - копируем данные туда-обратно
    return hybrid_writeconsolew()
```

## Следующие шаги

1. ✅ Создан `src/core/hybrid_stubs.py` с категориями
2. ⏳ Интегрировать в `WinAPIStubsV2`
3. ⏳ Реализовать passthrough для консольного вывода
4. ⏳ Реализовать passthrough для CPU features
5. ⏳ Тестировать CoreInfo с реальным выводом

## Результат

CoreInfo должен выводить:
```
Coreinfo v4.0 - Dump information on system CPU and memory topology
Copyright (C) 2008-2025 Mark Russinovich
Sysinternals - www.sysinternals.com

AMD Ryzen 5 3400G with Radeon Vega Graphics
...
AVX             *       Supports AVX instruction extensions
...
```

Вместо просто `ExitProcess(0)` без вывода.
