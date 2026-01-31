# Стратегия патчинга для Passthrough функций

## Концепция: "Виртуальная реальность"

Программа должна видеть **ВИРТУАЛЬНУЮ** систему, которая:
1. **Консистентна** - все данные согласованы между собой
2. **Правдоподобна** - выглядит как реальная система
3. **Безопасна** - не выдает эмуляцию

## Примеры патчинга из существующего кода:

### ✅ Timing (УЖЕ РЕАЛИЗОВАНО)

```python
# РЕАЛЬНАЯ система: QueryPerformanceCounter() → 123456789 (реальные такты)
# ВИРТУАЛЬНАЯ система: QueryPerformanceCounter() → 1000 (виртуальные такты)

def _custom_queryperformancecounter(self):
    # НЕ вызываем реальную функцию!
    # Возвращаем ВИРТУАЛЬНОЕ время
    counter = self.emu.clock.query_performance_counter()
    self.uc.mem_write(lpPerformanceCount, counter.to_bytes(8, 'little'))
```

**Результат:** Программа видит виртуальное время, не может детектировать эмуляцию через кросс-валидацию.

### ✅ Debugger Detection (УЖЕ РЕАЛИЗОВАНО)

```python
# РЕАЛЬНАЯ система: IsDebuggerPresent() → TRUE (мы в отладчике!)
# ВИРТУАЛЬНАЯ система: IsDebuggerPresent() → FALSE (нет отладчика)

def _custom_isdebuggerpresent(self):
    # НЕ вызываем реальную функцию!
    # ВСЕГДА возвращаем FALSE
    self.uc.reg_write(UC_X86_REG_RAX, 0)
```

**Результат:** Программа не знает, что мы ее отлаживаем.

## Новая задача: CPU Features

### ❌ ПРОБЛЕМА: Наивный passthrough

```python
def _custom_isprocessorfeaturepresent(self):
    # Вызываем РЕАЛЬНУЮ функцию
    result = kernel32.IsProcessorFeaturePresent(feature)
    # Возвращаем РЕАЛЬНЫЙ результат
    self.uc.reg_write(UC_X86_REG_RAX, result)
```

**Проблема:**
- Реальный CPU: AVX2 = TRUE
- Unicorn: AVX2 = НЕ ПОДДЕРЖИВАЕТСЯ
- Программа пытается выполнить AVX2 инструкцию → CRASH!

### ✅ РЕШЕНИЕ: Умный патчинг (фильтрация)

```python
def _custom_isprocessorfeaturepresent(self):
    """ПАТЧИНГ: фильтруем features под возможности эмулятора"""
    feature = self.uc.reg_read(UC_X86_REG_RCX)
    
    # Виртуальный CPU profile (что эмулятор МОЖЕТ)
    VIRTUAL_CPU_FEATURES = {
        # Базовые features (Unicorn поддерживает)
        0: True,   # PF_FLOATING_POINT_PRECISION_ERRATA
        1: True,   # PF_FLOATING_POINT_EMULATED
        2: True,   # PF_COMPARE_EXCHANGE_DOUBLE
        3: True,   # PF_MMX_INSTRUCTIONS_AVAILABLE
        6: True,   # PF_XMMI_INSTRUCTIONS_AVAILABLE (SSE)
        7: True,   # PF_3DNOW_INSTRUCTIONS_AVAILABLE
        10: True,  # PF_XMMI64_INSTRUCTIONS_AVAILABLE (SSE2)
        13: True,  # PF_SSE3_INSTRUCTIONS_AVAILABLE
        17: True,  # PF_COMPARE_EXCHANGE128
        
        # Продвинутые features (Unicorn НЕ поддерживает)
        23: False,  # PF_AVX2_INSTRUCTIONS_AVAILABLE ← ПАТЧИМ!
        40: False,  # PF_AVX512F_INSTRUCTIONS_AVAILABLE
        # ... другие
    }
    
    # Проверяем в виртуальном профиле
    if feature in VIRTUAL_CPU_FEATURES:
        result = VIRTUAL_CPU_FEATURES[feature]
        print(f"[API] IsProcessorFeaturePresent({feature}) -> {result} [VIRTUAL CPU]")
        self.uc.reg_write(UC_X86_REG_RAX, result)
        return result
    
    # Для неизвестных features - passthrough (безопасно)
    result = kernel32.IsProcessorFeaturePresent(feature)
    print(f"[API] IsProcessorFeaturePresent({feature}) -> {result} [PASSTHROUGH]")
    self.uc.reg_write(UC_X86_REG_RAX, result)
    return result
```

**Результат:**
- Программа видит **ВИРТУАЛЬНЫЙ CPU** (не реальный!)
- Виртуальный CPU поддерживает только то, что может Unicorn
- Программа НЕ пытается выполнить неподдерживаемые инструкции
- Программа НЕ может детектировать эмуляцию

## Стратегия для других Passthrough функций:

### WriteConsoleW (вывод в консоль)

```python
def _custom_writeconsolew(self):
    """ПАТЧИНГ: копируем данные туда-обратно"""
    # 1. Читаем из ВИРТУАЛЬНОЙ памяти (Unicorn)
    data = self.uc.mem_read(lpBuffer, nChars * 2)
    text = data.decode('utf-16-le')
    
    # 2. Вызываем РЕАЛЬНУЮ функцию
    kernel32.WriteConsoleW(hConsoleOutput, text, nChars, ...)
    
    # 3. Результат записываем в ВИРТУАЛЬНУЮ память
    self.uc.mem_write(lpNumberOfCharsWritten, written.to_bytes(4, 'little'))
```

**Патчинг:** Копирование данных между виртуальной и реальной памятью.

### GetSystemInfo (информация о системе)

```python
def _custom_getsysteminfo(self):
    """ПАТЧИНГ: подменяем данные под виртуальную систему"""
    # Вызываем реальную функцию
    real_info = kernel32.GetSystemInfo()
    
    # ПАТЧИМ данные под виртуальную систему
    virtual_info = {
        'dwNumberOfProcessors': 4,  # Виртуальные CPU
        'dwPageSize': 4096,          # Виртуальный page size
        'lpMinimumApplicationAddress': 0x10000,  # Виртуальный адрес
        'lpMaximumApplicationAddress': 0x7FFFFFFF,  # Виртуальный адрес
        # ... другие поля
    }
    
    # Записываем ВИРТУАЛЬНЫЕ данные
    self.uc.mem_write(lpSystemInfo, struct.pack(..., virtual_info))
```

**Патчинг:** Подмена реальных данных на виртуальные.

### GetModuleHandleW (адрес модуля)

```python
def _custom_getmodulehandlew(self):
    """НЕ ПРОБРАСЫВАЕМ! Только эмуляция!"""
    # НЕ вызываем реальную функцию!
    # Возвращаем адрес ИЗ виртуальной памяти Unicorn
    
    if lpModuleName == NULL:
        # Адрес PE base в Unicorn
        self.uc.reg_write(UC_X86_REG_RAX, 0x140000000)
    else:
        # Ищем в виртуальных модулях
        module_addr = self.emu.pe_loader.get_module_base(module_name)
        self.uc.reg_write(UC_X86_REG_RAX, module_addr)
```

**Патчинг:** НЕТ passthrough! Только виртуальные адреса!

## Правила патчинга:

### 1. Функции БЕЗ адресов → Passthrough с фильтрацией
```python
# Безопасно пробрасывать:
IsProcessorFeaturePresent()  # Фильтруем под Unicorn
GetACP()                     # Кодовая страница
GetOEMCP()                   # OEM кодовая страница
```

### 2. Функции С адресами → Копирование данных
```python
# Копируем туда-обратно:
WriteConsoleW()    # Виртуальная память → Реальная консоль
ReadConsoleW()     # Реальная консоль → Виртуальная память
MultiByteToWideChar()  # Копируем строки
```

### 3. Функции С адресами модулей → Только эмуляция
```python
# НЕ пробрасываем:
GetModuleHandleW()   # Только виртуальные адреса
GetProcAddress()     # Только виртуальные адреса
LoadLibraryW()       # Только виртуальная загрузка
```

### 4. Функции С таймингом → Только эмуляция
```python
# НЕ пробрасываем:
QueryPerformanceCounter()  # Только VirtualClock
GetTickCount()             # Только VirtualClock
RDTSC                      # Только VirtualClock
```

## Итоговая архитектура:

```
┌─────────────────────────────────────────────────────────────┐
│                    РЕАЛЬНАЯ СИСТЕМА                         │
│  CPU: AMD Ryzen 5 3400G (AVX2, AVX512)                     │
│  Memory: 16GB RAM (0x00007FF...)                            │
│  Time: 2026-02-01 12:34:56.789                              │
└─────────────────────────────────────────────────────────────┘
                           ▲
                           │ PASSTHROUGH + ПАТЧИНГ
                           │
┌──────────────────────────┼──────────────────────────────────┐
│         МАППИНГ СЛОЙ     │                                  │
│  ┌───────────────────────┴────────────────────────────┐    │
│  │  IsProcessorFeaturePresent(AVX2) → FALSE (патчинг)│    │
│  │  WriteConsoleW(виртуальный буфер) → копирование   │    │
│  │  GetSystemInfo() → виртуальные данные              │    │
│  └────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────┐
│              ВИРТУАЛЬНАЯ СИСТЕМА (Unicorn)                  │
│  CPU: Virtual x64 (SSE, SSE2, SSE3 only)                   │
│  Memory: 0x140000000 (виртуальная)                         │
│  Time: VirtualClock (ticks=1000)                            │
│                                                              │
│  ┌───────────────────────────────────────────────────────┐ │
│  │         ПРОГРАММА (CoreInfo / Denuvo)                 │ │
│  │  - Видит ТОЛЬКО виртуальную систему                   │ │
│  │  - НЕ ЗНАЕТ о реальной системе                        │ │
│  │  - НЕ МОЖЕТ детектировать эмуляцию                    │ │
│  └───────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────┘
```

## Вывод:

**Суть двухслойной эмуляции:**
1. **Виртуальное ядро** - изолированное пространство (CPU, память, время)
2. **Маппинг слой** - патчинг данных между виртуальным и реальным
3. **Реальная обвязка** - passthrough для безопасных функций

**Программа НЕ МОЖЕТ обнаружить эмуляцию**, потому что:
- Видит только виртуальную систему
- Все данные консистентны
- Все таймеры синхронизированы
- Все адреса виртуальные

Это и есть **"виртуальная реальность"** для программы!
