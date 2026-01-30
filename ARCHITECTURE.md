# Архитектура двухслойной эмуляции

## Философия проекта

Большинство DRM систем сосредоточены на **детекции вмешательства**, а не на реальной функциональности. Поэтому остальные функции можно эмулировать "фейково, но правдоподобно" в нашей двухслойной архитектуре.

## Двухслойная архитектура

```
┌─────────────────────────────────────────────────────────────┐
│  Layer 1: CRITICAL (Anti-Tamper Focus)                      │
│  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━  │
│  • Timing (RDTSC, QPC, GetTickCount)                        │
│  • Debugger Detection (IsDebuggerPresent)                   │
│  • Memory Integrity (checksums, guards)                     │
│  • Hardware Info (CPUID, MSR)                               │
│  • Thread Information Block (TIB/GS)                        │
│                                                              │
│  → Должны быть ИДЕАЛЬНО точными и консистентными           │
│  → Математически связаны через VirtualClock                 │
│  → Любая ошибка = детекция эмуляции                         │
└─────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────┐
│  Layer 2: FUNCTIONAL (Fake but Valid)                       │
│  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━  │
│  • DirectX (возвращаем S_OK, фейковые device)               │
│  • Registry (фейковые ключи с правдоподобными данными)      │
│  • File System (VirtualFileSystem)                          │
│  • Network (эмуляция offline режима)                        │
│  • Audio/Video (stub устройства)                            │
│                                                              │
│  → Главное - правдоподобность, не точность                  │
│  → Консистентность данных между вызовами                    │
│  → Минимальная функциональность для прохождения проверок    │
└─────────────────────────────────────────────────────────────┘
```

## Примеры "правильной фейковости"

### ❌ ПЛОХО - слишком очевидно

```python
def GetSystemMetrics():
    return 0  # Подозрительно! Экран 0x0?

def GetTickCount():
    return 1000  # Время не идёт!

def RegQueryValueEx(key, name):
    return ERROR_FILE_NOT_FOUND  # Пустой реестр?
```

### ✅ ХОРОШО - правдоподобно

```python
def GetSystemMetrics(index):
    """Возвращаем реалистичные метрики системы"""
    metrics = {
        SM_CXSCREEN: 1920,      # Ширина экрана
        SM_CYSCREEN: 1080,      # Высота экрана
        SM_CMONITORS: 1,        # Количество мониторов
        SM_REMOTESESSION: 0,    # Не RDP сессия
    }
    return metrics.get(index, 0)

def GetTickCount():
    """Время растёт консистентно с VirtualClock"""
    return self.clock.get_tick_count()

def RegQueryValueEx(key, name):
    """Фейковый реестр с правдоподобными данными"""
    fake_registry = {
        "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProductName": 
            "Windows 10 Pro",
        "HKLM\\HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0\\ProcessorNameString": 
            "Intel Core i7-9700K",
    }
    return fake_registry.get(f"{key}\\{name}", ERROR_FILE_NOT_FOUND)
```

## Текущий статус реализации

### ✅ Уже реализовано (Layer 1 - Critical)

| Компонент | Статус | Описание |
|-----------|--------|----------|
| **VirtualClock** | ✅ 100% | Единый источник времени для всех таймеров |
| **RDTSC** | ✅ 100% | Эмуляция инструкции с консистентными значениями |
| **GetTickCount** | ✅ 100% | Миллисекунды с момента запуска |
| **QueryPerformanceCounter** | ✅ 100% | Высокоточный таймер (10 MHz) |
| **CPUID** | ✅ 100% | Эмуляция Intel Core i7-9700K |
| **TIB/GS Segment** | ✅ 100% | Thread Information Block |
| **PE Loader** | ✅ 100% | Загрузка x64 PE файлов |

### ✅ Уже реализовано (Layer 2 - Functional)

| Компонент | Статус | Описание |
|-----------|--------|----------|
| **File I/O** | ✅ 80% | CreateFile, ReadFile, WriteFile, CloseHandle |
| **Memory Management** | ✅ 90% | HeapAlloc, VirtualAlloc, VirtualProtect |
| **Threading** | ✅ 70% | TLS, Critical Sections, базовая синхронизация |
| **System Info** | ✅ 60% | GetSystemInfo, GetModuleHandle, GetProcAddress |
| **VirtualFileSystem** | ✅ 50% | Базовая файловая система в памяти |
| **DirectX Stubs** | ✅ 40% | Минимальные заглушки D3D |
| **Network Stubs** | ✅ 40% | Эмуляция offline режима |

### ⚠️ Частично реализовано

| Компонент | Статус | Что нужно |
|-----------|--------|-----------|
| **Registry** | ⚠️ 20% | Фейковый реестр с правдоподобными ключами |
| **Environment** | ⚠️ 30% | Переменные окружения, пути |
| **Graphics** | ⚠️ 20% | Расширенные DirectX/OpenGL stubs |
| **Audio** | ⚠️ 10% | DirectSound, WASAPI stubs |
| **Input** | ⚠️ 10% | Keyboard, Mouse, Gamepad stubs |

### ❌ Не реализовано (но не критично)

- Kernel drivers (MSR, PCI, USB) - требуют kernel mode
- COM/OLE - сложная инфраструктура
- WMI - Windows Management Instrumentation
- Services - Service Control Manager
- ETW - Event Tracing for Windows
- Полный NTDLL (~2000 функций)

## Стратегия реализации

### Приоритет 1: Anti-Tamper Critical ✅ ГОТОВО

- [x] Timing sources (RDTSC, GetTickCount, QPC)
- [x] VirtualClock с математической консистентностью
- [x] Debugger detection stubs
- [x] Memory integrity
- [x] CPUID emulation
- [x] TIB/GS segment

**Результат:** Эмулятор проходит 100% тестов комплексного анти-тампера!

### Приоритет 2: Common API (частично готово)

- [x] File I/O (CreateFile, ReadFile, WriteFile)
- [x] Memory (HeapAlloc, VirtualAlloc)
- [x] Threading (CreateThread, TLS)
- [x] Synchronization (Mutex, Event, CriticalSection)
- [ ] Process management (CreateProcess, WaitForSingleObject)
- [ ] Module loading (LoadLibrary, GetProcAddress - расширить)

### Приоритет 3: System Info (нужно расширить)

- [ ] **Registry Emulator** - фейковый реестр Windows
  - Правдоподобные ключи (Windows version, CPU info, etc.)
  - Консистентные данные между вызовами
  - Поддержка RegOpenKey, RegQueryValue, RegCloseKey
  
- [ ] **Environment Variables**
  - PATH, TEMP, USERNAME, COMPUTERNAME
  - Консистентные с System Info
  
- [ ] **System Metrics**
  - Разрешение экрана, количество мониторов
  - Версия Windows, Service Pack
  - Информация о процессоре, памяти

### Приоритет 4: Graphics/Audio (минимальная эмуляция)

- [ ] **DirectX Minimal Stubs**
  - D3D9/D3D11 device creation (возвращаем S_OK)
  - Фейковые device handles
  - Базовые методы (Present, Clear, etc.)
  
- [ ] **OpenGL Stubs**
  - Context creation
  - Базовые GL функции
  
- [ ] **Audio Stubs**
  - DirectSound/WASAPI device enumeration
  - Фейковые audio endpoints

### Приоритет 5: Network (базово есть)

- [x] WinSock (offline mode)
- [x] HTTP (фейковые ответы)
- [ ] SSL/TLS (certificate validation stubs)

## Ключевые принципы

### 1. Консистентность превыше всего

```python
# ВСЕ источники времени связаны через VirtualClock
rdtsc = clock.rdtsc()
tick_count = clock.get_tick_count()
qpc = clock.query_performance_counter()

# Математически консистентны:
# rdtsc / cpu_freq_hz * 1000 ≈ tick_count
# qpc / qpc_freq * 1000 ≈ tick_count
```

### 2. Правдоподобность, не точность

```python
# Не нужно эмулировать реальный DirectX
# Достаточно вернуть правдоподобные значения
def D3D11CreateDevice():
    return S_OK, fake_device_handle

# Не нужно реальное сетевое соединение
# Достаточно эмулировать offline режим
def connect():
    return WSAENOTCONN  # Network unavailable
```

### 3. Минимальная функциональность

```python
# Реализуем только то, что проверяет DRM
# Не нужно полное API - только критичные функции
```

## Тестирование

### Текущие тесты

1. ✅ **Complex Anti-Tamper Test** - 6/6 тестов (100%)
   - RDTSC timing checks
   - GetTickCount timing
   - QueryPerformanceCounter
   - License validation
   - Obfuscated checks
   - Multi-level validation

2. ✅ **License Check Tests** - 6/6 программ
   - Valid/Invalid license keys
   - Simple/Minimal/Complex variants

3. ⚠️ **CPU-Z** - слишком сложен для чистой эмуляции
   - Требует driver-level доступ (MSR, PCI)
   - Рекомендация: использовать Frida для таких случаев

### Планируемые тесты

- [ ] Steam DRM (базовая проверка)
- [ ] UPlay DRM
- [ ] Origin DRM
- [ ] Custom DRM samples

## Гибридный подход для сложных случаев

Для DRM систем, требующих driver-level доступ:

```
┌─────────────────────────────────────────┐
│  Эмулятор (Unicorn + WinAPI Stubs)      │
│  • Анализ алгоритмов                    │
│  • Timing checks                        │
│  • License validation                   │
└─────────────────────────────────────────┘
              +
┌─────────────────────────────────────────┐
│  Frida (Dynamic Instrumentation)        │
│  • Реальный процесс                     │
│  • Driver-level доступ                  │
│  • Hardware checks                      │
└─────────────────────────────────────────┘
              +
┌─────────────────────────────────────────┐
│  IDA/Ghidra (Static Analysis)           │
│  • Дизассемблирование                   │
│  • Control flow analysis                │
│  • Crypto analysis                      │
└─────────────────────────────────────────┘
```

## Выводы

1. **Layer 1 (Critical)** - готов и работает отлично ✅
2. **Layer 2 (Functional)** - достаточно для большинства DRM
3. **Гибридный подход** - для сложных случаев (Denuvo, VMProtect)
4. **Фокус на правдоподобности** - не на полноте реализации

## Следующие шаги

1. **Registry Emulator** - фейковый реестр Windows
2. **Extended System Info** - расширенная информация о системе
3. **DirectX Minimal Stubs** - минимальные заглушки для D3D
4. **Тестирование на реальных DRM** - Steam, UPlay, Origin

---

**Статус проекта:** Proof of Concept успешно работает! 🎉

**Commit:** `44923f2` - Fix: Virtual clock timing for anti-tamper detection

**Repository:** https://github.com/BigRaedCircle/DRM-explore
