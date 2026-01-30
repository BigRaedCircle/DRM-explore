# Руководство по использованию эмулятора

## Быстрый старт

### 1. Установка зависимостей

```bash
pip install -r requirements.txt
```

### 2. Базовое использование

#### Запуск простой программы

```python
from src.core.layered_emulator import LayeredEmulator

# Создаём эмулятор
emu = LayeredEmulator(cpu_freq_mhz=3000)

# Загружаем PE-файл
entry_point = emu.load_pe("path/to/program.exe")

# Запускаем эмуляцию
exit_code = emu.run(
    start_addr=entry_point,
    end_addr=0,
    max_instructions=1000000,  # Лимит инструкций
    verbose=False  # True для детального вывода
)

print(f"Exit code: {exit_code}")
print(f"Инструкций выполнено: {emu.instruction_count:,}")
```

#### Модификация командной строки

```python
# Патчим GetCommandLineW для передачи аргументов
def patched_get_command_line_w():
    cmd_line = "program.exe -arg1 -arg2\x00".encode('utf-16le')
    ptr = emu.os.HeapAlloc(emu.os.heap.process_heap, 0, len(cmd_line))
    emu.uc.mem_write(ptr, cmd_line)
    emu.uc.reg_write(emu.uc.arch_const.UC_X86_REG_RAX, ptr)
    return ptr

emu.winapi._stub_get_command_line_w = patched_get_command_line_w
```

## Готовые тесты

### Тесты лицензионных проверок

```bash
# Простая проверка лицензии
python demos/test_simple_check_valid.py
python demos/test_simple_check_invalid.py

# Минимальная проверка с RDTSC
python demos/test_minimal_rdtsc.py

# Дифференциальный анализ
python demos/test_differential_simple.py
python demos/test_differential_license.py
```

### Тесты CPU-Z

```bash
# Базовый запуск CPU-Z
python demos/test_cpuz_report.py

# Анализ структуры PE
python demos/analyze_cpuz_pe.py

# Трассировка выполнения
python demos/test_cpuz_trace_last.py
python demos/test_cpuz_api_log.py
python demos/test_cpuz_last_instructions.py

# Детальная отладка
python demos/test_cpuz_debug.py
python demos/test_cpuz_detailed.py
```

### Тесты реалистичных заглушек

```bash
# Интеграция реалистичных заглушек
python demos/test_integrated_realistic_stubs.py

# Тест виртуальных часов
python demos/test_time_sources.py
```

## Компоненты эмулятора

### LayeredEmulator

Главный класс эмулятора, объединяющий все компоненты:

```python
from src.core.layered_emulator import LayeredEmulator

emu = LayeredEmulator(cpu_freq_mhz=3000)

# Доступные компоненты:
emu.uc          # Unicorn Engine
emu.clock       # VirtualClock - виртуальные часы
emu.os          # MiniOS - минимальная ОС
emu.winapi      # WinAPIStubs - заглушки WinAPI
emu.pe_loader   # PELoader - загрузчик PE
emu.system_info # SystemInfo - информация о системе
emu.vfs         # VirtualFileSystem - виртуальная ФС
emu.directx     # DirectXStubs - заглушки DirectX
emu.network     # NetworkStubs - заглушки сети
```

### VirtualClock

Виртуальные часы для эмуляции времени:

```python
# Получить текущее время
ticks = emu.clock.rdtsc()
ms = emu.clock.get_tick_count()
qpc = emu.clock.query_performance_counter()

# Продвинуть время
emu.clock.advance(1000)  # +1000 тактов
```

### MiniOS

Минимальная ОС с управлением памятью:

```python
# Работа с кучей
heap = emu.os.GetProcessHeap()
ptr = emu.os.HeapAlloc(heap, 0, 1024)
emu.os.HeapFree(heap, 0, ptr)
```

### WinAPIStubs

Заглушки WinAPI функций:

```python
# Получить адрес заглушки
addr = emu.winapi.get_stub_address("CreateFileW")

# Добавить свою заглушку
def my_custom_stub():
    print("Custom stub called!")
    emu.uc.reg_write(emu.uc.arch_const.UC_X86_REG_RAX, 1)
    return 1

emu.winapi.stubs['MyFunction'] = {
    'address': 0x7FFF9000,
    'handler': my_custom_stub
}
```

## Диагностика и отладка

### Анализ PE-файла

```python
python demos/analyze_cpuz_pe.py
```

Показывает:
- Секции PE
- Импорты (DLL и функции)
- Точку входа
- Размер образа

### Трассировка API-вызовов

```python
python demos/test_cpuz_api_log.py
```

Показывает последние 50 API-вызовов перед остановкой.

### Просмотр последних инструкций

```python
python demos/test_cpuz_last_instructions.py
```

Показывает последние 20 инструкций с дизассемблированием.

### Проверка причины остановки

```python
python demos/test_why_stops.py
```

Показывает детальную информацию о том, почему эмуляция остановилась.

## Дифференциальный анализ

### Сравнение двух сценариев

```python
from src.core.differential_analyzer import DifferentialAnalyzer

# Запускаем два сценария
trace1, emu1 = run_scenario("Valid license")
trace2, emu2 = run_scenario("Invalid license")

# Анализируем различия
analyzer = DifferentialAnalyzer()
diff = analyzer.compare_traces(trace1, trace2)

# Находим точку расхождения
divergence = analyzer.find_divergence_point(trace1, trace2)
print(f"Расхождение на инструкции #{divergence}")
```

## Работа с файлами

### Реальные файлы

Эмулятор поддерживает реальные файловые операции:

```python
# CreateFileW/CreateFileA автоматически создают реальные файлы
# WriteFile записывает в реальные файлы
# ReadFile читает из реальных файлов
```

### Виртуальная файловая система

```python
# Использование VFS (если нужно)
emu.vfs.create_file("test.txt", b"Hello, World!")
data = emu.vfs.read_file("test.txt")
```

## Настройка эмулятора

### Изменение частоты CPU

```python
emu = LayeredEmulator(cpu_freq_mhz=2400)  # 2.4 GHz
```

### Увеличение лимита инструкций

```python
exit_code = emu.run(
    start_addr=entry_point,
    max_instructions=10000000  # 10 миллионов
)
```

### Включение детального вывода

```python
exit_code = emu.run(
    start_addr=entry_point,
    verbose=True  # Показывает каждый API-вызов
)
```

## Типичные проблемы и решения

### Unmapped memory read/write

**Проблема**: `UC_ERR_READ_UNMAPPED` или `UC_ERR_WRITE_UNMAPPED`

**Решение**: Эмулятор автоматически обрабатывает unmapped reads/writes для NULL-указателей и GS-сегмента. Если проблема сохраняется, возможно нужно добавить заглушку для функции, которая возвращает невалидный указатель.

### Unmapped code fetch

**Проблема**: `UC_ERR_FETCH_UNMAPPED`

**Решение**: Эмулятор автоматически создаёт RET-заглушки для невалидных адресов. Если это не помогает, проверьте, какая функция возвращает невалидный адрес.

### C++ exception

**Проблема**: CPU-Z бросает C++ exception (RCX=0xE06D7363)

**Решение**: Добавлена заглушка `RaiseException`, которая останавливает эмуляцию. Проверьте, какая функция вернула ошибку перед exception.

### Программа не создаёт файлы

**Проблема**: Программа выполняется, но не создаёт ожидаемые файлы

**Решение**: 
1. Проверьте рабочую директорию (`os.chdir()`)
2. Проверьте, вызывается ли `CreateFile` (используйте `test_cpuz_api_log.py`)
3. Увеличьте лимит инструкций
4. Проверьте, правильно ли переданы аргументы командной строки

## Расширение эмулятора

### Добавление новой WinAPI заглушки

1. Откройте `src/core/winapi_stubs.py`
2. Добавьте функцию в список `functions` в `_setup_stubs()`:

```python
('MyNewFunction', self._stub_my_new_function),
```

3. Реализуйте заглушку:

```python
def _stub_my_new_function(self):
    """MyNewFunction() - описание"""
    # RCX, RDX, R8, R9 - первые 4 аргумента
    arg1 = self.uc.reg_read(UC_X86_REG_RCX)
    
    print(f"[API] MyNewFunction(arg1=0x{arg1:x})")
    
    # Возвращаем результат в RAX
    self.uc.reg_write(UC_X86_REG_RAX, 1)
    return 1
```

### Добавление хука

```python
from unicorn import UC_HOOK_CODE

def my_hook(uc, address, size, user_data):
    print(f"Executing at 0x{address:x}")

emu.uc.hook_add(UC_HOOK_CODE, my_hook)
```

## Полезные ссылки

- **Документация Unicorn**: https://www.unicorn-engine.org/docs/
- **PE формат**: https://learn.microsoft.com/en-us/windows/win32/debug/pe-format
- **WinAPI**: https://learn.microsoft.com/en-us/windows/win32/api/
- **x64 calling convention**: https://learn.microsoft.com/en-us/cpp/build/x64-calling-convention

## Примеры использования

### Пример 1: Простая программа с лицензией

```python
from src.core.layered_emulator import LayeredEmulator

emu = LayeredEmulator(cpu_freq_mhz=3000)

# Патчим командную строку для передачи лицензии
def patched_cmd():
    cmd = "program.exe VALID-KEY-1234\x00".encode('utf-16le')
    ptr = emu.os.HeapAlloc(emu.os.heap.process_heap, 0, len(cmd))
    emu.uc.mem_write(ptr, cmd)
    emu.uc.reg_write(emu.uc.arch_const.UC_X86_REG_RAX, ptr)
    return ptr

emu.winapi._stub_get_command_line_w = patched_cmd

# Загружаем и запускаем
entry = emu.load_pe("demos/license_valid.exe")
exit_code = emu.run(entry, max_instructions=50000)

print(f"Exit code: {exit_code}")
```

### Пример 2: Дифференциальный анализ

```python
from src.core.layered_emulator import LayeredEmulator

def run_with_key(key):
    emu = LayeredEmulator(cpu_freq_mhz=3000)
    
    def patched_cmd():
        cmd = f"program.exe {key}\x00".encode('utf-16le')
        ptr = emu.os.HeapAlloc(emu.os.heap.process_heap, 0, len(cmd))
        emu.uc.mem_write(ptr, cmd)
        emu.uc.reg_write(emu.uc.arch_const.UC_X86_REG_RAX, ptr)
        return ptr
    
    emu.winapi._stub_get_command_line_w = patched_cmd
    
    entry = emu.load_pe("demos/license_check.exe")
    exit_code = emu.run(entry, max_instructions=50000, verbose=False)
    
    return exit_code, emu.instruction_count

# Сравниваем
exit1, count1 = run_with_key("VALID-KEY")
exit2, count2 = run_with_key("INVALID-KEY")

print(f"Valid:   exit={exit1}, instructions={count1:,}")
print(f"Invalid: exit={exit2}, instructions={count2:,}")
print(f"Difference: {abs(count1 - count2):,} instructions")
```

### Пример 3: Анализ CPU-Z

```python
import os
from src.core.layered_emulator import LayeredEmulator

# Переходим в папку CPU-Z
os.chdir("sandbox/CPU-Z")

emu = LayeredEmulator(cpu_freq_mhz=3000)

# Патчим командную строку
def patched_cmd():
    cmd = "cpuz.exe -txt=report\x00".encode('utf-16le')
    ptr = emu.os.HeapAlloc(emu.os.heap.process_heap, 0, len(cmd))
    emu.uc.mem_write(ptr, cmd)
    emu.uc.reg_write(emu.uc.arch_const.UC_X86_REG_RAX, ptr)
    return ptr

emu.winapi._stub_get_command_line_w = patched_cmd

# Загружаем и запускаем
entry = emu.load_pe("cpuz.exe")
exit_code = emu.run(entry, max_instructions=10000000, verbose=False)

print(f"Exit code: {exit_code}")
print(f"Instructions: {emu.instruction_count:,}")

# Проверяем, создался ли файл
if os.path.exists("report.txt"):
    print("✓ Report created!")
    with open("report.txt", "r") as f:
        print(f.read()[:500])
else:
    print("✗ Report not created")

os.chdir("../..")
```

## Заключение

Эмулятор предоставляет мощные возможности для анализа Windows PE-файлов:
- Эмуляция выполнения без реального запуска
- Дифференциальный анализ для поиска различий
- Трассировка API-вызовов
- Виртуальное время для обхода time-based защит
- Реалистичные заглушки для периферийных устройств

Для дополнительной информации смотрите файлы в папке `demos/`.
