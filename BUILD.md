# Инструкция по сборке и запуску

## Зависимости

### Python пакеты
```bash
pip install unicorn-engine capstone pefile
```

### Компилятор C
Нужен один из:
- GCC (MinGW-w64 для Windows)
- MSVC (Visual Studio Build Tools)
- Clang

## Сборка учебного анти-тампера

### С GCC:
```bash
gcc -O2 demos/time_check_demo.c -o demos/time_check_demo.exe
```

### С MSVC:
```bash
cl /O2 demos/time_check_demo.c /Fe:demos/time_check_demo.exe
```

## Тестирование

### 1. Проверка VirtualClock
```bash
python src/core/virtual_clock.py
```
Ожидаемый результат: все таймеры консистентны

### 2. Проверка SimpleEmulator
```bash
python src/core/simple_emulator.py
```
Ожидаемый результат: эмуляция RDTSC работает

### 3. Запуск учебного анти-тампера нативно
```bash
demos/time_check_demo.exe VALID-KEY-1234
```
Ожидаемый результат: все проверки пройдены

### 4. Запуск в эмуляторе (TODO)
```bash
python test_emulation.py demos/time_check_demo.exe
```
Ожидаемый результат: анти-тампер НЕ детектирует эмуляцию

## Структура проекта

```
.
├── src/core/
│   ├── virtual_clock.py        # Единый источник времени
│   └── simple_emulator.py      # Минимальный эмулятор
├── demos/
│   └── time_check_demo.c       # Учебный анти-тампер
└── tests/
    └── test_emulation.py       # Тесты (TODO)
```
