# Установка пропатченной версии Unicorn с фиксом REP инструкций

## Проблема
Unicorn 2.1.4 не корректно обрабатывает REP префиксы (STOSB, MOVSB, etc.) когда установлен UC_HOOK_CODE:
- Hook вызывается на каждой итерации REP
- RCX не декрементируется автоматически
- Результат: бесконечный цикл

## Решение
Патч в `qemu/target/i386/translate.c`:
```c
// Строка 9328: Форсируем repz_opt = 1 для атомарного выполнения REP
dc->repz_opt = 1;
```

## Компиляция (уже выполнено)
```bash
cd unicorn-source/build
cmake .. -G "NMake Makefiles" -DCMAKE_BUILD_TYPE=Release
nmake
```

## Установка после успешной компиляции

### Шаг 1: Найти скомпилированные файлы
```bash
# Python binding
unicorn-source/bindings/python/

# Библиотеки
unicorn-source/build/unicorn.dll
unicorn-source/build/unicorn.lib
```

### Шаг 2: Установить Python binding
```bash
cd unicorn-source/bindings/python
pip uninstall unicorn -y
pip install .
```

### Шаг 3: Проверить версию
```bash
python -c "import unicorn; print(unicorn.__version__)"
```

### Шаг 4: Тестировать на simple_sysinfo.exe (с CRT)
```bash
python demos/test_simple_sysinfo.py
```

Ожидаемый результат:
- Программа выполняется БЕЗ зависания
- REP STOSB обрабатывается корректно
- Вывод программы совпадает с нативным запуском

## Откат (если что-то пошло не так)
```bash
pip uninstall unicorn -y
pip install unicorn==2.1.4
```

## Файлы патча
- `unicorn-source/unicorn_rep_fix.patch` - описание патча
- `unicorn-source/qemu/target/i386/translate.c` - пропатченный файл (строка 9328)
