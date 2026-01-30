# Исправление бага с массивами в парсерах

## Проблема

Парсеры генерировали невалидный Python код для параметров-массивов:
```python
aSegmentArray[] = self.uc.reg_read(...)  # ❌ SyntaxError
```

## Решение

Добавлена очистка квадратных скобок `[]` из имён параметров:
```python
param_name = param_name.replace('[', '').replace(']', '')
```

## Исправлено

1. ✅ `tools/header_parser.py` - WinAPI парсер
2. ✅ `tools/directx_parser.py` - DirectX парсер

## Регенерировано

3. ✅ `tools/generated/winapi_stubs_generated.py` - 436 функций
4. ✅ `tools/generated/directx_stubs_generated.py` - 6 функций

## Результаты тестирования

```
WinAPI Tests:  4/4 passed (100%) ✅
DirectX Tests: 2/2 passed (100%) ✅
Total:         6/6 passed (100%) ✅
```

## Команды для проверки

```bash
# Регенерация
python tools/header_parser.py
python tools/directx_parser.py

# Тестирование
python test_stub_override.py
python test_directx_stubs.py

# Синтаксическая проверка
python -m py_compile tools/generated/winapi_stubs_generated.py
python -m py_compile tools/generated/directx_stubs_generated.py
```

**Статус:** ✅ Исправлено и протестировано  
**Дата:** 2026-01-30
