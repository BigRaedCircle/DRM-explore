# Unicorn REP Instructions Issue - Final Analysis

## Проблема
Unicorn 2.1.4 не корректно обрабатывает REP префиксы (STOSB, MOVSB, etc.) когда установлен `UC_HOOK_CODE`:
- Hook вызывается на каждой итерации REP (518 раз для RCX=0x206)
- Это не баг - это особенность архитектуры QEMU TCG
- RCX корректно декрементируется, но hook вызывается слишком часто

## Попытки решения

### 1. Python Hotfix (`src/core/unicorn_rep_fix.py`)
**Статус**: ❌ Не работает
**Причина**: Hook вызывается ПОСЛЕ выполнения инструкции, невозможно перехватить ДО

### 2. Патч Unicorn C код - `repz_opt = 1`
**Статус**: ❌ Не работает  
**Файл**: `unicorn-source/qemu/target/i386/translate.c:9328`
**Причина**: `repz_opt = 1` добавляет оптимизацию выхода из цикла, но не убирает сам цикл

### 3. Патч Unicorn C код - `repz_opt = 0`
**Статус**: ❌ Не работает
**Причина**: `gen_jmp(s, cur_eip)` всё равно генерирует прыжок обратно

### 4. Глубокий патч QEMU TCG
**Статус**: ⚠️ Возможно, но очень сложно
**Требуется**: Переписать `gen_repz_stos` для атомарного выполнения через helper function
**Проблема**: Требует глубокого понимания QEMU TCG архитектуры

## ✅ Рабочее решение

### Компиляция без CRT (`/NODEFAULTLIB`)
**Статус**: ✅ Работает идеально!

**Пример**: `demos/simple_sysinfo_nocrt.c`
- Использует только Windows API напрямую
- Нет CRT инициализации с REP STOSB
- Полностью эмулируется: 2,626 инструкций
- Exit code: 0

**Результат**:
```
=================================================
Simple System Information Tool (No CRT)
=================================================

Hardware Information:
---------------------
  Number of processors: 8
  Page size: 4096 bytes
  Processor architecture: x64 (AMD or Intel)

Processor Features:
-------------------
  [+] MMX instructions
  [+] SSE instructions
  [+] SSE2 instructions
  [+] SSE3 instructions
  [+] RDTSC instruction

Total: 5 features supported
=================================================
```

## Выводы для DRM анализа

1. **Для тестовых программ**: Компилировать без CRT
2. **Для реальных DRM-защищённых программ**: 
   - Использовать другой эмулятор (Qiling, Speakeasy)
   - Или патчить Unicorn на уровне QEMU TCG (сложно)
   - Или принять что hook вызывается часто (не критично для анализа)

3. **Hybrid Passthrough работает**: GetSystemInfo, IsProcessorFeaturePresent возвращают реальные данные системы

## Файлы

- `src/core/unicorn_rep_fix.py` - Python hotfix (не работает, но оставлен для reference)
- `demos/simple_sysinfo_nocrt.c` - Рабочий пример без CRT
- `demos/test_nocrt_clean.py` - Тест с чистым выводом
- `test_unicorn_rep.py` - Тест для проверки REP инструкций
- `unicorn-source/` - Исходники Unicorn с попытками патча

## Статистика

- **С CRT**: Зависает на REP STOSB (518 итераций hook)
- **Без CRT**: ✅ 2,626 инструкций, работает идеально
- **Hybrid passthrough**: ✅ Реальные данные CPU через GetSystemInfo
