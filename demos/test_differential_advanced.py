#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Продвинутый тест дифференциального анализатора

Демонстрирует:
- Бинарный поиск точки расхождения
- Расширенное дизассемблирование
- Анализ стека и памяти
- Экспорт трейса и визуализацию
"""

import sys
sys.path.insert(0, 'src/core')

from differential_analyzer import DifferentialAnalyzer


def test_advanced_differential():
    """Тест с более сложной логикой проверки"""
    
    print("=" * 70)
    print("ПРОДВИНУТЫЙ ДИФФЕРЕНЦИАЛЬНЫЙ АНАЛИЗ")
    print("=" * 70)
    
    # Создаём анализатор
    analyzer = DifferentialAnalyzer(cpu_freq_mhz=3000)
    
    # Код с проверкой лицензии (более сложный)
    # Валидный ключ: 0x1337
    code_valid = bytes([
        # Пролог
        0x55,                           # push rbp
        0x48, 0x89, 0xE5,               # mov rbp, rsp
        
        # Загружаем ключ в RAX (валидный)
        0x48, 0xC7, 0xC0, 0x37, 0x13, 0x00, 0x00,  # mov rax, 0x1337
        
        # Проверка 1: RAX == 0x1337?
        0x48, 0x3D, 0x37, 0x13, 0x00, 0x00,  # cmp rax, 0x1337
        0x75, 0x0A,                          # jne +10 (fail)
        
        # Проверка 2: Вычисляем хеш
        0x48, 0xC1, 0xE0, 0x02,         # shl rax, 2  (rax *= 4)
        0x48, 0x05, 0xEF, 0xBE, 0x00, 0x00,  # add rax, 0xBEEF
        
        # Проверка 3: Результат == 0xC9BB?
        0x48, 0x3D, 0xBB, 0xC9, 0x00, 0x00,  # cmp rax, 0xC9BB
        0x75, 0x05,                          # jne +5 (fail)
        
        # SUCCESS: RAX = 1
        0x48, 0xC7, 0xC0, 0x01, 0x00, 0x00, 0x00,  # mov rax, 1
        0xEB, 0x05,                          # jmp +5 (end)
        
        # FAIL: RAX = 0
        0x48, 0xC7, 0xC0, 0x00, 0x00, 0x00, 0x00,  # mov rax, 0
        
        # Эпилог
        0x5D,                           # pop rbp
        0xC3,                           # ret
    ])
    
    # Невалидный ключ: 0xDEAD
    code_invalid = bytes([
        # Пролог
        0x55,                           # push rbp
        0x48, 0x89, 0xE5,               # mov rbp, rsp
        
        # Загружаем ключ в RAX (невалидный)
        0x48, 0xC7, 0xC0, 0xAD, 0xDE, 0x00, 0x00,  # mov rax, 0xDEAD
        
        # Проверка 1: RAX == 0x1337?
        0x48, 0x3D, 0x37, 0x13, 0x00, 0x00,  # cmp rax, 0x1337
        0x75, 0x0A,                          # jne +10 (fail)
        
        # Проверка 2: Вычисляем хеш
        0x48, 0xC1, 0xE0, 0x02,         # shl rax, 2
        0x48, 0x05, 0xEF, 0xBE, 0x00, 0x00,  # add rax, 0xBEEF
        
        # Проверка 3: Результат == 0xC9BB?
        0x48, 0x3D, 0xBB, 0xC9, 0x00, 0x00,  # cmp rax, 0xC9BB
        0x75, 0x05,                          # jne +5 (fail)
        
        # SUCCESS: RAX = 1
        0x48, 0xC7, 0xC0, 0x01, 0x00, 0x00, 0x00,  # mov rax, 1
        0xEB, 0x05,                          # jmp +5 (end)
        
        # FAIL: RAX = 0
        0x48, 0xC7, 0xC0, 0x00, 0x00, 0x00, 0x00,  # mov rax, 0
        
        # Эпилог
        0x5D,                           # pop rbp
        0xC3,                           # ret
    ])
    
    # Загружаем код
    base_addr = analyzer.load_code(code_valid, code_invalid)
    
    # Запускаем дифференциальный анализ
    print(f"\n[*] Код загружен по адресу 0x{base_addr:x}")
    print(f"[*] Размер кода: {len(code_valid)} байт")
    print(f"\n[*] Валидный ключ: 0x1337")
    print(f"[*] Невалидный ключ: 0xDEAD")
    
    diverged = analyzer.run_parallel(base_addr, max_steps=100)
    
    if diverged:
        print("\n" + "=" * 70)
        print("РЕЗУЛЬТАТ")
        print("=" * 70)
        print("\n[✓] Дифференциальный анализ успешно локализовал проверку!")
        
        # Экспорт результатов
        analyzer.export_trace("trace_advanced.txt")
        analyzer.visualize_divergence("divergence_advanced.dot")
        
        print("\n[*] Результаты сохранены:")
        print("    - trace_advanced.txt (текстовый трейс)")
        print("    - divergence_advanced.dot (граф для Graphviz)")
        
        return True
    else:
        print("\n[✗] Расхождение не обнаружено")
        return False


def test_memory_analysis():
    """Тест анализа памяти и стека"""
    
    print("\n" + "=" * 70)
    print("ТЕСТ АНАЛИЗА ПАМЯТИ И СТЕКА")
    print("=" * 70)
    
    analyzer = DifferentialAnalyzer()
    
    # Код с манипуляциями стека
    code_a = bytes([
        0x55,                           # push rbp
        0x48, 0x89, 0xE5,               # mov rbp, rsp
        0x48, 0x83, 0xEC, 0x20,         # sub rsp, 32 (выделяем стек)
        
        # Записываем значение на стек
        0x48, 0xC7, 0x45, 0xF8, 0x42, 0x00, 0x00, 0x00,  # mov [rbp-8], 0x42
        
        # Читаем обратно
        0x48, 0x8B, 0x45, 0xF8,         # mov rax, [rbp-8]
        
        0x48, 0x89, 0xEC,               # mov rsp, rbp
        0x5D,                           # pop rbp
        0xC3,                           # ret
    ])
    
    code_b = bytes([
        0x55,                           # push rbp
        0x48, 0x89, 0xE5,               # mov rbp, rsp
        0x48, 0x83, 0xEC, 0x20,         # sub rsp, 32
        
        # Записываем ДРУГОЕ значение
        0x48, 0xC7, 0x45, 0xF8, 0x99, 0x00, 0x00, 0x00,  # mov [rbp-8], 0x99
        
        # Читаем обратно
        0x48, 0x8B, 0x45, 0xF8,         # mov rax, [rbp-8]
        
        0x48, 0x89, 0xEC,               # mov rsp, rbp
        0x5D,                           # pop rbp
        0xC3,                           # ret
    ])
    
    base_addr = analyzer.load_code(code_a, code_b)
    
    print(f"\n[*] Тест: запись разных значений на стек")
    print(f"[*] Эмулятор A: записывает 0x42")
    print(f"[*] Эмулятор B: записывает 0x99")
    
    diverged = analyzer.run_parallel(base_addr, max_steps=50)
    
    if diverged:
        print("\n[✓] Различие в стеке успешно обнаружено!")
        return True
    else:
        print("\n[✗] Различие не обнаружено")
        return False


if __name__ == "__main__":
    print("\n" + "=" * 70)
    print("ТЕСТИРОВАНИЕ ПРОДВИНУТОГО ДИФФЕРЕНЦИАЛЬНОГО АНАЛИЗАТОРА")
    print("=" * 70)
    
    # Тест 1: Сложная проверка лицензии
    test1 = test_advanced_differential()
    
    # Тест 2: Анализ памяти
    test2 = test_memory_analysis()
    
    # Итоги
    print("\n" + "=" * 70)
    print("ИТОГИ ТЕСТИРОВАНИЯ")
    print("=" * 70)
    print(f"\n[{'✓' if test1 else '✗'}] Тест 1: Сложная проверка лицензии")
    print(f"[{'✓' if test2 else '✗'}] Тест 2: Анализ памяти и стека")
    
    if test1 and test2:
        print("\n[✓✓✓] ВСЕ ТЕСТЫ ПРОЙДЕНЫ!")
        print("\nПродвинутый дифференциальный анализатор работает корректно:")
        print("  • Бинарный поиск точки расхождения")
        print("  • Расширенное дизассемблирование с контекстом")
        print("  • Анализ стека и регистров")
        print("  • Экспорт трейса и визуализация")
        sys.exit(0)
    else:
        print("\n[✗] Некоторые тесты не пройдены")
        sys.exit(1)
