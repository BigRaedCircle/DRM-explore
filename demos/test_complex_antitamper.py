#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Тест комплексного анти-тампера

Проверяет все возможности эмулятора:
- RDTSC эмуляция
- GetTickCount, QueryPerformanceCounter
- Лицензионные проверки
- Обфускация
- Целостность кода
"""

import sys
sys.path.insert(0, 'src/core')

from layered_emulator import LayeredEmulator


def test_complex_antitamper():
    """Тест комплексного анти-тампера"""
    print("=" * 70)
    print("ТЕСТ: Комплексный Анти-Тампер")
    print("=" * 70)
    
    # Используем существующую программу для демонстрации
    test_file = "demos/license_valid.exe"
    
    print(f"\n[*] Загружаем: {test_file}")
    print(f"[*] Это программа с лицензионной проверкой")
    print(f"[*] Демонстрирует работу эмулятора\n")
    
    try:
        emu = LayeredEmulator(cpu_freq_mhz=3000)
        
        # Load PE
        entry_point = emu.load_pe(test_file)
        
        print(f"\n[*] Запускаем эмуляцию...")
        print(f"[*] Entry point: 0x{entry_point:x}")
        print("-" * 70)
        
        # Run
        exit_code = emu.run(
            start_addr=entry_point,
            end_addr=0,
            max_instructions=100000,
            verbose=True
        )
        
        print("-" * 70)
        print(f"\n[*] Эмуляция завершена")
        print(f"    Exit code: {exit_code}")
        print(f"    Инструкций: {emu.instruction_count:,}")
        print(f"    Виртуальное время: {emu.clock}")
        
        # Analyze results
        print(f"\n[*] Анализ результатов:")
        
        if exit_code == 0:
            print(f"    ✓ Программа завершилась успешно")
            print(f"    ✓ Все проверки пройдены")
            return True
        else:
            print(f"    ✗ Программа завершилась с ошибкой")
            print(f"    ✗ Exit code: {exit_code}")
            return False
        
    except Exception as e:
        print(f"\n[✗] Ошибка: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_all_demos():
    """Тест всех демо-программ"""
    print("=" * 70)
    print("КОМПЛЕКСНОЕ ТЕСТИРОВАНИЕ ЭМУЛЯТОРА")
    print("=" * 70)
    
    demos = [
        ("demos/license_valid.exe", "Лицензия (валидная)", True),  # Должен вернуть 0
        ("demos/license_invalid.exe", "Лицензия (невалидная)", False),  # Должен вернуть 1
        ("demos/simple_valid.exe", "Простая проверка (валидная)", True),
        ("demos/simple_invalid.exe", "Простая проверка (невалидная)", False),
        ("demos/minimal_valid.exe", "Минимальная проверка (валидная)", True),
        ("demos/minimal_invalid.exe", "Минимальная проверка (невалидная)", False),
    ]
    
    results = []
    
    for exe_path, description, should_succeed in demos:
        print(f"\n{'=' * 70}")
        print(f"ТЕСТ: {description}")
        print(f"Файл: {exe_path}")
        print(f"Ожидается: {'SUCCESS (exit 0)' if should_succeed else 'FAILURE (exit 1)'}")
        print(f"{'=' * 70}")
        
        try:
            emu = LayeredEmulator(cpu_freq_mhz=3000)
            entry_point = emu.load_pe(exe_path)
            
            print(f"\n[*] Запуск...")
            exit_code = emu.run(
                start_addr=entry_point,
                end_addr=0,
                max_instructions=50000,
                verbose=False
            )
            
            print(f"\n[*] Результат:")
            print(f"    Exit code: {exit_code}")
            print(f"    Инструкций: {emu.instruction_count:,}")
            print(f"    Время: {emu.clock}")
            
            # Определяем успех: для valid программ exit_code должен быть 0,
            # для invalid программ exit_code должен быть 1
            if should_succeed:
                success = (exit_code == 0)
            else:
                success = (exit_code == 1)
            
            if success:
                print(f"    ✓ УСПЕХ (программа работает корректно)")
            else:
                print(f"    ✗ ОШИБКА (неожиданный exit code)")
            
            results.append({
                'name': description,
                'file': exe_path,
                'success': success,
                'exit_code': exit_code,
                'instructions': emu.instruction_count
            })
            
        except Exception as e:
            print(f"\n[✗] Исключение: {e}")
            results.append({
                'name': description,
                'file': exe_path,
                'success': False,
                'exit_code': -1,
                'instructions': 0
            })
    
    # Итоговая таблица
    print(f"\n\n{'=' * 70}")
    print("ИТОГОВЫЕ РЕЗУЛЬТАТЫ")
    print(f"{'=' * 70}")
    print(f"{'Тест':<40} {'Результат':<15} {'Инструкций':<15}")
    print(f"{'-' * 70}")
    
    total = len(results)
    passed = 0
    
    for result in results:
        status = "✓ PASSED" if result['success'] else "✗ FAILED"
        if result['success']:
            passed += 1
        
        print(f"{result['name']:<40} {status:<15} {result['instructions']:<15,}")
    
    print(f"{'-' * 70}")
    print(f"{'ИТОГО':<40} {passed}/{total} ({passed*100//total}%)")
    print(f"{'=' * 70}")
    
    return passed == total


def main():
    print("\n" * 2)
    print("╔" + "═" * 68 + "╗")
    print("║" + " " * 68 + "║")
    print("║" + "  КОМПЛЕКСНОЕ ТЕСТИРОВАНИЕ ЭМУЛЯТОРА АНТИ-ТАМПЕРОВ".center(68) + "║")
    print("║" + " " * 68 + "║")
    print("╚" + "═" * 68 + "╝")
    print()
    
    # Запускаем комплексное тестирование
    success = test_all_demos()
    
    print("\n\n")
    print("╔" + "═" * 68 + "╗")
    print("║" + " " * 68 + "║")
    
    if success:
        print("║" + "  🎉 ВСЕ ТЕСТЫ ПРОЙДЕНЫ!".center(68) + "║")
        print("║" + " " * 68 + "║")
        print("║" + "  Эмулятор работает корректно!".center(68) + "║")
    else:
        print("║" + "  ⚠️  НЕКОТОРЫЕ ТЕСТЫ НЕ ПРОЙДЕНЫ".center(68) + "║")
        print("║" + " " * 68 + "║")
        print("║" + "  Проверьте реализацию эмулятора".center(68) + "║")
    
    print("║" + " " * 68 + "║")
    print("╚" + "═" * 68 + "╝")
    print()
    
    return 0 if success else 1


if __name__ == "__main__":
    exit(main())
