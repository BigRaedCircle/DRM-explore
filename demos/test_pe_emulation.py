#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Тест: Запуск реального PE-файла в расслоенной эмуляции

Цель: Запустить time_check_demo.exe и проверить, что:
1. Анти-тампер НЕ детектирует эмуляцию
2. Проверка лицензии работает корректно
"""

import sys
sys.path.insert(0, 'src/core')

from layered_emulator import LayeredEmulator


def test_pe_emulation():
    """Тест запуска PE-файла"""
    print("=" * 70)
    print("ТЕСТ: Запуск PE-файла в расслоенной эмуляции")
    print("=" * 70)
    print()
    
    # Создаём эмулятор
    print("[*] Инициализация расслоенного эмулятора...")
    emu = LayeredEmulator(cpu_freq_mhz=3000)
    
    # Загружаем PE
    pe_path = "demos/time_check_demo.exe"
    try:
        entry_point = emu.load_pe(pe_path)
    except FileNotFoundError:
        print(f"\n[!] Файл {pe_path} не найден")
        print("[!] Сначала скомпилируйте: gcc -O2 demos/time_check_demo.c -o demos/time_check_demo.exe")
        return False
    except Exception as e:
        print(f"\n[!] Ошибка загрузки PE: {e}")
        return False
    
    # Запускаем
    print("\n[*] Запуск эмуляции...")
    exit_code = emu.run(entry_point)
    
    print(f"\n[*] Код возврата: {exit_code}")
    
    if exit_code == 0:
        print("\n[OK] SUCCESS! PE-файл выполнен успешно")
        print("[OK] Анти-тампер НЕ детектировал эмуляцию")
        return True
    elif exit_code == 1:
        print("\n[!] Анти-тампер детектировал эмуляцию")
        return False
    elif exit_code == 2:
        print("\n[!] Невалидная лицензия (ожидаемо — не передали ключ)")
        return True  # Это нормально для теста
    else:
        print(f"\n[?] Неожиданный код возврата: {exit_code}")
        return False


if __name__ == "__main__":
    success = test_pe_emulation()
    sys.exit(0 if success else 1)
