#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Запуск учебного анти-тампера в расслоенном эмуляторе

Демонстрирует ключевую идею: анти-тампер НЕ детектирует эмуляцию,
потому что все таймеры синхронизированы через VirtualClock.
"""

import sys
import os
sys.path.insert(0, 'src/core')

from simple_emulator import SimpleEmulator
from pe_loader import PELoader


def run_in_emulator(exe_path, license_key="VALID-KEY-1234"):
    """Запустить EXE в эмуляторе"""
    
    print("=" * 70)
    print("ЗАПУСК В РАССЛОЕННОМ ЭМУЛЯТОРЕ")
    print("=" * 70)
    print(f"\nФайл: {exe_path}")
    print(f"Ключ: {license_key}\n")
    
    # Создаём эмулятор
    emu = SimpleEmulator(cpu_freq_mhz=3000)
    
    # Загружаем PE
    loader = PELoader(emu)
    entry_point = loader.load(exe_path)
    
    # TODO: Передать аргументы командной строки (license_key)
    # Пока просто запускаем
    
    print("[*] Запуск эмуляции...")
    print("-" * 70)
    
    try:
        # Запускаем с таймаутом (чтобы не зависнуть)
        emu.run(entry_point, 0, timeout=10_000_000)  # 10 млн микросекунд = 10 сек
        
        print("-" * 70)
        print("\n[OK] Эмуляция завершена успешно!")
        
        # Проверяем exit code
        rax = emu.get_register(emu.uc.x86_const.UC_X86_REG_RAX)
        print(f"[*] Exit code: {rax}")
        
        return rax
        
    except KeyboardInterrupt:
        print("\n[!] Прервано пользователем")
        return -1
    except Exception as e:
        print(f"\n[!] Ошибка эмуляции: {e}")
        import traceback
        traceback.print_exc()
        return -1


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Использование: python run_in_emulator.py <файл.exe> [ключ]")
        print("\nПример:")
        print("  python run_in_emulator.py demos/time_check_demo.exe VALID-KEY-1234")
        sys.exit(1)
    
    exe_path = sys.argv[1]
    license_key = sys.argv[2] if len(sys.argv) > 2 else "VALID-KEY-1234"
    
    if not os.path.exists(exe_path):
        print(f"[!] Файл не найден: {exe_path}")
        sys.exit(1)
    
    exit_code = run_in_emulator(exe_path, license_key)
    sys.exit(exit_code if exit_code >= 0 else 1)
