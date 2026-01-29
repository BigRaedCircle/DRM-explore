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
    """Test PE file execution"""
    print("=" * 70)
    print("TEST: Running PE file in layered emulation")
    print("=" * 70)
    print()
    
    # Create emulator
    print("[*] Initializing layered emulator...")
    emu = LayeredEmulator(cpu_freq_mhz=3000)
    
    # Load PE
    pe_path = "demos/time_check_demo.exe"
    try:
        entry_point = emu.load_pe(pe_path)
    except FileNotFoundError:
        print(f"\n[!] File {pe_path} not found")
        print("[!] Compile first: gcc -O2 demos/time_check_demo.c -o demos/time_check_demo.exe")
        return False
    except Exception as e:
        print(f"\n[!] PE loading error: {e}")
        return False
    
    # Run
    print("\n[*] Starting emulation...")
    exit_code = emu.run(entry_point)
    
    print(f"\n[*] Exit code: {exit_code}")
    
    if exit_code == 0:
        print("\n[OK] SUCCESS! PE file executed successfully")
        print("[OK] Anti-tamper did NOT detect emulation")
        return True
    elif exit_code == 1:
        print("\n[!] Anti-tamper detected emulation")
        return False
    elif exit_code == 2:
        print("\n[!] Invalid license (expected - no key passed)")
        return True  # This is normal for test
    else:
        print(f"\n[?] Unexpected exit code: {exit_code}")
        return False


if __name__ == "__main__":
    success = test_pe_emulation()
    sys.exit(0 if success else 1)
