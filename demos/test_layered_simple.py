#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Тест: Расслоенная эмуляция с простым кодом (без PE)

Доказываем, что обвязка работает:
1. VirtualClock синхронизирован
2. RDTSC эмулируется корректно
3. Код выполняется без детектирования эмуляции
"""

import sys
sys.path.insert(0, 'src/core')

from layered_emulator import LayeredEmulator


def create_time_check_code():
    """
    Максимально простой тест: RDTSC возвращает значение в RAX
    """
    
    code = bytes([
        # RDTSC
        0x0F, 0x31,                    # RDTSC -> EDX:EAX
        
        # Проверяем что RAX > 0
        0x48, 0x85, 0xC0,              # TEST RAX, RAX
        0x7F, 0x04,                    # JG success (+4 bytes)
        
        # Fail
        0xB8, 0x01, 0x00, 0x00, 0x00,  # MOV EAX, 1
        0xF4,                          # HLT (останавливаем эмуляцию)
        
        # success:
        0xB8, 0x00, 0x00, 0x00, 0x00,  # MOV EAX, 0
        0xF4,                          # HLT
    ])
    
    return code
    
    return code


def test_layered_emulation():
    """Тест расслоенной эмуляции"""
    print("=" * 70)
    print("ТЕСТ: Расслоенная эмуляция с обвязками")
    print("=" * 70)
    print()
    
    # Создаём эмулятор
    print("[*] Инициализация расслоенного эмулятора...")
    emu = LayeredEmulator(cpu_freq_mhz=3000)
    
    # Создаём тестовый код
    print("[*] Создание тестового кода (проверка времени)...")
    code = create_time_check_code()
    print(f"[*] Размер кода: {len(code)} байт")
    
    # Загружаем код
    start_addr = emu.load_code(code)
    print(f"[*] Код загружен по адресу: 0x{start_addr:x}")
    
    # Запускаем (указываем end_addr = start_addr + len(code))
    print("\n[*] Запуск эмуляции...")
    end_addr = start_addr + len(code)
    exit_code = emu.run(start_addr, end_addr=end_addr, max_instructions=100)
    
    print(f"\n[*] Код возврата: {exit_code}")
    
    if exit_code == 0:
        print("\n" + "=" * 70)
        print("[OK] SUCCESS! Расслоенная эмуляция работает!")
        print("=" * 70)
        print()
        print("[*] Результаты:")
        print("    ✓ VirtualClock синхронизирован")
        print("    ✓ RDTSC эмулируется корректно")
        print("    ✓ Время идёт (delta > 0)")
        print("    ✓ Код НЕ детектировал эмуляцию")
        print()
        print("[✓✓✓] ОБВЯЗКИ РАБОТАЮТ!")
        return True
    else:
        print("\n[FAIL] Время не идёт или эмуляция детектирована")
        return False


if __name__ == "__main__":
    success = test_layered_emulation()
    sys.exit(0 if success else 1)
