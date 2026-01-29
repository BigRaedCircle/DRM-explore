#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Тест RDTSC в эмуляторе — минимальный proof of concept

Создаёт простой машинный код, который:
1. Вызывает RDTSC дважды
2. Проверяет что время идёт (t2 > t1)
3. Возвращает результат в RAX
"""

import sys
sys.path.insert(0, 'src/core')

from simple_emulator import SimpleEmulator
from unicorn.x86_const import *


def create_test_code():
    """Создать тестовый машинный код"""
    # Упрощённый тест:
    # RDTSC #1
    # Сохранить в RBX
    # Цикл
    # RDTSC #2
    # Вычесть RBX из RAX
    # RET (результат в RAX = delta)
    
    code = bytes([
        # RDTSC #1
        0x0F, 0x31,                          # RDTSC
        0x48, 0x89, 0xC3,                    # MOV RBX, RAX (сохраняем t1)
        
        # Цикл (1000 итераций)
        0x48, 0xC7, 0xC6, 0xE8, 0x03, 0x00, 0x00,  # MOV RSI, 1000
        # loop:
        0x48, 0xFF, 0xCE,                    # DEC RSI
        0x75, 0xFB,                          # JNZ loop
        
        # RDTSC #2
        0x0F, 0x31,                          # RDTSC
        
        # Вычисляем delta
        0x48, 0x29, 0xD8,                    # SUB RAX, RBX (delta = t2 - t1)
        
        # RET
        0xC3,                                # RET
    ])
    
    return code


def test_rdtsc_emulation():
    """Тест эмуляции RDTSC"""
    print("=" * 70)
    print("ТЕСТ: RDTSC в расслоенном эмуляторе")
    print("=" * 70)
    print()
    
    # Создаём эмулятор
    emu = SimpleEmulator(cpu_freq_mhz=3000)
    
    # Создаём тестовый код
    code = create_test_code()
    print(f"[*] Создан тестовый код: {len(code)} байт")
    print(f"[*] Код проверяет: RDTSC возвращает растущее время\n")
    
    # Загружаем код
    addr = emu.load_code(code)
    
    # Запускаем
    print("[*] Запуск эмуляции...")
    print("-" * 70)
    emu.run(addr, 0)
    print("-" * 70)
    
    # Проверяем результат
    result = emu.get_register(UC_X86_REG_RAX)
    
    print(f"\n[*] Результат: RAX = {result} (delta тактов)")
    
    if result > 0:
        print("[OK] SUCCESS! RDTSC работает корректно в эмуляторе")
        print(f"[OK] Время идёт: прошло {result} виртуальных тактов")
        print("[OK] VirtualClock интегрирован правильно!")
        return True
    else:
        print("[FAIL] Тест не прошёл: delta = 0, время не идёт")
        return False


if __name__ == "__main__":
    success = test_rdtsc_emulation()
    sys.exit(0 if success else 1)
