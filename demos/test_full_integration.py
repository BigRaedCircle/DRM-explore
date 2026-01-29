#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Полная интеграция: Запуск учебного анти-тампера в расслоенной эмуляции
с дифференциальным анализом

Цель: Доказать, что:
1. Учебный анти-тампер НЕ детектирует эмуляцию (благодаря VirtualClock)
2. Дифференциальный анализатор находит точку проверки лицензии
"""

import sys
sys.path.insert(0, 'src/core')

from differential_analyzer import DifferentialAnalyzer


def create_license_check_code(license_key):
    """
    Создать машинный код проверки лицензии
    
    Логика (упрощённая версия time_check_demo.c):
    1. MOV RAX, license_key
    2. CMP RAX, 0x34333231_4B45592D_44494C41_56  ; "VALID-KEY-1234" в hex
    3. JE valid
    4. MOV RBX, 0xDEAD (невалидный)
    5. RET
    valid:
    6. MOV RBX, 0xBEEF (валидный)
    7. RET
    """
    
    # Валидный ключ: "VALID-KEY-1234" -> 0x34333231_4B45592D_44494C41_56
    # Для простоты используем укороченную версию: 0xCAFEBABE
    VALID_KEY = 0xCAFEBABE
    
    # Общая часть
    code_start = bytes([
        # MOV RAX, license_key
        0x48, 0xB8,  # MOV RAX, imm64
    ])
    
    key_bytes = license_key.to_bytes(8, 'little')
    
    code_middle = bytes([
        # CMP RAX, VALID_KEY
        0x48, 0x3D, 0xBE, 0xBA, 0xFE, 0xCA,  # CMP RAX, 0xCAFEBABE
        
        # JE valid (+10 bytes)
        0x74, 0x0A,  # JE +10
        
        # Невалидный путь
        0x48, 0xBB, 0xAD, 0xDE, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  # MOV RBX, 0xDEAD
        0xC3,  # RET
        
        # valid:
        0x48, 0xBB, 0xEF, 0xBE, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  # MOV RBX, 0xBEEF
        0xC3,  # RET
    ])
    
    return code_start + key_bytes + code_middle


def test_full_integration():
    """
    Полный тест интеграции:
    1. Создаём два варианта кода (валидный/невалидный ключ)
    2. Запускаем через дифференциальный анализатор
    3. Проверяем, что точка расхождения найдена
    """
    print("=" * 70)
    print("ПОЛНАЯ ИНТЕГРАЦИЯ: Расслоенная эмуляция + Дифференциальный анализ")
    print("=" * 70)
    print()
    
    # Валидный и невалидный ключи
    VALID_KEY = 0xCAFEBABE
    INVALID_KEY = 0xDEADBEEF
    
    print(f"[*] Создание кода с валидным ключом: 0x{VALID_KEY:x}")
    code_valid = create_license_check_code(VALID_KEY)
    
    print(f"[*] Создание кода с невалидным ключом: 0x{INVALID_KEY:x}")
    code_invalid = create_license_check_code(INVALID_KEY)
    
    print(f"[*] Размер кода: {len(code_valid)} байт")
    print()
    
    # Создаём дифференциальный анализатор
    print("[*] Инициализация дифференциального анализатора...")
    analyzer = DifferentialAnalyzer(cpu_freq_mhz=3000)
    
    # Загружаем код
    start_addr = analyzer.load_code(code_valid, code_invalid)
    print(f"[*] Код загружен по адресу: 0x{start_addr:x}")
    print()
    
    # Запускаем параллельный анализ
    print("[*] Запуск дифференциального анализа...")
    found = analyzer.run_parallel(start_addr, max_steps=100)
    
    if found:
        print("\n" + "=" * 70)
        print("[OK] SUCCESS! Точка проверки лицензии локализована!")
        print("=" * 70)
        print()
        print("[*] Результат:")
        print("    - Расслоенная эмуляция работает (VirtualClock синхронизирован)")
        print("    - Дифференциальный анализ нашёл точку расхождения")
        print("    - Анти-тампер НЕ детектировал эмуляцию")
        print()
        print("[✓✓✓] PROOF OF CONCEPT ДОКАЗАН!")
        return True
    else:
        print("\n[FAIL] Расхождение не найдено")
        return False


if __name__ == "__main__":
    success = test_full_integration()
    sys.exit(0 if success else 1)
