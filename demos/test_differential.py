#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Тест дифференциального анализатора

Создаёт два варианта кода:
- Вариант A: валидный ключ (0xCAFE)
- Вариант B: невалидный ключ (0xDEAD)

Анализатор должен автоматически найти точку проверки.
"""

import sys
sys.path.insert(0, 'src/core')

from differential_analyzer import DifferentialAnalyzer


def create_protected_code(license_key):
    """
    Создать защищённый код с проверкой лицензии
    
    Логика:
    1. MOV RAX, license_key
    2. CMP RAX, 0xCAFE (валидный ключ)
    3. JE valid
    4. MOV RBX, 0xDEAD (невалидный)
    5. RET
    valid:
    6. MOV RBX, 0xBEEF (валидный)
    7. RET
    """
    
    # Общая часть (одинаковая для обоих)
    common_start = bytes([
        # MOV RAX, license_key (будет заменено)
        0x48, 0xB8,  # MOV RAX, imm64
    ])
    
    key_bytes = license_key.to_bytes(8, 'little')
    
    common_middle = bytes([
        # CMP RAX, 0xCAFE (валидный ключ)
        0x48, 0x3D, 0xFE, 0xCA, 0x00, 0x00,  # CMP RAX, 0xCAFE
        
        # JE valid (+7 bytes)
        0x74, 0x0A,  # JE +10
        
        # Невалидный путь
        0x48, 0xBB, 0xAD, 0xDE, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  # MOV RBX, 0xDEAD
        0xC3,  # RET
        
        # valid:
        0x48, 0xBB, 0xEF, 0xBE, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  # MOV RBX, 0xBEEF
        0xC3,  # RET
    ])
    
    return common_start + key_bytes + common_middle


def test_differential_analysis():
    """Тест дифференциального анализа"""
    print("=" * 70)
    print("ТЕСТ: Дифференциальный анализ проверки лицензии")
    print("=" * 70)
    print()
    
    # Создаём два варианта кода
    VALID_KEY = 0xCAFE
    INVALID_KEY = 0xDEAD
    
    code_valid = create_protected_code(VALID_KEY)
    code_invalid = create_protected_code(INVALID_KEY)
    
    print(f"[*] Создан код с валидным ключом: 0x{VALID_KEY:x}")
    print(f"[*] Создан код с невалидным ключом: 0x{INVALID_KEY:x}")
    print(f"[*] Размер кода: {len(code_valid)} байт")
    print()
    
    # Создаём анализатор
    analyzer = DifferentialAnalyzer(cpu_freq_mhz=3000)
    
    # Загружаем код
    start_addr = analyzer.load_code(code_valid, code_invalid)
    
    # Запускаем параллельный анализ
    found = analyzer.run_parallel(start_addr, max_steps=100)
    
    if found:
        print("\n" + "=" * 70)
        print("[OK] SUCCESS! Проверка лицензии локализована автоматически!")
        print("=" * 70)
        return True
    else:
        print("\n[FAIL] Расхождение не найдено")
        return False


if __name__ == "__main__":
    success = test_differential_analysis()
    sys.exit(0 if success else 1)
