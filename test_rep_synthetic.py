#!/usr/bin/env python3
"""
Синтетические тесты для проверки Python REP hotfix
"""

import sys
sys.path.insert(0, 'src/core')

from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_HOOK_CODE
from unicorn.x86_const import *
from unicorn_rep_fix import UnicornRepFix


def test_rep_stosb_simple():
    """Тест 1: Простой REP STOSB с малым RCX"""
    print("=" * 70)
    print("TEST 1: REP STOSB (RCX=10)")
    print("=" * 70)
    
    uc = Uc(UC_ARCH_X86, UC_MODE_64)
    rep_fix = UnicornRepFix(uc)
    rep_fix.verbose = True
    
    # Память
    CODE_ADDR = 0x1000
    DATA_ADDR = 0x20000
    STACK_ADDR = 0x10000
    
    uc.mem_map(CODE_ADDR, 0x1000)
    uc.mem_map(DATA_ADDR, 0x10000)
    uc.mem_map(STACK_ADDR, 0x10000)
    
    # Код: REP STOSB + RET
    code = b'\xF3\xAA'  # rep stosb
    code += b'\xC3'     # ret
    uc.mem_write(CODE_ADDR, code)
    
    # Регистры
    uc.reg_write(UC_X86_REG_RCX, 10)
    uc.reg_write(UC_X86_REG_RDI, DATA_ADDR)
    uc.reg_write(UC_X86_REG_RAX, 0x42)
    uc.reg_write(UC_X86_REG_RSP, STACK_ADDR + 0x1000)
    
    # Счётчик
    stats = {'instructions': 0, 'rep_handled': 0}
    
    def hook_code(uc, address, size, user_data):
        stats['instructions'] += 1
        
        # Проверяем REP инструкцию (hotfix заменит на NOP)
        rep_fix.check_and_handle_rep(address)
    
    uc.hook_add(UC_HOOK_CODE, hook_code)
    
    # Запуск (один раз, без перезапусков)
    try:
        uc.emu_start(CODE_ADDR, CODE_ADDR + len(code), count=1000)
        
        # Проверка результата
        rcx = uc.reg_read(UC_X86_REG_RCX)
        rdi = uc.reg_read(UC_X86_REG_RDI)
        data = uc.mem_read(DATA_ADDR, 10)
        
        print(f"\n[*] Results:")
        print(f"    Instructions: {stats['instructions']}")
        print(f"    REP handled: {stats['rep_handled']}")
        print(f"    RCX after: {rcx} (expected: 0)")
        print(f"    RDI after: 0x{rdi:x} (expected: 0x{DATA_ADDR + 10:x})")
        print(f"    Data: {data.hex()} (expected: 42 * 10)")
        
        if rcx == 0 and data == b'\x42' * 10 and stats['instructions'] < 20:
            print("\n[SUCCESS] REP STOSB hotfix works!")
            return True
        else:
            print("\n[FAIL] REP STOSB hotfix doesn't work")
            return False
            
    except Exception as e:
        print(f"\n[ERROR] {e}")
        import traceback
        traceback.print_exc()
        return False


def test_rep_stosb_large():
    """Тест 2: REP STOSB с большим RCX (как в CRT)"""
    print("\n" + "=" * 70)
    print("TEST 2: REP STOSB (RCX=0x206, like CRT init)")
    print("=" * 70)
    
    uc = Uc(UC_ARCH_X86, UC_MODE_64)
    rep_fix = UnicornRepFix(uc)
    
    # Память
    CODE_ADDR = 0x1000
    DATA_ADDR = 0x20000
    STACK_ADDR = 0x10000
    
    uc.mem_map(CODE_ADDR, 0x1000)
    uc.mem_map(DATA_ADDR, 0x10000)
    uc.mem_map(STACK_ADDR, 0x10000)
    
    # Код: REP STOSB + RET
    code = b'\xF3\xAA\xC3'
    uc.mem_write(CODE_ADDR, code)
    
    # Регистры
    uc.reg_write(UC_X86_REG_RCX, 0x206)  # 518 bytes
    uc.reg_write(UC_X86_REG_RDI, DATA_ADDR)
    uc.reg_write(UC_X86_REG_RAX, 0x00)
    uc.reg_write(UC_X86_REG_RSP, STACK_ADDR + 0x1000)
    
    # Счётчик
    stats = {'instructions': 0, 'rep_handled': 0}
    
    def hook_code(uc, address, size, user_data):
        stats['instructions'] += 1
        rep_fix.check_and_handle_rep(address)
    
    uc.hook_add(UC_HOOK_CODE, hook_code)
    
    # Запуск
    try:
        uc.emu_start(CODE_ADDR, CODE_ADDR + len(code), count=1000)
        
        # Проверка
        rcx = uc.reg_read(UC_X86_REG_RCX)
        rdi = uc.reg_read(UC_X86_REG_RDI)
        data = uc.mem_read(DATA_ADDR, 10)
        
        print(f"\n[*] Results:")
        print(f"    Instructions: {stats['instructions']}")
        print(f"    REP handled: {stats['rep_handled']}")
        print(f"    RCX after: {rcx} (expected: 0)")
        print(f"    RDI after: 0x{rdi:x} (expected: 0x{DATA_ADDR + 0x206:x})")
        print(f"    First 10 bytes: {data.hex()} (expected: all zeros)")
        
        if rcx == 0 and stats['instructions'] < 50:
            print("\n[SUCCESS] Large REP STOSB hotfix works!")
            return True
        else:
            print("\n[FAIL] Large REP STOSB hotfix doesn't work")
            return False
            
    except Exception as e:
        print(f"\n[ERROR] {e}")
        import traceback
        traceback.print_exc()
        return False


def test_rep_movsb():
    """Тест 3: REP MOVSB (копирование памяти)"""
    print("\n" + "=" * 70)
    print("TEST 3: REP MOVSB (memory copy)")
    print("=" * 70)
    
    uc = Uc(UC_ARCH_X86, UC_MODE_64)
    rep_fix = UnicornRepFix(uc)
    
    # Память
    CODE_ADDR = 0x1000
    SRC_ADDR = 0x20000
    DST_ADDR = 0x30000
    STACK_ADDR = 0x10000
    
    uc.mem_map(CODE_ADDR, 0x1000)
    uc.mem_map(SRC_ADDR, 0x10000)
    uc.mem_map(DST_ADDR, 0x10000)
    uc.mem_map(STACK_ADDR, 0x10000)
    
    # Исходные данные
    src_data = b'Hello, World!'
    uc.mem_write(SRC_ADDR, src_data)
    
    # Код: REP MOVSB + RET
    code = b'\xF3\xA4\xC3'  # rep movsb, ret
    uc.mem_write(CODE_ADDR, code)
    
    # Регистры
    uc.reg_write(UC_X86_REG_RCX, len(src_data))
    uc.reg_write(UC_X86_REG_RSI, SRC_ADDR)
    uc.reg_write(UC_X86_REG_RDI, DST_ADDR)
    uc.reg_write(UC_X86_REG_RSP, STACK_ADDR + 0x1000)
    
    # Счётчик
    stats = {'instructions': 0, 'rep_handled': 0}
    
    def hook_code(uc, address, size, user_data):
        stats['instructions'] += 1
        rep_fix.check_and_handle_rep(address)
    
    uc.hook_add(UC_HOOK_CODE, hook_code)
    
    # Запуск
    try:
        uc.emu_start(CODE_ADDR, CODE_ADDR + len(code), count=1000)
        
        # Проверка
        rcx = uc.reg_read(UC_X86_REG_RCX)
        dst_data = uc.mem_read(DST_ADDR, len(src_data))
        
        print(f"\n[*] Results:")
        print(f"    Instructions: {stats['instructions']}")
        print(f"    REP handled: {stats['rep_handled']}")
        print(f"    RCX after: {rcx} (expected: 0)")
        print(f"    Source: {src_data}")
        print(f"    Copied: {dst_data}")
        
        if rcx == 0 and dst_data == src_data and stats['instructions'] < 30:
            print("\n[SUCCESS] REP MOVSB hotfix works!")
            return True
        else:
            print("\n[FAIL] REP MOVSB hotfix doesn't work")
            return False
            
    except Exception as e:
        print(f"\n[ERROR] {e}")
        import traceback
        traceback.print_exc()
        return False


if __name__ == '__main__':
    print("\n")
    print("=" * 70)
    print(" " * 15 + "Unicorn REP Hotfix - Synthetic Tests")
    print("=" * 70)
    print()
    
    results = []
    
    results.append(("REP STOSB (small)", test_rep_stosb_simple()))
    results.append(("REP STOSB (large)", test_rep_stosb_large()))
    results.append(("REP MOVSB", test_rep_movsb()))
    
    print("\n")
    print("=" * 70)
    print("SUMMARY")
    print("=" * 70)
    
    for name, result in results:
        status = "✓ PASS" if result else "✗ FAIL"
        print(f"  {status}  {name}")
    
    all_passed = all(r[1] for r in results)
    
    print()
    if all_passed:
        print("=" * 70)
        print("ALL TESTS PASSED!")
        print("=" * 70)
    else:
        print("=" * 70)
        print("SOME TESTS FAILED")
        print("=" * 70)
    print()
