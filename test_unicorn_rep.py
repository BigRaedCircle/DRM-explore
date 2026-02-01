#!/usr/bin/env python3
"""
Простой тест для проверки работы REP STOSB в Unicorn
"""

from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_HOOK_CODE
from unicorn.x86_const import *
import unicorn

print(f"Unicorn version: {unicorn.__version__}")
print(f"Unicorn location: {unicorn.__file__}")

# Создаём эмулятор
uc = Uc(UC_ARCH_X86, UC_MODE_64)

# Выделяем память
CODE_ADDR = 0x1000
CODE_SIZE = 0x1000
STACK_ADDR = 0x10000
STACK_SIZE = 0x10000
DATA_ADDR = 0x20000
DATA_SIZE = 0x10000

uc.mem_map(CODE_ADDR, CODE_SIZE)
uc.mem_map(STACK_ADDR, STACK_SIZE)
uc.mem_map(DATA_ADDR, DATA_SIZE)

# Код: REP STOSB
# F3 AA = rep stosb byte ptr [rdi], al
code = b'\xF3\xAA'  # rep stosb
uc.mem_write(CODE_ADDR, code)

# Настраиваем регистры
uc.reg_write(UC_X86_REG_RCX, 0x206)  # Повторить 518 раз (как в simple_sysinfo)
uc.reg_write(UC_X86_REG_RDI, DATA_ADDR)  # Адрес назначения
uc.reg_write(UC_X86_REG_RAX, 0x00)  # Байт для записи (0x00 = обнуление)
uc.reg_write(UC_X86_REG_RSP, STACK_ADDR + STACK_SIZE - 0x100)

# Счётчик инструкций
instruction_count = [0]
last_rip = [0]

def hook_code(uc, address, size, user_data):
    instruction_count[0] += 1
    last_rip[0] = address
    
    # Если больше 1000 инструкций на одном адресе - это зацикливание
    if instruction_count[0] > 1000:
        print(f"[!] INFINITE LOOP DETECTED!")
        print(f"    Stuck at address: 0x{address:x}")
        print(f"    Instructions executed: {instruction_count[0]}")
        rcx = uc.reg_read(UC_X86_REG_RCX)
        print(f"    RCX = 0x{rcx:x} (should decrement to 0)")
        uc.emu_stop()

# Устанавливаем hook
uc.hook_add(UC_HOOK_CODE, hook_code)

print("\n[*] Testing REP STOSB with UC_HOOK_CODE...")
print(f"    RCX = 0x206 (518 bytes - same as simple_sysinfo)")
print(f"    RDI = 0x{DATA_ADDR:x} (destination)")
print(f"    AL = 0x00 (byte to write)")
print(f"    This will detect infinite loop if patch is NOT applied")

try:
    # Запускаем эмуляцию
    uc.emu_start(CODE_ADDR, CODE_ADDR + len(code), count=10000)
    
    # Проверяем результат
    rcx_after = uc.reg_read(UC_X86_REG_RCX)
    rdi_after = uc.reg_read(UC_X86_REG_RDI)
    
    print(f"\n[*] Emulation finished!")
    print(f"    Instructions executed: {instruction_count[0]}")
    print(f"    RCX after: {rcx_after} (should be 0)")
    print(f"    RDI after: 0x{rdi_after:x} (should be 0x{DATA_ADDR + 0x206:x})")
    
    # Читаем первые 10 байт
    data = uc.mem_read(DATA_ADDR, 10)
    print(f"    First 10 bytes: {data.hex()} (should be all zeros)")
    
    if instruction_count[0] > 1000:
        print("\n[FAIL] Infinite loop detected! Patch is NOT applied.")
        print("       Unicorn is calling hook on every REP iteration.")
    elif rcx_after == 0 and instruction_count[0] < 100:
        print("\n[SUCCESS] REP STOSB works correctly! Patch IS applied.")
        print(f"          Only {instruction_count[0]} instructions executed (atomic REP)")
    else:
        print("\n[UNKNOWN] Unexpected behavior.")
        
except Exception as e:
    print(f"\n[ERROR] Emulation failed: {e}")
    print(f"    Instructions executed before error: {instruction_count[0]}")
    
    if instruction_count[0] > 1000:
        print("\n[FAIL] Infinite loop detected! Patch is NOT applied.")
    else:
        print("\n[FAIL] Other error occurred.")
