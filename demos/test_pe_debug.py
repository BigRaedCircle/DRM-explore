#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Тест: Отладка загрузки PE с детальным логированием
"""

import sys
sys.path.insert(0, 'src/core')

from layered_emulator import LayeredEmulator
from unicorn import UcError


def test_pe_debug():
    """Тест с детальной отладкой"""
    print("=" * 70)
    print("ОТЛАДКА: Загрузка PE с детальным логированием")
    print("=" * 70)
    print()
    
    # Создаём эмулятор
    emu = LayeredEmulator(cpu_freq_mhz=3000)
    
    # Загружаем PE
    pe_path = "demos/time_check_demo.exe"
    try:
        entry_point = emu.load_pe(pe_path)
    except Exception as e:
        print(f"\n[!] Ошибка загрузки: {e}")
        import traceback
        traceback.print_exc()
        return False
    
    # Добавляем хук для отладки каждой инструкции
    instruction_log = []
    
    def debug_hook(uc, address, size, user_data):
        # Логируем первые 20 инструкций
        if len(instruction_log) < 20:
            try:
                code = uc.mem_read(address, min(size, 15))
                rip = uc.reg_read(0x21)  # UC_X86_REG_RIP
                rsp = uc.reg_read(0x2c)  # UC_X86_REG_RSP
                rax = uc.reg_read(0x23)  # UC_X86_REG_RAX
                
                instruction_log.append({
                    'addr': address,
                    'code': code.hex(),
                    'rip': rip,
                    'rsp': rsp,
                    'rax': rax
                })
                
                print(f"[{len(instruction_log):3d}] RIP=0x{rip:016x} RSP=0x{rsp:016x} RAX=0x{rax:016x} CODE={code[:8].hex()}")
            except:
                pass
    
    from unicorn import UC_HOOK_CODE
    emu.uc.hook_add(UC_HOOK_CODE, debug_hook)
    
    # Запускаем
    print(f"\n[*] Запуск с entry point: 0x{entry_point:x}")
    print("-" * 70)
    
    try:
        emu.uc.reg_write(0x21, entry_point)  # UC_X86_REG_RIP
        emu.uc.emu_start(entry_point, 0, count=100)
        print("\n[OK] Эмуляция завершена успешно")
        return True
    except UcError as e:
        print(f"\n[!] Ошибка: {e}")
        print(f"[!] RIP: 0x{emu.uc.reg_read(0x21):x}")
        print(f"[!] Всего инструкций: {len(instruction_log)}")
        
        # Показываем последние 5 инструкций
        if instruction_log:
            print("\n[*] Последние инструкции:")
            for entry in instruction_log[-5:]:
                print(f"    0x{entry['addr']:016x}: {entry['code']}")
        
        return False


if __name__ == "__main__":
    success = test_pe_debug()
    sys.exit(0 if success else 1)
