#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Отладочный тест CPU-Z - детальное логирование выполнения
"""

import sys
import os
sys.path.insert(0, 'src/core')

from layered_emulator import LayeredEmulator
from unicorn import UcError


def test_cpuz_debug():
    """Отладочный запуск CPU-Z с детальным логированием"""
    print("=" * 70)
    print("ОТЛАДКА: CPU-Z выполнение")
    print("=" * 70)
    
    cpuz_path = "sandbox/CPU-Z/cpuz.exe"
    
    print(f"\n[*] Загружаем: {cpuz_path}")
    
    emu = LayeredEmulator(cpu_freq_mhz=3000)
    
    # Модифицируем GetCommandLineW
    def patched_get_command_line_w():
        cmd_line = "cpuz.exe -txt=report\x00".encode('utf-16le')
        ptr = emu.os.HeapAlloc(emu.os.heap.process_heap, 0, len(cmd_line))
        emu.uc.mem_write(ptr, cmd_line)
        emu.uc.reg_write(emu.uc.arch_const.UC_X86_REG_RAX, ptr)
        print(f"[API] GetCommandLineW() -> \"cpuz.exe -txt=report\"")
        return ptr
    
    emu.winapi._stub_get_command_line_w = patched_get_command_line_w
    
    # Загружаем PE
    entry_point = emu.load_pe(cpuz_path)
    
    print(f"\n[*] Начинаем эмуляцию с детальным логированием...")
    print(f"[*] Entry point: 0x{entry_point:x}")
    print("-" * 70)
    
    # Счётчик инструкций для отладки
    last_rip = 0
    instruction_limit = 10000
    
    try:
        # Запускаем с небольшим лимитом для отладки
        emu.run(
            start_addr=entry_point,
            end_addr=0,
            max_instructions=instruction_limit,
            verbose=True  # Включаем детальный вывод
        )
    except UcError as e:
        print(f"\n[!] Unicorn Error: {e}")
        rip = emu.uc.reg_read(emu.uc.arch_const.UC_X86_REG_RIP)
        rsp = emu.uc.reg_read(emu.uc.arch_const.UC_X86_REG_RSP)
        rax = emu.uc.reg_read(emu.uc.arch_const.UC_X86_REG_RAX)
        
        print(f"[!] RIP: 0x{rip:x}")
        print(f"[!] RSP: 0x{rsp:x}")
        print(f"[!] RAX: 0x{rax:x}")
        
        # Пытаемся прочитать код в точке ошибки
        try:
            code = emu.uc.mem_read(rip, 16)
            print(f"[!] Code at RIP: {code.hex()}")
        except:
            print(f"[!] Cannot read code at RIP")
        
        # Пытаемся прочитать стек
        try:
            stack = emu.uc.mem_read(rsp, 64)
            print(f"[!] Stack at RSP:")
            for i in range(0, 64, 8):
                val = int.from_bytes(stack[i:i+8], 'little')
                print(f"      RSP+{i:02x}: 0x{val:016x}")
        except:
            print(f"[!] Cannot read stack at RSP")
    
    except Exception as e:
        print(f"\n[!] Exception: {e}")
        import traceback
        traceback.print_exc()
    
    print("-" * 70)
    print(f"\n[*] Эмуляция остановлена")
    print(f"    Инструкций выполнено: {emu.instruction_count:,}")
    print(f"    Виртуальное время: {emu.clock}")
    
    # Проверяем последний RIP
    final_rip = emu.uc.reg_read(emu.uc.arch_const.UC_X86_REG_RIP)
    print(f"    Последний RIP: 0x{final_rip:x}")
    
    # Проверяем, в какой секции находится RIP
    if emu.pe_loader and emu.pe_loader.pe:
        for section in emu.pe_loader.pe.sections:
            section_start = emu.pe_loader.image_base + section.VirtualAddress
            section_end = section_start + section.Misc_VirtualSize
            if section_start <= final_rip < section_end:
                section_name = section.Name.decode('ascii', errors='ignore').rstrip('\x00')
                offset = final_rip - section_start
                print(f"    Секция: {section_name} (offset: 0x{offset:x})")
                break


if __name__ == "__main__":
    test_cpuz_debug()
