#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Trace all function calls in CoreInfo to understand why there's no output
"""

import sys
import os
sys.path.insert(0, 'src/core')

from unicorn import Uc, UC_ARCH_X86, UC_MODE_64
from unicorn.x86_const import *
from virtual_clock import VirtualClock
from mini_os import MiniOS
from winapi_stubs_v2 import WinAPIStubsV2
from pe_loader import PELoader


class LayeredEmulatorV2:
    """Эмулятор с трассировкой всех вызовов"""
    
    def __init__(self, cpu_freq_mhz=3000):
        self.uc = Uc(UC_ARCH_X86, UC_MODE_64)
        self.clock = VirtualClock(cpu_freq_mhz)
        self.os = MiniOS(self.uc, self.clock)
        
        self.instruction_count = 0
        self.syscall_count = 0
        self.function_calls = []  # Трассировка вызовов
        
        self.last_instructions = []
        self.max_last_instructions = 50
        self.pending_restart_rip = None
        
        # Стек
        self.STACK_BASE = 0x00100000
        self.STACK_SIZE = 0x00100000
        self.uc.mem_map(self.STACK_BASE, self.STACK_SIZE)
        self.uc.reg_write(UC_X86_REG_RSP, self.STACK_BASE + self.STACK_SIZE - 0x1000)
        
        # TIB
        self.TIB_BASE = 0x00030000
        self.TIB_SIZE = 0x2000
        self.uc.mem_map(self.TIB_BASE, self.TIB_SIZE)
        self._setup_tib()
        
        # GS segment
        try:
            self.uc.mem_map(0x0, 0x3000)
            tib_data = self.uc.mem_read(self.TIB_BASE, self.TIB_SIZE)
            self.uc.mem_write(0x0, tib_data)
        except:
            pass
        
        # Stub memory
        STUB_BASE = 0x7FFF0000
        STUB_SIZE = 0x40000000  # 1GB
        self.uc.mem_map(STUB_BASE, STUB_SIZE)
        
        # Новая система заглушек
        self.winapi = WinAPIStubsV2(self)
        
        self.pe_loader = None
        self._setup_hooks()
    
    def _setup_tib(self):
        """Настройка TIB"""
        import struct
        tib_data = bytearray(self.TIB_SIZE)
        struct.pack_into('<Q', tib_data, 0x30, self.TIB_BASE)
        struct.pack_into('<Q', tib_data, 0x58, self.TIB_BASE)
        self.uc.mem_write(self.TIB_BASE, bytes(tib_data))
    
    def _setup_hooks(self):
        """Настройка хуков"""
        from unicorn import (UC_HOOK_CODE, UC_HOOK_INSN, UC_HOOK_MEM_UNMAPPED, 
                            UC_HOOK_MEM_FETCH_UNMAPPED, UC_HOOK_INTR,
                            UC_HOOK_MEM_READ_UNMAPPED, UC_HOOK_MEM_WRITE_UNMAPPED)
        from unicorn.x86_const import UC_X86_INS_RDTSC, UC_X86_INS_SYSCALL
        
        self.uc.hook_add(UC_HOOK_CODE, self._hook_code)
        self.uc.hook_add(UC_HOOK_MEM_READ_UNMAPPED, self._hook_mem_unmapped)
        self.uc.hook_add(UC_HOOK_MEM_WRITE_UNMAPPED, self._hook_mem_unmapped)
        self.uc.hook_add(UC_HOOK_MEM_FETCH_UNMAPPED, self._hook_mem_fetch_unmapped)
        self.uc.hook_add(UC_HOOK_INTR, self._hook_interrupt)
        
        try:
            self.uc.hook_add(UC_HOOK_INSN, self._hook_rdtsc, None, 1, 0, UC_X86_INS_RDTSC)
        except:
            pass
        
        try:
            self.uc.hook_add(UC_HOOK_INSN, self._hook_syscall, None, 1, 0, UC_X86_INS_SYSCALL)
        except:
            pass
    
    def _hook_code(self, uc, address, size, user_data):
        """Hook на каждую инструкцию"""
        self.instruction_count += 1
        
        if len(self.last_instructions) >= self.max_last_instructions:
            self.last_instructions.pop(0)
        self.last_instructions.append({
            'count': self.instruction_count,
            'address': address,
            'rsp': uc.reg_read(UC_X86_REG_RSP),
            'rax': uc.reg_read(UC_X86_REG_RAX),
        })
        
        # Детектируем вход в stub region
        STUB_BASE = 0x7FFF0000
        STUB_SIZE = 0x40000000
        
        if STUB_BASE <= address < STUB_BASE + STUB_SIZE:
            # Сохраняем информацию о вызове
            ret_addr = self.winapi.handle_stub_call(address)
            self.pending_restart_rip = ret_addr
            uc.emu_stop()
            return
        
        # Проверяем, что RIP в допустимых пределах
        PE_BASE = 0x140000000
        PE_SIZE = 0x00100000
        
        is_in_pe = PE_BASE <= address < PE_BASE + PE_SIZE
        is_in_stub = STUB_BASE <= address < STUB_BASE + STUB_SIZE
        
        if not is_in_pe and not is_in_stub:
            uc.emu_stop()
            return
        
        if self.instruction_count % 1000 == 0:
            print(f"[PROGRESS] {self.instruction_count:,} instructions")
        
        if self.instruction_count % 10 == 0:
            self.clock.advance(1)
    
    def _hook_rdtsc(self, uc, user_data):
        """Hook на RDTSC"""
        tsc = self.clock.rdtsc()
        eax = tsc & 0xFFFFFFFF
        edx = (tsc >> 32) & 0xFFFFFFFF
        uc.reg_write(UC_X86_REG_RAX, eax)
        uc.reg_write(UC_X86_REG_RDX, edx)
        rip = uc.reg_read(UC_X86_REG_RIP)
        uc.reg_write(UC_X86_REG_RIP, rip + 2)
    
    def _hook_syscall(self, uc, user_data):
        """Hook на SYSCALL"""
        self.syscall_count += 1
        syscall_num = uc.reg_read(UC_X86_REG_RAX)
        self.os.handle_syscall(syscall_num)
    
    def _hook_interrupt(self, uc, intno, user_data):
        """Hook на INT"""
        rip = uc.reg_read(UC_X86_REG_RIP)
        uc.reg_write(UC_X86_REG_RIP, rip + 2)
    
    def _hook_mem_unmapped(self, uc, access, address, size, value, user_data):
        """Hook на unmapped memory"""
        from unicorn import UC_MEM_WRITE, UC_MEM_READ, UC_MEM_FETCH
        
        if access == UC_MEM_FETCH:
            rip = uc.reg_read(UC_X86_REG_RIP)
            IAT_START = 0x14003a000
            IAT_END = 0x14003a600
            
            if IAT_START <= rip < IAT_END:
                try:
                    iat_value = int.from_bytes(uc.mem_read(rip, 8), 'little')
                    dummy_stub = 0x7fff0000
                    uc.mem_write(rip, dummy_stub.to_bytes(8, 'little'))
                    prev_rip = rip - 6
                    self.pending_restart_rip = prev_rip
                    uc.emu_stop()
                    return True
                except:
                    pass
            return False
        
        if address > 0x10000000000:
            return False
        
        if address < 0x10000:
            try:
                self.uc.mem_map(0x0, 0x10000)
                self.uc.mem_write(0x0, b'\x00' * 0x10000)
                return True
            except:
                return False
        
        page_size = 0x1000
        page_start = (address // page_size) * page_size
        alloc_size = 0x100000
        
        try:
            self.uc.mem_map(page_start, alloc_size)
            self.uc.mem_write(page_start, b'\x00' * alloc_size)
            return True
        except:
            return False
    
    def _hook_mem_fetch_unmapped(self, uc, access, address, size, value, user_data):
        """Hook на unmapped fetch"""
        return False
    
    def load_pe(self, pe_path):
        """Загрузка PE файла"""
        self.pe_loader = PELoader(self)
        return self.pe_loader.load(pe_path)
    
    def run(self, start_addr, end_addr=0, max_instructions=10000000, verbose=False):
        """Запуск эмуляции"""
        current_addr = start_addr
        
        while self.instruction_count < max_instructions:
            try:
                remaining = max_instructions - self.instruction_count
                self.uc.emu_start(current_addr, end_addr, count=remaining)
                
                if self.pending_restart_rip:
                    current_addr = self.pending_restart_rip
                    self.pending_restart_rip = None
                    continue
                
                return 0
                
            except Exception as e:
                if self.pending_restart_rip:
                    current_addr = self.pending_restart_rip
                    self.pending_restart_rip = None
                    continue
                
                if verbose:
                    print(f"\n[!] Эмуляция остановлена: {e}")
                return 1
        
        return 0


def test_coreinfo_trace():
    """Test CoreInfo with full function call tracing"""
    print("=" * 70)
    print("CoreInfo - Function Call Trace")
    print("=" * 70)
    
    original_dir = os.getcwd()
    os.chdir("sandbox/CoreInfo")
    
    coreinfo_path = "Coreinfo64.exe"
    
    try:
        emu = LayeredEmulatorV2(cpu_freq_mhz=3000)
        
        # Загружаем PE
        entry_point = emu.load_pe(coreinfo_path)
        
        # Патчим IAT
        IAT_START = 0x14003a000
        IAT_END = 0x14003a600
        IAT_SIZE = IAT_END - IAT_START
        
        try:
            iat_data = emu.uc.mem_read(IAT_START, IAT_SIZE)
            unpatched_count = 0
            
            for offset in range(0, IAT_SIZE, 8):
                addr = IAT_START + offset
                value = int.from_bytes(iat_data[offset:offset+8], 'little')
                
                STUB_BASE = 0x7FFF0000
                STUB_END = 0xBFFF0000
                
                if value != 0 and not (STUB_BASE <= value < STUB_END):
                    stub_addr = STUB_BASE + (unpatched_count * 0x100)
                    func_name = f"unknown_iat_0x{addr:x}"
                    emu.winapi.stub_addresses[stub_addr] = func_name
                    emu.uc.mem_write(stub_addr, bytes([0xC3]))
                    emu.uc.mem_write(addr, stub_addr.to_bytes(8, 'little'))
                    unpatched_count += 1
        except:
            pass
        
        print(f"\n[*] Starting emulation...")
        print(f"[*] Entry point: 0x{entry_point:x}")
        print("-" * 70)
        
        # Запускаем
        exit_code = emu.run(
            start_addr=entry_point,
            end_addr=0,
            max_instructions=10000000,
            verbose=True
        )
        
        print("-" * 70)
        print(f"\n[*] Emulation finished")
        print(f"    Exit code: {exit_code}")
        print(f"    Instructions: {emu.instruction_count:,}")
        print(f"    Function calls: {len(emu.function_calls)}")
        
        # Показываем все вызовы функций
        print(f"\n[*] Function calls made:")
        func_counts = {}
        for call in emu.function_calls:
            func_name = call.get('name', 'unknown')
            func_counts[func_name] = func_counts.get(func_name, 0) + 1
        
        for func_name, count in sorted(func_counts.items(), key=lambda x: -x[1]):
            print(f"    {func_name}: {count} calls")
        
        return True
    
    except Exception as e:
        print(f"\n[!] Error: {e}")
        import traceback
        traceback.print_exc()
        return False
    
    finally:
        os.chdir(original_dir)


if __name__ == '__main__':
    test_coreinfo_trace()
