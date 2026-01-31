#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Test simple_sysinfo_nocrt.exe - версия БЕЗ CRT
Должна избежать проблемы с rep stosb в CRT инициализации
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
    """Эмулятор для simple_sysinfo_nocrt"""
    
    def __init__(self, cpu_freq_mhz=3000):
        self.uc = Uc(UC_ARCH_X86, UC_MODE_64)
        self.clock = VirtualClock(cpu_freq_mhz)
        self.os = MiniOS(self.uc, self.clock)
        
        self.instruction_count = 0
        self.syscall_count = 0
        self.pending_restart_rip = None
        self.program_exited = False
        self.exit_code = 0
        
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
        
        # WinAPI stubs
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
        
        # Детектируем вход в stub region
        STUB_BASE = 0x7FFF0000
        STUB_SIZE = 0x40000000
        
        if STUB_BASE <= address < STUB_BASE + STUB_SIZE:
            ret_addr = self.winapi.handle_stub_call(address)
            self.pending_restart_rip = ret_addr
            uc.emu_stop()
            return
        
        # Логируем прогресс
        if self.instruction_count % 10000 == 0:  # Реже логируем
            pass  # Отключаем логи прогресса для чистого вывода
    
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
                
                # Проверяем, завершилась ли программа через ExitProcess
                if self.program_exited:
                    return self.exit_code
                
                if self.pending_restart_rip:
                    current_addr = self.pending_restart_rip
                    self.pending_restart_rip = None
                    continue
                
                return 0
                
            except Exception as e:
                # Проверяем, завершилась ли программа через ExitProcess
                if self.program_exited:
                    return self.exit_code
                
                if self.pending_restart_rip:
                    current_addr = self.pending_restart_rip
                    self.pending_restart_rip = None
                    continue
                
                if verbose:
                    print(f"\n[!] Emulation stopped: {e}")
                return 1
        
        return 0


def test_nocrt():
    """Test simple_sysinfo_nocrt.exe"""
    print("=" * 70)
    print("TEST: simple_sysinfo_nocrt.exe - NO CRT VERSION")
    print("=" * 70)
    
    exe_path = "demos/simple_sysinfo_nocrt.exe"
    
    if not os.path.exists(exe_path):
        print(f"\n[!] Error: {exe_path} not found!")
        print("[!] Please compile it first: compile_nocrt.bat")
        return False
    
    print(f"\n[*] Loading: {exe_path}")
    
    try:
        emu = LayeredEmulatorV2(cpu_freq_mhz=3000)
        
        # Загружаем PE
        entry_point = emu.load_pe(exe_path)
        
        print(f"\n[*] Starting emulation...")
        print(f"[*] Entry point: 0x{entry_point:x}")
        print("-" * 70)
        print()
        
        # Запускаем
        exit_code = emu.run(
            start_addr=entry_point,
            end_addr=0,
            max_instructions=10000000,
            verbose=True
        )
        
        print()
        print("-" * 70)
        print(f"\n[*] Emulation finished")
        print(f"    Exit code: {exit_code}")
        print(f"    Instructions: {emu.instruction_count:,}")
        print(f"    Syscalls: {emu.syscall_count:,}")
        
        if exit_code == 0:
            print(f"\n[SUCCESS] Program executed successfully!")
        
        return exit_code == 0
    
    except Exception as e:
        print(f"\n[!] Error: {e}")
        import traceback
        traceback.print_exc()
        return False


if __name__ == '__main__':
    print("\n")
    print("=" * 70)
    print(" " * 15 + "NO CRT Emulation Test")
    print("=" * 70)
    print()
    
    success = test_nocrt()
    
    print("\n")
    if success:
        print("=" * 70)
        print("TEST PASSED!")
        print("=" * 70)
    else:
        print("=" * 70)
        print("TEST FAILED")
        print("=" * 70)
    print()
