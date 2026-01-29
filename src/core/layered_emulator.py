#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Layered Emulator — расслоенная эмуляция с поддержкой WinAPI

Объединяет:
- VirtualClock (единый источник времени)
- SimpleEmulator (эмуляция CPU)
- WinAPIStubs (заглушки системных вызовов)
- PELoader (загрузка PE-файлов)
"""

import sys
sys.path.insert(0, '.')

from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UcError
from unicorn import UC_HOOK_CODE, UC_HOOK_INSN
from unicorn.x86_const import *
from virtual_clock import VirtualClock
from winapi_stubs import WinAPIStubs
from pe_loader import PELoader


class LayeredEmulator:
    """Расслоенный эмулятор с поддержкой PE и WinAPI"""
    
    def __init__(self, cpu_freq_mhz=3000):
        # Инициализация Unicorn
        self.uc = Uc(UC_ARCH_X86, UC_MODE_64)
        
        # Виртуальные часы
        self.clock = VirtualClock(cpu_freq_mhz)
        
        # Счётчики
        self.instruction_count = 0
        self.syscall_count = 0
        
        # Выделение памяти для стека
        self.STACK_BASE = 0x00100000
        self.STACK_SIZE = 0x00100000  # 1 МБ
        self.uc.mem_map(self.STACK_BASE, self.STACK_SIZE)
        self.uc.reg_write(UC_X86_REG_RSP, self.STACK_BASE + self.STACK_SIZE - 0x1000)
        
        # Выделение памяти для заглушек WinAPI (ПЕРЕД созданием WinAPIStubs!)
        STUB_BASE = 0x7FFF0000
        self.uc.mem_map(STUB_BASE, 0x10000)
        
        # WinAPI заглушки
        self.winapi = WinAPIStubs(self)
        
        # PE Loader
        self.pe_loader = None
        
        # Настройка хуков
        self._setup_hooks()
    
    def _setup_hooks(self):
        """Настроить хуки для перехвата инструкций"""
        # Хук на каждую инструкцию (для подсчёта тактов и перехвата RDTSC)
        self.uc.hook_add(UC_HOOK_CODE, self._hook_instruction)
    
    def _hook_instruction(self, uc, address, size, user_data):
        """Hook on every instruction - advance virtual time"""
        self.clock.advance(1)
        self.instruction_count += 1
        
        # Read instruction to check for RDTSC
        try:
            code = uc.mem_read(address, min(size, 15))
            
            # RDTSC = 0x0F 0x31
            if len(code) >= 2 and code[0] == 0x0F and code[1] == 0x31:
                self._handle_rdtsc(uc)
        except:
            pass
    
    def _handle_rdtsc(self, uc):
        """Handle RDTSC instruction"""
        ticks = self.clock.rdtsc()
        
        # RDTSC returns value in EDX:EAX
        eax = ticks & 0xFFFFFFFF
        edx = (ticks >> 32) & 0xFFFFFFFF
        
        uc.reg_write(UC_X86_REG_RAX, eax)
        uc.reg_write(UC_X86_REG_RDX, edx)
        
        print(f"[RDTSC] @ 0x{uc.reg_read(UC_X86_REG_RIP):x} -> {ticks} ticks")
    
    def load_pe(self, pe_path):
        """Load PE file"""
        print(f"\n[*] Loading PE: {pe_path}")
        
        self.pe_loader = PELoader(self)
        entry_point = self.pe_loader.load(pe_path)
        
        print(f"[*] Entry point: 0x{entry_point:x}")
        print(f"[*] Image base: 0x{self.pe_loader.image_base:x}")
        
        return entry_point
    
    def load_code(self, code, base_addr=0x400000):
        """Load machine code directly"""
        # Allocate memory
        code_size = ((len(code) + 0xFFF) // 0x1000) * 0x1000  # Align to 4KB
        self.uc.mem_map(base_addr, code_size)
        
        # Write code
        self.uc.mem_write(base_addr, code)
        
        return base_addr
    
    def run(self, start_addr, end_addr=0, max_instructions=100000):
        """Run emulation"""
        print(f"\n[*] Starting emulation from address 0x{start_addr:x}")
        print(f"[*] Initial state: {self.clock}")
        print("-" * 70)
        
        try:
            # Set RIP
            self.uc.reg_write(UC_X86_REG_RIP, start_addr)
            
            # Start emulation
            self.uc.emu_start(start_addr, end_addr, count=max_instructions)
            
        except UcError as e:
            print(f"\n[!] Emulation error: {e}")
            print(f"[!] RIP: 0x{self.uc.reg_read(UC_X86_REG_RIP):x}")
        
        print("-" * 70)
        print(f"\n[*] Emulation finished")
        print(f"[*] Final state: {self.clock}")
        print(f"[*] Instructions executed: {self.instruction_count:,}")
        print(f"[*] System calls: {self.syscall_count}")
        
        # Return RAX (exit code)
        return self.uc.reg_read(UC_X86_REG_RAX)


if __name__ == "__main__":
    print("Layered Emulator — расслоенная эмуляция с WinAPI")
    print("\nИспользование:")
    print("  from layered_emulator import LayeredEmulator")
    print("  emu = LayeredEmulator()")
    print("  entry = emu.load_pe('demo.exe')")
    print("  emu.run(entry)")
