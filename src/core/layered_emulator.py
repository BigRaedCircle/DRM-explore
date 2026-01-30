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
from mini_os import MiniOS
from winapi_stubs import WinAPIStubs
from pe_loader import PELoader
from realistic_stubs import SystemInfo, VirtualFileSystem, DirectXStubs, NetworkStubs


class LayeredEmulator:
    """Расслоенный эмулятор с поддержкой PE и WinAPI"""
    
    def __init__(self, cpu_freq_mhz=3000):
        # Инициализация Unicorn
        self.uc = Uc(UC_ARCH_X86, UC_MODE_64)
        
        # Виртуальные часы
        self.clock = VirtualClock(cpu_freq_mhz)
        
        # Реалистичные заглушки для периферии
        self.system_info = SystemInfo()
        self.vfs = VirtualFileSystem(base_path=".")
        self.directx = DirectXStubs(self.system_info, self.clock)
        self.network = NetworkStubs(self.clock)
        
        # Минимальный OS-слой
        self.os = MiniOS(self.uc, self.clock)
        
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
        
        # WinAPI заглушки (теперь используют MiniOS)
        self.winapi = WinAPIStubs(self)
        
        # PE Loader
        self.pe_loader = None
        
        # Настройка хуков
        self._setup_hooks()
    
    def _setup_hooks(self):
        """Setup hooks for instruction interception"""
        # Hook on every instruction (for cycle counting and RDTSC)
        self.uc.hook_add(UC_HOOK_CODE, self._hook_instruction)
        
        # Hook for INT instructions (system calls)
        from unicorn import UC_HOOK_INTR
        self.uc.hook_add(UC_HOOK_INTR, self._hook_interrupt)
    
    def _hook_instruction(self, uc, address, size, user_data):
        """Hook on every instruction - advance virtual time"""
        self.clock.advance(1)
        self.instruction_count += 1
        
        # Check if we're executing in stub area - handle it immediately
        if self.winapi.STUB_BASE <= address < self.winapi.STUB_BASE + 0x10000:
            # We're in a stub - handle it
            self.winapi.handle_stub_call(address)
            # Pop return address and jump there
            rsp = uc.reg_read(UC_X86_REG_RSP)
            ret_addr = int.from_bytes(uc.mem_read(rsp, 8), 'little')
            uc.reg_write(UC_X86_REG_RSP, rsp + 8)
            uc.reg_write(UC_X86_REG_RIP, ret_addr)
            print(f"  <- returning to 0x{ret_addr:x}")
            return
        
        # Read instruction to check for RDTSC
        try:
            code = uc.mem_read(address, min(size, 15))
            
            # RDTSC = 0x0F 0x31
            if len(code) >= 2 and code[0] == 0x0F and code[1] == 0x31:
                # Handle RDTSC
                ticks = self.clock.rdtsc()
                eax = ticks & 0xFFFFFFFF
                edx = (ticks >> 32) & 0xFFFFFFFF
                uc.reg_write(UC_X86_REG_RAX, eax)
                uc.reg_write(UC_X86_REG_RDX, edx)
                print(f"[RDTSC] @ 0x{address:x} -> {ticks} ticks")
            
            # Check for indirect JMP/CALL through memory (0xFF opcode)
            elif len(code) >= 2 and code[0] == 0xFF:
                modrm = code[1]
                # Check if it's JMP [mem] (opcode /4) or CALL [mem] (opcode /2)
                reg = (modrm >> 3) & 0x7
                if reg == 4 or reg == 2:  # JMP or CALL
                    # This might be IAT call - log it
                    rax = uc.reg_read(UC_X86_REG_RAX)
                    if rax == 0:
                        print(f"[WARN] Indirect {'CALL' if reg == 2 else 'JMP'} @ 0x{address:x} with RAX=0")
        except:
            pass
    
    def _hook_interrupt(self, uc, intno, user_data):
        """Handle INT instructions (system calls)"""
        rip = uc.reg_read(UC_X86_REG_RIP)
        
        if intno == 0x03:
            # INT 0x03 - Breakpoint / Our stub marker
            # Check if this is our stub
            if rip >= self.winapi.STUB_BASE and rip < self.winapi.STUB_BASE + 0x10000:
                # This is our stub - call handler
                self.winapi.handle_stub_call(rip)
                # Emulate RET: pop return address from stack
                rsp = uc.reg_read(UC_X86_REG_RSP)
                ret_addr = int.from_bytes(uc.mem_read(rsp, 8), 'little')
                uc.reg_write(UC_X86_REG_RSP, rsp + 8)
                uc.reg_write(UC_X86_REG_RIP, ret_addr)
                print(f"  <- returning to 0x{ret_addr:x}")
            else:
                # INT3 in user code - use as RDTSC marker
                ticks = self.clock.rdtsc()
                eax = ticks & 0xFFFFFFFF
                edx = (ticks >> 32) & 0xFFFFFFFF
                uc.reg_write(UC_X86_REG_RAX, eax)
                uc.reg_write(UC_X86_REG_RDX, edx)
                print(f"[RDTSC via INT3] @ 0x{rip:x} -> {ticks} ticks (EAX=0x{eax:x}, EDX=0x{edx:x})")
                # Advance RIP past INT3 (1 byte)
                uc.reg_write(UC_X86_REG_RIP, rip + 1)
        elif intno == 0x29:
            # INT 0x29 - Windows fast debug output
            # Just skip it - advance RIP by 2 bytes (CD 29)
            print(f"[INT 0x29] @ 0x{rip:x} - Windows debug output (skipped)")
            uc.reg_write(UC_X86_REG_RIP, rip + 2)
        elif intno == 0x2E:
            # INT 0x2E - Windows system call (old method)
            print(f"[INT 0x2E] @ 0x{rip:x} - Windows syscall (skipped)")
            uc.reg_write(UC_X86_REG_RIP, rip + 2)
        else:
            print(f"[INT 0x{intno:02x}] @ 0x{rip:x} - Unknown interrupt")
            # Let it crash for debugging
    
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
        # Allocate memory (at least 4KB, aligned)
        code_size = max(((len(code) + 0xFFF) // 0x1000) * 0x1000, 0x1000)
        self.uc.mem_map(base_addr, code_size)
        
        # Write code
        self.uc.mem_write(base_addr, code)
        
        print(f"[*] Allocated {code_size} bytes at 0x{base_addr:x}")
        
        return base_addr
    
    def run(self, start_addr, end_addr=0, max_instructions=100000, verbose=True):
        """Run emulation"""
        if verbose:
            print(f"\n[*] Starting emulation from address 0x{start_addr:x}")
            print(f"[*] Initial state: {self.clock}")
            print("-" * 70)
        
        try:
            # Set RIP
            self.uc.reg_write(UC_X86_REG_RIP, start_addr)
            
            # Start emulation
            self.uc.emu_start(start_addr, end_addr, count=max_instructions)
            
        except UcError as e:
            if verbose:
                print(f"\n[!] Emulation error: {e}")
                print(f"[!] RIP: 0x{self.uc.reg_read(UC_X86_REG_RIP):x}")
        
        if verbose:
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
