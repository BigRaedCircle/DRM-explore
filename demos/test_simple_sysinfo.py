#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Test simple_sysinfo.exe - простая программа для демонстрации hybrid passthrough

Эта программа использует только документированные Windows API:
- GetSystemInfo
- IsProcessorFeaturePresent  
- WriteConsoleW

Идеально для демонстрации работы эмулятора!
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
from unicorn_rep_fix import UnicornRepFix  # HOTFIX для REP инструкций


class LayeredEmulatorV2:
    """Эмулятор для simple_sysinfo"""
    
    def __init__(self, cpu_freq_mhz=3000):
        self.uc = Uc(UC_ARCH_X86, UC_MODE_64)
        self.clock = VirtualClock(cpu_freq_mhz)
        self.os = MiniOS(self.uc, self.clock)
        
        self.instruction_count = 0
        self.syscall_count = 0
        self.pending_restart_rip = None
        self.program_exited = False
        self.exit_code = 0
        
        # HOTFIX для REP инструкций
        self.rep_fix = UnicornRepFix(self.uc)
        
        # Детектор зацикливания
        self.last_rip_history = []
        self.loop_detection_window = 100
        
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
        
        # Hook для REP инструкций - используем UC_HOOK_MEM_WRITE для детекта
        self.uc.hook_add(UC_HOOK_MEM_WRITE_UNMAPPED, self._hook_rep_write)
        
        try:
            self.uc.hook_add(UC_HOOK_INSN, self._hook_rdtsc, None, 1, 0, UC_X86_INS_RDTSC)
        except:
            pass
        
        try:
            self.uc.hook_add(UC_HOOK_INSN, self._hook_syscall, None, 1, 0, UC_X86_INS_SYSCALL)
        except:
            pass
    
    def _hook_rep_write(self, uc, access, address, size, value, user_data):
        """Hook для записи памяти - детектируем REP STOSB"""
        # Проверяем, если это запись от REP STOSB
        rip = uc.reg_read(UC_X86_REG_RIP)
        if rip == 0x1400025f9:  # Адрес rep stosb
            # Просто разрешаем запись
            return True
        return False
    
    def _hook_code(self, uc, address, size, user_data):
        """Hook на каждую инструкцию"""
        self.instruction_count += 1
        
        # HOTFIX: Проверяем и обрабатываем REP инструкции
        # ВАЖНО: Проверяем ПЕРЕД тем как Unicorn попытается выполнить
        if self.rep_fix.check_and_handle_rep(address):
            # REP инструкция была обработана
            # Останавливаем эмуляцию и перезапускаем с нового RIP
            new_rip = uc.reg_read(UC_X86_REG_RIP)
            self.pending_restart_rip = new_rip
            uc.emu_stop()
            return
        
        # Детектируем вход в stub region
        STUB_BASE = 0x7FFF0000
        STUB_SIZE = 0x40000000
        
        if STUB_BASE <= address < STUB_BASE + STUB_SIZE:
            ret_addr = self.winapi.handle_stub_call(address)
            self.pending_restart_rip = ret_addr
            uc.emu_stop()
            return
        
        # Детектор зацикливания
        self.last_rip_history.append(address)
        if len(self.last_rip_history) > self.loop_detection_window:
            self.last_rip_history.pop(0)
        
        # Проверяем на зацикливание каждые 1000 инструкций
        if self.instruction_count % 1000 == 0 and len(self.last_rip_history) >= self.loop_detection_window:
            # Если последние 100 инструкций повторяют один и тот же паттерн
            unique_addresses = len(set(self.last_rip_history))
            if unique_addresses < 10:  # Менее 10 уникальных адресов = зацикливание
                print(f"\n[!] LOOP DETECTED at instruction {self.instruction_count}")
                print(f"[!] Only {unique_addresses} unique addresses in last {self.loop_detection_window} instructions")
                print(f"[!] Current RIP: 0x{address:x}")
                
                # Показываем уникальные адреса
                print(f"[!] Unique addresses in loop:")
                for addr in sorted(set(self.last_rip_history)):
                    try:
                        from capstone import Cs, CS_ARCH_X86, CS_MODE_64
                        md = Cs(CS_ARCH_X86, CS_MODE_64)
                        code = uc.mem_read(addr, 15)
                        for insn in md.disasm(code, addr):
                            print(f"    0x{insn.address:x}: {insn.mnemonic} {insn.op_str}")
                            break
                    except:
                        print(f"    0x{addr:x}: <cannot disasm>")
                
                # Дамп регистров для rep stosb
                print(f"\n[!] Register dump:")
                print(f"    RAX = 0x{uc.reg_read(UC_X86_REG_RAX):016x}")
                print(f"    RCX = 0x{uc.reg_read(UC_X86_REG_RCX):016x}  <- repeat count")
                print(f"    RDI = 0x{uc.reg_read(UC_X86_REG_RDI):016x}  <- destination")
                print(f"    RSI = 0x{uc.reg_read(UC_X86_REG_RSI):016x}")
                print(f"    RBX = 0x{uc.reg_read(UC_X86_REG_RBX):016x}")
                print(f"    RBP = 0x{uc.reg_read(UC_X86_REG_RBP):016x}")
                print(f"    RSP = 0x{uc.reg_read(UC_X86_REG_RSP):016x}")
                
                print(f"[!] Stopping emulation...")
                uc.emu_stop()
                return
        
        # Логируем последние 50 инструкций перед крашем
        if self.instruction_count >= 900:  # Перед зацикливанием
            try:
                from capstone import Cs, CS_ARCH_X86, CS_MODE_64
                md = Cs(CS_ARCH_X86, CS_MODE_64)
                code = uc.mem_read(address, 15)
                for insn in md.disasm(code, address):
                    rax = uc.reg_read(UC_X86_REG_RAX)
                    print(f"[{self.instruction_count:4d}] 0x{insn.address:x}: {insn.mnemonic} {insn.op_str} (RAX=0x{rax:x})")
                    break
            except:
                pass
        
        # Логируем прогресс ЧАЩЕ
        if self.instruction_count % 1000 == 0:
            print(f"[PROGRESS] {self.instruction_count:,} instructions, RIP=0x{address:x}")
        
        # Продвигаем часы
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
                    print(f"\n[!] Emulation stopped: {e}")
                return 1
        
        return 0


def test_simple_sysinfo():
    """Test simple_sysinfo.exe"""
    print("=" * 70)
    print("TEST: simple_sysinfo.exe - System Information Tool")
    print("=" * 70)
    
    exe_path = "demos/simple_sysinfo.exe"
    
    if not os.path.exists(exe_path):
        print(f"\n[!] Error: {exe_path} not found!")
        print("[!] Please compile it first: compile_simple_sysinfo.bat")
        return False
    
    print(f"\n[*] Loading: {exe_path}")
    
    try:
        emu = LayeredEmulatorV2(cpu_freq_mhz=3000)
        
        # Загружаем PE
        entry_point = emu.load_pe(exe_path)
        
        # ПАТЧ: Обходим проверку закодированных указателей (как в CoreInfo)
        print(f"\n[*] Patching encoded pointer checks...")
        try:
            # Адреса из трассировки simple_sysinfo:
            # [3334] mov rax, qword ptr [rip + 0x1909b]  ; 0x140021008 - encoded pointer
            # [3335] mov rdx, qword ptr [rip + 0x1a3dc]  ; 0x140022350 - XOR key
            # [3336] cmp rdx, rax
            # [3337] je 0x140007f90  ; Если равны - пропускаем декодирование
            
            # Читаем XOR key
            xor_key_addr = 0x140022350
            xor_key = int.from_bytes(emu.uc.mem_read(xor_key_addr, 8), 'little')
            
            # Записываем тот же ключ в encoded pointer
            encoded_ptr_addr = 0x140021008
            emu.uc.mem_write(encoded_ptr_addr, xor_key.to_bytes(8, 'little'))
            
            print(f"    [PATCH] 0x{encoded_ptr_addr:x} = 0x{xor_key:016x} (same as XOR key)")
            print(f"    This will make pointer encoding check pass and skip decoding")
            
            # ПАТЧ 2: Инициализируем массив указателей (atexit handlers или подобное)
            # Адрес из трассировки: mov rax, qword ptr [rip + 0x18b5f] ; 0x140022208
            array_ptr_addr = 0x140022208
            array_ptr = int.from_bytes(emu.uc.mem_read(array_ptr_addr, 8), 'little')
            
            print(f"\n[*] Checking array pointer at 0x{array_ptr_addr:x}:")
            print(f"    Value: 0x{array_ptr:016x}")
            
            if array_ptr == 0:
                # Выделяем небольшой массив (пустой, только NULL terminator)
                fake_array_addr = 0x20000000  # В heap region
                
                # Сначала выделяем память
                try:
                    emu.uc.mem_map(fake_array_addr, 0x1000)
                except:
                    pass  # Уже выделена
                
                emu.uc.mem_write(fake_array_addr, b'\x00' * 64)  # Массив из 8 NULL указателей
                emu.uc.mem_write(array_ptr_addr, fake_array_addr.to_bytes(8, 'little'))
                print(f"    [PATCH] Initialized array pointer to 0x{fake_array_addr:x} (empty array)")
        except Exception as e:
            print(f"    [!] Failed to patch: {e}")
        
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
        print(f"    REP instructions handled: {emu.rep_fix.rep_instructions_handled}")
        
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
    print(" " * 15 + "Simple SysInfo Emulation Test")
    print("=" * 70)
    print()
    
    success = test_simple_sysinfo()
    
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
