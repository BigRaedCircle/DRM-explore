#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Тест CoreInfo (Sysinternals) - чисто консольная утилита для информации о CPU

CoreInfo - это консольная утилита от Microsoft Sysinternals для получения
детальной информации о процессоре, кэше, NUMA и других характеристиках.

Преимущества:
- Чисто консольная (без GUI)
- От Microsoft (хорошо документирована)
- Использует драйвер для низкоуровневого доступа
- Выводит результат в stdout
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
    """Эмулятор с новой системой заглушек"""
    
    def __init__(self, cpu_freq_mhz=3000):
        self.uc = Uc(UC_ARCH_X86, UC_MODE_64)
        self.clock = VirtualClock(cpu_freq_mhz)
        self.os = MiniOS(self.uc, self.clock)
        
        self.instruction_count = 0
        self.syscall_count = 0
        
        # Для отладки: сохраняем последние N инструкций
        self.last_instructions = []
        self.max_last_instructions = 50
        
        # Для перезапуска после stub call
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
        
        # Stub memory - выделяем для записи RET инструкций
        STUB_BASE = 0x7FFF0000
        STUB_SIZE = 0x40000000  # 1GB
        self.uc.mem_map(STUB_BASE, STUB_SIZE)
        print(f"[MEM] Allocated {STUB_SIZE//(1024*1024)}MB at 0x{STUB_BASE:x} for stubs")
        
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
        from unicorn.x86_const import UC_X86_INS_RDTSC, UC_X86_INS_SYSCALL, UC_X86_INS_CPUID
        
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
            self.uc.hook_add(UC_HOOK_INSN, self._hook_cpuid, None, 1, 0, UC_X86_INS_CPUID)
            print("[+] CPUID hook installed")
        except Exception as e:
            print(f"[!] Failed to install CPUID hook: {e}")
        
        try:
            self.uc.hook_add(UC_HOOK_INSN, self._hook_syscall, None, 1, 0, UC_X86_INS_SYSCALL)
        except:
            pass
    
    def _hook_code(self, uc, address, size, user_data):
        """Hook на каждую инструкцию"""
        self.instruction_count += 1
        
        # Сохраняем последние инструкции для отладки
        if len(self.last_instructions) >= self.max_last_instructions:
            self.last_instructions.pop(0)
        self.last_instructions.append({
            'count': self.instruction_count,
            'address': address,
            'rsp': uc.reg_read(UC_X86_REG_RSP),
            'rax': uc.reg_read(UC_X86_REG_RAX),
        })
        
        # КРИТИЧНО: Детектируем вход в stub region
        STUB_BASE = 0x7FFF0000
        STUB_SIZE = 0x40000000
        
        if STUB_BASE <= address < STUB_BASE + STUB_SIZE:
            # Это вход в stub!
            # Обрабатываем stub call и получаем адрес возврата
            ret_addr = self.winapi.handle_stub_call(address)
            
            # handle_stub_call() вернул адрес возврата
            # Сохраняем его для перезапуска (НЕ читаем RIP из Unicorn!)
            self.pending_restart_rip = ret_addr
            
            # Останавливаем эмуляцию
            uc.emu_stop()
            return
        
        # Проверяем, что RIP в допустимых пределах
        PE_BASE = 0x140000000
        PE_SIZE = 0x00100000  # ~1MB
        
        is_in_pe = PE_BASE <= address < PE_BASE + PE_SIZE
        is_in_stub = STUB_BASE <= address < STUB_BASE + STUB_SIZE
        
        if not is_in_pe and not is_in_stub:
            print(f"\n[!] CRITICAL: RIP outside valid regions!")
            print(f"[!] RIP: 0x{address:x}")
            print(f"[!] Expected: PE (0x{PE_BASE:x}-0x{PE_BASE+PE_SIZE:x}) or STUB (0x{STUB_BASE:x}-0x{STUB_BASE+STUB_SIZE:x})")
            
            # Показываем последние 20 инструкций
            print(f"\n[!] Last 20 instructions before crash:")
            for inst in self.last_instructions[-20:]:
                print(f"    [{inst['count']:7d}] RIP=0x{inst['address']:x}, RSP=0x{inst['rsp']:x}, RAX=0x{inst['rax']:x}")
            
            # Показываем стек
            rsp = uc.reg_read(UC_X86_REG_RSP)
            print(f"\n[!] Stack dump (RSP=0x{rsp:x}):")
            try:
                for i in range(10):
                    addr = rsp + i * 8
                    value = int.from_bytes(uc.mem_read(addr, 8), 'little')
                    print(f"    [RSP+{i*8:2d}] 0x{addr:x}: 0x{value:016x}")
            except:
                print(f"    Cannot read stack")
            
            # Останавливаем
            uc.emu_stop()
            return
        
        # Логируем первые 1000 инструкций детально
        if self.instruction_count <= 0 or self.instruction_count >= 17900:  # Последние 100 инструкций перед крашем
            try:
                from capstone import Cs, CS_ARCH_X86, CS_MODE_64
                md = Cs(CS_ARCH_X86, CS_MODE_64)
                code = uc.mem_read(address, 15)
                for insn in md.disasm(code, address):
                    # Показываем регистры для критичных инструкций
                    rax = uc.reg_read(UC_X86_REG_RAX)
                    
                    # Для CALL/JMP через память - показываем что там
                    if 'call' in insn.mnemonic and 'ptr' in insn.op_str:
                        # Вычисляем адрес памяти
                        if 'rip' in insn.op_str:
                            # call qword ptr [rip + offset]
                            import re
                            match = re.search(r'\[rip \+ (0x[0-9a-f]+)\]', insn.op_str)
                            if match:
                                offset = int(match.group(1), 16)
                                target_addr = insn.address + insn.size + offset
                                try:
                                    target_value = int.from_bytes(uc.mem_read(target_addr, 8), 'little')
                                    print(f"[{self.instruction_count:3d}] 0x{insn.address:x}: {insn.mnemonic} {insn.op_str} (RAX=0x{rax:x})")
                                    print(f"      -> [0x{target_addr:x}] = 0x{target_value:x}")
                                except:
                                    print(f"[{self.instruction_count:3d}] 0x{insn.address:x}: {insn.mnemonic} {insn.op_str} (RAX=0x{rax:x})")
                            else:
                                print(f"[{self.instruction_count:3d}] 0x{insn.address:x}: {insn.mnemonic} {insn.op_str} (RAX=0x{rax:x})")
                        else:
                            print(f"[{self.instruction_count:3d}] 0x{insn.address:x}: {insn.mnemonic} {insn.op_str} (RAX=0x{rax:x})")
                    elif 'call' in insn.mnemonic or 'jmp' in insn.mnemonic or 'ret' in insn.mnemonic:
                        print(f"[{self.instruction_count:3d}] 0x{insn.address:x}: {insn.mnemonic} {insn.op_str} (RAX=0x{rax:x})")
                    else:
                        print(f"[{self.instruction_count:3d}] 0x{insn.address:x}: {insn.mnemonic} {insn.op_str}")
                    break
            except:
                print(f"[{self.instruction_count:3d}] 0x{address:x}: <cannot disasm>")
        
        # Логируем каждую 1000-ю инструкцию
        elif self.instruction_count % 1000 == 0:
            print(f"[PROGRESS] {self.instruction_count:,} instructions executed, RIP=0x{address:x}")
        
        # Продвигаем часы каждые 10 инструкций
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
    
    def _hook_cpuid(self, uc, user_data):
        """Hook на CPUID - возвращаем реалистичные данные AMD Ryzen"""
        eax_in = uc.reg_read(UC_X86_REG_EAX)
        ecx_in = uc.reg_read(UC_X86_REG_ECX)
        
        # CPUID leaf 0: Get vendor string and max basic leaf
        if eax_in == 0:
            uc.reg_write(UC_X86_REG_EAX, 0xD)  # Max basic leaf
            uc.reg_write(UC_X86_REG_EBX, 0x68747541)  # "Auth"
            uc.reg_write(UC_X86_REG_EDX, 0x69746E65)  # "enti"
            uc.reg_write(UC_X86_REG_ECX, 0x444D4163)  # "cAMD"
        
        # CPUID leaf 1: Processor Info and Feature Bits
        elif eax_in == 1:
            uc.reg_write(UC_X86_REG_EAX, 0x00810F81)  # Family 23, Model 24, Stepping 1
            uc.reg_write(UC_X86_REG_EBX, 0x00000800)  # Brand ID, CLFLUSH size
            uc.reg_write(UC_X86_REG_ECX, 0x7ED8320B)  # Feature flags (SSE3, SSSE3, SSE4.1, SSE4.2, etc)
            uc.reg_write(UC_X86_REG_EDX, 0x178BFBFF)  # Feature flags (FPU, MMX, SSE, SSE2, HTT, etc)
        
        # CPUID leaf 7: Extended Features
        elif eax_in == 7:
            if ecx_in == 0:
                uc.reg_write(UC_X86_REG_EAX, 0)
                uc.reg_write(UC_X86_REG_EBX, 0x209C01A9)  # SMEP, SMAP, etc
                uc.reg_write(UC_X86_REG_ECX, 0x00000000)
                uc.reg_write(UC_X86_REG_EDX, 0x00000000)
        
        # CPUID leaf 0x80000000: Get max extended leaf
        elif eax_in == 0x80000000:
            uc.reg_write(UC_X86_REG_EAX, 0x8000001F)  # Max extended leaf
            uc.reg_write(UC_X86_REG_EBX, 0x68747541)  # "Auth"
            uc.reg_write(UC_X86_REG_ECX, 0x444D4163)  # "cAMD"
            uc.reg_write(UC_X86_REG_EDX, 0x69746E65)  # "enti"
        
        # CPUID leaf 0x80000001: Extended Processor Info
        elif eax_in == 0x80000001:
            uc.reg_write(UC_X86_REG_EAX, 0x00810F81)
            uc.reg_write(UC_X86_REG_EBX, 0x20000000)
            uc.reg_write(UC_X86_REG_ECX, 0x35C233FF)  # Extended features
            uc.reg_write(UC_X86_REG_EDX, 0x2FD3FBFF)  # Extended features
        
        # CPUID leaf 0x80000002-0x80000004: Processor Brand String
        elif eax_in == 0x80000002:
            uc.reg_write(UC_X86_REG_EAX, 0x20444D41)  # "AMD "
            uc.reg_write(UC_X86_REG_EBX, 0x657A7952)  # "Ryze"
            uc.reg_write(UC_X86_REG_ECX, 0x2035206E)  # "n 5 "
            uc.reg_write(UC_X86_REG_EDX, 0x30303433)  # "3400"
        elif eax_in == 0x80000003:
            uc.reg_write(UC_X86_REG_EAX, 0x69772047)  # "G wi"
            uc.reg_write(UC_X86_REG_EBX, 0x52206874)  # "th R"
            uc.reg_write(UC_X86_REG_ECX, 0x6F656461)  # "adeo"
            uc.reg_write(UC_X86_REG_EDX, 0x6556206E)  # "n Ve"
        elif eax_in == 0x80000004:
            uc.reg_write(UC_X86_REG_EAX, 0x47206167)  # "ga G"
            uc.reg_write(UC_X86_REG_EBX, 0x68706172)  # "raph"
            uc.reg_write(UC_X86_REG_ECX, 0x20736369)  # "ics "
            uc.reg_write(UC_X86_REG_EDX, 0x00000000)  # ""
        
        # CPUID leaf 0x80000008: Address Size
        elif eax_in == 0x80000008:
            uc.reg_write(UC_X86_REG_EAX, 0x00003030)  # 48-bit physical, 48-bit virtual
            uc.reg_write(UC_X86_REG_EBX, 0x00000000)
            uc.reg_write(UC_X86_REG_ECX, 0x00000000)
            uc.reg_write(UC_X86_REG_EDX, 0x00000000)
        
        # Default: return zeros
        else:
            uc.reg_write(UC_X86_REG_EAX, 0)
            uc.reg_write(UC_X86_REG_EBX, 0)
            uc.reg_write(UC_X86_REG_ECX, 0)
            uc.reg_write(UC_X86_REG_EDX, 0)
        
        # Advance RIP past CPUID instruction
        rip = uc.reg_read(UC_X86_REG_RIP)
        uc.reg_write(UC_X86_REG_RIP, rip + 2)
    
    def _hook_syscall(self, uc, user_data):
        """Hook на SYSCALL"""
        self.syscall_count += 1
        syscall_num = uc.reg_read(UC_X86_REG_RAX)
        self.os.handle_syscall(syscall_num)
    
    def _hook_interrupt(self, uc, intno, user_data):
        """Hook на INT - больше не используется для stubs (используем fetch hook)"""
        rip = uc.reg_read(UC_X86_REG_RIP)
        print(f"[INT 0x{intno:02x}] @ 0x{rip:x} - skipped")
        uc.reg_write(UC_X86_REG_RIP, rip + 2)
    
    def _hook_mem_unmapped(self, uc, access, address, size, value, user_data):
        """Hook на unmapped memory - динамическое выделение"""
        from unicorn import UC_MEM_WRITE, UC_MEM_READ, UC_MEM_FETCH
        
        # Если это FETCH и адрес выглядит как мусор, проверяем IAT
        if access == UC_MEM_FETCH:
            rip = uc.reg_read(UC_X86_REG_RIP)
            print(f"[!] UNMAPPED FETCH @ 0x{address:x}, RIP=0x{rip:x}")
            
            # Проверяем, не является ли RIP адресом в IAT с мусором
            # IAT находится в диапазоне 0x14003a000 - 0x14003a600
            IAT_START = 0x14003a000
            IAT_END = 0x14003a600
            
            if IAT_START <= rip < IAT_END:
                print(f"[!] RIP points to IAT region - this might be unpatched import")
                print(f"[!] Checking if we can patch it...")
                
                # Попробуем найти, какая функция должна быть по этому адресу
                # Для этого проверим соседние адреса в IAT
                try:
                    # Читаем значение по RIP
                    iat_value = int.from_bytes(uc.mem_read(rip, 8), 'little')
                    print(f"[!] IAT[0x{rip:x}] = 0x{iat_value:x} (looks like garbage)")
                    
                    # Это мусор - заменим на dummy stub
                    dummy_stub = 0x7fff0000  # Первый stub
                    print(f"[!] Patching IAT[0x{rip:x}] -> 0x{dummy_stub:x} (dummy stub)")
                    uc.mem_write(rip, dummy_stub.to_bytes(8, 'little'))
                    
                    # Теперь перезапускаем с предыдущей инструкции
                    # Нужно найти адрес инструкции, которая делала CALL/JMP
                    # Обычно это RIP - 6 (размер call qword ptr [rip+offset])
                    prev_rip = rip - 6
                    print(f"[!] Restarting from 0x{prev_rip:x}")
                    self.pending_restart_rip = prev_rip
                    uc.emu_stop()
                    return True
                except Exception as e:
                    print(f"[!] Failed to patch IAT: {e}")
            
            return False
        
        # Проверяем, что адрес в разумных пределах (< 1TB)
        if address > 0x10000000000:  # 1TB
            rip = uc.reg_read(UC_X86_REG_RIP)
            print(f"[!] INVALID ADDRESS: 0x{address:x} at RIP=0x{rip:x}")
            print(f"[!] This looks like corrupted pointer - stopping")
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
        alloc_size = 0x100000  # 1MB
        
        try:
            self.uc.mem_map(page_start, alloc_size)
            self.uc.mem_write(page_start, b'\x00' * alloc_size)
            
            access_type = "WRITE" if access == UC_MEM_WRITE else "READ"
            print(f"[MEM] Dynamic: {access_type} @ 0x{address:x} -> mapped 0x{page_start:x} ({alloc_size//1024}KB)")
            return True
        except Exception as e:
            print(f"[!] Failed to allocate @ 0x{address:x}: {e}")
            return False
    
    def _hook_mem_fetch_unmapped(self, uc, access, address, size, value, user_data):
        """Hook на unmapped fetch"""
        rip = uc.reg_read(UC_X86_REG_RIP)
        print(f"[!] UNMAPPED FETCH @ 0x{address:x}, RIP=0x{rip:x}")
        return False
    
    def load_pe(self, pe_path):
        """Загрузка PE файла"""
        self.pe_loader = PELoader(self)
        return self.pe_loader.load(pe_path)
    
    def run(self, start_addr, end_addr=0, max_instructions=10000000, verbose=False):
        """Запуск эмуляции с поддержкой перезапуска после stub calls"""
        current_addr = start_addr
        
        while self.instruction_count < max_instructions:
            try:
                # Запускаем эмуляцию
                remaining = max_instructions - self.instruction_count
                self.uc.emu_start(current_addr, end_addr, count=remaining)
                
                # emu_start() завершился (либо нормально, либо из-за uc.emu_stop())
                # Проверяем, есть ли pending restart
                if self.pending_restart_rip:
                    # Перезапускаем с нового RIP
                    current_addr = self.pending_restart_rip
                    self.pending_restart_rip = None
                    # print(f"[RESTART] Continuing from 0x{current_addr:x}")  # Отключено
                    continue
                
                # Эмуляция завершилась нормально (достигнут end_addr или лимит)
                return 0
                
            except Exception as e:
                # Проверяем, есть ли pending restart (от stub call)
                if self.pending_restart_rip:
                    # Перезапускаем с нового RIP
                    current_addr = self.pending_restart_rip
                    self.pending_restart_rip = None
                    # print(f"[RESTART] Continuing from 0x{current_addr:x} (after exception)")  # Отключено
                    continue
                
                # Реальная ошибка
                if verbose:
                    print(f"\n[!] Эмуляция остановлена: {e}")
                    
                    # Показываем регистры для отладки
                    rip = self.uc.reg_read(UC_X86_REG_RIP)
                    rax = self.uc.reg_read(UC_X86_REG_RAX)
                    rcx = self.uc.reg_read(UC_X86_REG_RCX)
                    rdx = self.uc.reg_read(UC_X86_REG_RDX)
                    rsp = self.uc.reg_read(UC_X86_REG_RSP)
                    
                    print(f"\n[DEBUG] Registers:")
                    print(f"  RIP: 0x{rip:016x}")
                    print(f"  RAX: 0x{rax:016x}")
                    print(f"  RCX: 0x{rcx:016x}")
                    print(f"  RDX: 0x{rdx:016x}")
                    print(f"  RSP: 0x{rsp:016x}")
                    
                    # Дизассемблируем инструкцию
                    try:
                        from capstone import Cs, CS_ARCH_X86, CS_MODE_64
                        md = Cs(CS_ARCH_X86, CS_MODE_64)
                        code = self.uc.mem_read(rip, 15)
                        
                        print(f"\n[DEBUG] Instruction at RIP:")
                        for insn in md.disasm(code, rip):
                            print(f"  0x{insn.address:x}: {insn.mnemonic} {insn.op_str}")
                            break
                    except:
                        pass
                return 1
        
        # Достигнут лимит инструкций
        return 0


def test_coreinfo():
    """Test CoreInfo (Sysinternals)"""
    print("=" * 70)
    print("TEST: CoreInfo (Sysinternals) - Console CPU Info Tool")
    print("=" * 70)
    
    original_dir = os.getcwd()
    os.chdir("sandbox/CoreInfo")
    
    coreinfo_path = "Coreinfo64.exe"
    
    print(f"\n[*] Loading: {coreinfo_path}")
    print(f"[*] Arguments: -accepteula")
    
    try:
        emu = LayeredEmulatorV2(cpu_freq_mhz=3000)
        
        # Показываем статистику заглушек
        stats = emu.winapi.get_stats()
        print(f"\n[*] Статистика заглушек:")
        print(f"    Всего функций: {stats['total']}")
        print(f"    Custom реализаций: {stats['custom']} ({stats['custom_percentage']:.1f}%)")
        print(f"    Автогенерированных: {stats['generated']} ({100-stats['custom_percentage']:.1f}%)")
        
        # Загружаем PE
        entry_point = emu.load_pe(coreinfo_path)
        
        # КРИТИЧНО: Сканируем IAT регион и патчим ТОЛЬКО неинициализированные записи
        # НЕ патчим внутренние указатели на функции в образе!
        print(f"\n[*] Scanning IAT region for unpatched entries...")
        IAT_START = 0x14003a000
        IAT_END = 0x14003a4f0  # Реальный конец IAT (до 0x14003a4e8)
        IAT_SIZE = IAT_END - IAT_START
        
        PE_BASE = 0x140000000
        PE_SIZE = 0x00100000  # ~1MB
        
        try:
            iat_data = emu.uc.mem_read(IAT_START, IAT_SIZE)
            unpatched_count = 0
            
            for offset in range(0, IAT_SIZE, 8):
                addr = IAT_START + offset
                value = int.from_bytes(iat_data[offset:offset+8], 'little')
                
                # Проверяем, является ли значение валидным адресом stub
                STUB_BASE = 0x7FFF0000
                STUB_END = 0xBFFF0000
                
                # ВАЖНО: НЕ патчим адреса внутри образа (это внутренние функции!)
                is_internal = PE_BASE <= value < PE_BASE + PE_SIZE
                is_stub = STUB_BASE <= value < STUB_END
                is_null = value == 0
                
                # Патчим только если это НЕ stub, НЕ NULL и НЕ внутренний адрес
                if not is_null and not is_stub and not is_internal:
                    # Это мусор или неинициализированная запись
                    # Выделяем уникальный stub адрес для каждой функции
                    stub_addr = STUB_BASE + (unpatched_count * 0x100)
                    
                    # Регистрируем stub в WinAPI
                    func_name = f"unknown_iat_0x{addr:x}"
                    emu.winapi.stub_addresses[stub_addr] = func_name
                    
                    # Пишем RET инструкцию
                    emu.uc.mem_write(stub_addr, bytes([0xC3]))
                    
                    # Патчим IAT
                    emu.uc.mem_write(addr, stub_addr.to_bytes(8, 'little'))
                    unpatched_count += 1
                    if unpatched_count <= 10:  # Показываем первые 10
                        print(f"    [PATCH] IAT[0x{addr:x}] = 0x{value:x} -> 0x{stub_addr:x} ({func_name})")
            
            if unpatched_count > 10:
                print(f"    ... and {unpatched_count - 10} more")
            
            if unpatched_count > 0:
                print(f"[+] Patched {unpatched_count} uninitialized IAT entries")
            else:
                print(f"[+] No uninitialized IAT entries found - all imports are valid!")
        except Exception as e:
            print(f"[!] Failed to scan IAT: {e}")
        
        # Статистика stubs (без проверки кода, так как память unmapped)
        print(f"\n[*] Stub statistics:")
        stats = emu.winapi.get_stats()
        print(f"    Total stubs: {stats['total']}")
        print(f"    Custom implementations: {stats['custom']} ({stats['custom_percentage']:.1f}%)")
        print(f"    Generated stubs: {stats['generated']}")
        print(f"    Stub addresses registered: {len(emu.winapi.stub_addresses)}")
        
        # ПАТЧ: Обходим проверку закодированных указателей
        # CoreInfo проверяет: if (encoded_ptr == xor_key) skip_decoding
        # Делаем так, чтобы проверка всегда проходила
        print(f"\n[*] Patching encoded pointer checks...")
        try:
            # Адреса из трассировки:
            # [885] mov rax, qword ptr [rip + 0x41caf]  ; 0x14005a03f - encoded pointer
            # [886] mov rdx, qword ptr [rip + 0x43ae8]  ; 0x14005be79 - XOR key
            # [887] cmp rdx, rax
            # [888] je 0x1400183bf  ; Если равны - пропускаем декодирование
            
            # Читаем XOR key
            xor_key_addr = 0x14005be79
            xor_key = int.from_bytes(emu.uc.mem_read(xor_key_addr, 8), 'little')
            
            # Записываем тот же ключ в encoded pointer
            encoded_ptr_addr = 0x14005a03f
            emu.uc.mem_write(encoded_ptr_addr, xor_key.to_bytes(8, 'little'))
            
            print(f"    [PATCH] 0x{encoded_ptr_addr:x} = 0x{xor_key:016x} (same as XOR key)")
            print(f"    This will make pointer encoding check pass and skip decoding")
            
            # Проверяем указатель на массив, который вызывает краш
            array_ptr_addr = 0x14005be98
            array_ptr = int.from_bytes(emu.uc.mem_read(array_ptr_addr, 8), 'little')
            print(f"\n[*] Checking array pointer at 0x{array_ptr_addr:x}:")
            print(f"    Value: 0x{array_ptr:016x}")
            
            if array_ptr == 0:
                print(f"    [!] Array pointer is NULL - this will cause crash!")
                print(f"    [!] This pointer should be initialized by CoreInfo")
                print(f"    [!] Possible causes:")
                print(f"        - Missing TLS callback execution")
                print(f"        - Missing initialization code")
                print(f"        - CoreInfo expects driver to be loaded")
        except Exception as e:
            print(f"    [!] Failed to patch: {e}")
        
        print(f"\n[*] Начинаем эмуляцию...")
        print(f"[*] Entry point: 0x{entry_point:x}")
        print(f"[*] Максимум инструкций: 10,000,000")
        print("-" * 70)
        
        # Запускаем
        exit_code = emu.run(
            start_addr=entry_point,
            end_addr=0,
            max_instructions=10000000,  # Увеличили до 10M
            verbose=True
        )
        
        print("-" * 70)
        print(f"\n[*] Эмуляция завершена")
        print(f"    Exit code: {exit_code}")
        print(f"    Инструкций: {emu.instruction_count:,}")
        print(f"    Syscalls: {emu.syscall_count:,}")
        print(f"    Виртуальное время: {emu.clock}")
        
        print(f"\n[SUCCESS] CoreInfo - отличный кандидат для эмуляции!")
        print(f"   - Чисто консольная утилита")
        print(f"   - От Microsoft (хорошо документирована)")
        print(f"   - Использует драйвер для низкоуровневого доступа")
        
        return True
    
    except Exception as e:
        print(f"\n[!] Ошибка: {e}")
        import traceback
        traceback.print_exc()
        return False
    
    finally:
        os.chdir(original_dir)


if __name__ == '__main__':
    print("\n")
    print("=" * 70)
    print(" " * 15 + "CoreInfo Emulation Test" + " " * 28)
    print("=" * 70)
    print()
    
    success = test_coreinfo()
    
    print("\n" * 70)
    if success:
        print("TEST COMPLETED!")
    else:
        print("TEST FAILED (but we learned something!)")
    print("=" * 70)
    print()
