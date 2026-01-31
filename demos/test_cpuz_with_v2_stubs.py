#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Тест CPU-Z с новой системой заглушек (winapi_stubs_v2)

Использует 442 автогенерированные заглушки + 11 custom реализаций
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
        
        # RDTSC memory
        try:
            self.uc.mem_map(0x3b9b0000, 0x100000)
            self.uc.mem_write(0x3b9b0000, b'\x00' * 0x100000)
        except:
            pass
        
        # Stub memory - ВАЖНО: выделяем ДО создания WinAPIStubsV2!
        # Выделяем 1GB для всех заглушек (основных + dummy)
        STUB_BASE = 0x7FFF0000
        STUB_SIZE = 0x40000000  # 1GB - с запасом для всех заглушек
        self.uc.mem_map(STUB_BASE, STUB_SIZE)
        print(f"[MEM] Allocated {STUB_SIZE//(1024*1024)}MB at 0x{STUB_BASE:x} for stubs")
        
        # Новая система заглушек! (ПОСЛЕ выделения памяти)
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
        
        # Hook на каждую инструкцию
        self.uc.hook_add(UC_HOOK_CODE, self._hook_code)
        
        # Hook на unmapped memory - РАЗДЕЛЬНО для read/write!
        self.uc.hook_add(UC_HOOK_MEM_READ_UNMAPPED, self._hook_mem_unmapped)
        self.uc.hook_add(UC_HOOK_MEM_WRITE_UNMAPPED, self._hook_mem_unmapped)
        
        # Hook на unmapped fetch (для заглушек!)
        self.uc.hook_add(UC_HOOK_MEM_FETCH_UNMAPPED, self._hook_mem_fetch_unmapped)
        
        # Hook на INT (для INT3 в заглушках!)
        self.uc.hook_add(UC_HOOK_INTR, self._hook_interrupt)
        
        # Hook на RDTSC
        try:
            self.uc.hook_add(UC_HOOK_INSN, self._hook_rdtsc, None, 1, 0, UC_X86_INS_RDTSC)
        except:
            pass
        
        # Hook на SYSCALL
        try:
            self.uc.hook_add(UC_HOOK_INSN, self._hook_syscall, None, 1, 0, UC_X86_INS_SYSCALL)
        except:
            pass
    
    def _hook_code(self, uc, address, size, user_data):
        """Hook на каждую инструкцию"""
        self.instruction_count += 1
        
        # Проверяем, не в области заглушек ли мы
        STUB_BASE = 0x7FFF0000
        STUB_SIZE = 0x40000000  # 1GB
        if STUB_BASE <= address < STUB_BASE + STUB_SIZE:
            # Вызываем обработчик заглушки
            self.winapi.handle_stub_call(address)
            return
        
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
        
        # Пропускаем инструкцию RDTSC
        rip = uc.reg_read(UC_X86_REG_RIP)
        uc.reg_write(UC_X86_REG_RIP, rip + 2)
    
    def _hook_syscall(self, uc, user_data):
        """Hook на SYSCALL"""
        self.syscall_count += 1
        syscall_num = uc.reg_read(UC_X86_REG_RAX)
        self.os.handle_syscall(syscall_num)
    
    def _hook_interrupt(self, uc, intno, user_data):
        """Hook на INT - обрабатываем INT3 в заглушках"""
        rip = uc.reg_read(UC_X86_REG_RIP)
        
        if intno == 0x03:
            # INT3 - breakpoint, используется в заглушках
            STUB_BASE = 0x7FFF0000
            STUB_SIZE = 0x40000000  # 1GB
            if STUB_BASE <= rip < STUB_BASE + STUB_SIZE:
                # Это наша заглушка! Вызываем обработчик
                self.winapi.handle_stub_call(rip)
                # Возвращаемся из функции: pop return address and jump
                rsp = uc.reg_read(UC_X86_REG_RSP)
                ret_addr = int.from_bytes(uc.mem_read(rsp, 8), 'little')
                uc.reg_write(UC_X86_REG_RSP, rsp + 8)
                uc.reg_write(UC_X86_REG_RIP, ret_addr)
                return
        
        # Неизвестное прерывание - игнорируем
        print(f"[INT 0x{intno:02x}] @ 0x{rip:x} - skipped")
        uc.reg_write(UC_X86_REG_RIP, rip + 2)  # Пропускаем INT инструкцию
    
    def _hook_mem_unmapped(self, uc, access, address, size, value, user_data):
        """Hook на unmapped memory - динамическое выделение"""
        from unicorn import UC_MEM_WRITE, UC_MEM_READ
        
        rip = uc.reg_read(UC_X86_REG_RIP)
        
        # Проверяем, не stub region ли это (там уже выделено)
        STUB_BASE = 0x7FFF0000
        STUB_SIZE = 0x40000000
        if STUB_BASE <= address < STUB_BASE + STUB_SIZE:
            # Это stub region - не должно быть unmapped
            print(f"[!] CRITICAL: Unmapped in stub region @ 0x{address:x}")
            return False
        
        # Проверяем, не NULL pointer ли это
        if address < 0x10000:
            print(f"[!] NULL pointer access @ 0x{address:x}, RIP=0x{rip:x}")
            # Выделяем zero page для NULL pointer dereference
            try:
                self.uc.mem_map(0x0, 0x10000)
                self.uc.mem_write(0x0, b'\x00' * 0x10000)
                print(f"[MEM] Mapped zero page at 0x0")
                return True
            except:
                return False
        
        # Динамическое выделение памяти!
        # Выравниваем адрес на границу страницы (4KB)
        page_size = 0x1000
        page_start = (address // page_size) * page_size
        
        # Выделяем 1MB (256 страниц) для запаса
        alloc_size = 0x100000  # 1MB
        
        try:
            self.uc.mem_map(page_start, alloc_size)
            # Заполняем нулями
            self.uc.mem_write(page_start, b'\x00' * alloc_size)
            
            access_type = "WRITE" if access == UC_MEM_WRITE else "READ"
            print(f"[MEM] Dynamic allocation: {access_type} @ 0x{address:x} -> mapped 0x{page_start:x} ({alloc_size//1024}KB)")
            
            # Продолжаем выполнение
            return True
            
        except Exception as e:
            print(f"\n[!] FAILED to allocate memory!")
            print(f"    Address: 0x{address:x}")
            print(f"    Page: 0x{page_start:x}")
            print(f"    Size: {alloc_size//1024}KB")
            print(f"    RIP: 0x{rip:x}")
            print(f"    Error: {e}")
            
            # Показываем регистры для отладки
            print(f"    RAX: 0x{uc.reg_read(UC_X86_REG_RAX):x}")
            print(f"    RCX: 0x{uc.reg_read(UC_X86_REG_RCX):x}")
            print(f"    RDX: 0x{uc.reg_read(UC_X86_REG_RDX):x}")
            print(f"    RSP: 0x{uc.reg_read(UC_X86_REG_RSP):x}")
            
            return False  # Останавливаем эмуляцию
    
    def _hook_mem_fetch_unmapped(self, uc, access, address, size, value, user_data):
        """Hook на unmapped fetch - для заглушек"""
        STUB_BASE = 0x7FFF0000
        STUB_SIZE = 0x40000000  # 1GB
        
        # Проверяем, не заглушка ли это
        if STUB_BASE <= address < STUB_BASE + STUB_SIZE:
            # Это заглушка! Обрабатываем её
            self.winapi.handle_stub_call(address)
            return True  # Продолжаем выполнение
        
        # Не заглушка - показываем ошибку
        rip = uc.reg_read(UC_X86_REG_RIP)
        print(f"\n[!] UNMAPPED FETCH!")
        print(f"    Address: 0x{address:x}")
        print(f"    RIP: 0x{rip:x}")
        return False
    
    def load_pe(self, pe_path):
        """Загрузка PE файла"""
        self.pe_loader = PELoader(self)  # Передаём весь эмулятор
        return self.pe_loader.load(pe_path)
    
    def run(self, start_addr, end_addr=0, max_instructions=1000000, verbose=False):
        """Запуск эмуляции с автоматическим выделением памяти"""
        while True:
            try:
                self.uc.emu_start(start_addr, end_addr, count=max_instructions)
                # Успешно завершилось
                return 0
                
            except Exception as e:
                error_str = str(e)
                
                # Проверяем, не access violation ли это
                if "access violation" in error_str:
                    # Извлекаем адрес из сообщения об ошибке
                    # Формат: "access violation writing 0x00000279BFC05000"
                    import re
                    match = re.search(r'0x([0-9a-fA-F]+)', error_str)
                    if match:
                        address = int(match.group(1), 16)
                        
                        # ДЕТАЛЬНОЕ ЛОГИРОВАНИЕ
                        print(f"\n{'='*70}")
                        print(f"ACCESS VIOLATION DETECTED")
                        print(f"{'='*70}")
                        print(f"Address: 0x{address:x}")
                        print(f"Error: {error_str}")
                        print(f"Instruction count: {self.instruction_count:,}")
                        
                        # Читаем все регистры
                        rip = self.uc.reg_read(UC_X86_REG_RIP)
                        rax = self.uc.reg_read(UC_X86_REG_RAX)
                        rbx = self.uc.reg_read(UC_X86_REG_RBX)
                        rcx = self.uc.reg_read(UC_X86_REG_RCX)
                        rdx = self.uc.reg_read(UC_X86_REG_RDX)
                        rsi = self.uc.reg_read(UC_X86_REG_RSI)
                        rdi = self.uc.reg_read(UC_X86_REG_RDI)
                        rbp = self.uc.reg_read(UC_X86_REG_RBP)
                        rsp = self.uc.reg_read(UC_X86_REG_RSP)
                        r8 = self.uc.reg_read(UC_X86_REG_R8)
                        r9 = self.uc.reg_read(UC_X86_REG_R9)
                        r10 = self.uc.reg_read(UC_X86_REG_R10)
                        r11 = self.uc.reg_read(UC_X86_REG_R11)
                        r12 = self.uc.reg_read(UC_X86_REG_R12)
                        r13 = self.uc.reg_read(UC_X86_REG_R13)
                        r14 = self.uc.reg_read(UC_X86_REG_R14)
                        r15 = self.uc.reg_read(UC_X86_REG_R15)
                        
                        print(f"\nRegisters at RIP=0x{rip:x}:")
                        print(f"  RAX: 0x{rax:016x}  RBX: 0x{rbx:016x}")
                        print(f"  RCX: 0x{rcx:016x}  RDX: 0x{rdx:016x}")
                        print(f"  RSI: 0x{rsi:016x}  RDI: 0x{rdi:016x}")
                        print(f"  RBP: 0x{rbp:016x}  RSP: 0x{rsp:016x}")
                        print(f"  R8:  0x{r8:016x}  R9:  0x{r9:016x}")
                        print(f"  R10: 0x{r10:016x}  R11: 0x{r11:016x}")
                        print(f"  R12: 0x{r12:016x}  R13: 0x{r13:016x}")
                        print(f"  R14: 0x{r14:016x}  R15: 0x{r15:016x}")
                        
                        # Дизассемблируем инструкцию
                        try:
                            from capstone import Cs, CS_ARCH_X86, CS_MODE_64
                            md = Cs(CS_ARCH_X86, CS_MODE_64)
                            code = self.uc.mem_read(rip, 15)
                            
                            print(f"\nInstruction at RIP:")
                            for insn in md.disasm(code, rip):
                                print(f"  0x{insn.address:x}: {insn.mnemonic} {insn.op_str}")
                                
                                # Анализируем операнды
                                if '[' in insn.op_str:
                                    print(f"  -> Memory access detected: {insn.op_str}")
                                    
                                    # Пытаемся понять, какой регистр используется
                                    for reg_name in ['rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'rbp', 'rsp',
                                                    'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15']:
                                        if reg_name in insn.op_str.lower():
                                            reg_val = self.uc.reg_read(getattr(UC_X86_REG, reg_name.upper()))
                                            print(f"  -> {reg_name.upper()} = 0x{reg_val:x}")
                                
                                break  # Только первая инструкция
                        except Exception as disasm_error:
                            print(f"  Cannot disassemble: {disasm_error}")
                        
                        # Читаем стек
                        print(f"\nStack (top 8 values):")
                        try:
                            for i in range(8):
                                stack_addr = rsp + (i * 8)
                                stack_val = int.from_bytes(self.uc.mem_read(stack_addr, 8), 'little')
                                print(f"  [RSP+0x{i*8:02x}] 0x{stack_addr:x} = 0x{stack_val:016x}")
                        except:
                            print(f"  Cannot read stack")
                        
                        print(f"{'='*70}\n")
                        
                        # Проверяем, что адрес в разумных пределах (< 48 бит)
                        MAX_ADDRESS = 0xFFFFFFFFFFFF  # 48 бит
                        if address > MAX_ADDRESS:
                            print(f"[!] Address 0x{address:x} is too large (> 48 bits)")
                            print(f"[!] This is likely a bug or invalid pointer")
                            print(f"[!] Stopping emulation for analysis")
                            return 1
                        
                        # Динамически выделяем память
                        page_size = 0x1000
                        page_start = (address // page_size) * page_size
                        alloc_size = 0x100000  # 1MB
                        
                        try:
                            self.uc.mem_map(page_start, alloc_size)
                            self.uc.mem_write(page_start, b'\x00' * alloc_size)
                            
                            print(f"[MEM] Dynamic allocation: @ 0x{address:x} -> mapped 0x{page_start:x} ({alloc_size//1024}KB)")
                            
                            # Продолжаем выполнение с того же места
                            start_addr = rip
                            max_instructions -= self.instruction_count
                            
                            if max_instructions <= 0:
                                print(f"[!] Instruction limit reached")
                                return 1
                            
                            # Продолжаем цикл - попробуем снова
                            continue
                            
                        except Exception as alloc_error:
                            print(f"[!] Failed to allocate memory @ 0x{page_start:x}: {alloc_error}")
                            return 1
                
                # Другая ошибка - выходим
                if verbose:
                    print(f"\n[!] Эмуляция остановлена: {e}")
                return 1


def test_cpuz_with_v2():
    """Test CPU-Z with new stubs"""
    print("=" * 70)
    print("TEST: CPU-Z with WinAPIStubsV2 (442 functions)")
    print("=" * 70)
    
    original_dir = os.getcwd()
    os.chdir("sandbox/CPU-Z")
    
    cpuz_path = "cpuz.exe"
    report_path = "report.txt"
    
    # Удаляем старый отчёт
    if os.path.exists(report_path):
        os.remove(report_path)
    
    print(f"\n[*] Loading: {cpuz_path}")
    print(f"[*] Arguments: -txt=report")
    
    try:
        emu = LayeredEmulatorV2(cpu_freq_mhz=3000)
        
        # Показываем статистику заглушек
        stats = emu.winapi.get_stats()
        print(f"\n[*] Статистика заглушек:")
        print(f"    Всего функций: {stats['total']}")
        print(f"    Custom реализаций: {stats['custom']} ({stats['custom_percentage']:.1f}%)")
        print(f"    Автогенерированных: {stats['generated']} ({100-stats['custom_percentage']:.1f}%)")
        
        # Патчим GetCommandLineW
        def patched_get_command_line_w():
            cmd_line = "cpuz.exe -txt=report\x00".encode('utf-16le')
            ptr = emu.os.HeapAlloc(emu.os.heap.process_heap, 0, len(cmd_line))
            emu.uc.mem_write(ptr, cmd_line)
            emu.uc.reg_write(UC_X86_REG_RAX, ptr)
            print(f"[API] GetCommandLineW() -> 0x{ptr:x} [PATCHED]")
            return ptr
        
        # Регистрируем патч как custom
        emu.winapi.registry.register_custom('getcommandlinew', patched_get_command_line_w)
        
        # Загружаем PE
        entry_point = emu.load_pe(cpuz_path)
        
        print(f"\n[*] Начинаем эмуляцию...")
        print(f"[*] Entry point: 0x{entry_point:x}")
        print(f"[*] Максимум инструкций: 5,000,000")
        print("-" * 70)
        
        # Запускаем
        exit_code = emu.run(
            start_addr=entry_point,
            end_addr=0,
            max_instructions=5000000,
            verbose=True  # Включаем детальный вывод для отладки
        )
        
        print("-" * 70)
        print(f"\n[*] Эмуляция завершена")
        print(f"    Exit code: {exit_code}")
        print(f"    Инструкций: {emu.instruction_count:,}")
        print(f"    Syscalls: {emu.syscall_count:,}")
        print(f"    Виртуальное время: {emu.clock}")
        
        # Проверяем отчёт
        print(f"\n[*] Проверяем отчёт...")
        
        if os.path.exists(report_path):
            file_size = os.path.getsize(report_path)
            print(f"[✓] Отчёт создан: {report_path} ({file_size} байт)")
            
            with open(report_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                print(f"\n[*] Содержимое (первые 500 символов):")
                print("-" * 70)
                print(content[:500])
                print("-" * 70)
            
            print(f"\n✅ УСПЕХ! CPU-Z сгенерировал отчёт с новыми заглушками!")
            return True
        else:
            print(f"[!] Отчёт не создан")
            print(f"[*] Возможные причины:")
            print(f"    - Программа застряла на unmapped memory")
            print(f"    - Не хватает реализаций критичных функций")
            print(f"    - Нужны дополнительные custom заглушки")
            return False
    
    except Exception as e:
        print(f"\n[!] Ошибка: {e}")
        import traceback
        traceback.print_exc()
        return False
    
    finally:
        os.chdir(original_dir)


def compare_with_old_version():
    """Comparison: Old vs New stub system"""
    print("\n" + "=" * 70)
    print("COMPARISON: Old vs New stub system")
    print("=" * 70)
    
    print("\nOld system (winapi_stubs.py):")
    print("    - ~100 manual stubs")
    print("    - Each function written by hand")
    print("    - Hard to add new functions")
    print("    - CPU-Z stuck at ~2M instructions")
    
    print("\nNew system (winapi_stubs_v2.py):")
    print("    - 442 auto-generated stubs")
    print("    - 11 critical custom implementations (2.5%)")
    print("    - Easy to add new (regeneration)")
    print("    - Coverage: kernel32, advapi32, DirectX")
    
    print("\nExpected result:")
    print("    - More functions = fewer unmapped calls")
    print("    - CPU-Z should progress further")
    print("    - Possibly reach report generation")


if __name__ == '__main__':
    print("\n")
    print("=" * 70)
    print(" " * 15 + "CPU-Z with new stubs" + " " * 28)
    print("=" * 70)
    print()
    
    compare_with_old_version()
    
    print("\n" + "=" * 70)
    print("Starting test...")
    print()
    
    success = test_cpuz_with_v2()
    
    print("\n" + "=" * 70)
    if success:
        print("TEST PASSED!")
    else:
        print("TEST NOT COMPLETED (but progress made!)")
    print("=" * 70)
    print()
