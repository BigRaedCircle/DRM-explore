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
        
        # WinAPI заглушки
        self.winapi = WinAPIStubs(self)
        
        # PE Loader
        self.pe_loader = None
        
        # Настройка хуков
        self._setup_hooks()
        
        # Выделение памяти для стека
        self.STACK_BASE = 0x00100000
        self.STACK_SIZE = 0x00100000  # 1 МБ
        self.uc.mem_map(self.STACK_BASE, self.STACK_SIZE)
        self.uc.reg_write(UC_X86_REG_RSP, self.STACK_BASE + self.STACK_SIZE - 0x1000)
        
        # Выделение памяти для заглушек WinAPI
        self.uc.mem_map(self.winapi.STUB_BASE, 0x10000)
    
    def _setup_hooks(self):
        """Настроить хуки для перехвата инструкций"""
        # Хук на каждую инструкцию (для подсчёта тактов и перехвата RDTSC)
        self.uc.hook_add(UC_HOOK_CODE, self._hook_instruction)
    
    def _hook_instruction(self, uc, address, size, user_data):
        """Хук на каждую инструкцию — продвигаем виртуальное время"""
        self.clock.advance(1)
        self.instruction_count += 1
        
        # Читаем инструкцию для проверки на RDTSC
        try:
            code = uc.mem_read(address, min(size, 15))
            
            # RDTSC = 0x0F 0x31
            if len(code) >= 2 and code[0] == 0x0F and code[1] == 0x31:
                self._handle_rdtsc(uc)
        except:
            pass
    
    def _handle_rdtsc(self, uc):
        """Обработка RDTSC"""
        ticks = self.clock.rdtsc()
        
        # RDTSC возвращает значение в EDX:EAX
        eax = ticks & 0xFFFFFFFF
        edx = (ticks >> 32) & 0xFFFFFFFF
        
        uc.reg_write(UC_X86_REG_RAX, eax)
        uc.reg_write(UC_X86_REG_RDX, edx)
        
        print(f"[RDTSC] @ 0x{uc.reg_read(UC_X86_REG_RIP):x} -> {ticks} тактов")
    
    def load_pe(self, pe_path):
        """Загрузить PE-файл"""
        print(f"\n[*] Загрузка PE: {pe_path}")
        
        self.pe_loader = PELoader(self)
        entry_point = self.pe_loader.load(pe_path)
        
        print(f"[*] Entry point: 0x{entry_point:x}")
        print(f"[*] Image base: 0x{self.pe_loader.image_base:x}")
        
        return entry_point
    
    def load_code(self, code, base_addr=0x400000):
        """Загрузить машинный код напрямую"""
        # Выделяем память
        code_size = ((len(code) + 0xFFF) // 0x1000) * 0x1000  # Выравнивание по 4KB
        self.uc.mem_map(base_addr, code_size)
        
        # Записываем код
        self.uc.mem_write(base_addr, code)
        
        return base_addr
    
    def run(self, start_addr, end_addr=0, max_instructions=100000):
        """Запустить эмуляцию"""
        print(f"\n[*] Запуск эмуляции с адреса 0x{start_addr:x}")
        print(f"[*] Начальное состояние: {self.clock}")
        print("-" * 70)
        
        try:
            # Устанавливаем RIP
            self.uc.reg_write(UC_X86_REG_RIP, start_addr)
            
            # Запускаем эмуляцию
            self.uc.emu_start(start_addr, end_addr, count=max_instructions)
            
        except UcError as e:
            print(f"\n[!] Ошибка эмуляции: {e}")
            print(f"[!] RIP: 0x{self.uc.reg_read(UC_X86_REG_RIP):x}")
        
        print("-" * 70)
        print(f"\n[*] Эмуляция завершена")
        print(f"[*] Конечное состояние: {self.clock}")
        print(f"[*] Инструкций выполнено: {self.instruction_count:,}")
        print(f"[*] Системных вызовов: {self.syscall_count}")
        
        # Возвращаем RAX (код возврата)
        return self.uc.reg_read(UC_X86_REG_RAX)


if __name__ == "__main__":
    print("Layered Emulator — расслоенная эмуляция с WinAPI")
    print("\nИспользование:")
    print("  from layered_emulator import LayeredEmulator")
    print("  emu = LayeredEmulator()")
    print("  entry = emu.load_pe('demo.exe')")
    print("  emu.run(entry)")
