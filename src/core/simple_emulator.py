#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SimpleEmulator — минимальная расслоенная эмуляция с VirtualClock

Демонстрирует ключевую идею: все таймеры синхронизированы через
единый источник времени, поэтому анти-тампер не может детектировать эмуляцию.
"""

from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_HOOK_CODE, UC_HOOK_INSN, UC_HOOK_INTR
from unicorn.x86_const import *
from virtual_clock import VirtualClock
from winapi_stubs import WinAPIStubs
from mini_kernel import MiniKernel
import struct


class SimpleEmulator:
    """Минимальный эмулятор с поддержкой VirtualClock"""
    
    def __init__(self, cpu_freq_mhz=3000):
        # Инициализация Unicorn (x64)
        self.uc = Uc(UC_ARCH_X86, UC_MODE_64)
        
        # Виртуальные часы
        self.clock = VirtualClock(cpu_freq_mhz)
        
        # Выделяем память (расширенная для PE-файлов)
        self.CODE_BASE = 0x400000
        self.STACK_BASE = 0x7FFF0000
        self.STACK_SIZE = 0x100000  # 1 MB стек
        
        # Выделяем большой блок для кода (для PE-файлов)
        self.uc.mem_map(0x140000000, 64 * 1024 * 1024)  # 64 MB для PE
        self.uc.mem_map(self.CODE_BASE, 16 * 1024 * 1024)  # 16 MB для простого кода
        self.uc.mem_map(self.STACK_BASE, self.STACK_SIZE)
        
        # Инициализация стека
        self.uc.reg_write(UC_X86_REG_RSP, self.STACK_BASE + self.STACK_SIZE - 0x1000)
        self.uc.reg_write(UC_X86_REG_RBP, self.STACK_BASE + self.STACK_SIZE - 0x1000)
        
        # Минимальное ядро ОС (ПОСЛЕ выделения памяти!)
        self.kernel = MiniKernel(self)
        
        # WinAPI заглушки (ПОСЛЕ выделения памяти!)
        self.winapi = WinAPIStubs(self)
        
        # Установка хуков
        self._setup_hooks()
        
        # Статистика
        self.instructions_executed = 0
        self.syscalls_intercepted = 0
    
    def _setup_hooks(self):
        """Установка хуков для перехвата инструкций"""
        # Хук на каждую инструкцию (для подсчёта тактов)
        self.uc.hook_add(UC_HOOK_CODE, self._hook_code)
        
        # Хук на прерывания (для перехвата вызовов API)
        self.uc.hook_add(UC_HOOK_INTR, self._hook_interrupt)
        
        # Хук на RDTSC
        try:
            self.uc.hook_add(UC_HOOK_INSN, self._hook_rdtsc, arg1=UC_X86_INS_RDTSC)
        except:
            pass
        
        # Хук на SYSCALL
        try:
            self.uc.hook_add(UC_HOOK_INSN, self._hook_syscall, arg1=UC_X86_INS_SYSCALL)
        except:
            pass
    
    def _hook_interrupt(self, uc, intno, user_data):
        """Хук на прерывания (INT)"""
        # INT 3 — breakpoint (игнорируем)
        if intno == 3:
            return
        
        print(f"[INT] Прерывание {intno}")
    
    def _hook_code(self, uc, address, size, user_data):
        """Хук на каждую инструкцию — продвигаем виртуальное время"""
        # Читаем инструкцию
        try:
            code = uc.mem_read(address, min(size, 2))
            
            # Проверяем на RDTSC (0x0F 0x31)
            if len(code) >= 2 and code[0] == 0x0F and code[1] == 0x31:
                # Эмулируем RDTSC
                ticks = self.clock.rdtsc()
                eax = ticks & 0xFFFFFFFF
                edx = (ticks >> 32) & 0xFFFFFFFF
                
                uc.reg_write(UC_X86_REG_RAX, eax)
                uc.reg_write(UC_X86_REG_RDX, edx)
                
                print(f"[RDTSC] @ 0x{address:x} -> {ticks} тактов")
                
                # Пропускаем инструкцию
                uc.reg_write(UC_X86_REG_RIP, address + 2)
                
                # Латентность RDTSC
                self.clock.advance(25)
                return
        except:
            pass
        
        # Примерная стоимость инструкции в тактах (упрощённо)
        cycles = 1
        self.clock.advance(cycles)
        self.instructions_executed += 1
    
    def _hook_rdtsc(self, uc, user_data):
        """Перехват инструкции RDTSC — возвращаем виртуальные такты"""
        ticks = self.clock.rdtsc()
        
        # RDTSC возвращает 64-битное значение в EDX:EAX
        eax = ticks & 0xFFFFFFFF
        edx = (ticks >> 32) & 0xFFFFFFFF
        
        uc.reg_write(UC_X86_REG_RAX, eax)
        uc.reg_write(UC_X86_REG_RDX, edx)
        
        # Латентность RDTSC — примерно 20-30 тактов
        self.clock.advance(25)
        
        print(f"[RDTSC] Возвращено: {ticks:,} тактов")
    
    def _hook_syscall(self, uc, user_data):
        """Перехват системных вызовов"""
        # В Windows x64 системные вызовы через SYSCALL
        # Номер вызова в RAX
        syscall_num = uc.reg_read(UC_X86_REG_RAX)
        
        self.syscalls_intercepted += 1
        
        # Передаём в MiniKernel
        status = self.kernel.handle_syscall(syscall_num)
        
        # Возвращаем статус в RAX
        uc.reg_write(UC_X86_REG_RAX, status)
        
        # Пропускаем инструкцию SYSCALL
        rip = uc.reg_read(UC_X86_REG_RIP)
        uc.reg_write(UC_X86_REG_RIP, rip + 2)
    
    def _emulate_get_tick_count(self, uc):
        """Эмуляция GetTickCount64()"""
        tick_count = self.clock.get_tick_count()
        uc.reg_write(UC_X86_REG_RAX, tick_count)
        print(f"[GetTickCount64] Возвращено: {tick_count} мс")
    
    def _emulate_query_performance_counter(self, uc):
        """Эмуляция QueryPerformanceCounter()"""
        qpc = self.clock.query_performance_counter()
        uc.reg_write(UC_X86_REG_RAX, qpc)
        print(f"[QueryPerformanceCounter] Возвращено: {qpc:,}")
    
    def load_code(self, code, address=None):
        """Загрузка кода в память"""
        if address is None:
            address = self.CODE_BASE
        
        self.uc.mem_write(address, code)
        return address
    
    def run(self, start_addr, end_addr=0, timeout=0):
        """Запуск эмуляции"""
        try:
            print(f"\n[*] Запуск эмуляции с адреса 0x{start_addr:x}")
            print(f"[*] Начальное состояние: {self.clock}\n")
            
            self.uc.emu_start(start_addr, end_addr, timeout=timeout)
            
            print(f"\n[*] Эмуляция завершена")
            print(f"[*] Конечное состояние: {self.clock}")
            print(f"[*] Инструкций выполнено: {self.instructions_executed:,}")
            print(f"[*] Системных вызовов: {self.syscalls_intercepted}")
            
        except Exception as e:
            rip = self.uc.reg_read(UC_X86_REG_RIP)
            print(f"\n[!] Ошибка эмуляции на адресе 0x{rip:x}: {e}")
            raise
    
    def get_register(self, reg):
        """Получить значение регистра"""
        return self.uc.reg_read(reg)
    
    def set_register(self, reg, value):
        """Установить значение регистра"""
        self.uc.reg_write(reg, value)


def demo_simple_code():
    """Демонстрация на простом коде"""
    print("=== Демонстрация SimpleEmulator ===\n")
    
    # Простой код: RDTSC + RET
    # 0F 31       RDTSC
    # C3          RET
    code = bytes([
        0x0F, 0x31,  # RDTSC
        0xC3         # RET
    ])
    
    emu = SimpleEmulator(cpu_freq_mhz=3000)
    addr = emu.load_code(code)
    
    # Запускаем (end_addr = 0 означает выполнять до RET)
    emu.run(addr, 0)
    
    # Проверяем результат
    rax = emu.get_register(UC_X86_REG_RAX)
    rdx = emu.get_register(UC_X86_REG_RDX)
    result = (rdx << 32) | rax
    
    print(f"\n[OK] Результат RDTSC: {result:,} тактов")
    print(f"[OK] Соответствует VirtualClock: {emu.clock.rdtsc():,} тактов")


if __name__ == "__main__":
    demo_simple_code()
