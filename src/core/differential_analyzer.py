#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Differential Analyzer — автоматическая локализация проверок защиты

Ключевая идея: Два идентичных эмулятора с разными входными параметрами
→ пошаговое сравнение → локализация точки расхождения.
"""

import sys
sys.path.insert(0, '.')

from simple_emulator import SimpleEmulator
from unicorn.x86_const import *


class DifferentialAnalyzer:
    """Дифференциальный анализатор для локализации проверок"""
    
    def __init__(self, cpu_freq_mhz=3000):
        # Два идентичных эмулятора с ОДНИМ VirtualClock
        self.emu_a = SimpleEmulator(cpu_freq_mhz)
        self.emu_b = SimpleEmulator(cpu_freq_mhz)
        
        # Общий clock для синхронизации
        from virtual_clock import VirtualClock
        shared_clock = VirtualClock(cpu_freq_mhz)
        self.emu_a.clock = shared_clock
        self.emu_b.clock = shared_clock
        
        # История выполнения
        self.trace_a = []
        self.trace_b = []
        
        # Точка расхождения
        self.divergence_point = None
    
    def load_code(self, code_a, code_b, base_addr=0x400000):
        """Загрузить код в оба эмулятора"""
        self.emu_a.load_code(code_a, base_addr)
        self.emu_b.load_code(code_b, base_addr)
        return base_addr
    
    def run_parallel(self, start_addr, max_steps=10000):
        """Запустить оба эмулятора параллельно с пошаговым сравнением"""
        print("\n" + "=" * 70)
        print("ДИФФЕРЕНЦИАЛЬНЫЙ АНАЛИЗ")
        print("=" * 70)
        print(f"\n[*] Запуск двух эмуляторов с адреса 0x{start_addr:x}")
        print(f"[*] Максимум шагов: {max_steps:,}\n")
        
        # Устанавливаем начальные адреса
        self.emu_a.uc.reg_write(UC_X86_REG_RIP, start_addr)
        self.emu_b.uc.reg_write(UC_X86_REG_RIP, start_addr)
        
        step = 0
        diverged = False
        
        while step < max_steps:
            # Получаем текущие состояния
            state_a = self._get_state(self.emu_a)
            state_b = self._get_state(self.emu_b)
            
            # Сохраняем в трейс
            self.trace_a.append(state_a)
            self.trace_b.append(state_b)
            
            # Проверяем расхождение
            if state_a['rip'] != state_b['rip'] or state_a['rax'] != state_b['rax']:
                diverged = True
                self.divergence_point = step
                print(f"\n[!] РАСХОЖДЕНИЕ ОБНАРУЖЕНО на шаге {step}")
                break
            
            # Выполняем один шаг в каждом эмуляторе
            try:
                self._step(self.emu_a)
                self._step(self.emu_b)
            except:
                # Один из эмуляторов завершился
                break
            
            step += 1
            
            # Прогресс каждые 1000 шагов
            if step % 1000 == 0:
                print(f"[*] Шаг {step:,} - состояния идентичны")
        
        if diverged:
            self._analyze_divergence()
            return True
        else:
            print(f"\n[*] Выполнено {step} шагов - расхождения не обнаружено")
            return False
    
    def _step(self, emu):
        """Выполнить один шаг эмуляции"""
        rip = emu.uc.reg_read(UC_X86_REG_RIP)
        
        # Читаем инструкцию
        try:
            code = emu.uc.mem_read(rip, 15)  # Максимум 15 байт
        except:
            raise Exception("End of execution")
        
        # Эмулируем одну инструкцию
        emu.uc.emu_start(rip, 0, count=1)
    
    def _get_state(self, emu):
        """Получить текущее состояние эмулятора"""
        return {
            'rip': emu.uc.reg_read(UC_X86_REG_RIP),
            'rax': emu.uc.reg_read(UC_X86_REG_RAX),
            'rbx': emu.uc.reg_read(UC_X86_REG_RBX),
            'rcx': emu.uc.reg_read(UC_X86_REG_RCX),
            'rdx': emu.uc.reg_read(UC_X86_REG_RDX),
            'rsi': emu.uc.reg_read(UC_X86_REG_RSI),
            'rdi': emu.uc.reg_read(UC_X86_REG_RDI),
        }
    
    def _analyze_divergence(self):
        """Анализ точки расхождения"""
        if self.divergence_point is None:
            return
        
        step = self.divergence_point
        state_a = self.trace_a[step]
        state_b = self.trace_b[step]
        
        print("\n" + "=" * 70)
        print("АНАЛИЗ ТОЧКИ РАСХОЖДЕНИЯ")
        print("=" * 70)
        
        print(f"\n[*] Шаг: {step}")
        print(f"[*] Адрес: 0x{state_a['rip']:x}")
        
        print(f"\n[ЭМУЛЯТОР A] Состояние:")
        self._print_state(state_a)
        
        print(f"\n[ЭМУЛЯТОР B] Состояние:")
        self._print_state(state_b)
        
        print(f"\n[РАЗЛИЧИЯ]:")
        for reg in ['rip', 'rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi']:
            if state_a[reg] != state_b[reg]:
                print(f"  {reg.upper()}: 0x{state_a[reg]:x} vs 0x{state_b[reg]:x}")
        
        # Контекст (предыдущие 3 шага)
        print(f"\n[КОНТЕКСТ] Предыдущие 3 шага:")
        for i in range(max(0, step-3), step):
            print(f"  Шаг {i}: RIP=0x{self.trace_a[i]['rip']:x}, RAX=0x{self.trace_a[i]['rax']:x}")
    
    def _print_state(self, state):
        """Вывести состояние регистров"""
        print(f"  RIP: 0x{state['rip']:016x}")
        print(f"  RAX: 0x{state['rax']:016x}  RBX: 0x{state['rbx']:016x}")
        print(f"  RCX: 0x{state['rcx']:016x}  RDX: 0x{state['rdx']:016x}")
        print(f"  RSI: 0x{state['rsi']:016x}  RDI: 0x{state['rdi']:016x}")


if __name__ == "__main__":
    print("Differential Analyzer — автоматическая локализация проверок защиты")
    print("\nИспользование:")
    print("  from differential_analyzer import DifferentialAnalyzer")
    print("  analyzer = DifferentialAnalyzer()")
    print("  analyzer.load_code(code_valid, code_invalid)")
    print("  analyzer.run_parallel(start_addr)")
