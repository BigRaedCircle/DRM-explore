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

try:
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64
    CAPSTONE_AVAILABLE = True
except ImportError:
    CAPSTONE_AVAILABLE = False


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
        self.divergence_details = {}
        
        # Дизассемблер (если доступен Capstone)
        if CAPSTONE_AVAILABLE:
            self.disasm = Cs(CS_ARCH_X86, CS_MODE_64)
            self.disasm.detail = True  # Включаем детальную информацию
        else:
            self.disasm = None
    
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
        """Получить текущее состояние эмулятора (расширенное)"""
        rsp = emu.uc.reg_read(UC_X86_REG_RSP)
        
        # Читаем стек (8 значений)
        stack = []
        try:
            for i in range(8):
                val = int.from_bytes(emu.uc.mem_read(rsp + i*8, 8), 'little')
                stack.append(val)
        except:
            stack = [0] * 8
        
        return {
            'rip': emu.uc.reg_read(UC_X86_REG_RIP),
            'rax': emu.uc.reg_read(UC_X86_REG_RAX),
            'rbx': emu.uc.reg_read(UC_X86_REG_RBX),
            'rcx': emu.uc.reg_read(UC_X86_REG_RCX),
            'rdx': emu.uc.reg_read(UC_X86_REG_RDX),
            'rsi': emu.uc.reg_read(UC_X86_REG_RSI),
            'rdi': emu.uc.reg_read(UC_X86_REG_RDI),
            'rsp': rsp,
            'rbp': emu.uc.reg_read(UC_X86_REG_RBP),
            'r8': emu.uc.reg_read(UC_X86_REG_R8),
            'r9': emu.uc.reg_read(UC_X86_REG_R9),
            'stack': stack,
        }
    
    def _analyze_divergence(self):
        """Анализ точки расхождения с бинарным поиском"""
        if self.divergence_point is None:
            return
        
        step = self.divergence_point
        state_a = self.trace_a[step]
        state_b = self.trace_b[step]
        
        print("\n" + "=" * 70)
        print("АНАЛИЗ ТОЧКИ РАСХОЖДЕНИЯ")
        print("=" * 70)
        
        # Бинарный поиск первой различающейся инструкции
        first_diff = self._binary_search_divergence(step)
        if first_diff < step:
            print(f"\n[*] Бинарный поиск: первое расхождение на шаге {first_diff}")
            step = first_diff
            state_a = self.trace_a[step]
            state_b = self.trace_b[step]
        
        print(f"\n[*] Шаг: {step}")
        print(f"[*] Адрес: 0x{state_a['rip']:x}")
        
        # Дизассемблирование с расширенным контекстом
        self._disassemble_context(state_a['rip'], state_a, state_b)
        
        # Состояния регистров
        print(f"\n[ЭМУЛЯТОР A] Состояние:")
        self._print_state(state_a)
        
        print(f"\n[ЭМУЛЯТОР B] Состояние:")
        self._print_state(state_b)
        
        # Различия
        self._print_differences(state_a, state_b)
        
        # Анализ стека
        self._analyze_stack(state_a, state_b)
        
        # История выполнения
        self._print_execution_history(step)
        
        # Сохраняем детали для дальнейшего анализа
        self.divergence_details = {
            'step': step,
            'address': state_a['rip'],
            'state_a': state_a,
            'state_b': state_b,
        }
    
    def _binary_search_divergence(self, known_divergence):
        """Бинарный поиск первой точки расхождения"""
        left, right = 0, known_divergence
        
        while left < right:
            mid = (left + right) // 2
            
            # Сравниваем состояния на середине
            if self._states_equal(self.trace_a[mid], self.trace_b[mid]):
                left = mid + 1
            else:
                right = mid
        
        return left
    
    def _states_equal(self, state_a, state_b):
        """Проверка равенства состояний"""
        regs = ['rip', 'rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'rsp', 'rbp']
        return all(state_a.get(reg) == state_b.get(reg) for reg in regs)
    
    def _disassemble_context(self, addr, state_a, state_b):
        """Дизассемблирование с расширенным контекстом"""
        if not self.disasm:
            return
        
        print(f"\n[ДИЗАССЕМБЛИРОВАНИЕ] Контекст вокруг 0x{addr:x}:")
        
        # Читаем больший блок кода для контекста
        try:
            context_addr = addr - 30  # ~6-10 инструкций назад
            context_code = self.emu_a.uc.mem_read(context_addr, 90)
            
            instructions = []
            for insn in self.disasm.disasm(bytes(context_code), context_addr):
                instructions.append(insn)
                if len(instructions) >= 15:  # Ограничиваем вывод
                    break
            
            # Находим текущую инструкцию
            current_idx = None
            for i, insn in enumerate(instructions):
                if insn.address == addr:
                    current_idx = i
                    break
            
            # Выводим с маркером
            for i, insn in enumerate(instructions):
                if i == current_idx:
                    marker = " >>> "
                    color = "\033[91m"  # Красный
                    reset = "\033[0m"
                else:
                    marker = "     "
                    color = reset = ""
                
                print(f"{color}{marker}0x{insn.address:08x}: {insn.mnemonic:8} {insn.op_str}{reset}")
                
                # Дополнительная информация для критичной инструкции
                if i == current_idx and hasattr(insn, 'groups'):
                    if any(g in [1, 2, 3] for g in insn.groups):  # Jump/Call/Ret
                        print(f"       └─> Инструкция управления потоком!")
        
        except Exception as e:
            print(f"[!] Ошибка дизассемблирования: {e}")
    
    def _print_differences(self, state_a, state_b):
        """Вывод различий между состояниями"""
        print(f"\n[РАЗЛИЧИЯ]:")
        
        regs = ['rip', 'rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'rsp', 'rbp', 'r8', 'r9']
        has_diff = False
        
        for reg in regs:
            val_a = state_a.get(reg, 0)
            val_b = state_b.get(reg, 0)
            if val_a != val_b:
                has_diff = True
                diff = val_a - val_b if val_a > val_b else val_b - val_a
                print(f"  {reg.upper():4}: 0x{val_a:016x} vs 0x{val_b:016x}  (Δ = {diff})")
        
        if not has_diff:
            print("  Регистры идентичны")
    
    def _analyze_stack(self, state_a, state_b):
        """Анализ различий в стеке"""
        print(f"\n[СТЕК] RSP = 0x{state_a['rsp']:x}")
        
        stack_a = state_a.get('stack', [])
        stack_b = state_b.get('stack', [])
        
        has_diff = False
        for i, (val_a, val_b) in enumerate(zip(stack_a, stack_b)):
            if val_a != val_b:
                has_diff = True
                print(f"  [RSP+{i*8:2}] 0x{val_a:016x} vs 0x{val_b:016x}")
        
        if not has_diff:
            print("  Стек идентичен")
    
    def _print_execution_history(self, step):
        """Вывод истории выполнения"""
        print(f"\n[ИСТОРИЯ] Последние 5 шагов:")
        
        start = max(0, step - 5)
        for i in range(start, step):
            state = self.trace_a[i]
            print(f"  Шаг {i:4}: RIP=0x{state['rip']:08x}, RAX=0x{state['rax']:016x}")
    
    def _print_state(self, state):
        """Вывести состояние регистров (расширенное)"""
        print(f"  RIP: 0x{state['rip']:016x}  RSP: 0x{state.get('rsp', 0):016x}")
        print(f"  RAX: 0x{state['rax']:016x}  RBX: 0x{state['rbx']:016x}")
        print(f"  RCX: 0x{state['rcx']:016x}  RDX: 0x{state['rdx']:016x}")
        print(f"  RSI: 0x{state['rsi']:016x}  RDI: 0x{state['rdi']:016x}")
        print(f"  RBP: 0x{state.get('rbp', 0):016x}  R8:  0x{state.get('r8', 0):016x}")
        print(f"  R9:  0x{state.get('r9', 0):016x}")
    
    def export_trace(self, filename="trace.txt"):
        """Экспорт трейса выполнения в файл"""
        if not self.trace_a:
            print("[!] Нет данных для экспорта")
            return
        
        with open(filename, 'w') as f:
            f.write("DIFFERENTIAL TRACE ANALYSIS\n")
            f.write("=" * 70 + "\n\n")
            
            f.write(f"Total steps: {len(self.trace_a)}\n")
            if self.divergence_point is not None:
                f.write(f"Divergence at step: {self.divergence_point}\n")
            f.write("\n")
            
            # Экспорт трейса
            for i, (state_a, state_b) in enumerate(zip(self.trace_a, self.trace_b)):
                marker = " >>> " if i == self.divergence_point else "     "
                f.write(f"{marker}Step {i:5}: RIP=0x{state_a['rip']:08x}, RAX=0x{state_a['rax']:016x}\n")
                
                if i == self.divergence_point:
                    f.write(f"              [A] RIP=0x{state_a['rip']:08x}, RAX=0x{state_a['rax']:016x}\n")
                    f.write(f"              [B] RIP=0x{state_b['rip']:08x}, RAX=0x{state_b['rax']:016x}\n")
        
        print(f"\n[*] Трейс экспортирован в {filename}")
    
    def visualize_divergence(self, output_file="divergence.dot"):
        """Создание графа выполнения в формате DOT (Graphviz)"""
        if self.divergence_point is None:
            print("[!] Нет точки расхождения для визуализации")
            return
        
        try:
            with open(output_file, 'w') as f:
                f.write("digraph DivergenceAnalysis {\n")
                f.write("  rankdir=TB;\n")
                f.write("  node [shape=box, style=rounded];\n\n")
                
                # Узлы для ключевых шагов
                start = max(0, self.divergence_point - 5)
                end = min(len(self.trace_a), self.divergence_point + 3)
                
                for i in range(start, end):
                    state = self.trace_a[i]
                    label = f"Step {i}\\n0x{state['rip']:08x}"
                    
                    if i == self.divergence_point:
                        f.write(f'  step{i} [label="{label}", fillcolor=red, style="filled,rounded"];\n')
                    else:
                        f.write(f'  step{i} [label="{label}"];\n')
                
                # Рёбра
                for i in range(start, end - 1):
                    f.write(f"  step{i} -> step{i+1};\n")
                
                # Точка расхождения
                if self.divergence_point < len(self.trace_a):
                    state_a = self.trace_a[self.divergence_point]
                    state_b = self.trace_b[self.divergence_point]
                    
                    rip_a = state_a['rip']
                    rip_b = state_b['rip']
                    f.write(f'\n  diverge_a [label="Path A\\n0x{rip_a:08x}", fillcolor=lightblue, style=filled];\n')
                    f.write(f'  diverge_b [label="Path B\\n0x{rip_b:08x}", fillcolor=lightgreen, style=filled];\n')
                    f.write(f"  step{self.divergence_point} -> diverge_a;\n")
                    f.write(f"  step{self.divergence_point} -> diverge_b;\n")
                
                f.write("}\n")
            
            print(f"\n[*] Граф сохранён в {output_file}")
            print(f"[*] Для визуализации: dot -Tpng {output_file} -o divergence.png")
        
        except Exception as e:
            print(f"[!] Ошибка создания графа: {e}")


if __name__ == "__main__":
    print("Differential Analyzer — автоматическая локализация проверок защиты")
    print("\nИспользование:")
    print("  from differential_analyzer import DifferentialAnalyzer")
    print("  analyzer = DifferentialAnalyzer()")
    print("  analyzer.load_code(code_valid, code_invalid)")
    print("  analyzer.run_parallel(start_addr)")
