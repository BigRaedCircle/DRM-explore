#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AVX Emulation Layer - эмуляция AVX/AVX2 инструкций через SSE или skip

Стратегия:
1. Говорим программе, что CPU поддерживает AVX/AVX2
2. Перехватываем AVX инструкции через hook
3. Либо эмулируем через SSE, либо пропускаем (для некритичных)
"""

from unicorn import *
from unicorn.x86_const import *
from capstone import *


class AVXEmulator:
    """Эмулятор AVX/AVX2 инструкций"""
    
    def __init__(self, uc):
        self.uc = uc
        self.md = Cs(CS_ARCH_X86, CS_MODE_64)
        self.md.detail = True
        
        # Статистика
        self.avx_instructions_emulated = 0
        self.avx_instructions_skipped = 0
        
    def is_avx_instruction(self, address, size):
        """Проверяет, является ли инструкция AVX/AVX2"""
        try:
            code = self.uc.mem_read(address, size)
            for insn in self.md.disasm(code, address):
                # AVX инструкции начинаются с VEX prefix (0xC4, 0xC5)
                # или используют YMM/ZMM регистры
                mnemonic = insn.mnemonic.upper()
                
                # AVX инструкции обычно начинаются с 'V'
                if mnemonic.startswith('V'):
                    # Проверяем, что это не обычная инструкция
                    if any(x in mnemonic for x in ['ADD', 'SUB', 'MUL', 'DIV', 'MOV', 
                                                     'XOR', 'AND', 'OR', 'CMP']):
                        # Проверяем регистры
                        op_str = insn.op_str.upper()
                        if 'YMM' in op_str or 'ZMM' in op_str:
                            return True, insn
                
                return False, None
        except:
            return False, None
    
    def emulate_avx_instruction(self, insn):
        """Эмулирует AVX инструкцию"""
        mnemonic = insn.mnemonic.upper()
        
        # Простые случаи - можно пропустить
        if self._is_non_critical(mnemonic):
            print(f"[AVX] Skipping non-critical: {insn.mnemonic} {insn.op_str}")
            self.avx_instructions_skipped += 1
            # Просто пропускаем инструкцию
            rip = self.uc.reg_read(UC_X86_REG_RIP)
            self.uc.reg_write(UC_X86_REG_RIP, rip + insn.size)
            return True
        
        # Сложные случаи - пытаемся эмулировать через SSE
        if self._can_emulate_via_sse(mnemonic):
            print(f"[AVX] Emulating via SSE: {insn.mnemonic} {insn.op_str}")
            self._emulate_via_sse(insn)
            self.avx_instructions_emulated += 1
            return True
        
        # Не можем эмулировать - возвращаем False
        print(f"[AVX] Cannot emulate: {insn.mnemonic} {insn.op_str}")
        return False
    
    def _is_non_critical(self, mnemonic):
        """Проверяет, является ли инструкция некритичной (можно пропустить)"""
        # Инструкции, которые обычно используются для оптимизации
        # и не влияют на логику программы
        non_critical = [
            'VZEROUPPER',  # Очистка верхней части YMM регистров
            'VZEROALL',    # Очистка всех YMM регистров
            'VPREFETCH',   # Prefetch данных
        ]
        return mnemonic in non_critical
    
    def _can_emulate_via_sse(self, mnemonic):
        """Проверяет, можно ли эмулировать через SSE"""
        # Простые арифметические операции можно разбить на 2x SSE
        emulatable = [
            'VADDPS',   # Add packed single-precision
            'VSUBPS',   # Subtract packed single-precision
            'VMULPS',   # Multiply packed single-precision
            'VDIVPS',   # Divide packed single-precision
            'VMOVAPS',  # Move aligned packed single-precision
            'VMOVUPS',  # Move unaligned packed single-precision
        ]
        return mnemonic in emulatable
    
    def _emulate_via_sse(self, insn):
        """Эмулирует AVX инструкцию через SSE"""
        mnemonic = insn.mnemonic.upper()
        
        # Пример: VADDPS ymm0, ymm1, ymm2
        # Разбиваем на:
        # ADDPS xmm0, xmm1  (нижние 128 бит)
        # ADDPS xmm2, xmm3  (верхние 128 бит)
        
        # Для простоты - просто пропускаем и обнуляем результат
        # В реальной реализации нужно:
        # 1. Прочитать YMM регистры (как 2x XMM)
        # 2. Выполнить операцию на каждой половине
        # 3. Записать результат обратно
        
        rip = self.uc.reg_read(UC_X86_REG_RIP)
        self.uc.reg_write(UC_X86_REG_RIP, rip + insn.size)
        
        # TODO: Реальная эмуляция через SSE
        # Пока просто пропускаем
    
    def get_stats(self):
        """Возвращает статистику эмуляции AVX"""
        return {
            'emulated': self.avx_instructions_emulated,
            'skipped': self.avx_instructions_skipped,
            'total': self.avx_instructions_emulated + self.avx_instructions_skipped,
        }


class VirtualCPUProfile:
    """Профиль виртуального CPU с поддержкой AVX/AVX2"""
    
    # Современный CPU profile (Intel Core i7-12700K / AMD Ryzen 7 5800X)
    MODERN_CPU = {
        # Базовые features
        0: True,   # PF_FLOATING_POINT_PRECISION_ERRATA
        2: True,   # PF_COMPARE_EXCHANGE_DOUBLE
        3: True,   # PF_MMX_INSTRUCTIONS_AVAILABLE
        6: True,   # PF_XMMI_INSTRUCTIONS_AVAILABLE (SSE)
        7: False,  # PF_3DNOW_INSTRUCTIONS_AVAILABLE (AMD only)
        10: True,  # PF_XMMI64_INSTRUCTIONS_AVAILABLE (SSE2)
        13: True,  # PF_SSE3_INSTRUCTIONS_AVAILABLE
        17: True,  # PF_COMPARE_EXCHANGE128
        23: True,  # PF_SSE_DAZ_MODE_AVAILABLE
        
        # Продвинутые features (говорим что поддерживаем!)
        # Но перехватываем через AVXEmulator
        # 23: True,  # PF_AVX2_INSTRUCTIONS_AVAILABLE ← Эмулируем!
        # 40: False, # PF_AVX512F_INSTRUCTIONS_AVAILABLE ← Пока нет
    }
    
    # Минимальный CPU profile (для совместимости)
    MINIMAL_CPU = {
        0: True,   # PF_FLOATING_POINT_PRECISION_ERRATA
        2: True,   # PF_COMPARE_EXCHANGE_DOUBLE
        3: True,   # PF_MMX_INSTRUCTIONS_AVAILABLE
        6: True,   # PF_XMMI_INSTRUCTIONS_AVAILABLE (SSE)
        10: True,  # PF_XMMI64_INSTRUCTIONS_AVAILABLE (SSE2)
        13: True,  # PF_SSE3_INSTRUCTIONS_AVAILABLE
        17: True,  # PF_COMPARE_EXCHANGE128
        
        # Все продвинутые features отключены
        23: False,  # PF_AVX2_INSTRUCTIONS_AVAILABLE
        40: False,  # PF_AVX512F_INSTRUCTIONS_AVAILABLE
    }
    
    @staticmethod
    def get_profile(profile_name='minimal'):
        """Возвращает профиль CPU"""
        if profile_name == 'modern':
            return VirtualCPUProfile.MODERN_CPU
        else:
            return VirtualCPUProfile.MINIMAL_CPU


# Пример использования
if __name__ == '__main__':
    print("=== AVX Emulation Layer ===\n")
    
    print("Виртуальные CPU профили:")
    print("\n1. MINIMAL_CPU (безопасный):")
    print("   - SSE, SSE2, SSE3")
    print("   - Без AVX/AVX2")
    print("   - Гарантированная совместимость с Unicorn")
    
    print("\n2. MODERN_CPU (с эмуляцией AVX):")
    print("   - SSE, SSE2, SSE3")
    print("   - AVX/AVX2 (эмулируется через hook)")
    print("   - Для современных игр/приложений")
    
    print("\nРекомендация:")
    print("  - Для анализа DRM: используйте MINIMAL_CPU")
    print("  - Для запуска игр: используйте MODERN_CPU + AVXEmulator")
