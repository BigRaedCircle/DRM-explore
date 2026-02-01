#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Unicorn REP Instructions Hotfix

Проблема: Unicorn 2.1.4 не корректно обрабатывает REP префиксы (STOSB, MOVSB, etc.)
- UC_HOOK_CODE вызывается на каждой итерации REP
- RCX не декрементируется автоматически
- Результат: бесконечный цикл

Решение: Перехватываем REP инструкции и эмулируем их вручную

Поддерживаемые инструкции:
- REP STOSB (F3 AA) - заполнение памяти байтом
- REP STOSW (F3 AB) - заполнение памяти словом
- REP STOSD (F3 AB) - заполнение памяти dword
- REP STOSQ (F3 48 AB) - заполнение памяти qword
- REP MOVSB (F3 A4) - копирование памяти побайтно
- REP MOVSW (F3 A5) - копирование памяти пословно
- REP MOVSD (F3 A5) - копирование памяти по dword
- REP MOVSQ (F3 48 A5) - копирование памяти по qword
"""

from unicorn.x86_const import *


class UnicornRepFix:
    """Hotfix для REP инструкций в Unicorn"""
    
    def __init__(self, uc):
        self.uc = uc
        self.rep_instructions_handled = 0
        self.verbose = False  # Включить для отладки
    
    def check_and_handle_rep(self, address):
        """
        Проверяет, является ли инструкция REP, и обрабатывает её
        
        Returns:
            True - если инструкция была обработана (нужно пропустить)
            False - если это не REP инструкция (продолжить нормально)
        """
        try:
            # Читаем до 4 байт для определения инструкции
            opcode = self.uc.mem_read(address, 4)
            
            # REP STOSB (F3 AA)
            if opcode[0] == 0xF3 and opcode[1] == 0xAA:
                return self._handle_rep_stosb(address)
            
            # REP STOSW (F3 66 AB) или REP STOSD (F3 AB)
            if opcode[0] == 0xF3:
                if opcode[1] == 0x66 and opcode[2] == 0xAB:
                    return self._handle_rep_stosw(address)
                elif opcode[1] == 0xAB:
                    return self._handle_rep_stosd(address)
            
            # REP STOSQ (F3 48 AB)
            if opcode[0] == 0xF3 and opcode[1] == 0x48 and opcode[2] == 0xAB:
                return self._handle_rep_stosq(address)
            
            # REP MOVSB (F3 A4)
            if opcode[0] == 0xF3 and opcode[1] == 0xA4:
                return self._handle_rep_movsb(address)
            
            # REP MOVSW (F3 66 A5) или REP MOVSD (F3 A5)
            if opcode[0] == 0xF3:
                if opcode[1] == 0x66 and opcode[2] == 0xA5:
                    return self._handle_rep_movsw(address)
                elif opcode[1] == 0xA5:
                    return self._handle_rep_movsd(address)
            
            # REP MOVSQ (F3 48 A5)
            if opcode[0] == 0xF3 and opcode[1] == 0x48 and opcode[2] == 0xA5:
                return self._handle_rep_movsq(address)
            
            return False
            
        except Exception as e:
            if self.verbose:
                print(f"[REP_FIX] Error checking instruction at 0x{address:x}: {e}")
            return False
    
    def _handle_rep_stosb(self, address):
        """REP STOSB - заполнение памяти байтом"""
        rcx = self.uc.reg_read(UC_X86_REG_RCX)
        
        if rcx == 0:
            # Ничего не делаем, просто пропускаем инструкцию
            self.uc.reg_write(UC_X86_REG_RIP, address + 2)
            return True
        
        rdi = self.uc.reg_read(UC_X86_REG_RDI)
        al = self.uc.reg_read(UC_X86_REG_RAX) & 0xFF
        
        # Записываем байты
        data = bytes([al] * rcx)
        try:
            self.uc.mem_write(rdi, data)
        except Exception as e:
            if self.verbose:
                print(f"[REP_FIX] rep stosb: memory write failed at 0x{rdi:x}: {e}")
        
        # Обновляем регистры
        self.uc.reg_write(UC_X86_REG_RDI, rdi + rcx)
        self.uc.reg_write(UC_X86_REG_RCX, 0)
        self.uc.reg_write(UC_X86_REG_RIP, address + 2)
        
        self.rep_instructions_handled += 1
        
        if self.verbose:
            print(f"[REP_FIX] rep stosb: wrote {rcx} bytes of 0x{al:02x} to 0x{rdi:x}")
        
        return True
    
    def _handle_rep_stosw(self, address):
        """REP STOSW - заполнение памяти словом (2 байта)"""
        rcx = self.uc.reg_read(UC_X86_REG_RCX)
        
        if rcx == 0:
            self.uc.reg_write(UC_X86_REG_RIP, address + 3)
            return True
        
        rdi = self.uc.reg_read(UC_X86_REG_RDI)
        ax = self.uc.reg_read(UC_X86_REG_RAX) & 0xFFFF
        
        # Записываем слова
        data = (ax.to_bytes(2, 'little') * rcx)
        try:
            self.uc.mem_write(rdi, data)
        except Exception as e:
            if self.verbose:
                print(f"[REP_FIX] rep stosw: memory write failed: {e}")
        
        self.uc.reg_write(UC_X86_REG_RDI, rdi + rcx * 2)
        self.uc.reg_write(UC_X86_REG_RCX, 0)
        self.uc.reg_write(UC_X86_REG_RIP, address + 3)
        
        self.rep_instructions_handled += 1
        return True
    
    def _handle_rep_stosd(self, address):
        """REP STOSD - заполнение памяти dword (4 байта)"""
        rcx = self.uc.reg_read(UC_X86_REG_RCX)
        
        if rcx == 0:
            self.uc.reg_write(UC_X86_REG_RIP, address + 2)
            return True
        
        rdi = self.uc.reg_read(UC_X86_REG_RDI)
        eax = self.uc.reg_read(UC_X86_REG_RAX) & 0xFFFFFFFF
        
        # Записываем dwords
        data = (eax.to_bytes(4, 'little') * rcx)
        try:
            self.uc.mem_write(rdi, data)
        except Exception as e:
            if self.verbose:
                print(f"[REP_FIX] rep stosd: memory write failed: {e}")
        
        self.uc.reg_write(UC_X86_REG_RDI, rdi + rcx * 4)
        self.uc.reg_write(UC_X86_REG_RCX, 0)
        self.uc.reg_write(UC_X86_REG_RIP, address + 2)
        
        self.rep_instructions_handled += 1
        return True
    
    def _handle_rep_stosq(self, address):
        """REP STOSQ - заполнение памяти qword (8 байт)"""
        rcx = self.uc.reg_read(UC_X86_REG_RCX)
        
        if rcx == 0:
            self.uc.reg_write(UC_X86_REG_RIP, address + 3)
            return True
        
        rdi = self.uc.reg_read(UC_X86_REG_RDI)
        rax = self.uc.reg_read(UC_X86_REG_RAX)
        
        # Записываем qwords
        data = (rax.to_bytes(8, 'little') * rcx)
        try:
            self.uc.mem_write(rdi, data)
        except Exception as e:
            if self.verbose:
                print(f"[REP_FIX] rep stosq: memory write failed: {e}")
        
        self.uc.reg_write(UC_X86_REG_RDI, rdi + rcx * 8)
        self.uc.reg_write(UC_X86_REG_RCX, 0)
        self.uc.reg_write(UC_X86_REG_RIP, address + 3)
        
        self.rep_instructions_handled += 1
        return True
    
    def _handle_rep_movsb(self, address):
        """REP MOVSB - копирование памяти побайтно"""
        rcx = self.uc.reg_read(UC_X86_REG_RCX)
        
        if rcx == 0:
            self.uc.reg_write(UC_X86_REG_RIP, address + 2)
            return True
        
        rsi = self.uc.reg_read(UC_X86_REG_RSI)
        rdi = self.uc.reg_read(UC_X86_REG_RDI)
        
        # Копируем данные
        try:
            data = self.uc.mem_read(rsi, rcx)
            self.uc.mem_write(rdi, bytes(data))
        except Exception as e:
            if self.verbose:
                print(f"[REP_FIX] rep movsb: memory operation failed: {e}")
        
        self.uc.reg_write(UC_X86_REG_RSI, rsi + rcx)
        self.uc.reg_write(UC_X86_REG_RDI, rdi + rcx)
        self.uc.reg_write(UC_X86_REG_RCX, 0)
        self.uc.reg_write(UC_X86_REG_RIP, address + 2)
        
        self.rep_instructions_handled += 1
        return True
    
    def _handle_rep_movsw(self, address):
        """REP MOVSW - копирование памяти пословно"""
        rcx = self.uc.reg_read(UC_X86_REG_RCX)
        
        if rcx == 0:
            self.uc.reg_write(UC_X86_REG_RIP, address + 3)
            return True
        
        rsi = self.uc.reg_read(UC_X86_REG_RSI)
        rdi = self.uc.reg_read(UC_X86_REG_RDI)
        
        try:
            data = self.uc.mem_read(rsi, rcx * 2)
            self.uc.mem_write(rdi, bytes(data))
        except Exception as e:
            if self.verbose:
                print(f"[REP_FIX] rep movsw: memory operation failed: {e}")
        
        self.uc.reg_write(UC_X86_REG_RSI, rsi + rcx * 2)
        self.uc.reg_write(UC_X86_REG_RDI, rdi + rcx * 2)
        self.uc.reg_write(UC_X86_REG_RCX, 0)
        self.uc.reg_write(UC_X86_REG_RIP, address + 3)
        
        self.rep_instructions_handled += 1
        return True
    
    def _handle_rep_movsd(self, address):
        """REP MOVSD - копирование памяти по dword"""
        rcx = self.uc.reg_read(UC_X86_REG_RCX)
        
        if rcx == 0:
            self.uc.reg_write(UC_X86_REG_RIP, address + 2)
            return True
        
        rsi = self.uc.reg_read(UC_X86_REG_RSI)
        rdi = self.uc.reg_read(UC_X86_REG_RDI)
        
        try:
            data = self.uc.mem_read(rsi, rcx * 4)
            self.uc.mem_write(rdi, bytes(data))
        except Exception as e:
            if self.verbose:
                print(f"[REP_FIX] rep movsd: memory operation failed: {e}")
        
        self.uc.reg_write(UC_X86_REG_RSI, rsi + rcx * 4)
        self.uc.reg_write(UC_X86_REG_RDI, rdi + rcx * 4)
        self.uc.reg_write(UC_X86_REG_RCX, 0)
        self.uc.reg_write(UC_X86_REG_RIP, address + 2)
        
        self.rep_instructions_handled += 1
        return True
    
    def _handle_rep_movsq(self, address):
        """REP MOVSQ - копирование памяти по qword"""
        rcx = self.uc.reg_read(UC_X86_REG_RCX)
        
        if rcx == 0:
            self.uc.reg_write(UC_X86_REG_RIP, address + 3)
            return True
        
        rsi = self.uc.reg_read(UC_X86_REG_RSI)
        rdi = self.uc.reg_read(UC_X86_REG_RDI)
        
        try:
            data = self.uc.mem_read(rsi, rcx * 8)
            self.uc.mem_write(rdi, bytes(data))
        except Exception as e:
            if self.verbose:
                print(f"[REP_FIX] rep movsq: memory operation failed: {e}")
        
        self.uc.reg_write(UC_X86_REG_RSI, rsi + rcx * 8)
        self.uc.reg_write(UC_X86_REG_RDI, rdi + rcx * 8)
        self.uc.reg_write(UC_X86_REG_RCX, 0)
        self.uc.reg_write(UC_X86_REG_RIP, address + 3)
        
        self.rep_instructions_handled += 1
        return True
    
    def get_stats(self):
        """Возвращает статистику обработанных REP инструкций"""
        return {
            'rep_instructions_handled': self.rep_instructions_handled
        }
