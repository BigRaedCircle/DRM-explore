#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
WinAPI Stubs — заглушки для базовых функций Windows API

Минимальная реализация для запуска учебного анти-тампера.
"""

from unicorn.x86_const import *


class WinAPIStubs:
    """Заглушки Windows API"""
    
    def __init__(self, emulator):
        self.emu = emulator
        self.uc = emulator.uc
        
        # Адреса заглушек (выделяем в высокой памяти)
        self.STUB_BASE = 0x7FFF0000
        self.stubs = {}
        
        self._setup_stubs()
    
    def _setup_stubs(self):
        """Создать заглушки для основных функций"""
        # Список функций для эмуляции
        functions = [
            ('GetTickCount64', self._stub_get_tick_count64),
            ('QueryPerformanceCounter', self._stub_query_performance_counter),
            ('printf', self._stub_printf),
            ('puts', self._stub_puts),
            ('exit', self._stub_exit),
            ('ExitProcess', self._stub_exit),
        ]
        
        addr = self.STUB_BASE
        for name, handler in functions:
            self.stubs[name] = {
                'address': addr,
                'handler': handler
            }
            addr += 0x100  # 256 байт на функцию
    
    def _stub_get_tick_count64(self):
        """GetTickCount64() — возвращает миллисекунды"""
        tick_count = self.emu.clock.get_tick_count()
        self.uc.reg_write(UC_X86_REG_RAX, tick_count)
        print(f"[API] GetTickCount64() -> {tick_count} мс")
        return tick_count
    
    def _stub_query_performance_counter(self):
        """QueryPerformanceCounter() — высокоточный счётчик"""
        # RCX = указатель на LARGE_INTEGER
        ptr = self.uc.reg_read(UC_X86_REG_RCX)
        qpc = self.emu.clock.query_performance_counter()
        
        # Записываем 64-битное значение
        self.uc.mem_write(ptr, qpc.to_bytes(8, 'little'))
        self.uc.reg_write(UC_X86_REG_RAX, 1)  # TRUE
        
        print(f"[API] QueryPerformanceCounter() -> {qpc}")
        return 1
    
    def _stub_printf(self):
        """printf() — вывод строки"""
        # RCX = указатель на format string
        fmt_ptr = self.uc.reg_read(UC_X86_REG_RCX)
        
        try:
            # Читаем строку из памяти
            fmt_str = self._read_string(fmt_ptr)
            print(f"[PRINTF] {fmt_str}")
            self.uc.reg_write(UC_X86_REG_RAX, len(fmt_str))
        except:
            print(f"[PRINTF] <error reading string>")
            self.uc.reg_write(UC_X86_REG_RAX, 0)
        
        return 0
    
    def _stub_puts(self):
        """puts() — вывод строки с переводом строки"""
        # RCX = указатель на строку
        str_ptr = self.uc.reg_read(UC_X86_REG_RCX)
        
        try:
            string = self._read_string(str_ptr)
            print(f"[PUTS] {string}")
            self.uc.reg_write(UC_X86_REG_RAX, len(string))
        except:
            print(f"[PUTS] <error reading string>")
            self.uc.reg_write(UC_X86_REG_RAX, -1)
        
        return 0
    
    def _stub_exit(self):
        """exit() / ExitProcess() — завершение программы"""
        # RCX = exit code
        exit_code = self.uc.reg_read(UC_X86_REG_RCX)
        print(f"[API] exit({exit_code})")
        
        # Останавливаем эмуляцию
        self.uc.emu_stop()
        return exit_code
    
    def _read_string(self, addr, max_len=1024):
        """Прочитать null-terminated строку из памяти"""
        result = []
        for i in range(max_len):
            try:
                byte = self.uc.mem_read(addr + i, 1)[0]
                if byte == 0:
                    break
                result.append(byte)
            except:
                break
        
        return bytes(result).decode('utf-8', errors='ignore')
    
    def get_stub_address(self, func_name):
        """Получить адрес заглушки функции"""
        if func_name in self.stubs:
            return self.stubs[func_name]['address']
        return None
    
    def call_stub(self, func_name):
        """Вызвать заглушку функции"""
        if func_name in self.stubs:
            handler = self.stubs[func_name]['handler']
            return handler()
        return None


if __name__ == "__main__":
    print("WinAPI Stubs — заглушки для эмуляции Windows API")
    print("\nПоддерживаемые функции:")
    
    # Создаём временный эмулятор для демонстрации
    import sys
    sys.path.insert(0, '.')
    from simple_emulator import SimpleEmulator
    
    emu = SimpleEmulator()
    stubs = WinAPIStubs(emu)
    
    for name, info in stubs.stubs.items():
        print(f"  {name:<30} @ 0x{info['address']:x}")
