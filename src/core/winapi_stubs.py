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
            # === ИСТОЧНИКИ ВРЕМЕНИ (все через VirtualClock) ===
            ('GetTickCount', self._stub_get_tick_count),
            ('GetTickCount64', self._stub_get_tick_count64),
            ('QueryPerformanceCounter', self._stub_query_performance_counter),
            ('QueryPerformanceFrequency', self._stub_query_performance_frequency),
            ('GetSystemTime', self._stub_get_system_time),
            ('GetLocalTime', self._stub_get_local_time),
            ('GetSystemTimeAsFileTime', self._stub_get_system_time_as_filetime),
            ('timeGetTime', self._stub_time_get_time),
            ('NtQuerySystemTime', self._stub_nt_query_system_time),
            ('RtlQueryPerformanceCounter', self._stub_rtl_query_performance_counter),
            
            # === ВЫВОД ===
            ('printf', self._stub_printf),
            ('puts', self._stub_puts),
            
            # === ЗАВЕРШЕНИЕ ===
            ('exit', self._stub_exit),
            ('ExitProcess', self._stub_exit),
        ]
        
        addr = self.STUB_BASE
        for name, handler in functions:
            self.stubs[name] = {
                'address': addr,
                'handler': handler
            }
            
            # Записываем простую заглушку: XOR RAX, RAX; RET
            # Это временное решение - в будущем нужно будет вызывать handler
            stub_code = bytes([
                0x48, 0x31, 0xC0,  # XOR RAX, RAX
                0xC3,              # RET
            ])
            self.uc.mem_write(addr, stub_code)
            
            addr += 0x100  # 256 байт на функцию
    
    def _stub_get_tick_count(self):
        """GetTickCount() — возвращает миллисекунды (32-бит)"""
        tick_count = self.emu.clock.get_tick_count() & 0xFFFFFFFF
        self.uc.reg_write(UC_X86_REG_RAX, tick_count)
        print(f"[API] GetTickCount() -> {tick_count} мс")
        return tick_count
    
    def _stub_get_tick_count64(self):
        """GetTickCount64() — возвращает миллисекунды (64-бит)"""
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
    
    def _stub_query_performance_frequency(self):
        """QueryPerformanceFrequency() — частота счётчика"""
        # RCX = указатель на LARGE_INTEGER
        ptr = self.uc.reg_read(UC_X86_REG_RCX)
        freq = self.emu.clock.qpc_frequency
        
        # Записываем частоту
        self.uc.mem_write(ptr, freq.to_bytes(8, 'little'))
        self.uc.reg_write(UC_X86_REG_RAX, 1)  # TRUE
        
        print(f"[API] QueryPerformanceFrequency() -> {freq} Hz")
        return 1
    
    def _stub_get_system_time(self):
        """GetSystemTime() — системное время (UTC)"""
        # RCX = указатель на SYSTEMTIME структуру
        ptr = self.uc.reg_read(UC_X86_REG_RCX)
        
        # Вычисляем время на основе VirtualClock
        # Базовое время: 2026-01-30 12:00:00 + виртуальные миллисекунды
        base_time_ms = 1738238400000  # 2026-01-30 12:00:00 UTC в миллисекундах
        current_ms = base_time_ms + self.emu.clock.get_tick_count()
        
        # Упрощённая SYSTEMTIME структура (16 байт)
        # wYear, wMonth, wDayOfWeek, wDay, wHour, wMinute, wSecond, wMilliseconds
        systemtime = bytes([
            0xEA, 0x07,  # wYear = 2026
            0x01, 0x00,  # wMonth = 1 (январь)
            0x04, 0x00,  # wDayOfWeek = 4 (четверг)
            0x1E, 0x00,  # wDay = 30
            0x0C, 0x00,  # wHour = 12
            0x00, 0x00,  # wMinute = 0
            0x00, 0x00,  # wSecond = 0
            (current_ms & 0xFF), ((current_ms >> 8) & 0xFF),  # wMilliseconds
        ])
        
        self.uc.mem_write(ptr, systemtime)
        print(f"[API] GetSystemTime() -> 2026-01-30 12:00:00.{current_ms % 1000:03d}")
        return 0
    
    def _stub_get_local_time(self):
        """GetLocalTime() — локальное время"""
        # Для простоты возвращаем то же что GetSystemTime
        return self._stub_get_system_time()
    
    def _stub_get_system_time_as_filetime(self):
        """GetSystemTimeAsFileTime() — время в формате FILETIME"""
        # RCX = указатель на FILETIME (64-бит)
        ptr = self.uc.reg_read(UC_X86_REG_RCX)
        
        # FILETIME = 100-наносекундные интервалы с 1601-01-01
        # Базовое время: 2026-01-30 12:00:00
        base_filetime = 133838880000000000  # 2026-01-30 12:00:00 в FILETIME
        current_filetime = base_filetime + (self.emu.clock.get_tick_count() * 10000)
        
        self.uc.mem_write(ptr, current_filetime.to_bytes(8, 'little'))
        print(f"[API] GetSystemTimeAsFileTime() -> {current_filetime}")
        return 0
    
    def _stub_time_get_time(self):
        """timeGetTime() — мультимедийный таймер"""
        tick_count = self.emu.clock.get_tick_count() & 0xFFFFFFFF
        self.uc.reg_write(UC_X86_REG_RAX, tick_count)
        print(f"[API] timeGetTime() -> {tick_count} мс")
        return tick_count
    
    def _stub_nt_query_system_time(self):
        """NtQuerySystemTime() — NT kernel time"""
        # RCX = указатель на LARGE_INTEGER
        ptr = self.uc.reg_read(UC_X86_REG_RCX)
        
        # Возвращаем то же что GetSystemTimeAsFileTime
        base_filetime = 133838880000000000
        current_filetime = base_filetime + (self.emu.clock.get_tick_count() * 10000)
        
        self.uc.mem_write(ptr, current_filetime.to_bytes(8, 'little'))
        self.uc.reg_write(UC_X86_REG_RAX, 0)  # STATUS_SUCCESS
        
        print(f"[API] NtQuerySystemTime() -> {current_filetime}")
        return 0
    
    def _stub_rtl_query_performance_counter(self):
        """RtlQueryPerformanceCounter() — kernel-mode QPC"""
        # То же что QueryPerformanceCounter
        return self._stub_query_performance_counter()
    
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
