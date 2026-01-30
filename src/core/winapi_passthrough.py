#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
WinAPI Passthrough - вызов реальных Windows API с логированием

Стратегия: НЕ эмулируем, а вызываем РЕАЛЬНЫЕ функции Windows!
Логируем все вызовы для последующего создания заглушек.
"""

import ctypes
import struct
from ctypes import wintypes
from unicorn.x86_const import *


# Load Windows DLLs
kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
ntdll = ctypes.WinDLL('ntdll', use_last_error=True)
user32 = ctypes.WinDLL('user32', use_last_error=True)
gdi32 = ctypes.WinDLL('gdi32', use_last_error=True)


class WinAPIPassthrough:
    """Passthrough к реальным Windows API с логированием"""
    
    def __init__(self, emulator, log_file="winapi_calls.log"):
        self.emu = emulator
        self.uc = emulator.uc
        self.log_file = log_file
        self.call_count = 0
        
        # Открываем лог-файл
        self.log = open(log_file, 'w', encoding='utf-8')
        self.log.write("# WinAPI Call Log\n")
        self.log.write("# Format: [call_number] function_name(args) -> result\n\n")
        
        # Stub addresses (allocate in high memory)
        self.STUB_BASE = 0x7FFF0000
        self.stubs = {}
        
        self._setup_stubs()
    
    def __del__(self):
        """Закрываем лог при уничтожении"""
        if hasattr(self, 'log'):
            self.log.close()
    
    def _log_call(self, func_name, args_str, result_str):
        """Логирование вызова API"""
        self.call_count += 1
        log_line = f"[{self.call_count:06d}] {func_name}({args_str}) -> {result_str}\n"
        self.log.write(log_line)
        self.log.flush()  # Сразу записываем на диск
        print(f"[API] {func_name}({args_str}) -> {result_str}")
    
    def _setup_stubs(self):
        """Create stubs for main functions"""
        # Минимальный набор функций для перехвата
        functions = [
            # Критичные для эмулятора
            ('ExitProcess', self._stub_exit_process),
            ('GetCommandLineW', self._stub_get_command_line_w),
        ]
        
        addr = self.STUB_BASE
        for name, handler in functions:
            self.stubs[name] = {
                'address': addr,
                'handler': handler
            }
            
            # Write stub: INT3 (will be caught and handled)
            stub_code = bytes([
                0xCC,  # INT3 - breakpoint
                0xC3,  # RET (in case INT3 is skipped)
            ])
            self.uc.mem_write(addr, stub_code)
            
            addr += 0x100  # 256 bytes per function
    
    def get_stub_address(self, func_name):
        """Get stub function address"""
        if func_name in self.stubs:
            return self.stubs[func_name]['address']
        return None
    
    def handle_stub_call(self, address):
        """Handle call to stub - find and execute handler"""
        for name, stub_info in self.stubs.items():
            if stub_info['address'] == address:
                return stub_info['handler']()
        return None
    
    # === КРИТИЧНЫЕ ФУНКЦИИ (перехватываем) ===
    
    def _stub_exit_process(self):
        """ExitProcess() - stop emulation"""
        exit_code = self.uc.reg_read(UC_X86_REG_RCX)
        self._log_call("ExitProcess", f"{exit_code}", "STOP")
        self.uc.reg_write(UC_X86_REG_RAX, exit_code)
        self.uc.emu_stop()
        return exit_code
    
    def _stub_get_command_line_w(self):
        """GetCommandLineW() - return pointer to wide command line"""
        # Allocate and write wide command line string
        cmd_line = "cpuz.exe -txt=report\x00".encode('utf-16le')
        ptr = self.emu.os.HeapAlloc(self.emu.os.heap.process_heap, 0, len(cmd_line))
        self.uc.mem_write(ptr, cmd_line)
        self.uc.reg_write(UC_X86_REG_RAX, ptr)
        
        self._log_call("GetCommandLineW", "", f"0x{ptr:x} (\"cpuz.exe -txt=report\")")
        return ptr
