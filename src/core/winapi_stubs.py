#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
WinAPI Stubs - bridge between emulator and real Windows API

Strategy: Call REAL Windows functions, not emulate them!
"""

import ctypes
from ctypes import wintypes
from unicorn.x86_const import *


# Load Windows DLLs
kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
ntdll = ctypes.WinDLL('ntdll', use_last_error=True)


class WinAPIStubs:
    """Bridge to real Windows API"""
    
    def __init__(self, emulator):
        self.emu = emulator
        self.uc = emulator.uc
        
        # Stub addresses (allocate in high memory)
        self.STUB_BASE = 0x7FFF0000
        self.stubs = {}
        
        self._setup_stubs()
    
    def _setup_stubs(self):
        """Create stubs for main functions"""
        # List of functions to bridge
        functions = [
            # === TIME SOURCES (all through VirtualClock) ===
            ('GetTickCount64', self._stub_get_tick_count64),
            ('QueryPerformanceCounter', self._stub_query_performance_counter),
            ('QueryPerformanceFrequency', self._stub_query_performance_frequency),
            ('GetSystemTimeAsFileTime', self._stub_get_system_time_as_filetime),
            
            # === MEMORY MANAGEMENT (call real Windows) ===
            ('GetProcessHeap', self._stub_get_process_heap),
            ('HeapAlloc', self._stub_heap_alloc),
            ('HeapFree', self._stub_heap_free),
            ('HeapSize', self._stub_heap_size),
            ('HeapReAlloc', self._stub_heap_realloc),
            
            # === PROCESS/THREAD INFO (call real Windows) ===
            ('GetCurrentProcessId', self._stub_get_current_process_id),
            ('GetCurrentThreadId', self._stub_get_current_thread_id),
            ('GetCurrentProcess', self._stub_get_current_process),
            
            # === EXIT ===
            ('ExitProcess', self._stub_exit),
        ]
        
        addr = self.STUB_BASE
        for name, handler in functions:
            self.stubs[name] = {
                'address': addr,
                'handler': handler
            }
            
            # Write stub: INT3 (will be caught and handled)
            # We'll use INT3 as marker to call Python handler
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
                print(f"[API] {name}()")
                return stub_info['handler']()
        return None
    
    # === TIME SOURCE STUBS (use VirtualClock) ===
    
    def _stub_get_tick_count64(self):
        """GetTickCount64() - returns milliseconds (64-bit)"""
        tick_count = self.emu.clock.get_tick_count()
        self.uc.reg_write(UC_X86_REG_RAX, tick_count)
        print(f"  -> {tick_count} ms")
        return tick_count
    
    def _stub_query_performance_counter(self):
        """QueryPerformanceCounter() - high precision counter"""
        # RCX = pointer to LARGE_INTEGER
        ptr = self.uc.reg_read(UC_X86_REG_RCX)
        qpc = self.emu.clock.query_performance_counter()
        
        # Write 64-bit value
        self.uc.mem_write(ptr, qpc.to_bytes(8, 'little'))
        self.uc.reg_write(UC_X86_REG_RAX, 1)  # TRUE
        
        print(f"  -> {qpc}")
        return 1
    
    def _stub_query_performance_frequency(self):
        """QueryPerformanceFrequency() - counter frequency"""
        # RCX = pointer to LARGE_INTEGER
        ptr = self.uc.reg_read(UC_X86_REG_RCX)
        freq = self.emu.clock.qpc_frequency
        
        # Write frequency
        self.uc.mem_write(ptr, freq.to_bytes(8, 'little'))
        self.uc.reg_write(UC_X86_REG_RAX, 1)  # TRUE
        
        print(f"  -> {freq} Hz")
        return 1
    
    def _stub_get_system_time_as_filetime(self):
        """GetSystemTimeAsFileTime() - time in FILETIME format"""
        # RCX = pointer to FILETIME (64-bit)
        ptr = self.uc.reg_read(UC_X86_REG_RCX)
        
        # FILETIME = 100-nanosecond intervals since 1601-01-01
        # Base time: 2026-01-30 12:00:00
        base_filetime = 133838880000000000  # 2026-01-30 12:00:00 in FILETIME
        current_filetime = base_filetime + (self.emu.clock.get_tick_count() * 10000)
        
        self.uc.mem_write(ptr, current_filetime.to_bytes(8, 'little'))
        print(f"  -> {current_filetime}")
        return 0
    
    # === MEMORY MANAGEMENT (call REAL Windows API) ===
    
    def _stub_get_process_heap(self):
        """GetProcessHeap() - call REAL Windows function"""
        # Call real Windows API
        heap_handle = kernel32.GetProcessHeap()
        self.uc.reg_write(UC_X86_REG_RAX, heap_handle)
        print(f"  -> 0x{heap_handle:x} (REAL)")
        return heap_handle
    
    def _stub_heap_alloc(self):
        """HeapAlloc() - call REAL Windows function"""
        # RCX = heap handle, RDX = flags, R8 = size
        heap = self.uc.reg_read(UC_X86_REG_RCX)
        flags = self.uc.reg_read(UC_X86_REG_RDX)
        size = self.uc.reg_read(UC_X86_REG_R8)
        
        # Call real Windows API
        result = kernel32.HeapAlloc(heap, flags, size)
        self.uc.reg_write(UC_X86_REG_RAX, result)
        print(f"  HeapAlloc(0x{heap:x}, 0x{flags:x}, {size}) -> 0x{result:x} (REAL)")
        return result
    
    def _stub_heap_free(self):
        """HeapFree() - call REAL Windows function"""
        # RCX = heap handle, RDX = flags, R8 = ptr
        heap = self.uc.reg_read(UC_X86_REG_RCX)
        flags = self.uc.reg_read(UC_X86_REG_RDX)
        ptr = self.uc.reg_read(UC_X86_REG_R8)
        
        # Call real Windows API
        result = kernel32.HeapFree(heap, flags, ptr)
        self.uc.reg_write(UC_X86_REG_RAX, result)
        print(f"  HeapFree(0x{heap:x}, 0x{flags:x}, 0x{ptr:x}) -> {result} (REAL)")
        return result
    
    def _stub_heap_size(self):
        """HeapSize() - call REAL Windows function"""
        # RCX = heap handle, RDX = flags, R8 = ptr
        heap = self.uc.reg_read(UC_X86_REG_RCX)
        flags = self.uc.reg_read(UC_X86_REG_RDX)
        ptr = self.uc.reg_read(UC_X86_REG_R8)
        
        # Call real Windows API
        result = kernel32.HeapSize(heap, flags, ptr)
        self.uc.reg_write(UC_X86_REG_RAX, result)
        print(f"  HeapSize(0x{heap:x}, 0x{flags:x}, 0x{ptr:x}) -> {result} (REAL)")
        return result
    
    def _stub_heap_realloc(self):
        """HeapReAlloc() - call REAL Windows function"""
        # RCX = heap handle, RDX = flags, R8 = ptr, R9 = new size
        heap = self.uc.reg_read(UC_X86_REG_RCX)
        flags = self.uc.reg_read(UC_X86_REG_RDX)
        ptr = self.uc.reg_read(UC_X86_REG_R8)
        new_size = self.uc.reg_read(UC_X86_REG_R9)
        
        # Call real Windows API
        result = kernel32.HeapReAlloc(heap, flags, ptr, new_size)
        self.uc.reg_write(UC_X86_REG_RAX, result)
        print(f"  HeapReAlloc(0x{heap:x}, 0x{flags:x}, 0x{ptr:x}, {new_size}) -> 0x{result:x} (REAL)")
        return result
    
    # === PROCESS/THREAD INFO (call REAL Windows API) ===
    
    def _stub_get_current_process_id(self):
        """GetCurrentProcessId() - call REAL Windows function"""
        pid = kernel32.GetCurrentProcessId()
        self.uc.reg_write(UC_X86_REG_RAX, pid)
        print(f"  -> {pid} (REAL)")
        return pid
    
    def _stub_get_current_thread_id(self):
        """GetCurrentThreadId() - call REAL Windows function"""
        tid = kernel32.GetCurrentThreadId()
        self.uc.reg_write(UC_X86_REG_RAX, tid)
        print(f"  -> {tid} (REAL)")
        return tid
    
    def _stub_get_current_process(self):
        """GetCurrentProcess() - call REAL Windows function"""
        handle = kernel32.GetCurrentProcess()
        self.uc.reg_write(UC_X86_REG_RAX, handle)
        print(f"  -> 0x{handle:x} (REAL)")
        return handle
    
    # === EXIT ===
    
    def _stub_exit(self):
        """ExitProcess() - stop emulation"""
        # RCX = exit code
        exit_code = self.uc.reg_read(UC_X86_REG_RCX)
        print(f"  ExitProcess({exit_code})")
        
        # Stop emulation
        self.uc.emu_stop()
        return exit_code
    
    def _stub_get_tick_count(self):
        """GetTickCount() — возвращает миллисекунды (32-бит)"""
        tick_count = self.emu.clock.get_tick_count() & 0xFFFFFFFF
        self.uc.reg_write(UC_X86_REG_RAX, tick_count)
        print(f"[API] GetTickCount() -> {tick_count} мс")
