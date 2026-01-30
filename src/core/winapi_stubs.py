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
            ('VirtualProtect', self._stub_virtual_protect),
            
            # === PROCESS/THREAD INFO (call real Windows) ===
            ('GetCurrentProcessId', self._stub_get_current_process_id),
            ('GetCurrentThreadId', self._stub_get_current_thread_id),
            ('GetCurrentProcess', self._stub_get_current_process),
            
            # === DLL/MODULE LOADING (заглушки) ===
            ('LoadLibraryA', self._stub_load_library_a),
            ('LoadLibraryW', self._stub_load_library_a),  # Используем ту же заглушку
            ('GetProcAddress', self._stub_get_proc_address),
            ('GetModuleHandleW', self._stub_get_module_handle_w),
            
            # === FILE I/O (заглушки) ===
            ('CreateFileA', self._stub_create_file_a),
            ('CreateFileW', self._stub_create_file_a),  # Используем ту же заглушку
            ('ReadFile', self._stub_read_file),
            ('CloseHandle', self._stub_close_handle),
            
            # === UI (заглушки) ===
            ('MessageBoxA', self._stub_message_box_a),
            ('MessageBoxW', self._stub_message_box_a),
            
            # === SYSTEM INFO (заглушки) ===
            ('GetSystemInfo', self._stub_get_system_info),
            ('Sleep', self._stub_sleep),
            
            # === CRT SUPPORT ===
            ('GetCommandLineA', self._stub_get_command_line_a),
            ('GetCommandLineW', self._stub_get_command_line_w),
            ('GetStartupInfoW', self._stub_get_startup_info_w),
            ('InitializeSListHead', self._stub_initialize_slist_head),
            ('SetUnhandledExceptionFilter', self._stub_set_unhandled_exception_filter),
            
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
    
    # === MEMORY MANAGEMENT (use MiniOS) ===
    
    def _stub_get_process_heap(self):
        """GetProcessHeap() - use MiniOS"""
        heap_handle = self.emu.os.GetProcessHeap()
        self.uc.reg_write(UC_X86_REG_RAX, heap_handle)
        print(f"  -> 0x{heap_handle:x}")
        return heap_handle
    
    def _stub_heap_alloc(self):
        """HeapAlloc() - use MiniOS"""
        # RCX = heap handle, RDX = flags, R8 = size
        heap = self.uc.reg_read(UC_X86_REG_RCX)
        flags = self.uc.reg_read(UC_X86_REG_RDX)
        size = self.uc.reg_read(UC_X86_REG_R8)
        
        result = self.emu.os.HeapAlloc(heap, flags, size)
        self.uc.reg_write(UC_X86_REG_RAX, result)
        print(f"  HeapAlloc(0x{heap:x}, 0x{flags:x}, {size}) -> 0x{result:x}")
        return result
    
    def _stub_heap_free(self):
        """HeapFree() - use MiniOS"""
        # RCX = heap handle, RDX = flags, R8 = ptr
        heap = self.uc.reg_read(UC_X86_REG_RCX)
        flags = self.uc.reg_read(UC_X86_REG_RDX)
        ptr = self.uc.reg_read(UC_X86_REG_R8)
        
        result = self.emu.os.HeapFree(heap, flags, ptr)
        self.uc.reg_write(UC_X86_REG_RAX, result)
        print(f"  HeapFree(0x{heap:x}, 0x{flags:x}, 0x{ptr:x}) -> {result}")
        return result
    
    def _stub_heap_size(self):
        """HeapSize() - simplified"""
        # RCX = heap handle, RDX = flags, R8 = ptr
        heap = self.uc.reg_read(UC_X86_REG_RCX)
        flags = self.uc.reg_read(UC_X86_REG_RDX)
        ptr = self.uc.reg_read(UC_X86_REG_R8)
        
        # Return size from heap manager
        if ptr in self.emu.os.heap.allocations:
            result = self.emu.os.heap.allocations[ptr]
        else:
            result = 0
        
        self.uc.reg_write(UC_X86_REG_RAX, result)
        print(f"  HeapSize(0x{heap:x}, 0x{flags:x}, 0x{ptr:x}) -> {result}")
        return result
    
    def _stub_heap_realloc(self):
        """HeapReAlloc() - use MiniOS"""
        # RCX = heap handle, RDX = flags, R8 = ptr, R9 = new size
        heap = self.uc.reg_read(UC_X86_REG_RCX)
        flags = self.uc.reg_read(UC_X86_REG_RDX)
        ptr = self.uc.reg_read(UC_X86_REG_R8)
        new_size = self.uc.reg_read(UC_X86_REG_R9)
        
        result = self.emu.os.HeapReAlloc(heap, flags, ptr, new_size)
        self.uc.reg_write(UC_X86_REG_RAX, result)
        print(f"  HeapReAlloc(0x{heap:x}, 0x{flags:x}, 0x{ptr:x}, {new_size}) -> 0x{result:x}")
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
        print(f"  ExitProcess({exit_code}) - stopping emulation")
        
        # Set RAX to exit code
        self.uc.reg_write(UC_X86_REG_RAX, exit_code)
        
        # Stop emulation immediately - don't return!
        self.uc.emu_stop()
        return exit_code
    
    # === CRT SUPPORT ===
    
    def _stub_get_command_line_a(self):
        """GetCommandLineA() - return pointer to command line"""
        # Allocate and write command line string
        cmd_line = b"time_check_demo.exe INVALID-KEY\x00"
        ptr = self.emu.os.HeapAlloc(self.emu.os.heap.process_heap, 0, len(cmd_line))
        self.uc.mem_write(ptr, cmd_line)
        self.uc.reg_write(UC_X86_REG_RAX, ptr)
        print(f"  -> 0x{ptr:x}")
        return ptr
    
    def _stub_get_command_line_w(self):
        """GetCommandLineW() - return pointer to wide command line"""
        # Allocate and write wide command line string
        cmd_line = "time_check_demo.exe INVALID-KEY\x00".encode('utf-16le')
        ptr = self.emu.os.HeapAlloc(self.emu.os.heap.process_heap, 0, len(cmd_line))
        self.uc.mem_write(ptr, cmd_line)
        self.uc.reg_write(UC_X86_REG_RAX, ptr)
        print(f"  -> 0x{ptr:x}")
        return ptr
    
    def _stub_get_module_handle_w(self):
        """GetModuleHandleW() - return module handle"""
        # RCX = module name (or NULL for exe)
        ptr = self.uc.reg_read(UC_X86_REG_RCX)
        if ptr == 0:
            # Return image base as module handle
            handle = self.emu.pe_loader.image_base if self.emu.pe_loader else 0x140000000
        else:
            # Return fake handle
            handle = 0x140000000
        self.uc.reg_write(UC_X86_REG_RAX, handle)
        print(f"  -> 0x{handle:x}")
        return handle
    
    def _stub_get_startup_info_w(self):
        """GetStartupInfoW() - fill STARTUPINFOW structure"""
        # RCX = pointer to STARTUPINFOW
        ptr = self.uc.reg_read(UC_X86_REG_RCX)
        # Zero out structure (simplified)
        self.uc.mem_write(ptr, b'\x00' * 104)  # sizeof(STARTUPINFOW)
        print(f"  -> filled structure at 0x{ptr:x}")
        return 0
    
    def _stub_initialize_slist_head(self):
        """InitializeSListHead() - initialize singly linked list"""
        # RCX = pointer to SLIST_HEADER
        ptr = self.uc.reg_read(UC_X86_REG_RCX)
        # Zero out header
        self.uc.mem_write(ptr, b'\x00' * 16)
        print(f"  -> initialized at 0x{ptr:x}")
        return 0
    
    def _stub_set_unhandled_exception_filter(self):
        """SetUnhandledExceptionFilter() - set exception filter"""
        # RCX = filter function pointer
        filter_ptr = self.uc.reg_read(UC_X86_REG_RCX)
        # Return previous filter (NULL)
        self.uc.reg_write(UC_X86_REG_RAX, 0)
        print(f"  -> 0x0 (previous filter)")
        return 0
    
    def _stub_get_tick_count(self):
        """GetTickCount() — возвращает миллисекунды (32-бит)"""
        tick_count = self.emu.clock.get_tick_count() & 0xFFFFFFFF
        self.uc.reg_write(UC_X86_REG_RAX, tick_count)
        print(f"[API] GetTickCount() -> {tick_count} мс")

    def handle_unknown_function(self, func_name):
        """Мягкая обработка неизвестной функции"""
        print(f"[API] {func_name}() - NOT IMPLEMENTED")
        print(f"  -> Returning 1 (success stub)")
        
        # Возвращаем "успех" (1 = TRUE/SUCCESS для большинства WinAPI)
        self.uc.reg_write(UC_X86_REG_RAX, 1)
        return 1
    
    def handle_missing_dll(self, dll_name):
        """Мягкая обработка отсутствующей DLL"""
        print(f"[DLL] {dll_name} - NOT FOUND")
        print(f"  -> Returning NULL (DLL not loaded)")
        
        # LoadLibrary возвращает NULL при ошибке
        self.uc.reg_write(UC_X86_REG_RAX, 0)
        
        # Устанавливаем код ошибки ERROR_MOD_NOT_FOUND (126)
        if hasattr(self.emu.os, 'last_error'):
            self.emu.os.last_error = 126
        
        return 0


    # === ЗАГЛУШКИ ДЛЯ "ПЕРИФЕРИИ" (не блокируют основную ветку) ===
    
    def _stub_load_library_a(self):
        """LoadLibraryA() - заглушка для загрузки DLL"""
        # RCX = имя DLL
        ptr = self.uc.reg_read(UC_X86_REG_RCX)
        try:
            dll_name = self._read_string(ptr)
            print(f"[API] LoadLibraryA('{dll_name}')")
            
            # Возвращаем фейковый handle (не NULL, чтобы код продолжился)
            fake_handle = 0x70000000 + hash(dll_name) % 0x10000000
            self.uc.reg_write(UC_X86_REG_RAX, fake_handle)
            print(f"  -> 0x{fake_handle:x} (fake handle)")
            return fake_handle
        except:
            return self.handle_missing_dll("unknown.dll")
    
    def _stub_get_proc_address(self):
        """GetProcAddress() - заглушка для получения адреса функции"""
        # RCX = module handle, RDX = function name
        module = self.uc.reg_read(UC_X86_REG_RCX)
        name_ptr = self.uc.reg_read(UC_X86_REG_RDX)
        
        try:
            func_name = self._read_string(name_ptr)
            print(f"[API] GetProcAddress(0x{module:x}, '{func_name}')")
            
            # Проверяем, есть ли у нас stub для этой функции
            if func_name in self.stubs:
                addr = self.stubs[func_name]['address']
                print(f"  -> 0x{addr:x} (our stub)")
            else:
                # Возвращаем фейковый адрес (не NULL)
                addr = 0x71000000 + hash(func_name) % 0x10000000
                print(f"  -> 0x{addr:x} (fake address)")
            
            self.uc.reg_write(UC_X86_REG_RAX, addr)
            return addr
        except:
            return self.handle_unknown_function("GetProcAddress")
    
    def _stub_create_file_a(self):
        """CreateFileA() - заглушка для открытия файла"""
        # RCX = filename
        ptr = self.uc.reg_read(UC_X86_REG_RCX)
        try:
            filename = self._read_string(ptr)
            print(f"[API] CreateFileA('{filename}')")
            
            # Возвращаем фейковый handle (не INVALID_HANDLE_VALUE)
            fake_handle = 0x80000000 + hash(filename) % 0x10000000
            self.uc.reg_write(UC_X86_REG_RAX, fake_handle)
            print(f"  -> 0x{fake_handle:x} (fake file handle)")
            return fake_handle
        except:
            # INVALID_HANDLE_VALUE = -1
            self.uc.reg_write(UC_X86_REG_RAX, 0xFFFFFFFFFFFFFFFF)
            return 0xFFFFFFFFFFFFFFFF
    
    def _stub_read_file(self):
        """ReadFile() - заглушка для чтения файла"""
        # RCX = handle, RDX = buffer, R8 = bytes to read, R9 = bytes read
        handle = self.uc.reg_read(UC_X86_REG_RCX)
        buffer = self.uc.reg_read(UC_X86_REG_RDX)
        size = self.uc.reg_read(UC_X86_REG_R8)
        
        print(f"[API] ReadFile(0x{handle:x}, 0x{buffer:x}, {size})")
        
        # Записываем нули в буфер (имитация чтения)
        try:
            self.uc.mem_write(buffer, b'\x00' * size)
        except:
            pass
        
        # Возвращаем TRUE (успех)
        self.uc.reg_write(UC_X86_REG_RAX, 1)
        print(f"  -> TRUE (fake read)")
        return 1
    
    def _stub_close_handle(self):
        """CloseHandle() - заглушка для закрытия handle"""
        handle = self.uc.reg_read(UC_X86_REG_RCX)
        print(f"[API] CloseHandle(0x{handle:x})")
        
        # Всегда успех
        self.uc.reg_write(UC_X86_REG_RAX, 1)
        print(f"  -> TRUE")
        return 1
    
    def _stub_message_box_a(self):
        """MessageBoxA() - заглушка для диалога"""
        # RCX = hwnd, RDX = text, R8 = caption, R9 = type
        text_ptr = self.uc.reg_read(UC_X86_REG_RDX)
        caption_ptr = self.uc.reg_read(UC_X86_REG_R8)
        
        try:
            text = self._read_string(text_ptr)
            caption = self._read_string(caption_ptr)
            print(f"[API] MessageBoxA('{caption}', '{text}')")
        except:
            print(f"[API] MessageBoxA(...)")
        
        # Возвращаем IDOK (1)
        self.uc.reg_write(UC_X86_REG_RAX, 1)
        print(f"  -> IDOK (suppressed)")
        return 1
    
    def _stub_sleep(self):
        """Sleep() - заглушка для задержки"""
        ms = self.uc.reg_read(UC_X86_REG_RCX)
        print(f"[API] Sleep({ms} ms)")
        
        # Продвигаем виртуальное время вместо реальной задержки
        ticks = ms * self.emu.clock.cpu_freq_mhz * 1000
        self.emu.clock.advance(ticks)
        
        print(f"  -> advanced {ticks:,} virtual ticks")
        return 0
    
    def _stub_get_system_info(self):
        """GetSystemInfo() - заглушка для информации о системе"""
        # RCX = pointer to SYSTEM_INFO
        ptr = self.uc.reg_read(UC_X86_REG_RCX)
        
        print(f"[API] GetSystemInfo(0x{ptr:x})")
        
        # Заполняем минимальную структуру SYSTEM_INFO
        # dwPageSize = 4096, dwNumberOfProcessors = 8, etc.
        system_info = struct.pack('<IIIQQIIII',
            4096,      # dwPageSize
            0x10000,   # lpMinimumApplicationAddress
            0x7FFFFFFF, # lpMaximumApplicationAddress (low)
            0,         # lpMaximumApplicationAddress (high)
            0xFF,      # dwActiveProcessorMask (8 cores)
            8,         # dwNumberOfProcessors
            0,         # dwProcessorType
            4096,      # dwAllocationGranularity
            0,         # wProcessorLevel
            0          # wProcessorRevision
        )
        
        try:
            self.uc.mem_write(ptr, system_info)
            print(f"  -> filled (8 cores, 4KB pages)")
        except:
            pass
        
        return 0
    
    def _stub_virtual_protect(self):
        """VirtualProtect() - заглушка для изменения защиты памяти"""
        # RCX = address, RDX = size, R8 = new protect, R9 = old protect ptr
        addr = self.uc.reg_read(UC_X86_REG_RCX)
        size = self.uc.reg_read(UC_X86_REG_RDX)
        new_protect = self.uc.reg_read(UC_X86_REG_R8)
        old_protect_ptr = self.uc.reg_read(UC_X86_REG_R9)
        
        print(f"[API] VirtualProtect(0x{addr:x}, {size}, 0x{new_protect:x})")
        
        # Записываем старую защиту (PAGE_READWRITE)
        try:
            self.uc.mem_write(old_protect_ptr, struct.pack('<I', 0x04))
        except:
            pass
        
        # Возвращаем TRUE
        self.uc.reg_write(UC_X86_REG_RAX, 1)
        print(f"  -> TRUE")
        return 1
    
    def _read_string(self, ptr, max_len=256):
        """Вспомогательная функция: читает null-terminated строку"""
        data = b''
        for i in range(max_len):
            byte = self.uc.mem_read(ptr + i, 1)[0]
            if byte == 0:
                break
            data += bytes([byte])
        return data.decode('ascii', errors='ignore')
