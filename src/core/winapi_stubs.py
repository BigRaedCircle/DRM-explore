#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
WinAPI Stubs - bridge between emulator and real Windows API

Strategy: Call REAL Windows functions, not emulate them!
"""

import ctypes
import struct
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
        
        # Реалистичные заглушки (если доступны)
        self.system_info = getattr(emulator, 'system_info', None)
        self.vfs = getattr(emulator, 'vfs', None)
        self.directx = getattr(emulator, 'directx', None)
        self.network = getattr(emulator, 'network', None)
        
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
            ('GlobalAlloc', self._stub_global_alloc),
            ('GlobalLock', self._stub_global_lock),
            ('GlobalUnlock', self._stub_global_unlock),
            ('GlobalFree', self._stub_global_free),
            ('LocalAlloc', self._stub_local_alloc),
            ('LocalFree', self._stub_local_free),
            
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
            ('CreateFileW', self._stub_create_file_w),
            ('ReadFile', self._stub_read_file),
            ('WriteFile', self._stub_write_file),
            ('CloseHandle', self._stub_close_handle),
            
            # === UI (заглушки) ===
            ('MessageBoxA', self._stub_message_box_a),
            ('MessageBoxW', self._stub_message_box_a),
            ('EnumFontFamiliesW', self._stub_enum_font_families_w),
            ('EnumFontFamiliesExW', self._stub_enum_font_families_ex_w),
            ('CreateFontIndirectW', self._stub_create_font_indirect_w),
            ('CreateFontW', self._stub_create_font_w),
            ('GetDC', self._stub_get_dc),
            ('ReleaseDC', self._stub_release_dc),
            
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
            
            # === CRITICAL SECTIONS (threading) ===
            ('InitializeCriticalSectionAndSpinCount', self._stub_init_critical_section),
            ('EnterCriticalSection', self._stub_enter_critical_section),
            ('LeaveCriticalSection', self._stub_leave_critical_section),
            ('DeleteCriticalSection', self._stub_delete_critical_section),
            
            # === ERROR HANDLING ===
            ('GetLastError', self._stub_get_last_error),
            ('SetLastError', self._stub_set_last_error),
            ('RaiseException', self._stub_raise_exception),
            ('RtlPcToFileHeader', self._stub_rtl_pc_to_file_header),
            
            # === POINTER ENCODING (security) ===
            ('EncodePointer', self._stub_encode_pointer),
            ('DecodePointer', self._stub_decode_pointer),
            
            # === FIBER LOCAL STORAGE ===
            ('FlsAlloc', self._stub_fls_alloc),
            ('FlsGetValue', self._stub_fls_get_value),
            ('FlsSetValue', self._stub_fls_set_value),
            ('FlsFree', self._stub_fls_free),
            
            # === THREAD LOCAL STORAGE ===
            ('TlsAlloc', self._stub_tls_alloc),
            ('TlsGetValue', self._stub_tls_get_value),
            ('TlsSetValue', self._stub_tls_set_value),
            ('TlsFree', self._stub_tls_free),
            
            # === STANDARD HANDLES ===
            ('GetStdHandle', self._stub_get_std_handle),
            ('GetFileType', self._stub_get_file_type),
            ('SetHandleCount', self._stub_set_handle_count),
            
            # === ENVIRONMENT ===
            ('GetEnvironmentStringsW', self._stub_get_environment_strings_w),
            ('FreeEnvironmentStringsW', self._stub_free_environment_strings_w),
            ('GetModuleFileNameW', self._stub_get_module_filename_w),
            ('GetACP', self._stub_get_acp),
            ('GetStartupInfoA', self._stub_get_startup_info_a),
            ('GetTickCount', self._stub_get_tick_count),
            
            # === LOCALE AND CODE PAGES ===
            ('IsValidCodePage', self._stub_is_valid_code_page),
            ('GetCPInfo', self._stub_get_cp_info),
            ('GetStringTypeW', self._stub_get_string_type_w),
            ('MultiByteToWideChar', self._stub_multi_byte_to_wide_char),
            ('WideCharToMultiByte', self._stub_wide_char_to_multi_byte),
            ('LCMapStringW', self._stub_lc_map_string_w),
            ('HeapCreate', self._stub_heap_create),
            ('HeapSetInformation', self._stub_heap_set_information),
            
            # === DIRECTX (реалистичные заглушки) ===
            ('D3D11CreateDevice', self._stub_d3d11_create_device),
            ('CreateSwapChain', self._stub_create_swap_chain),
            ('Present', self._stub_present),
            ('GetAdapterDesc', self._stub_get_adapter_desc),
            
            # === NETWORK (реалистичные заглушки) ===
            ('connect', self._stub_connect),
            ('send', self._stub_send),
            ('recv', self._stub_recv),
            ('socket', self._stub_socket),
            ('closesocket', self._stub_closesocket),
            ('WSAStartup', self._stub_wsa_startup),
            ('WSACleanup', self._stub_wsa_cleanup),
            ('WSAGetLastError', self._stub_wsa_get_last_error),
            ('InternetOpenA', self._stub_internet_open_a),
            ('InternetOpenW', self._stub_internet_open_w),
            ('InternetOpenUrlA', self._stub_internet_open_url_a),
            ('InternetOpenUrlW', self._stub_internet_open_url_w),
            ('InternetReadFile', self._stub_internet_read_file),
            ('InternetCloseHandle', self._stub_internet_close_handle),
            ('HttpOpenRequestA', self._stub_http_open_request_a),
            ('HttpOpenRequestW', self._stub_http_open_request_w),
            ('HttpSendRequestA', self._stub_http_send_request_a),
            ('HttpSendRequestW', self._stub_http_send_request_w),
            ('InternetConnectA', self._stub_internet_connect_a),
            ('InternetConnectW', self._stub_internet_connect_w),
            
            # === GUI MESSAGE LOOP ===
            ('GetMessageA', self._stub_get_message_a),
            ('GetMessageW', self._stub_get_message_w),
            ('PeekMessageA', self._stub_peek_message_a),
            ('PeekMessageW', self._stub_peek_message_w),
            ('DispatchMessageA', self._stub_dispatch_message_a),
            ('DispatchMessageW', self._stub_dispatch_message_w),
            ('TranslateMessage', self._stub_translate_message),
            ('PostQuitMessage', self._stub_post_quit_message),
            ('DefWindowProcA', self._stub_def_window_proc_a),
            ('DefWindowProcW', self._stub_def_window_proc_w),
            ('WaitForSingleObject', self._stub_wait_for_single_object),
            ('WaitForMultipleObjects', self._stub_wait_for_multiple_objects),
            ('MsgWaitForMultipleObjects', self._stub_msg_wait_for_multiple_objects),
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
        """GetTickCount() - returns milliseconds (32-bit)"""
        tick_count = self.emu.clock.get_tick_count() & 0xFFFFFFFF
        self.uc.reg_write(UC_X86_REG_RAX, tick_count)
        print(f"  -> {tick_count} ms")
        return tick_count

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
        """CreateFileA() - открытие/создание файла"""
        # RCX = filename, RDX = desired access, R8 = share mode, R9 = security attributes
        # Stack: creation disposition, flags, template file
        ptr = self.uc.reg_read(UC_X86_REG_RCX)
        desired_access = self.uc.reg_read(UC_X86_REG_RDX)
        share_mode = self.uc.reg_read(UC_X86_REG_R8)
        
        # Read creation disposition from stack
        rsp = self.uc.reg_read(UC_X86_REG_RSP)
        try:
            stack_params = self.uc.mem_read(rsp + 0x28, 8)
            creation_disposition = struct.unpack('<Q', stack_params)[0]
        except:
            creation_disposition = 3  # OPEN_EXISTING
        
        try:
            filename = self._read_string(ptr)
            
            # Decode access flags
            GENERIC_READ = 0x80000000
            GENERIC_WRITE = 0x40000000
            
            # Decode creation disposition
            # CREATE_NEW = 1, CREATE_ALWAYS = 2, OPEN_EXISTING = 3, OPEN_ALWAYS = 4, TRUNCATE_EXISTING = 5
            
            mode_str = ""
            if desired_access & GENERIC_WRITE:
                if creation_disposition == 2:  # CREATE_ALWAYS
                    mode_str = "wb"
                elif creation_disposition == 4:  # OPEN_ALWAYS
                    mode_str = "ab"
                else:
                    mode_str = "wb"
            elif desired_access & GENERIC_READ:
                mode_str = "rb"
            else:
                mode_str = "rb"
            
            print(f"[API] CreateFileA('{filename}', access=0x{desired_access:x}, disposition={creation_disposition})")
            print(f"  -> mode: {mode_str}")
            
            # Используем реальную файловую систему для записи
            if not hasattr(self, '_file_handles'):
                self._file_handles = {}
                self._next_handle = 0x1000
            
            try:
                # Открываем реальный файл
                file_obj = open(filename, mode_str)
                handle = self._next_handle
                self._next_handle += 1
                
                self._file_handles[handle] = {
                    'file': file_obj,
                    'name': filename,
                    'mode': mode_str
                }
                
                self.uc.reg_write(UC_X86_REG_RAX, handle)
                print(f"  -> 0x{handle:x} (REAL file handle)")
                return handle
            except Exception as e:
                print(f"  -> INVALID_HANDLE_VALUE (error: {e})")
                # INVALID_HANDLE_VALUE = -1
                self.uc.reg_write(UC_X86_REG_RAX, 0xFFFFFFFFFFFFFFFF)
                return 0xFFFFFFFFFFFFFFFF
        except Exception as e:
            print(f"[API] CreateFileA() - error: {e}")
            # INVALID_HANDLE_VALUE = -1
            self.uc.reg_write(UC_X86_REG_RAX, 0xFFFFFFFFFFFFFFFF)
            return 0xFFFFFFFFFFFFFFFF
    
    def _stub_create_file_w(self):
        """CreateFileW() - открытие/создание файла (Unicode)"""
        # RCX = filename, RDX = desired access, R8 = share mode, R9 = security attributes
        # Stack: creation disposition, flags, template file
        ptr = self.uc.reg_read(UC_X86_REG_RCX)
        desired_access = self.uc.reg_read(UC_X86_REG_RDX)
        share_mode = self.uc.reg_read(UC_X86_REG_R8)
        
        # Read creation disposition from stack
        rsp = self.uc.reg_read(UC_X86_REG_RSP)
        try:
            stack_params = self.uc.mem_read(rsp + 0x28, 8)
            creation_disposition = struct.unpack('<Q', stack_params)[0]
        except:
            creation_disposition = 3  # OPEN_EXISTING
        
        try:
            # Read wide string
            filename_w = b''
            for i in range(260):  # MAX_PATH
                char = self.uc.mem_read(ptr + i*2, 2)
                if char == b'\x00\x00':
                    break
                filename_w += char
            filename = filename_w.decode('utf-16le', errors='ignore')
            
            # Decode access flags
            GENERIC_READ = 0x80000000
            GENERIC_WRITE = 0x40000000
            
            mode_str = ""
            if desired_access & GENERIC_WRITE:
                if creation_disposition == 2:  # CREATE_ALWAYS
                    mode_str = "wb"
                elif creation_disposition == 4:  # OPEN_ALWAYS
                    mode_str = "ab"
                else:
                    mode_str = "wb"
            elif desired_access & GENERIC_READ:
                mode_str = "rb"
            else:
                mode_str = "rb"
            
            print(f"[API] CreateFileW('{filename}', access=0x{desired_access:x}, disposition={creation_disposition})")
            print(f"  -> mode: {mode_str}")
            
            # Используем реальную файловую систему для записи
            if not hasattr(self, '_file_handles'):
                self._file_handles = {}
                self._next_handle = 0x1000
            
            try:
                # Открываем реальный файл
                file_obj = open(filename, mode_str)
                handle = self._next_handle
                self._next_handle += 1
                
                self._file_handles[handle] = {
                    'file': file_obj,
                    'name': filename,
                    'mode': mode_str
                }
                
                self.uc.reg_write(UC_X86_REG_RAX, handle)
                print(f"  -> 0x{handle:x} (REAL file handle)")
                return handle
            except Exception as e:
                print(f"  -> INVALID_HANDLE_VALUE (error: {e})")
                # INVALID_HANDLE_VALUE = -1
                self.uc.reg_write(UC_X86_REG_RAX, 0xFFFFFFFFFFFFFFFF)
                return 0xFFFFFFFFFFFFFFFF
        except Exception as e:
            print(f"[API] CreateFileW() - error: {e}")
            # INVALID_HANDLE_VALUE = -1
            self.uc.reg_write(UC_X86_REG_RAX, 0xFFFFFFFFFFFFFFFF)
            return 0xFFFFFFFFFFFFFFFF
    
    def _stub_write_file(self):
        """WriteFile() - запись в файл"""
        # RCX = handle, RDX = buffer, R8 = bytes to write, R9 = bytes written ptr
        # Stack: overlapped
        handle = self.uc.reg_read(UC_X86_REG_RCX)
        buffer = self.uc.reg_read(UC_X86_REG_RDX)
        size = self.uc.reg_read(UC_X86_REG_R8)
        bytes_written_ptr = self.uc.reg_read(UC_X86_REG_R9)
        
        print(f"[API] WriteFile(0x{handle:x}, 0x{buffer:x}, {size})")
        
        # Проверяем, есть ли у нас реальный файл
        if hasattr(self, '_file_handles') and handle in self._file_handles:
            try:
                # Читаем данные из буфера эмулятора
                data = self.uc.mem_read(buffer, size)
                
                # Записываем в реальный файл
                file_obj = self._file_handles[handle]['file']
                file_obj.write(data)
                file_obj.flush()  # Сразу сбрасываем на диск
                
                # Записываем количество записанных байт
                if bytes_written_ptr:
                    self.uc.mem_write(bytes_written_ptr, size.to_bytes(4, 'little'))
                
                self.uc.reg_write(UC_X86_REG_RAX, 1)  # TRUE
                print(f"  -> TRUE (wrote {size} bytes to '{self._file_handles[handle]['name']}')")
                return 1
            except Exception as e:
                print(f"  -> FALSE (error: {e})")
                self.uc.reg_write(UC_X86_REG_RAX, 0)  # FALSE
                return 0
        
        # Handle stdout (handle 7 = STD_OUTPUT_HANDLE)
        if handle == 7 or handle == 0xfffffff5:  # STD_OUTPUT_HANDLE = -11 = 0xfffffff5
            try:
                data = self.uc.mem_read(buffer, size)
                text = data.decode('utf-8', errors='ignore')
                print(f"[STDOUT] {text}", end='')
            except:
                pass
        
        # Fallback: имитация записи
        print(f"  -> TRUE (fake write, handle not found)")
        if bytes_written_ptr:
            try:
                self.uc.mem_write(bytes_written_ptr, size.to_bytes(4, 'little'))
            except:
                pass
        
        self.uc.reg_write(UC_X86_REG_RAX, 1)  # TRUE
        return 1
    
    def _stub_read_file(self):
        """ReadFile() - чтение файла"""
        # RCX = handle, RDX = buffer, R8 = bytes to read, R9 = bytes read
        handle = self.uc.reg_read(UC_X86_REG_RCX)
        buffer = self.uc.reg_read(UC_X86_REG_RDX)
        size = self.uc.reg_read(UC_X86_REG_R8)
        bytes_read_ptr = self.uc.reg_read(UC_X86_REG_R9)
        
        print(f"[API] ReadFile(0x{handle:x}, 0x{buffer:x}, {size})")
        
        # Проверяем, есть ли у нас реальный файл
        if hasattr(self, '_file_handles') and handle in self._file_handles:
            try:
                # Читаем из реального файла
                file_obj = self._file_handles[handle]['file']
                data = file_obj.read(size)
                
                # Записываем в буфер эмулятора
                self.uc.mem_write(buffer, data)
                
                # Записываем количество прочитанных байт
                if bytes_read_ptr:
                    self.uc.mem_write(bytes_read_ptr, len(data).to_bytes(4, 'little'))
                
                self.uc.reg_write(UC_X86_REG_RAX, 1)  # TRUE
                print(f"  -> TRUE (read {len(data)} bytes from '{self._file_handles[handle]['name']}')")
                return 1
            except Exception as e:
                print(f"  -> FALSE (error: {e})")
                self.uc.reg_write(UC_X86_REG_RAX, 0)  # FALSE
                return 0
        
        # Используем VirtualFileSystem если доступна
        if self.vfs:
            data = self.vfs.read(handle, size)
            if data:
                try:
                    self.uc.mem_write(buffer, data)
                    # Записываем количество прочитанных байт
                    if bytes_read_ptr:
                        self.uc.mem_write(bytes_read_ptr, len(data).to_bytes(4, 'little'))
                    self.uc.reg_write(UC_X86_REG_RAX, 1)
                    print(f"  -> TRUE (read {len(data)} bytes from VFS)")
                    return 1
                except:
                    pass
        
        # Fallback: записываем нули в буфер (имитация чтения)
        try:
            self.uc.mem_write(buffer, b'\x00' * size)
            if bytes_read_ptr:
                self.uc.mem_write(bytes_read_ptr, size.to_bytes(4, 'little'))
        except:
            pass
        
        # Возвращаем TRUE (успех)
        self.uc.reg_write(UC_X86_REG_RAX, 1)
        print(f"  -> TRUE (fake read)")
        return 1
    
    def _stub_close_handle(self):
        """CloseHandle() - закрытие handle"""
        handle = self.uc.reg_read(UC_X86_REG_RCX)
        print(f"[API] CloseHandle(0x{handle:x})")
        
        # Проверяем, есть ли у нас реальный файл
        if hasattr(self, '_file_handles') and handle in self._file_handles:
            try:
                file_obj = self._file_handles[handle]['file']
                file_name = self._file_handles[handle]['name']
                file_obj.close()
                del self._file_handles[handle]
                
                self.uc.reg_write(UC_X86_REG_RAX, 1)
                print(f"  -> TRUE (closed REAL file '{file_name}')")
                return 1
            except Exception as e:
                print(f"  -> FALSE (error: {e})")
                self.uc.reg_write(UC_X86_REG_RAX, 0)
                return 0
        
        # Используем VirtualFileSystem если доступна
        if self.vfs and self.vfs.close(handle):
            self.uc.reg_write(UC_X86_REG_RAX, 1)
            print(f"  -> TRUE (closed VFS handle)")
            return 1
        
        # Fallback: всегда успех
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
    
    def _stub_enum_font_families_w(self):
        """EnumFontFamiliesW() - перечисление шрифтов"""
        # RCX = hdc, RDX = family name, R8 = callback, R9 = lParam
        hdc = self.uc.reg_read(UC_X86_REG_RCX)
        callback = self.uc.reg_read(UC_X86_REG_R8)
        
        print(f"[API] EnumFontFamiliesW(hdc=0x{hdc:x}, callback=0x{callback:x})")
        
        # Возвращаем 0 - нет шрифтов (или ошибка)
        # В режиме командной строки шрифты не нужны
        self.uc.reg_write(UC_X86_REG_RAX, 0)
        print(f"  -> 0 (no fonts, command-line mode)")
        return 0
    
    def _stub_enum_font_families_ex_w(self):
        """EnumFontFamiliesExW() - расширенное перечисление шрифтов"""
        # RCX = hdc, RDX = LOGFONT, R8 = callback, R9 = lParam
        hdc = self.uc.reg_read(UC_X86_REG_RCX)
        callback = self.uc.reg_read(UC_X86_REG_R8)
        
        print(f"[API] EnumFontFamiliesExW(hdc=0x{hdc:x}, callback=0x{callback:x})")
        
        # Возвращаем 0 - нет шрифтов (или ошибка)
        # В режиме командной строки шрифты не нужны
        self.uc.reg_write(UC_X86_REG_RAX, 0)
        print(f"  -> 0 (no fonts, command-line mode)")
        return 0
    
    def _stub_create_font_indirect_w(self):
        """CreateFontIndirectW() - создание шрифта"""
        # RCX = LOGFONT pointer
        logfont_ptr = self.uc.reg_read(UC_X86_REG_RCX)
        
        print(f"[API] CreateFontIndirectW(logfont=0x{logfont_ptr:x})")
        
        # Возвращаем фейковый handle (не NULL!)
        # Это позволит CPU-Z продолжить, даже если он не использует шрифт
        fake_handle = 0x50000001  # Фейковый HFONT
        self.uc.reg_write(UC_X86_REG_RAX, fake_handle)
        print(f"  -> 0x{fake_handle:x} (fake font handle)")
        return fake_handle
    
    def _stub_create_font_w(self):
        """CreateFontW() - создание шрифта"""
        print(f"[API] CreateFontW()")
        
        # Возвращаем фейковый handle (не NULL!)
        fake_handle = 0x50000002  # Фейковый HFONT
        self.uc.reg_write(UC_X86_REG_RAX, fake_handle)
        print(f"  -> 0x{fake_handle:x} (fake font handle)")
        return fake_handle
    
    def _stub_get_dc(self):
        """GetDC() - получение device context"""
        # RCX = hwnd
        hwnd = self.uc.reg_read(UC_X86_REG_RCX)
        
        print(f"[API] GetDC(hwnd=0x{hwnd:x})")
        
        # Выделяем память для фейкового DC и заполняем нулями
        if not hasattr(self, '_fake_dc_counter'):
            self._fake_dc_counter = 0
            self._fake_dc_base = 0x60000000
            # Выделяем 1MB для фейковых DC
            try:
                self.uc.mem_map(self._fake_dc_base, 0x100000)
                self.uc.mem_write(self._fake_dc_base, b'\x00' * 0x100000)
                print(f"[DC] Allocated fake DC region at 0x{self._fake_dc_base:x}")
            except:
                pass
        
        # Возвращаем адрес в выделенной области
        fake_dc = self._fake_dc_base + (self._fake_dc_counter * 0x1000)
        self._fake_dc_counter += 1
        
        self.uc.reg_write(UC_X86_REG_RAX, fake_dc)
        print(f"  -> 0x{fake_dc:x} (fake DC with allocated memory)")
        return fake_dc
    
    def _stub_release_dc(self):
        """ReleaseDC() - освобождение device context"""
        # RCX = hwnd, RDX = hdc
        hwnd = self.uc.reg_read(UC_X86_REG_RCX)
        hdc = self.uc.reg_read(UC_X86_REG_RDX)
        
        print(f"[API] ReleaseDC(hwnd=0x{hwnd:x}, hdc=0x{hdc:x})")
        
        # Возвращаем 1 - успех
        self.uc.reg_write(UC_X86_REG_RAX, 1)
        print(f"  -> 1 (success)")
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
        """GetSystemInfo() - реальная информация о системе"""
        # RCX = pointer to SYSTEM_INFO
        ptr = self.uc.reg_read(UC_X86_REG_RCX)
        
        print(f"[API] GetSystemInfo(0x{ptr:x})")
        
        # Используем реальные данные если доступны
        if self.system_info:
            cpu_cores = self.system_info.cpu_cores
            print(f"  -> Using REAL system data: {cpu_cores} cores")
        else:
            cpu_cores = 8  # Fallback
        
        # Заполняем структуру SYSTEM_INFO с реальными данными
        # typedef struct _SYSTEM_INFO {
        #   DWORD dwPageSize;                    // 4 bytes
        #   LPVOID lpMinimumApplicationAddress; // 8 bytes (pointer)
        #   LPVOID lpMaximumApplicationAddress; // 8 bytes (pointer)
        #   DWORD_PTR dwActiveProcessorMask;    // 8 bytes
        #   DWORD dwNumberOfProcessors;         // 4 bytes
        #   DWORD dwProcessorType;              // 4 bytes
        #   DWORD dwAllocationGranularity;      // 4 bytes
        #   WORD wProcessorLevel;               // 2 bytes
        #   WORD wProcessorRevision;            // 2 bytes
        # } SYSTEM_INFO;
        system_info = struct.pack('<IQQQQIIHH',
            4096,      # dwPageSize
            0x10000,   # lpMinimumApplicationAddress
            0x7FFFFFFF000,  # lpMaximumApplicationAddress
            (1 << cpu_cores) - 1,  # dwActiveProcessorMask (маска для всех ядер)
            cpu_cores, # dwNumberOfProcessors (REAL)
            0,         # dwProcessorType
            4096,      # dwAllocationGranularity
            0,         # wProcessorLevel
            0          # wProcessorRevision
        )
        
        try:
            self.uc.mem_write(ptr, system_info)
            print(f"  -> filled ({cpu_cores} cores, 4KB pages)")
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
    
    def _stub_global_alloc(self):
        """GlobalAlloc() - allocate global memory"""
        # RCX = flags, RDX = size
        flags = self.uc.reg_read(UC_X86_REG_RCX)
        size = self.uc.reg_read(UC_X86_REG_RDX)
        
        # Use heap allocator
        result = self.emu.os.HeapAlloc(self.emu.os.heap.process_heap, flags, size)
        self.uc.reg_write(UC_X86_REG_RAX, result)
        print(f"  GlobalAlloc(0x{flags:x}, {size}) -> 0x{result:x}")
        return result
    
    def _stub_global_lock(self):
        """GlobalLock() - lock global memory (just return the handle)"""
        # RCX = handle
        handle = self.uc.reg_read(UC_X86_REG_RCX)
        # In modern Windows, GlobalLock just returns the pointer
        self.uc.reg_write(UC_X86_REG_RAX, handle)
        print(f"  GlobalLock(0x{handle:x}) -> 0x{handle:x}")
        return handle
    
    def _stub_global_unlock(self):
        """GlobalUnlock() - unlock global memory"""
        # RCX = handle
        handle = self.uc.reg_read(UC_X86_REG_RCX)
        # Always return TRUE
        self.uc.reg_write(UC_X86_REG_RAX, 1)
        print(f"  GlobalUnlock(0x{handle:x}) -> TRUE")
        return 1
    
    def _stub_global_free(self):
        """GlobalFree() - free global memory"""
        # RCX = handle
        handle = self.uc.reg_read(UC_X86_REG_RCX)
        # Use heap free
        result = self.emu.os.HeapFree(self.emu.os.heap.process_heap, 0, handle)
        self.uc.reg_write(UC_X86_REG_RAX, 0 if result else handle)
        print(f"  GlobalFree(0x{handle:x}) -> {0 if result else handle}")
        return 0 if result else handle
    
    def _stub_local_alloc(self):
        """LocalAlloc() - allocate local memory"""
        # RCX = flags, RDX = size
        flags = self.uc.reg_read(UC_X86_REG_RCX)
        size = self.uc.reg_read(UC_X86_REG_RDX)
        
        # Use heap allocator
        result = self.emu.os.HeapAlloc(self.emu.os.heap.process_heap, flags, size)
        self.uc.reg_write(UC_X86_REG_RAX, result)
        print(f"  LocalAlloc(0x{flags:x}, {size}) -> 0x{result:x}")
        return result
    
    def _stub_local_free(self):
        """LocalFree() - free local memory"""
        # RCX = handle
        handle = self.uc.reg_read(UC_X86_REG_RCX)
        # Use heap free
        result = self.emu.os.HeapFree(self.emu.os.heap.process_heap, 0, handle)
        self.uc.reg_write(UC_X86_REG_RAX, 0 if result else handle)
        print(f"  LocalFree(0x{handle:x}) -> {0 if result else handle}")
        return 0 if result else handle
    
    # === CRITICAL SECTIONS (threading) ===
    
    def _stub_init_critical_section(self):
        """InitializeCriticalSectionAndSpinCount() - initialize critical section"""
        # RCX = pointer to CRITICAL_SECTION, RDX = spin count
        ptr = self.uc.reg_read(UC_X86_REG_RCX)
        spin_count = self.uc.reg_read(UC_X86_REG_RDX)
        
        # Just zero out the structure (40 bytes)
        try:
            self.uc.mem_write(ptr, b'\x00' * 40)
        except:
            pass
        
        # Return TRUE
        self.uc.reg_write(UC_X86_REG_RAX, 1)
        return 1
    
    def _stub_enter_critical_section(self):
        """EnterCriticalSection() - enter critical section (no-op in single-threaded)"""
        # RCX = pointer to CRITICAL_SECTION
        # In single-threaded emulation, this is a no-op
        return 0
    
    def _stub_leave_critical_section(self):
        """LeaveCriticalSection() - leave critical section (no-op in single-threaded)"""
        # RCX = pointer to CRITICAL_SECTION
        # In single-threaded emulation, this is a no-op
        return 0
    
    def _stub_delete_critical_section(self):
        """DeleteCriticalSection() - delete critical section"""
        # RCX = pointer to CRITICAL_SECTION
        # No-op
        return 0
    
    # === ERROR HANDLING ===
    
    def _stub_get_last_error(self):
        """GetLastError() - get last error code"""
        error = getattr(self.emu.os, 'last_error', 0)
        self.uc.reg_write(UC_X86_REG_RAX, error)
        return error
    
    def _stub_set_last_error(self):
        """SetLastError() - set last error code"""
        # RCX = error code
        error = self.uc.reg_read(UC_X86_REG_RCX)
        self.emu.os.last_error = error
        return 0
    
    def _stub_raise_exception(self):
        """RaiseException() - raise an exception (stop emulation)"""
        # RCX = exception code, RDX = exception flags, R8 = number of arguments, R9 = arguments
        exception_code = self.uc.reg_read(UC_X86_REG_RCX)
        exception_flags = self.uc.reg_read(UC_X86_REG_RDX)
        
        print(f"[API] RaiseException(code=0x{exception_code:x}, flags=0x{exception_flags:x})")
        
        # Check if it's a C++ exception (0xE06D7363 = Microsoft C++ Exception)
        if exception_code == 0xE06D7363:
            print(f"  -> C++ exception detected - stopping emulation")
            print(f"  -> This means CPU-Z encountered an error during initialization")
        else:
            print(f"  -> Exception code: 0x{exception_code:x}")
        
        # Stop emulation - don't return!
        self.uc.emu_stop()
        return 0
    
    def _stub_rtl_pc_to_file_header(self):
        """RtlPcToFileHeader() - get module base from PC"""
        # RCX = PC address, RDX = pointer to receive base address
        pc = self.uc.reg_read(UC_X86_REG_RCX)
        base_ptr = self.uc.reg_read(UC_X86_REG_RDX)
        
        # Return image base
        image_base = self.emu.pe_loader.image_base if self.emu.pe_loader else 0x140000000
        
        try:
            self.uc.mem_write(base_ptr, image_base.to_bytes(8, 'little'))
        except:
            pass
        
        # Return image base in RAX
        self.uc.reg_write(UC_X86_REG_RAX, image_base)
        return image_base
    
    # === POINTER ENCODING (security) ===
    
    def _stub_encode_pointer(self):
        """EncodePointer() - encode pointer (just return as-is for simplicity)"""
        # RCX = pointer to encode
        ptr = self.uc.reg_read(UC_X86_REG_RCX)
        # In real Windows, this XORs with a secret cookie
        # For emulation, just return the pointer as-is
        self.uc.reg_write(UC_X86_REG_RAX, ptr)
        return ptr
    
    def _stub_decode_pointer(self):
        """DecodePointer() - decode pointer (just return as-is for simplicity)"""
        # RCX = pointer to decode
        ptr = self.uc.reg_read(UC_X86_REG_RCX)
        # In real Windows, this XORs with a secret cookie
        # For emulation, just return the pointer as-is
        self.uc.reg_write(UC_X86_REG_RAX, ptr)
        return ptr
    
    # === FIBER LOCAL STORAGE ===
    
    def _stub_fls_alloc(self):
        """FlsAlloc() - allocate fiber local storage index"""
        # RCX = callback function (optional)
        # Return a fake FLS index
        if not hasattr(self, '_fls_counter'):
            self._fls_counter = 1
            self._fls_data = {}
        
        index = self._fls_counter
        self._fls_counter += 1
        self._fls_data[index] = 0
        
        self.uc.reg_write(UC_X86_REG_RAX, index)
        return index
    
    def _stub_fls_get_value(self):
        """FlsGetValue() - get fiber local storage value"""
        # RCX = FLS index
        index = self.uc.reg_read(UC_X86_REG_RCX)
        
        if not hasattr(self, '_fls_data'):
            self._fls_data = {}
        
        value = self._fls_data.get(index, 0)
        self.uc.reg_write(UC_X86_REG_RAX, value)
        return value
    
    def _stub_fls_set_value(self):
        """FlsSetValue() - set fiber local storage value"""
        # RCX = FLS index, RDX = value
        index = self.uc.reg_read(UC_X86_REG_RCX)
        value = self.uc.reg_read(UC_X86_REG_RDX)
        
        if not hasattr(self, '_fls_data'):
            self._fls_data = {}
        
        self._fls_data[index] = value
        self.uc.reg_write(UC_X86_REG_RAX, 1)  # TRUE
        return 1
    
    def _stub_fls_free(self):
        """FlsFree() - free fiber local storage index"""
        # RCX = FLS index
        index = self.uc.reg_read(UC_X86_REG_RCX)
        
        if hasattr(self, '_fls_data') and index in self._fls_data:
            del self._fls_data[index]
        
        self.uc.reg_write(UC_X86_REG_RAX, 1)  # TRUE
        return 1
    
    # === THREAD LOCAL STORAGE ===
    
    def _stub_tls_alloc(self):
        """TlsAlloc() - allocate thread local storage index"""
        if not hasattr(self, '_tls_counter'):
            self._tls_counter = 1
            self._tls_data = {}
        
        index = self._tls_counter
        self._tls_counter += 1
        self._tls_data[index] = 0
        
        self.uc.reg_write(UC_X86_REG_RAX, index)
        print(f"  TlsAlloc() -> {index}")
        return index
    
    def _stub_tls_get_value(self):
        """TlsGetValue() - get thread local storage value"""
        # RCX = TLS index
        index = self.uc.reg_read(UC_X86_REG_RCX)
        
        if not hasattr(self, '_tls_data'):
            self._tls_data = {}
        
        value = self._tls_data.get(index, 0)
        self.uc.reg_write(UC_X86_REG_RAX, value)
        print(f"  TlsGetValue({index}) -> 0x{value:x}")
        return value
    
    def _stub_tls_set_value(self):
        """TlsSetValue() - set thread local storage value"""
        # RCX = TLS index, RDX = value
        index = self.uc.reg_read(UC_X86_REG_RCX)
        value = self.uc.reg_read(UC_X86_REG_RDX)
        
        if not hasattr(self, '_tls_data'):
            self._tls_data = {}
        
        self._tls_data[index] = value
        self.uc.reg_write(UC_X86_REG_RAX, 1)  # TRUE
        print(f"  TlsSetValue({index}, 0x{value:x}) -> TRUE")
        return 1
    
    def _stub_tls_free(self):
        """TlsFree() - free thread local storage index"""
        # RCX = TLS index
        index = self.uc.reg_read(UC_X86_REG_RCX)
        
        if hasattr(self, '_tls_data') and index in self._tls_data:
            del self._tls_data[index]
        
        self.uc.reg_write(UC_X86_REG_RAX, 1)  # TRUE
        print(f"  TlsFree({index}) -> TRUE")
        return 1
    
    # === STANDARD HANDLES ===
    
    def _stub_get_std_handle(self):
        """GetStdHandle() - get standard handle"""
        # RCX = std handle type (-10 = stdin, -11 = stdout, -12 = stderr)
        std_type = self.uc.reg_read(UC_X86_REG_RCX) & 0xFFFFFFFF
        
        # Return fake handles
        if std_type == 0xFFFFFFF6:  # STD_INPUT_HANDLE (-10)
            handle = 0x3
        elif std_type == 0xFFFFFFF5:  # STD_OUTPUT_HANDLE (-11)
            handle = 0x7
        elif std_type == 0xFFFFFFF4:  # STD_ERROR_HANDLE (-12)
            handle = 0xB
        else:
            handle = 0
        
        self.uc.reg_write(UC_X86_REG_RAX, handle)
        return handle
    
    def _stub_get_file_type(self):
        """GetFileType() - get file type"""
        # RCX = file handle
        # Return FILE_TYPE_CHAR (0x0002) for console
        self.uc.reg_write(UC_X86_REG_RAX, 0x0002)
        return 0x0002
    
    def _stub_set_handle_count(self):
        """SetHandleCount() - set handle count (legacy function)"""
        # RCX = number of handles
        # Just return the same number
        count = self.uc.reg_read(UC_X86_REG_RCX)
        self.uc.reg_write(UC_X86_REG_RAX, count)
        return count
    
    # === ENVIRONMENT ===
    
    def _stub_get_environment_strings_w(self):
        """GetEnvironmentStringsW() - get environment strings"""
        # Return pointer to empty environment block (just double null terminator)
        if not hasattr(self, '_env_strings_ptr'):
            # Allocate memory for environment strings
            env_data = b'\x00\x00\x00\x00'  # Empty environment (double null)
            self._env_strings_ptr = self.emu.os.HeapAlloc(self.emu.os.heap.process_heap, 0, len(env_data))
            self.uc.mem_write(self._env_strings_ptr, env_data)
        
        self.uc.reg_write(UC_X86_REG_RAX, self._env_strings_ptr)
        return self._env_strings_ptr
    
    def _stub_free_environment_strings_w(self):
        """FreeEnvironmentStringsW() - free environment strings"""
        # RCX = pointer to environment strings
        # No-op (we don't actually free it)
        self.uc.reg_write(UC_X86_REG_RAX, 1)  # TRUE
        return 1
    
    def _stub_get_module_filename_w(self):
        """GetModuleFileNameW() - get module file name"""
        # RCX = module handle, RDX = buffer, R8 = buffer size
        buffer = self.uc.reg_read(UC_X86_REG_RDX)
        size = self.uc.reg_read(UC_X86_REG_R8)
        
        # Write fake module name
        module_name = "C:\\cpuz.exe\x00".encode('utf-16le')
        try:
            self.uc.mem_write(buffer, module_name[:size*2])
        except:
            pass
        
        # Return length (in characters, not bytes)
        length = len(module_name) // 2 - 1  # Exclude null terminator
        self.uc.reg_write(UC_X86_REG_RAX, length)
        return length
    
    def _stub_get_acp(self):
        """GetACP() - get active code page"""
        # Return 1252 (Western European)
        self.uc.reg_write(UC_X86_REG_RAX, 1252)
        return 1252
    
    def _stub_get_startup_info_a(self):
        """GetStartupInfoA() - get startup info (ANSI version)"""
        # RCX = pointer to STARTUPINFOA
        ptr = self.uc.reg_read(UC_X86_REG_RCX)
        # Zero out structure (68 bytes for STARTUPINFOA)
        try:
            self.uc.mem_write(ptr, b'\x00' * 68)
        except:
            pass
        return 0
    
    # === LOCALE AND CODE PAGES ===
    
    def _stub_is_valid_code_page(self):
        """IsValidCodePage() - check if code page is valid"""
        # RCX = code page
        code_page = self.uc.reg_read(UC_X86_REG_RCX)
        
        # Accept common code pages
        valid_pages = [1252, 1251, 1250, 65001, 437, 850, 1200, 1201]
        is_valid = 1 if code_page in valid_pages else 0
        
        self.uc.reg_write(UC_X86_REG_RAX, is_valid)
        return is_valid
    
    def _stub_get_cp_info(self):
        """GetCPInfo() - get code page information"""
        # RCX = code page, RDX = pointer to CPINFO structure
        code_page = self.uc.reg_read(UC_X86_REG_RCX)
        ptr = self.uc.reg_read(UC_X86_REG_RDX)
        
        # Fill CPINFO structure (simplified)
        # typedef struct _cpinfo {
        #   UINT MaxCharSize;        // 4 bytes
        #   BYTE DefaultChar[2];     // 2 bytes
        #   BYTE LeadByte[12];       // 12 bytes
        # } CPINFO;
        
        max_char_size = 1  # Single-byte for most code pages
        if code_page == 65001:  # UTF-8
            max_char_size = 4
        
        cpinfo = struct.pack('<I2s12s', 
            max_char_size,
            b'?_',  # Default char
            b'\x00' * 12  # No lead bytes for single-byte encodings
        )
        
        try:
            self.uc.mem_write(ptr, cpinfo)
        except:
            pass
        
        self.uc.reg_write(UC_X86_REG_RAX, 1)  # TRUE
        return 1
    
    def _stub_get_string_type_w(self):
        """GetStringTypeW() - get character type information"""
        # RCX = info type, RDX = string, R8 = count, R9 = char type buffer
        info_type = self.uc.reg_read(UC_X86_REG_RCX)
        string_ptr = self.uc.reg_read(UC_X86_REG_RDX)
        count = self.uc.reg_read(UC_X86_REG_R8)
        buffer_ptr = self.uc.reg_read(UC_X86_REG_R9)
        
        # Fill buffer with generic character types (all printable)
        # CT_CTYPE1: 0x0001 = C1_UPPER, 0x0002 = C1_LOWER, 0x0008 = C1_SPACE, etc.
        try:
            # Just mark all as printable (0x0040 = C1_PRINT)
            char_types = struct.pack('<' + 'H' * count, *([0x0040] * count))
            self.uc.mem_write(buffer_ptr, char_types)
        except:
            pass
        
        self.uc.reg_write(UC_X86_REG_RAX, 1)  # TRUE
        return 1
    
    def _stub_multi_byte_to_wide_char(self):
        """MultiByteToWideChar() - convert multibyte to wide char"""
        # RCX = code page, RDX = flags, R8 = multibyte string, R9 = byte count
        # Stack: wide char buffer, wide char count
        code_page = self.uc.reg_read(UC_X86_REG_RCX)
        flags = self.uc.reg_read(UC_X86_REG_RDX)
        mb_str_ptr = self.uc.reg_read(UC_X86_REG_R8)
        mb_count = self.uc.reg_read(UC_X86_REG_R9)
        
        # Read parameters from stack
        rsp = self.uc.reg_read(UC_X86_REG_RSP)
        try:
            stack_params = self.uc.mem_read(rsp + 0x20, 16)
            wc_buffer_ptr = struct.unpack('<Q', stack_params[0:8])[0]
            wc_count = struct.unpack('<Q', stack_params[8:16])[0]
        except:
            wc_buffer_ptr = 0
            wc_count = 0
        
        if mb_count == 0xFFFFFFFF or mb_count == 0xFFFFFFFFFFFFFFFF:
            # Calculate length
            try:
                mb_data = self.uc.mem_read(mb_str_ptr, 256)
                mb_count = mb_data.find(b'\x00')
                if mb_count == -1:
                    mb_count = 256
            except:
                mb_count = 0
        
        # If buffer is NULL, return required size
        if wc_buffer_ptr == 0:
            # Return number of wide chars needed (same as byte count for ASCII)
            result = mb_count + 1  # +1 for null terminator
            self.uc.reg_write(UC_X86_REG_RAX, result)
            return result
        
        # Convert (simplified: just copy bytes as wide chars)
        try:
            mb_data = self.uc.mem_read(mb_str_ptr, min(mb_count, 256))
            wc_data = b''.join(bytes([b, 0]) for b in mb_data) + b'\x00\x00'
            self.uc.mem_write(wc_buffer_ptr, wc_data[:wc_count*2])
        except:
            pass
        
        # Return number of wide chars written
        result = min(mb_count + 1, wc_count)
        self.uc.reg_write(UC_X86_REG_RAX, result)
        return result
    
    def _stub_wide_char_to_multi_byte(self):
        """WideCharToMultiByte() - convert wide char to multibyte"""
        # RCX = code page, RDX = flags, R8 = wide char string, R9 = wide char count
        # Stack: multibyte buffer, multibyte count, default char, used default char
        code_page = self.uc.reg_read(UC_X86_REG_RCX)
        flags = self.uc.reg_read(UC_X86_REG_RDX)
        wc_str_ptr = self.uc.reg_read(UC_X86_REG_R8)
        wc_count = self.uc.reg_read(UC_X86_REG_R9)
        
        # Read parameters from stack
        rsp = self.uc.reg_read(UC_X86_REG_RSP)
        try:
            stack_params = self.uc.mem_read(rsp + 0x28, 16)
            mb_buffer_ptr = struct.unpack('<Q', stack_params[0:8])[0]
            mb_count = struct.unpack('<Q', stack_params[8:16])[0]
        except:
            mb_buffer_ptr = 0
            mb_count = 0
        
        if wc_count == 0xFFFFFFFF or wc_count == 0xFFFFFFFFFFFFFFFF:
            # Calculate length (count wide chars until null terminator)
            try:
                wc_data = self.uc.mem_read(wc_str_ptr, 512)
                wc_count = 0
                for i in range(0, len(wc_data), 2):
                    if wc_data[i] == 0 and wc_data[i+1] == 0:
                        break
                    wc_count += 1
            except:
                wc_count = 0
        
        # If buffer is NULL, return required size
        if mb_buffer_ptr == 0:
            # Return number of bytes needed (same as wide char count for ASCII)
            result = wc_count + 1  # +1 for null terminator
            self.uc.reg_write(UC_X86_REG_RAX, result)
            return result
        
        # Convert (simplified: just take low byte of each wide char)
        try:
            wc_data = self.uc.mem_read(wc_str_ptr, min(wc_count * 2, 512))
            mb_data = bytes([wc_data[i] for i in range(0, len(wc_data), 2)]) + b'\x00'
            self.uc.mem_write(mb_buffer_ptr, mb_data[:mb_count])
        except:
            pass
        
        # Return number of bytes written
        result = min(wc_count + 1, mb_count)
        self.uc.reg_write(UC_X86_REG_RAX, result)
        return result
    
    def _stub_lc_map_string_w(self):
        """LCMapStringW() - map string to locale"""
        # RCX = locale, RDX = flags, R8 = source, R9 = source count
        # Stack: dest buffer, dest count
        locale = self.uc.reg_read(UC_X86_REG_RCX)
        flags = self.uc.reg_read(UC_X86_REG_RDX)
        src_ptr = self.uc.reg_read(UC_X86_REG_R8)
        src_count = self.uc.reg_read(UC_X86_REG_R9)
        
        # Read parameters from stack
        rsp = self.uc.reg_read(UC_X86_REG_RSP)
        try:
            stack_params = self.uc.mem_read(rsp + 0x28, 16)
            dest_ptr = struct.unpack('<Q', stack_params[0:8])[0]
            dest_count = struct.unpack('<Q', stack_params[8:16])[0]
        except:
            dest_ptr = 0
            dest_count = 0
        
        # If dest is NULL, return required size
        if dest_ptr == 0:
            result = src_count
            self.uc.reg_write(UC_X86_REG_RAX, result)
            return result
        
        # Copy source to dest (simplified: no actual mapping)
        try:
            src_data = self.uc.mem_read(src_ptr, src_count * 2)  # Wide chars
            self.uc.mem_write(dest_ptr, src_data[:dest_count*2])
        except:
            pass
        
        # Return number of chars written
        result = min(src_count, dest_count)
        self.uc.reg_write(UC_X86_REG_RAX, result)
        return result
    
    def _stub_heap_create(self):
        """HeapCreate() - create a heap"""
        # RCX = options, RDX = initial size, R8 = maximum size
        options = self.uc.reg_read(UC_X86_REG_RCX)
        initial_size = self.uc.reg_read(UC_X86_REG_RDX)
        max_size = self.uc.reg_read(UC_X86_REG_R8)
        
        # Return a fake heap handle (use process heap)
        heap_handle = self.emu.os.heap.process_heap
        self.uc.reg_write(UC_X86_REG_RAX, heap_handle)
        return heap_handle
    
    def _stub_heap_set_information(self):
        """HeapSetInformation() - set heap information"""
        # RCX = heap, RDX = info class, R8 = info, R9 = info length
        # Just return success
        self.uc.reg_write(UC_X86_REG_RAX, 1)  # TRUE
        return 1
    
    # === DIRECTX STUBS (реалистичные) ===
    
    def _stub_d3d11_create_device(self):
        """D3D11CreateDevice() - создание DirectX устройства"""
        print(f"[API] D3D11CreateDevice()")
        
        if self.directx:
            # Используем реалистичную заглушку
            result = self.directx.D3D11CreateDevice(None, 0, None, 0, None, 0)
            self.uc.reg_write(UC_X86_REG_RAX, result[0])  # HRESULT
            print(f"  -> S_OK (realistic DirectX stub)")
            return result[0]
        else:
            # Fallback
            self.uc.reg_write(UC_X86_REG_RAX, 0)  # S_OK
            print(f"  -> S_OK (fallback)")
            return 0
    
    def _stub_create_swap_chain(self):
        """CreateSwapChain() - создание swap chain"""
        print(f"[API] CreateSwapChain()")
        
        if self.directx:
            # Используем реалистичную заглушку
            desc = {'width': 1920, 'height': 1080, 'format': 'DXGI_FORMAT_R8G8B8A8_UNORM'}
            result = self.directx.CreateSwapChain(None, desc)
            self.uc.reg_write(UC_X86_REG_RAX, result[0])  # HRESULT
            print(f"  -> S_OK (realistic DirectX stub)")
            return result[0]
        else:
            # Fallback
            self.uc.reg_write(UC_X86_REG_RAX, 0)  # S_OK
            print(f"  -> S_OK (fallback)")
            return 0
    
    def _stub_present(self):
        """Present() - презентация кадра (vsync)"""
        # RCX = sync_interval
        sync_interval = self.uc.reg_read(UC_X86_REG_RCX)
        
        print(f"[API] Present(sync_interval={sync_interval})")
        
        if self.directx:
            # Используем реалистичную заглушку (продвигает VirtualClock!)
            result = self.directx.Present(sync_interval)
            self.uc.reg_write(UC_X86_REG_RAX, result)
            return result
        else:
            # Fallback: имитируем задержку vsync
            if sync_interval > 0:
                # 60 FPS = 16.67 мс на кадр
                ticks = int(16.67 * self.emu.clock.cpu_freq_mhz * 1000)
                self.emu.clock.advance(ticks)
                print(f"  -> S_OK (vsync wait: 16.67 ms)")
            else:
                # Без vsync — минимальная задержка (~1 мс)
                ticks = int(1 * self.emu.clock.cpu_freq_mhz * 1000)
                self.emu.clock.advance(ticks)
                print(f"  -> S_OK (no vsync, 1 ms)")
            
            self.uc.reg_write(UC_X86_REG_RAX, 0)  # S_OK
            return 0
    
    def _stub_get_adapter_desc(self):
        """GetAdapterDesc() - получить описание GPU"""
        # RCX = pointer to DXGI_ADAPTER_DESC
        ptr = self.uc.reg_read(UC_X86_REG_RCX)
        
        print(f"[API] GetAdapterDesc(0x{ptr:x})")
        
        if self.directx:
            # Используем реалистичную заглушку
            desc = self.directx.GetAdapterDesc()
            
            # Записываем структуру DXGI_ADAPTER_DESC (упрощённо)
            try:
                # Description (wide string, 128 chars)
                desc_str = desc['Description'].encode('utf-16le')[:256]
                desc_str += b'\x00' * (256 - len(desc_str))
                
                # Остальные поля
                adapter_data = desc_str + struct.pack('<IIIQQQ',
                    desc['VendorId'],
                    desc['DeviceId'],
                    desc['SubSysId'],
                    desc['Revision'],
                    desc['DedicatedVideoMemory'],
                    desc['DedicatedSystemMemory'],
                    desc['SharedSystemMemory']
                )
                
                self.uc.mem_write(ptr, adapter_data)
                print(f"  -> {desc['Description']}, VRAM: {desc['DedicatedVideoMemory'] // (1024*1024)} MB")
            except:
                pass
            
            self.uc.reg_write(UC_X86_REG_RAX, 0)  # S_OK
            return 0
        else:
            # Fallback
            self.uc.reg_write(UC_X86_REG_RAX, 0)  # S_OK
            print(f"  -> S_OK (fallback)")
            return 0
    
    # === NETWORK STUBS (реалистичные) ===
    
    def _stub_connect(self):
        """connect() - подключение к серверу"""
        # RCX = socket, RDX = sockaddr, R8 = addrlen
        socket_fd = self.uc.reg_read(UC_X86_REG_RCX)
        sockaddr_ptr = self.uc.reg_read(UC_X86_REG_RDX)
        
        print(f"[API] connect(socket={socket_fd})")
        
        if self.network:
            # Используем реалистичную заглушку (имитирует задержку!)
            result = self.network.connect("example.com", 80)
            self.uc.reg_write(UC_X86_REG_RAX, result)
            return result
        else:
            # Fallback: имитируем задержку подключения (~30 мс)
            ticks = int(30 * self.emu.clock.cpu_freq_mhz * 1000)
            self.emu.clock.advance(ticks)
            self.uc.reg_write(UC_X86_REG_RAX, 0)  # Success
            print(f"  -> 0 (connected, 30 ms latency)")
            return 0
    
    def _stub_send(self):
        """send() - отправка данных"""
        # RCX = socket, RDX = buffer, R8 = length, R9 = flags
        socket_fd = self.uc.reg_read(UC_X86_REG_RCX)
        buffer_ptr = self.uc.reg_read(UC_X86_REG_RDX)
        length = self.uc.reg_read(UC_X86_REG_R8)
        
        print(f"[API] send(socket={socket_fd}, length={length})")
        
        # Читаем данные из буфера
        try:
            data = self.uc.mem_read(buffer_ptr, length)
        except:
            data = b'\x00' * length
        
        if self.network:
            # Используем реалистичную заглушку (имитирует задержку!)
            result = self.network.send(socket_fd, data)
            self.uc.reg_write(UC_X86_REG_RAX, result)
            return result
        else:
            # Fallback: имитируем задержку отправки
            send_time_ms = (length * 8) / (100 * 1000) + 30  # 100 Мбит/с + 30 мс пинг
            ticks = int(send_time_ms * self.emu.clock.cpu_freq_mhz * 1000)
            self.emu.clock.advance(ticks)
            self.uc.reg_write(UC_X86_REG_RAX, length)  # Bytes sent
            print(f"  -> {length} bytes sent ({send_time_ms:.2f} ms)")
            return length
    
    def _stub_recv(self):
        """recv() - получение данных"""
        # RCX = socket, RDX = buffer, R8 = length, R9 = flags
        socket_fd = self.uc.reg_read(UC_X86_REG_RCX)
        buffer_ptr = self.uc.reg_read(UC_X86_REG_RDX)
        length = self.uc.reg_read(UC_X86_REG_R8)
        
        print(f"[API] recv(socket={socket_fd}, length={length})")
        
        # Возвращаем ошибку "сеть недоступна"
        self.uc.reg_write(UC_X86_REG_RAX, 0xFFFFFFFFFFFFFFFF)  # SOCKET_ERROR (-1)
        if hasattr(self.emu.os, 'last_error'):
            self.emu.os.last_error = 10061  # WSAECONNREFUSED
        print(f"  -> SOCKET_ERROR (network unavailable)")
        return 0xFFFFFFFFFFFFFFFF
    
    def _stub_socket(self):
        """socket() - создание сокета"""
        # RCX = af, RDX = type, R8 = protocol
        af = self.uc.reg_read(UC_X86_REG_RCX)
        sock_type = self.uc.reg_read(UC_X86_REG_RDX)
        protocol = self.uc.reg_read(UC_X86_REG_R8)
        
        print(f"[API] socket(af={af}, type={sock_type}, protocol={protocol})")
        
        # Возвращаем ошибку
        self.uc.reg_write(UC_X86_REG_RAX, 0xFFFFFFFFFFFFFFFF)  # INVALID_SOCKET
        print(f"  -> INVALID_SOCKET (network unavailable)")
        return 0xFFFFFFFFFFFFFFFF
    
    def _stub_closesocket(self):
        """closesocket() - закрытие сокета"""
        # RCX = socket
        socket_fd = self.uc.reg_read(UC_X86_REG_RCX)
        print(f"[API] closesocket({socket_fd})")
        self.uc.reg_write(UC_X86_REG_RAX, 0)  # Success
        return 0
    
    def _stub_wsa_startup(self):
        """WSAStartup() - инициализация Winsock"""
        # RCX = version, RDX = WSAData pointer
        version = self.uc.reg_read(UC_X86_REG_RCX)
        wsa_data_ptr = self.uc.reg_read(UC_X86_REG_RDX)
        
        print(f"[API] WSAStartup(version=0x{version:x})")
        
        # Заполняем структуру WSAData (упрощённо)
        try:
            wsa_data = struct.pack('<HH', version & 0xFFFF, version & 0xFFFF)
            wsa_data += b'\x00' * 400  # Остальные поля
            self.uc.mem_write(wsa_data_ptr, wsa_data[:408])
        except:
            pass
        
        # Возвращаем ошибку "сеть недоступна"
        self.uc.reg_write(UC_X86_REG_RAX, 10047)  # WSAEAFNOSUPPORT
        print(f"  -> WSAEAFNOSUPPORT (network unavailable)")
        return 10047
    
    def _stub_wsa_cleanup(self):
        """WSACleanup() - очистка Winsock"""
        print(f"[API] WSACleanup()")
        self.uc.reg_write(UC_X86_REG_RAX, 0)  # Success
        return 0
    
    def _stub_wsa_get_last_error(self):
        """WSAGetLastError() - получить код ошибки"""
        error = getattr(self.emu.os, 'last_error', 10061)  # WSAECONNREFUSED
        print(f"[API] WSAGetLastError() -> {error}")
        self.uc.reg_write(UC_X86_REG_RAX, error)
        return error
    
    # === WININET STUBS (для HTTP/HTTPS) ===
    
    def _stub_internet_open_a(self):
        """InternetOpenA() - инициализация WinINet"""
        # RCX = agent, RDX = access type, R8 = proxy, R9 = proxy bypass
        print(f"[API] InternetOpenA()")
        # Возвращаем NULL - сеть недоступна
        self.uc.reg_write(UC_X86_REG_RAX, 0)
        if hasattr(self.emu.os, 'last_error'):
            self.emu.os.last_error = 12029  # ERROR_INTERNET_CANNOT_CONNECT
        print(f"  -> NULL (network unavailable)")
        return 0
    
    def _stub_internet_open_w(self):
        """InternetOpenW() - инициализация WinINet (Unicode)"""
        print(f"[API] InternetOpenW()")
        # Возвращаем NULL - сеть недоступна
        self.uc.reg_write(UC_X86_REG_RAX, 0)
        if hasattr(self.emu.os, 'last_error'):
            self.emu.os.last_error = 12029  # ERROR_INTERNET_CANNOT_CONNECT
        print(f"  -> NULL (network unavailable)")
        return 0
    
    def _stub_internet_open_url_a(self):
        """InternetOpenUrlA() - открытие URL"""
        print(f"[API] InternetOpenUrlA()")
        # Возвращаем NULL - сеть недоступна
        self.uc.reg_write(UC_X86_REG_RAX, 0)
        if hasattr(self.emu.os, 'last_error'):
            self.emu.os.last_error = 12029  # ERROR_INTERNET_CANNOT_CONNECT
        print(f"  -> NULL (cannot connect)")
        return 0
    
    def _stub_internet_open_url_w(self):
        """InternetOpenUrlW() - открытие URL (Unicode)"""
        print(f"[API] InternetOpenUrlW()")
        # Возвращаем NULL - сеть недоступна
        self.uc.reg_write(UC_X86_REG_RAX, 0)
        if hasattr(self.emu.os, 'last_error'):
            self.emu.os.last_error = 12029  # ERROR_INTERNET_CANNOT_CONNECT
        print(f"  -> NULL (cannot connect)")
        return 0
    
    def _stub_internet_read_file(self):
        """InternetReadFile() - чтение данных из интернета"""
        print(f"[API] InternetReadFile()")
        # Возвращаем FALSE - ошибка
        self.uc.reg_write(UC_X86_REG_RAX, 0)
        if hasattr(self.emu.os, 'last_error'):
            self.emu.os.last_error = 12029  # ERROR_INTERNET_CANNOT_CONNECT
        print(f"  -> FALSE (cannot read)")
        return 0
    
    def _stub_internet_close_handle(self):
        """InternetCloseHandle() - закрытие интернет-хэндла"""
        # RCX = handle
        handle = self.uc.reg_read(UC_X86_REG_RCX)
        print(f"[API] InternetCloseHandle(0x{handle:x})")
        self.uc.reg_write(UC_X86_REG_RAX, 1)  # TRUE
        return 1
    
    def _stub_http_open_request_a(self):
        """HttpOpenRequestA() - открытие HTTP запроса"""
        print(f"[API] HttpOpenRequestA()")
        # Возвращаем NULL - сеть недоступна
        self.uc.reg_write(UC_X86_REG_RAX, 0)
        if hasattr(self.emu.os, 'last_error'):
            self.emu.os.last_error = 12029  # ERROR_INTERNET_CANNOT_CONNECT
        print(f"  -> NULL (cannot connect)")
        return 0
    
    def _stub_http_open_request_w(self):
        """HttpOpenRequestW() - открытие HTTP запроса (Unicode)"""
        print(f"[API] HttpOpenRequestW()")
        # Возвращаем NULL - сеть недоступна
        self.uc.reg_write(UC_X86_REG_RAX, 0)
        if hasattr(self.emu.os, 'last_error'):
            self.emu.os.last_error = 12029  # ERROR_INTERNET_CANNOT_CONNECT
        print(f"  -> NULL (cannot connect)")
        return 0
    
    def _stub_http_send_request_a(self):
        """HttpSendRequestA() - отправка HTTP запроса"""
        print(f"[API] HttpSendRequestA()")
        # Возвращаем FALSE - ошибка
        self.uc.reg_write(UC_X86_REG_RAX, 0)
        if hasattr(self.emu.os, 'last_error'):
            self.emu.os.last_error = 12029  # ERROR_INTERNET_CANNOT_CONNECT
        print(f"  -> FALSE (cannot send)")
        return 0
    
    def _stub_http_send_request_w(self):
        """HttpSendRequestW() - отправка HTTP запроса (Unicode)"""
        print(f"[API] HttpSendRequestW()")
        # Возвращаем FALSE - ошибка
        self.uc.reg_write(UC_X86_REG_RAX, 0)
        if hasattr(self.emu.os, 'last_error'):
            self.emu.os.last_error = 12029  # ERROR_INTERNET_CANNOT_CONNECT
        print(f"  -> FALSE (cannot send)")
        return 0
    
    def _stub_internet_connect_a(self):
        """InternetConnectA() - подключение к серверу"""
        print(f"[API] InternetConnectA()")
        # Возвращаем NULL - сеть недоступна
        self.uc.reg_write(UC_X86_REG_RAX, 0)
        if hasattr(self.emu.os, 'last_error'):
            self.emu.os.last_error = 12029  # ERROR_INTERNET_CANNOT_CONNECT
        print(f"  -> NULL (cannot connect)")
        return 0
    
    def _stub_internet_connect_w(self):
        """InternetConnectW() - подключение к серверу (Unicode)"""
        print(f"[API] InternetConnectW()")
        # Возвращаем NULL - сеть недоступна
        self.uc.reg_write(UC_X86_REG_RAX, 0)
        if hasattr(self.emu.os, 'last_error'):
            self.emu.os.last_error = 12029  # ERROR_INTERNET_CANNOT_CONNECT
        print(f"  -> NULL (cannot connect)")
        return 0
    
    def _read_string(self, ptr, max_len=256):
        """Вспомогательная функция: читает null-terminated строку"""
        data = b''
        for i in range(max_len):
            byte = self.uc.mem_read(ptr + i, 1)[0]
            if byte == 0:
                break
            data += bytes([byte])
        return data.decode('ascii', errors='ignore')


    # === GUI MESSAGE LOOP STUBS ===
    
    def _stub_get_message_a(self):
        """GetMessageA() - get message from queue (blocks until message)"""
        # RCX = MSG pointer, RDX = hwnd, R8 = filter min, R9 = filter max
        msg_ptr = self.uc.reg_read(UC_X86_REG_RCX)
        
        print(f"[API] GetMessageA(msg=0x{msg_ptr:x})")
        
        # In command-line mode, return WM_QUIT immediately to exit message loop
        # Fill MSG structure with WM_QUIT (0x0012)
        try:
            # typedef struct tagMSG {
            #   HWND   hwnd;      // 8 bytes
            #   UINT   message;   // 4 bytes
            #   WPARAM wParam;    // 8 bytes
            #   LPARAM lParam;    // 8 bytes
            #   DWORD  time;      // 4 bytes
            #   POINT  pt;        // 8 bytes (2x LONG)
            # } MSG;
            msg_data = struct.pack('<QIQIIQ',
                0,      # hwnd
                0x0012, # WM_QUIT
                0,      # wParam
                0,      # lParam
                0,      # time
                0       # pt (x, y)
            )
            self.uc.mem_write(msg_ptr, msg_data)
        except:
            pass
        
        # Return 0 for WM_QUIT (causes message loop to exit)
        self.uc.reg_write(UC_X86_REG_RAX, 0)
        print(f"  -> 0 (WM_QUIT - exit message loop)")
        return 0
    
    def _stub_get_message_w(self):
        """GetMessageW() - get message from queue (Unicode)"""
        # Same as GetMessageA
        return self._stub_get_message_a()
    
    def _stub_peek_message_a(self):
        """PeekMessageA() - check for message without blocking"""
        # RCX = MSG pointer, RDX = hwnd, R8 = filter min, R9 = filter max
        # Stack: remove flag
        msg_ptr = self.uc.reg_read(UC_X86_REG_RCX)
        
        print(f"[API] PeekMessageA(msg=0x{msg_ptr:x})")
        
        # Return FALSE - no messages available
        # This allows the program to continue without blocking
        self.uc.reg_write(UC_X86_REG_RAX, 0)
        print(f"  -> FALSE (no messages)")
        return 0
    
    def _stub_peek_message_w(self):
        """PeekMessageW() - check for message without blocking (Unicode)"""
        return self._stub_peek_message_a()
    
    def _stub_dispatch_message_a(self):
        """DispatchMessageA() - dispatch message to window procedure"""
        # RCX = MSG pointer
        print(f"[API] DispatchMessageA()")
        
        # Return 0 (message processed)
        self.uc.reg_write(UC_X86_REG_RAX, 0)
        print(f"  -> 0 (message dispatched)")
        return 0
    
    def _stub_dispatch_message_w(self):
        """DispatchMessageW() - dispatch message to window procedure (Unicode)"""
        return self._stub_dispatch_message_a()
    
    def _stub_translate_message(self):
        """TranslateMessage() - translate virtual-key messages"""
        # RCX = MSG pointer
        print(f"[API] TranslateMessage()")
        
        # Return FALSE (no translation needed)
        self.uc.reg_write(UC_X86_REG_RAX, 0)
        return 0
    
    def _stub_post_quit_message(self):
        """PostQuitMessage() - post WM_QUIT to message queue"""
        # RCX = exit code
        exit_code = self.uc.reg_read(UC_X86_REG_RCX)
        
        print(f"[API] PostQuitMessage({exit_code})")
        print(f"  -> Stopping emulation (application exit)")
        
        # Stop emulation
        self.uc.emu_stop()
        return 0
    
    def _stub_def_window_proc_a(self):
        """DefWindowProcA() - default window procedure"""
        # RCX = hwnd, RDX = msg, R8 = wParam, R9 = lParam
        hwnd = self.uc.reg_read(UC_X86_REG_RCX)
        msg = self.uc.reg_read(UC_X86_REG_RDX)
        
        print(f"[API] DefWindowProcA(hwnd=0x{hwnd:x}, msg=0x{msg:x})")
        
        # Return 0 (default processing)
        self.uc.reg_write(UC_X86_REG_RAX, 0)
        return 0
    
    def _stub_def_window_proc_w(self):
        """DefWindowProcW() - default window procedure (Unicode)"""
        return self._stub_def_window_proc_a()
    
    def _stub_wait_for_single_object(self):
        """WaitForSingleObject() - wait for object to be signaled"""
        # RCX = handle, RDX = timeout
        handle = self.uc.reg_read(UC_X86_REG_RCX)
        timeout = self.uc.reg_read(UC_X86_REG_RDX)
        
        print(f"[API] WaitForSingleObject(handle=0x{handle:x}, timeout={timeout})")
        
        # Advance virtual time by timeout (if not INFINITE)
        if timeout != 0xFFFFFFFF and timeout != 0xFFFFFFFFFFFFFFFF:
            ticks = int(timeout * self.emu.clock.cpu_freq_mhz * 1000)
            self.emu.clock.advance(ticks)
            print(f"  -> Advanced {timeout} ms")
        
        # Return WAIT_OBJECT_0 (0) - object is signaled
        self.uc.reg_write(UC_X86_REG_RAX, 0)
        print(f"  -> WAIT_OBJECT_0 (signaled)")
        return 0
    
    def _stub_wait_for_multiple_objects(self):
        """WaitForMultipleObjects() - wait for multiple objects"""
        # RCX = count, RDX = handles array, R8 = wait all, R9 = timeout
        count = self.uc.reg_read(UC_X86_REG_RCX)
        handles_ptr = self.uc.reg_read(UC_X86_REG_RDX)
        wait_all = self.uc.reg_read(UC_X86_REG_R8)
        timeout = self.uc.reg_read(UC_X86_REG_R9)
        
        print(f"[API] WaitForMultipleObjects(count={count}, wait_all={wait_all}, timeout={timeout})")
        
        # Advance virtual time by timeout (if not INFINITE)
        if timeout != 0xFFFFFFFF and timeout != 0xFFFFFFFFFFFFFFFF:
            ticks = int(timeout * self.emu.clock.cpu_freq_mhz * 1000)
            self.emu.clock.advance(ticks)
            print(f"  -> Advanced {timeout} ms")
        
        # Return WAIT_OBJECT_0 (0) - first object is signaled
        self.uc.reg_write(UC_X86_REG_RAX, 0)
        print(f"  -> WAIT_OBJECT_0 (signaled)")
        return 0
    
    def _stub_msg_wait_for_multiple_objects(self):
        """MsgWaitForMultipleObjects() - wait for objects or messages"""
        # RCX = count, RDX = handles array, R8 = wait all, R9 = timeout
        # Stack: wake mask
        count = self.uc.reg_read(UC_X86_REG_RCX)
        handles_ptr = self.uc.reg_read(UC_X86_REG_RDX)
        wait_all = self.uc.reg_read(UC_X86_REG_R8)
        timeout = self.uc.reg_read(UC_X86_REG_R9)
        
        print(f"[API] MsgWaitForMultipleObjects(count={count}, wait_all={wait_all}, timeout={timeout})")
        
        # Advance virtual time by a small amount (simulate checking for messages)
        ticks = int(10 * self.emu.clock.cpu_freq_mhz * 1000)  # 10 ms
        self.emu.clock.advance(ticks)
        
        # Return WAIT_TIMEOUT (0x102) - no objects signaled, no messages
        # This allows the program to continue without blocking
        self.uc.reg_write(UC_X86_REG_RAX, 0x102)
        print(f"  -> WAIT_TIMEOUT (continue execution)")
        return 0x102
