#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
WinAPI Stubs v2 - с поддержкой автогенерированных заглушек и переопределений

Архитектура:
1. Автогенерированные заглушки (tools/generated/) - НЕ ТРОГАТЬ!
2. Пользовательские реализации (этот файл) - модифицируем здесь
3. StubRegistry выбирает нужную версию по приоритету
"""

import sys
from pathlib import Path
from unicorn.x86_const import *

# Добавляем путь к сгенерированным заглушкам
sys.path.insert(0, str(Path(__file__).parent.parent.parent / 'tools'))

# Импортируем GUI заглушки
from gui_stubs import GUIStubs

# Импортируем гибридную систему
try:
    import sys
    from pathlib import Path
    # Добавляем путь к src/core
    core_path = Path(__file__).parent
    if str(core_path) not in sys.path:
        sys.path.insert(0, str(core_path))
    
    from hybrid_stubs import HybridStubs
    HYBRID_AVAILABLE = True
except ImportError as e:
    HYBRID_AVAILABLE = False
    print(f"[!] WARNING: Hybrid stubs not available: {e}")


class StubRegistry:
    """Реестр заглушек с приоритетами"""
    
    def __init__(self):
        self.generated = {}  # Автогенерированные
        self.custom = {}     # Пользовательские
    
    def register_generated(self, name, func):
        self.generated[name] = func
    
    def register_custom(self, name, func):
        self.custom[name] = func
    
    def get(self, name):
        # Приоритет: custom > generated
        return self.custom.get(name) or self.generated.get(name)
    
    def has_custom(self, name):
        return name in self.custom


class WinAPIStubsV2:
    """WinAPI заглушки с автогенерацией и переопределениями"""
    
    def __init__(self, emulator):
        self.emu = emulator
        self.uc = emulator.uc
        self.registry = StubRegistry()
        self.STUB_BASE = 0x7FFF0000
        
        # GUI заглушки
        self.gui = GUIStubs(emulator)
        
        # Гибридная система (эмуляция + passthrough)
        if HYBRID_AVAILABLE:
            self.hybrid = HybridStubs(self.uc, emulator)
            print("[+] Hybrid stubs (emulation + passthrough) enabled")
        else:
            self.hybrid = None
        
        # Загружаем автогенерированные заглушки
        self._load_generated_stubs()
        
        # Регистрируем пользовательские реализации
        self._register_custom_stubs()
        
        # Регистрируем GUI заглушки
        self._register_gui_stubs()
        
        # Создаём маппинг адресов (после того как stub memory выделена в LayeredEmulator!)
        self._create_stub_mapping()
    
    def _load_generated_stubs(self):
        """Загрузка автогенерированных заглушек"""
        try:
            from generated import winapi_stubs_generated
            
            print("[*] Loading generated WinAPI stubs...")
            count = 0
            
            for name in dir(winapi_stubs_generated):
                if name.startswith('_stub_'):
                    func_name = name[6:]  # Убираем _stub_
                    func = getattr(winapi_stubs_generated, name)
                    
                    # Биндим self
                    bound = lambda f=func: f(self)
                    self.registry.register_generated(func_name, bound)
                    count += 1
            
            print(f"[+] Loaded {count} generated stubs")
            
        except ImportError as e:
            print(f"[!] Failed to load generated stubs: {e}")
            print("[!] Run: python tools/header_parser.py")
    
    def _register_custom_stubs(self):
        """Регистрация пользовательских реализаций"""
        print("[*] Registering custom implementations...")
        
        # ===== КРИТИЧНЫЕ ФУНКЦИИ (полная реализация) =====
        
        # File I/O
        self.registry.register_custom('createfilea', self._custom_createfilea)
        self.registry.register_custom('createfilew', self._custom_createfilew)
        self.registry.register_custom('readfile', self._custom_readfile)
        self.registry.register_custom('writefile', self._custom_writefile)
        self.registry.register_custom('closehandle', self._custom_closehandle)
        
        # Memory
        self.registry.register_custom('getprocessheap', self._custom_getprocessheap)
        self.registry.register_custom('heapalloc', self._custom_heapalloc)
        self.registry.register_custom('heapfree', self._custom_heapfree)
        self.registry.register_custom('virtualalloc', self._custom_virtualalloc)
        
        # Timing (критично для анти-тампера!)
        self.registry.register_custom('gettickcount', self._custom_gettickcount)
        self.registry.register_custom('queryperformancecounter', self._custom_queryperformancecounter)
        self.registry.register_custom('queryperformancefrequency', self._custom_queryperformancefrequency)
        self.registry.register_custom('getsystemtimeasfiletime', self._custom_getsystemtimeasfiletime)
        
        # Debugging & Console (для CPU-Z и CoreInfo)
        self.registry.register_custom('isdebuggerpresent', self._custom_isdebuggerpresent)
        self.registry.register_custom('getconsolecp', self._custom_getconsolecp)
        self.registry.register_custom('getconsolemode', self._custom_getconsolemode)
        self.registry.register_custom('getacp', self._custom_getacp)
        self.registry.register_custom('getoemcp', self._custom_getoemcp)
        self.registry.register_custom('getstdhandle', self._custom_getstdhandle)
        self.registry.register_custom('writeconsolew', self._custom_writeconsolew)
        self.registry.register_custom('writeconsolea', self._custom_writeconsolea)
        
        # Window Station & Desktop
        self.registry.register_custom('getprocesswindowstation', self._custom_getprocesswindowstation)
        self.registry.register_custom('getuserobjectinformationa', self._custom_getuserobjectinformationa)
        self.registry.register_custom('getuserobjectinformationw', self._custom_getuserobjectinformationw)
        
        # .NET Runtime (mscoree.dll)
        self.registry.register_custom('corexitprocess', self._custom_corexitprocess)
        
        # Process control
        self.registry.register_custom('exitprocess', self._custom_exitprocess)
        
        # Module management
        self.registry.register_custom('getmodulefilenamea', self._custom_getmodulefilenamea)
        self.registry.register_custom('getmodulefilenamew', self._custom_getmodulefilenamew)
        self.registry.register_custom('getmodulehandlea', self._custom_getmodulehandlea)
        self.registry.register_custom('getmodulehandlew', self._custom_getmodulehandlew)
        self.registry.register_custom('loadlibrarya', self._custom_loadlibrarya)
        self.registry.register_custom('loadlibraryw', self._custom_loadlibraryw)
        self.registry.register_custom('getprocaddress', self._custom_getprocaddress)
        
        # Security
        self.registry.register_custom('encodepointer', self._custom_encodepointer)
        self.registry.register_custom('decodepointer', self._custom_decodepointer)
        
        # Critical Sections (для CoreInfo)
        self.registry.register_custom('entercriticalsection', self._custom_entercriticalsection)
        self.registry.register_custom('leavecriticalsection', self._custom_leavecriticalsection)
        self.registry.register_custom('initializecriticalsection', self._custom_initializecriticalsection)
        self.registry.register_custom('deletecriticalsection', self._custom_deletecriticalsection)
        
        # CPU Features (PASSTHROUGH для реальных данных)
        self.registry.register_custom('isprocessorfeaturepresent', self._custom_isprocessorfeaturepresent)
        
        # System Information (для simple_sysinfo)
        self.registry.register_custom('getsysteminfo', self._custom_getsysteminfo)
        
        # CPU Topology (для CoreInfo!)
        self.registry.register_custom('getlogicalprocessorinformation', self._custom_getlogicalprocessorinformation)
        self.registry.register_custom('getlogicalprocessorinformationex', self._custom_getlogicalprocessorinformationex)
        
        # Exception Handling (для CoreInfo)
        self.registry.register_custom('rtlcapturecontext', self._custom_rtlcapturecontext)
        self.registry.register_custom('rtllookupfunctionentry', self._custom_rtllookupfunctionentry)
        self.registry.register_custom('rtlvirtualunwind', self._custom_rtlvirtualunwind)
        
        custom_count = len(self.registry.custom)
        print(f"[+] Registered {custom_count} custom implementations")
    
    def _register_gui_stubs(self):
        """Регистрация GUI заглушек (user32.dll, gdi32.dll)"""
        print("[*] Registering GUI stubs...")
        
        # Список GUI функций, которые может вызывать CPU-Z
        gui_functions = [
            # user32.dll - Window Management
            'registerclassw', 'registerclassa',
            'createwindowexw', 'createwindowexa',
            'showwindow', 'updatewindow', 'destroywindow',
            'getdc', 'releasedc',
            'getsystemmetrics',
            'messageboxw', 'messageboxa',
            'defwindowprocw', 'defwindowproca',
            'postquitmessage',
            'getmessagew', 'getmessagea',
            'dispatchmessagew', 'dispatchmessagea',
            'translatemessage',
            
            # gdi32.dll - Graphics Device Interface
            'createfontw', 'createfonta',
            'selectobject', 'deleteobject',
            'textoutw', 'textouta',
            'settextcolor', 'setbkmode',
            'getstockobject',
        ]
        
        for func_name in gui_functions:
            stub = self.gui.get_stub(func_name)
            self.registry.register_custom(func_name, stub)
        
        gui_count = len(gui_functions)
        print(f"[+] Registered {gui_count} GUI stubs")
    
    def _create_stub_mapping(self):
        """Создание маппинга адресов к заглушкам"""
        self.stub_addresses = {}
        self.STUB_BASE = 0x7FFF0000
        
        # Создаём маппинг для всех заглушек
        all_stubs = set(self.registry.generated.keys()) | set(self.registry.custom.keys())
        
        current_addr = self.STUB_BASE
        for name in sorted(all_stubs):
            self.stub_addresses[current_addr] = name
            current_addr += 0x100  # 256 байт на заглушку
        
        # Записываем исполняемый код для всех заглушек
        self._write_all_stub_code()
    
    def _write_all_stub_code(self):
        """Записываем RET инструкцию для каждого stub"""
        print(f"[*] Writing RET instructions for {len(self.stub_addresses)} stubs...")
        print(f"[*] Stub region: 0x{self.STUB_BASE:x} - 0x{self.STUB_BASE + 0x40000000:x} (1GB)")
        
        # Проверяем, что память выделена
        try:
            test_read = self.uc.mem_read(self.STUB_BASE, 1)
            print(f"[+] Stub memory is accessible")
        except Exception as e:
            print(f"[!] CRITICAL: Stub memory NOT accessible: {e}")
            raise
        
        for address, func_name in self.stub_addresses.items():
            # Stub code: просто RET
            # Code hook перехватит вход в stub ДО выполнения RET
            stub_code = bytes([0xC3])  # RET
            
            try:
                self.uc.mem_write(address, stub_code)
            except Exception as e:
                print(f"[!] Failed to write stub code for {func_name} @ 0x{address:x}: {e}")
                raise
        
        print(f"[+] RET instructions written successfully")
    
    # ========================================================================
    # ПОЛЬЗОВАТЕЛЬСКИЕ РЕАЛИЗАЦИИ (модифицируем здесь!)
    # ========================================================================
    
    def _custom_createfilea(self):
        """CreateFileA() - с реальной VFS"""
        lpFileName = self.uc.reg_read(UC_X86_REG_RCX)
        dwDesiredAccess = self.uc.reg_read(UC_X86_REG_RDX)
        dwShareMode = self.uc.reg_read(UC_X86_REG_R8)
        
        filename = self._read_string(lpFileName)
        print(f"[API] CreateFileA('{filename}') [CUSTOM]")
        
        # Используем VirtualFileSystem
        if hasattr(self.emu, 'vfs'):
            handle = self.emu.vfs.open(filename, dwDesiredAccess)
            self.uc.reg_write(UC_X86_REG_RAX, handle)
            return handle
        else:
            # Fallback: фейковый handle
            self.uc.reg_write(UC_X86_REG_RAX, 0x1000)
            return 0x1000
    
    def _custom_createfilew(self):
        """CreateFileW() - с реальной VFS"""
        lpFileName = self.uc.reg_read(UC_X86_REG_RCX)
        dwDesiredAccess = self.uc.reg_read(UC_X86_REG_RDX)
        
        filename = self._read_wstring(lpFileName)
        print(f"[API] CreateFileW('{filename}') [CUSTOM]")
        
        if hasattr(self.emu, 'vfs'):
            handle = self.emu.vfs.open(filename, dwDesiredAccess)
            self.uc.reg_write(UC_X86_REG_RAX, handle)
            return handle
        else:
            self.uc.reg_write(UC_X86_REG_RAX, 0x1000)
            return 0x1000
    
    def _custom_readfile(self):
        """ReadFile() - с реальным чтением"""
        hFile = self.uc.reg_read(UC_X86_REG_RCX)
        lpBuffer = self.uc.reg_read(UC_X86_REG_RDX)
        nNumberOfBytesToRead = self.uc.reg_read(UC_X86_REG_R8)
        lpNumberOfBytesRead = self.uc.reg_read(UC_X86_REG_R9)
        
        print(f"[API] ReadFile(0x{hFile:x}, {nNumberOfBytesToRead}) [CUSTOM]")
        
        if hasattr(self.emu, 'vfs'):
            data = self.emu.vfs.read(hFile, nNumberOfBytesToRead)
            if data:
                self.uc.mem_write(lpBuffer, data)
                if lpNumberOfBytesRead:
                    self.uc.mem_write(lpNumberOfBytesRead, len(data).to_bytes(4, 'little'))
                self.uc.reg_write(UC_X86_REG_RAX, 1)  # TRUE
                return 1
        
        self.uc.reg_write(UC_X86_REG_RAX, 0)  # FALSE
        return 0
    
    def _custom_writefile(self):
        """WriteFile() - с реальной записью"""
        hFile = self.uc.reg_read(UC_X86_REG_RCX)
        lpBuffer = self.uc.reg_read(UC_X86_REG_RDX)
        nNumberOfBytesToWrite = self.uc.reg_read(UC_X86_REG_R8)
        lpNumberOfBytesWritten = self.uc.reg_read(UC_X86_REG_R9)
        
        print(f"[API] WriteFile(0x{hFile:x}, {nNumberOfBytesToWrite}) [CUSTOM]")
        
        # Обработка stdout
        if hFile == 7 or hFile == 0xfffffff5:
            try:
                data = self.uc.mem_read(lpBuffer, nNumberOfBytesToWrite)
                text = data.decode('utf-8', errors='ignore')
                print(f"[STDOUT] {text}", end='')
            except:
                pass
        
        if lpNumberOfBytesWritten:
            self.uc.mem_write(lpNumberOfBytesWritten, nNumberOfBytesToWrite.to_bytes(4, 'little'))
        
        self.uc.reg_write(UC_X86_REG_RAX, 1)  # TRUE
        return 1
    
    def _custom_closehandle(self):
        """CloseHandle() - с реальным закрытием"""
        hObject = self.uc.reg_read(UC_X86_REG_RCX)
        print(f"[API] CloseHandle(0x{hObject:x}) [CUSTOM]")
        
        if hasattr(self.emu, 'vfs'):
            self.emu.vfs.close(hObject)
        
        self.uc.reg_write(UC_X86_REG_RAX, 1)  # TRUE
        return 1
    
    def _custom_getprocessheap(self):
        """GetProcessHeap() - возвращает handle процессного heap из MiniOS"""
        heap_handle = self.emu.os.GetProcessHeap()
        print(f"[API] GetProcessHeap() -> 0x{heap_handle:x} [CUSTOM]")
        self.uc.reg_write(UC_X86_REG_RAX, heap_handle)
        return heap_handle
    
    def _custom_heapalloc(self):
        """HeapAlloc() - с реальной аллокацией через MiniOS"""
        hHeap = self.uc.reg_read(UC_X86_REG_RCX)
        dwFlags = self.uc.reg_read(UC_X86_REG_RDX)
        dwBytes = self.uc.reg_read(UC_X86_REG_R8)
        
        print(f"[API] HeapAlloc(0x{hHeap:x}, 0x{dwFlags:x}, {dwBytes}) [CUSTOM]")
        
        # Используем РЕАЛЬНЫЙ heap manager из MiniOS!
        addr = self.emu.os.HeapAlloc(hHeap, dwFlags, dwBytes)
        
        self.uc.reg_write(UC_X86_REG_RAX, addr)
        print(f"  -> 0x{addr:x}")
        return addr
    
    def _custom_heapfree(self):
        """HeapFree() - с реальным освобождением через MiniOS"""
        hHeap = self.uc.reg_read(UC_X86_REG_RCX)
        dwFlags = self.uc.reg_read(UC_X86_REG_RDX)
        lpMem = self.uc.reg_read(UC_X86_REG_R8)
        
        print(f"[API] HeapFree(0x{hHeap:x}, 0x{dwFlags:x}, 0x{lpMem:x}) [CUSTOM]")
        
        # Используем РЕАЛЬНЫЙ heap manager из MiniOS!
        result = self.emu.os.HeapFree(hHeap, dwFlags, lpMem)
        
        self.uc.reg_write(UC_X86_REG_RAX, result)
        print(f"  -> {result}")
        return result
    
    def _custom_virtualalloc(self):
        """VirtualAlloc() - с реальной аллокацией через Unicorn"""
        lpAddress = self.uc.reg_read(UC_X86_REG_RCX)
        dwSize = self.uc.reg_read(UC_X86_REG_RDX)
        flAllocationType = self.uc.reg_read(UC_X86_REG_R8)
        flProtect = self.uc.reg_read(UC_X86_REG_R9)
        
        print(f"[API] VirtualAlloc(0x{lpAddress:x}, {dwSize}, 0x{flAllocationType:x}, 0x{flProtect:x}) [CUSTOM]")
        
        # Используем MiniOS для аллокации
        addr = self.emu.os.VirtualAlloc(lpAddress, dwSize, flAllocationType, flProtect)
        
        self.uc.reg_write(UC_X86_REG_RAX, addr)
        print(f"  -> 0x{addr:x}")
        return addr
    
    def _custom_gettickcount(self):
        """GetTickCount() - КРИТИЧНО для анти-тампера!"""
        ms = self.emu.clock.get_tick_count()
        print(f"[API] GetTickCount() -> {ms} ms [CUSTOM]")
        self.uc.reg_write(UC_X86_REG_RAX, ms)
        return ms
    
    def _custom_queryperformancecounter(self):
        """QueryPerformanceCounter() - КРИТИЧНО для анти-тампера!"""
        lpPerformanceCount = self.uc.reg_read(UC_X86_REG_RCX)
        
        counter = self.emu.clock.query_performance_counter()
        print(f"[API] QueryPerformanceCounter() -> {counter} [CUSTOM]")
        
        if lpPerformanceCount:
            self.uc.mem_write(lpPerformanceCount, counter.to_bytes(8, 'little'))
        
        self.uc.reg_write(UC_X86_REG_RAX, 1)  # TRUE
        return 1
    
    def _custom_queryperformancefrequency(self):
        """QueryPerformanceFrequency() - КРИТИЧНО для анти-тампера!"""
        lpFrequency = self.uc.reg_read(UC_X86_REG_RCX)
        
        freq = self.emu.clock.query_performance_frequency()
        print(f"[API] QueryPerformanceFrequency() -> {freq} Hz [CUSTOM]")
        
        if lpFrequency:
            self.uc.mem_write(lpFrequency, freq.to_bytes(8, 'little'))
        
        self.uc.reg_write(UC_X86_REG_RAX, 1)  # TRUE
        return 1
    
    def _custom_getsystemtimeasfiletime(self):
        """GetSystemTimeAsFileTime() - получить системное время"""
        lpSystemTimeAsFileTime = self.uc.reg_read(UC_X86_REG_RCX)
        
        filetime = self.emu.os.GetSystemTimeAsFileTime()
        print(f"[API] GetSystemTimeAsFileTime(0x{lpSystemTimeAsFileTime:x}) -> {filetime} [CUSTOM]")
        
        if lpSystemTimeAsFileTime:
            self.uc.mem_write(lpSystemTimeAsFileTime, filetime.to_bytes(8, 'little'))
        
        # VOID function - не возвращает значение
        return
    
    def _custom_isdebuggerpresent(self):
        """IsDebuggerPresent() - проверка отладчика"""
        print(f"[API] IsDebuggerPresent() -> FALSE [CUSTOM]")
        self.uc.reg_write(UC_X86_REG_RAX, 0)  # FALSE - нет отладчика
        return 0
    
    def _custom_getconsolecp(self):
        """GetConsoleCP() - кодовая страница консоли"""
        cp = 437  # OEM US
        print(f"[API] GetConsoleCP() -> {cp} [CUSTOM]")
        self.uc.reg_write(UC_X86_REG_RAX, cp)
        return cp
    
    def _custom_getconsolemode(self):
        """GetConsoleMode() - режим консоли"""
        hConsoleHandle = self.uc.reg_read(UC_X86_REG_RCX)
        lpMode = self.uc.reg_read(UC_X86_REG_RDX)
        
        mode = 0x0007  # ENABLE_PROCESSED_INPUT | ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT
        print(f"[API] GetConsoleMode(0x{hConsoleHandle:x}) -> {mode} [CUSTOM]")
        
        if lpMode:
            self.uc.mem_write(lpMode, mode.to_bytes(4, 'little'))
        
        self.uc.reg_write(UC_X86_REG_RAX, 1)  # TRUE
        return 1
    
    def _custom_getacp(self):
        """GetACP() - ANSI кодовая страница"""
        cp = 1252  # Western European (Windows)
        print(f"[API] GetACP() -> {cp} [CUSTOM]")
        self.uc.reg_write(UC_X86_REG_RAX, cp)
        return cp
    
    def _custom_getoemcp(self):
        """GetOEMCP() - OEM кодовая страница"""
        cp = 437  # OEM US
        print(f"[API] GetOEMCP() -> {cp} [CUSTOM]")
        self.uc.reg_write(UC_X86_REG_RAX, cp)
        return cp
    
    def _custom_getstdhandle(self):
        """GetStdHandle() - получить handle стандартного устройства"""
        nStdHandle = self.uc.reg_read(UC_X86_REG_RCX)
        
        # STD_INPUT_HANDLE  = -10 (0xFFFFFFF6)
        # STD_OUTPUT_HANDLE = -11 (0xFFFFFFF5)
        # STD_ERROR_HANDLE  = -12 (0xFFFFFFF4)
        
        # Преобразуем в signed
        if nStdHandle > 0x7FFFFFFF:
            nStdHandle = nStdHandle - 0x100000000
        
        handle_map = {
            -10: 0x00000003,  # stdin
            -11: 0x00000007,  # stdout
            -12: 0x0000000B,  # stderr
        }
        
        handle = handle_map.get(nStdHandle, 0x00000007)  # По умолчанию stdout
        
        handle_name = {-10: "stdin", -11: "stdout", -12: "stderr"}.get(nStdHandle, "unknown")
        print(f"[API] GetStdHandle({nStdHandle}) -> 0x{handle:x} ({handle_name}) [CUSTOM]")
        
        self.uc.reg_write(UC_X86_REG_RAX, handle)
        return handle
    
    def _custom_writeconsolew(self):
        """WriteConsoleW() - запись в консоль (Unicode) - PASSTHROUGH"""
        hConsoleOutput = self.uc.reg_read(UC_X86_REG_RCX)
        lpBuffer = self.uc.reg_read(UC_X86_REG_RDX)
        nNumberOfCharsToWrite = self.uc.reg_read(UC_X86_REG_R8)
        lpNumberOfCharsWritten = self.uc.reg_read(UC_X86_REG_R9)
        
        # Читаем Unicode строку (UTF-16 LE)
        try:
            data = self.uc.mem_read(lpBuffer, nNumberOfCharsToWrite * 2)
            text = data.decode('utf-16-le', errors='ignore')
            
            # Выводим в stdout БЕЗ префикса [API]
            print(text, end='', flush=True)
            
            # Записываем количество записанных символов
            if lpNumberOfCharsWritten:
                self.uc.mem_write(lpNumberOfCharsWritten, nNumberOfCharsToWrite.to_bytes(4, 'little'))
            
            self.uc.reg_write(UC_X86_REG_RAX, 1)  # TRUE
            return 1
        except Exception as e:
            print(f"[!] WriteConsoleW failed: {e}")
            self.uc.reg_write(UC_X86_REG_RAX, 0)  # FALSE
            return 0
    
    def _custom_writeconsolea(self):
        """WriteConsoleA() - запись в консоль (ANSI)"""
        hConsoleOutput = self.uc.reg_read(UC_X86_REG_RCX)
        lpBuffer = self.uc.reg_read(UC_X86_REG_RDX)
        nNumberOfCharsToWrite = self.uc.reg_read(UC_X86_REG_R8)
        lpNumberOfCharsWritten = self.uc.reg_read(UC_X86_REG_R9)
        
        try:
            # Читаем ANSI строку
            data = self.uc.mem_read(lpBuffer, nNumberOfCharsToWrite)
            text = data.decode('cp1252', errors='ignore')  # Windows-1252
            
            # Выводим в stdout
            print(f"[STDOUT] {text}", end='')
            
            # Записываем количество записанных символов
            if lpNumberOfCharsWritten:
                self.uc.mem_write(lpNumberOfCharsWritten, nNumberOfCharsToWrite.to_bytes(4, 'little'))
            
            self.uc.reg_write(UC_X86_REG_RAX, 1)  # TRUE
            return 1
        except Exception as e:
            print(f"[!] WriteConsoleA failed: {e}")
            self.uc.reg_write(UC_X86_REG_RAX, 0)  # FALSE
            return 0
    
    def _custom_exitprocess(self):
        """ExitProcess() - завершение процесса"""
        exit_code = self.uc.reg_read(UC_X86_REG_RCX)
        print(f"[API] ExitProcess({exit_code}) [CUSTOM] - STOPPING EMULATION")
        
        # Устанавливаем флаг завершения
        if hasattr(self.emu, 'exit_code'):
            self.emu.exit_code = exit_code
            self.emu.program_exited = True
        
        # Останавливаем эмуляцию
        self.uc.emu_stop()
        
        # Устанавливаем exit code
        self.uc.reg_write(UC_X86_REG_RAX, exit_code)
        return exit_code
    
    def _custom_rtlcapturecontext(self):
        """RtlCaptureContext() - захват контекста процессора для exception handling"""
        pContextRecord = self.uc.reg_read(UC_X86_REG_RCX)
        
        print(f"[API] RtlCaptureContext(0x{pContextRecord:x}) [CUSTOM]")
        
        if pContextRecord == 0:
            return
        
        # CONTEXT structure для x64 (упрощенная версия)
        # Заполняем основные регистры
        import struct
        
        try:
            # Размер CONTEXT ~0x4D0 байт
            context_data = bytearray(0x4D0)
            
            # ContextFlags (offset 0x30)
            struct.pack_into('<I', context_data, 0x30, 0x10001F)  # CONTEXT_FULL
            
            # Регистры (offset 0x78+)
            struct.pack_into('<Q', context_data, 0x78, self.uc.reg_read(UC_X86_REG_RAX))
            struct.pack_into('<Q', context_data, 0x80, self.uc.reg_read(UC_X86_REG_RCX))
            struct.pack_into('<Q', context_data, 0x88, self.uc.reg_read(UC_X86_REG_RDX))
            struct.pack_into('<Q', context_data, 0x90, self.uc.reg_read(UC_X86_REG_RBX))
            struct.pack_into('<Q', context_data, 0x98, self.uc.reg_read(UC_X86_REG_RSP))
            struct.pack_into('<Q', context_data, 0xA0, self.uc.reg_read(UC_X86_REG_RBP))
            struct.pack_into('<Q', context_data, 0xA8, self.uc.reg_read(UC_X86_REG_RSI))
            struct.pack_into('<Q', context_data, 0xB0, self.uc.reg_read(UC_X86_REG_RDI))
            struct.pack_into('<Q', context_data, 0xF8, self.uc.reg_read(UC_X86_REG_RIP))
            
            # Записываем в память
            self.uc.mem_write(pContextRecord, bytes(context_data))
            
        except Exception as e:
            print(f"[!] RtlCaptureContext failed: {e}")
        
        # VOID function
        return
    
    def _custom_rtllookupfunctionentry(self):
        """RtlLookupFunctionEntry() - поиск exception handling информации для функции"""
        ControlPc = self.uc.reg_read(UC_X86_REG_RCX)
        ImageBase = self.uc.reg_read(UC_X86_REG_RDX)
        HistoryTable = self.uc.reg_read(UC_X86_REG_R8)
        
        print(f"[API] RtlLookupFunctionEntry(PC=0x{ControlPc:x}, Base=0x{ImageBase:x}) [CUSTOM]")
        
        # Возвращаем NULL - нет exception handling информации
        # Это безопаснее, чем возвращать мусор
        self.uc.reg_write(UC_X86_REG_RAX, 0)
        return 0
    
    def _custom_rtlvirtualunwind(self):
        """RtlVirtualUnwind() - раскрутка стека для exception handling"""
        HandlerType = self.uc.reg_read(UC_X86_REG_RCX)
        ImageBase = self.uc.reg_read(UC_X86_REG_RDX)
        ControlPc = self.uc.reg_read(UC_X86_REG_R8)
        FunctionEntry = self.uc.reg_read(UC_X86_REG_R9)
        
        print(f"[API] RtlVirtualUnwind(Type={HandlerType}, PC=0x{ControlPc:x}) [CUSTOM]")
        
        # Возвращаем NULL - нет handler
        self.uc.reg_write(UC_X86_REG_RAX, 0)
        return 0
    
    def _custom_getlogicalprocessorinformation(self):
        """GetLogicalProcessorInformation() - КЛЮЧЕВАЯ ФУНКЦИЯ для CoreInfo!"""
        pBuffer = self.uc.reg_read(UC_X86_REG_RCX)
        pReturnedLength = self.uc.reg_read(UC_X86_REG_RDX)
        
        print(f"[API] GetLogicalProcessorInformation(0x{pBuffer:x}, 0x{pReturnedLength:x}) [CUSTOM - PASSTHROUGH]")
        
        # Используем passthrough для получения РЕАЛЬНОЙ информации о CPU
        if self.hybrid and self.hybrid.passthrough_enabled:
            try:
                import ctypes
                from ctypes import wintypes, Structure, POINTER, byref, sizeof
                
                # Определяем структуры
                class SYSTEM_LOGICAL_PROCESSOR_INFORMATION(Structure):
                    _fields_ = [
                        ("ProcessorMask", ctypes.c_uint64),
                        ("Relationship", ctypes.c_int),
                        ("Reserved", ctypes.c_uint64 * 2),
                    ]
                
                kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
                
                # Сначала узнаем размер буфера
                returned_length = wintypes.DWORD()
                result = kernel32.GetLogicalProcessorInformation(None, byref(returned_length))
                
                if not result and ctypes.get_last_error() == 122:  # ERROR_INSUFFICIENT_BUFFER
                    # Записываем требуемый размер
                    if pReturnedLength:
                        self.uc.mem_write(pReturnedLength, returned_length.value.to_bytes(4, 'little'))
                    
                    print(f"    [PASSTHROUGH] Required buffer size: {returned_length.value} bytes")
                    
                    # Если буфер предоставлен, получаем данные
                    if pBuffer != 0:
                        # Выделяем буфер
                        buffer_size = returned_length.value
                        buffer = (SYSTEM_LOGICAL_PROCESSOR_INFORMATION * (buffer_size // sizeof(SYSTEM_LOGICAL_PROCESSOR_INFORMATION)))()
                        
                        # Получаем данные
                        result = kernel32.GetLogicalProcessorInformation(byref(buffer), byref(returned_length))
                        
                        if result:
                            # Копируем данные в память эмулятора
                            data = bytes(buffer)
                            self.uc.mem_write(pBuffer, data[:returned_length.value])
                            
                            # Записываем фактический размер
                            if pReturnedLength:
                                self.uc.mem_write(pReturnedLength, returned_length.value.to_bytes(4, 'little'))
                            
                            print(f"    [PASSTHROUGH] Copied {returned_length.value} bytes of CPU topology data")
                            print(f"    [PASSTHROUGH] Number of structures: {returned_length.value // sizeof(SYSTEM_LOGICAL_PROCESSOR_INFORMATION)}")
                            
                            self.uc.reg_write(UC_X86_REG_RAX, 1)  # TRUE
                            return 1
                    else:
                        # Только запрос размера
                        self.uc.reg_write(UC_X86_REG_RAX, 0)  # FALSE
                        # SetLastError(ERROR_INSUFFICIENT_BUFFER)
                        return 0
                
            except Exception as e:
                print(f"[!] GetLogicalProcessorInformation passthrough failed: {e}")
        
        # Fallback: возвращаем ошибку
        print(f"[API] GetLogicalProcessorInformation() -> ERROR [STUB]")
        self.uc.reg_write(UC_X86_REG_RAX, 0)
        return 0
    
    def _custom_getlogicalprocessorinformationex(self):
        """GetLogicalProcessorInformationEx() - расширенная версия"""
        RelationshipType = self.uc.reg_read(UC_X86_REG_RCX)
        pBuffer = self.uc.reg_read(UC_X86_REG_RDX)
        pReturnedLength = self.uc.reg_read(UC_X86_REG_R8)
        
        print(f"[API] GetLogicalProcessorInformationEx({RelationshipType}, 0x{pBuffer:x}, 0x{pReturnedLength:x}) [CUSTOM]")
        
        # Пока просто возвращаем ошибку - CoreInfo использует обычную версию
        self.uc.reg_write(UC_X86_REG_RAX, 0)
        return 0
    
    def _custom_getmodulefilenamea(self):
        """GetModuleFileNameA() - получить путь к exe"""
        hModule = self.uc.reg_read(UC_X86_REG_RCX)
        lpFilename = self.uc.reg_read(UC_X86_REG_RDX)
        nSize = self.uc.reg_read(UC_X86_REG_R8)
        
        # Возвращаем путь к CPU-Z
        path = "C:\\sandbox\\CPU-Z\\cpuz.exe\x00"
        
        if lpFilename and nSize > 0:
            write_len = min(len(path), nSize)
            self.uc.mem_write(lpFilename, path[:write_len].encode('ascii'))
            print(f"[API] GetModuleFileNameA(0x{hModule:x}) -> '{path.strip(chr(0))}' [CUSTOM]")
            self.uc.reg_write(UC_X86_REG_RAX, write_len - 1)  # Длина без null
            return write_len - 1
        
        self.uc.reg_write(UC_X86_REG_RAX, 0)
        return 0
    
    def _custom_getmodulefilenamew(self):
        """GetModuleFileNameW() - получить путь к exe (Unicode)"""
        hModule = self.uc.reg_read(UC_X86_REG_RCX)
        lpFilename = self.uc.reg_read(UC_X86_REG_RDX)
        nSize = self.uc.reg_read(UC_X86_REG_R8)
        
        # Возвращаем путь к CPU-Z
        path = "C:\\sandbox\\CPU-Z\\cpuz.exe\x00"
        path_wide = path.encode('utf-16-le')
        
        if lpFilename and nSize > 0:
            write_len = min(len(path_wide), nSize * 2)
            self.uc.mem_write(lpFilename, path_wide[:write_len])
            print(f"[API] GetModuleFileNameW(0x{hModule:x}) -> '{path.strip(chr(0))}' [CUSTOM]")
            self.uc.reg_write(UC_X86_REG_RAX, write_len // 2 - 1)  # Длина в символах без null
            return write_len // 2 - 1
        
        self.uc.reg_write(UC_X86_REG_RAX, 0)
        return 0
    
    def _custom_getmodulehandlea(self):
        """GetModuleHandleA() - получить handle модуля"""
        lpModuleName = self.uc.reg_read(UC_X86_REG_RCX)
        
        if lpModuleName == 0:
            # NULL = текущий exe
            handle = self.emu.pe_loader.image_base if hasattr(self.emu, 'pe_loader') else 0x140000000
            print(f"[API] GetModuleHandleA(NULL) -> 0x{handle:x} [CUSTOM]")
            self.uc.reg_write(UC_X86_REG_RAX, handle)
            return handle
        
        module_name = self._read_string(lpModuleName)
        print(f"[API] GetModuleHandleA('{module_name}') [CUSTOM]")
        
        # Возвращаем фейковый handle для DLL
        handle = 0x70000000 + hash(module_name.lower()) % 0x10000000
        self.uc.reg_write(UC_X86_REG_RAX, handle)
        return handle
    
    def _custom_getmodulehandlew(self):
        """GetModuleHandleW() - получить handle модуля (Unicode)"""
        lpModuleName = self.uc.reg_read(UC_X86_REG_RCX)
        
        if lpModuleName == 0:
            # NULL = текущий exe
            handle = self.emu.pe_loader.image_base if hasattr(self.emu, 'pe_loader') else 0x140000000
            print(f"[API] GetModuleHandleW(NULL) -> 0x{handle:x} [CUSTOM]")
            self.uc.reg_write(UC_X86_REG_RAX, handle)
            return handle
        
        module_name = self._read_wstring(lpModuleName)
        print(f"[API] GetModuleHandleW('{module_name}') [CUSTOM]")
        
        # Возвращаем фейковый handle для DLL
        handle = 0x70000000 + hash(module_name.lower()) % 0x10000000
        self.uc.reg_write(UC_X86_REG_RAX, handle)
        return handle
    
    def _custom_encodepointer(self):
        """EncodePointer() - кодирование указателя (для безопасности)"""
        ptr = self.uc.reg_read(UC_X86_REG_RCX)
        
        # Простое XOR с константой (в реальной Windows используется секретный ключ)
        encoded = ptr ^ 0xDEADBEEFCAFEBABE
        
        print(f"[API] EncodePointer(0x{ptr:x}) -> 0x{encoded:x} [CUSTOM]")
        self.uc.reg_write(UC_X86_REG_RAX, encoded)
        return encoded
    
    def _custom_decodepointer(self):
        """DecodePointer() - декодирование указателя"""
        encoded = self.uc.reg_read(UC_X86_REG_RCX)
        
        # Обратное XOR
        ptr = encoded ^ 0xDEADBEEFCAFEBABE
        
        print(f"[API] DecodePointer(0x{encoded:x}) -> 0x{ptr:x} [CUSTOM]")
        self.uc.reg_write(UC_X86_REG_RAX, ptr)
        return ptr
    
    def _custom_entercriticalsection(self):
        """EnterCriticalSection() - вход в критическую секцию"""
        lpCriticalSection = self.uc.reg_read(UC_X86_REG_RCX)
        print(f"[API] EnterCriticalSection(0x{lpCriticalSection:x}) [CUSTOM]")
        # VOID function - не возвращает значение
        # НО: очищаем RAX, чтобы не было мусора!
        self.uc.reg_write(UC_X86_REG_RAX, 0)
        return
    
    def _custom_leavecriticalsection(self):
        """LeaveCriticalSection() - выход из критической секции"""
        lpCriticalSection = self.uc.reg_read(UC_X86_REG_RCX)
        print(f"[API] LeaveCriticalSection(0x{lpCriticalSection:x}) [CUSTOM]")
        # VOID function
        self.uc.reg_write(UC_X86_REG_RAX, 0)
        return
    
    def _custom_initializecriticalsection(self):
        """InitializeCriticalSection() - инициализация критической секции"""
        lpCriticalSection = self.uc.reg_read(UC_X86_REG_RCX)
        print(f"[API] InitializeCriticalSection(0x{lpCriticalSection:x}) [CUSTOM]")
        # VOID function
        self.uc.reg_write(UC_X86_REG_RAX, 0)
        return
    
    def _custom_deletecriticalsection(self):
        """DeleteCriticalSection() - удаление критической секции"""
        lpCriticalSection = self.uc.reg_read(UC_X86_REG_RCX)
        print(f"[API] DeleteCriticalSection(0x{lpCriticalSection:x}) [CUSTOM]")
        # VOID function
        self.uc.reg_write(UC_X86_REG_RAX, 0)
        return
    
    def _custom_isprocessorfeaturepresent(self):
        """IsProcessorFeaturePresent() - УМНЫЙ ПАТЧИНГ под возможности Unicorn"""
        ProcessorFeature = self.uc.reg_read(UC_X86_REG_RCX)
        
        # Виртуальный CPU profile - что Unicorn МОЖЕТ эмулировать
        # https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-isprocessorfeaturepresent
        VIRTUAL_CPU_FEATURES = {
            # Базовые features (Unicorn поддерживает)
            0: True,   # PF_FLOATING_POINT_PRECISION_ERRATA
            1: False,  # PF_FLOATING_POINT_EMULATED
            2: True,   # PF_COMPARE_EXCHANGE_DOUBLE
            3: True,   # PF_MMX_INSTRUCTIONS_AVAILABLE
            6: True,   # PF_XMMI_INSTRUCTIONS_AVAILABLE (SSE)
            7: False,  # PF_3DNOW_INSTRUCTIONS_AVAILABLE
            10: True,  # PF_XMMI64_INSTRUCTIONS_AVAILABLE (SSE2)
            13: True,  # PF_SSE3_INSTRUCTIONS_AVAILABLE
            17: True,  # PF_COMPARE_EXCHANGE128
            23: False, # PF_SSE_DAZ_MODE_AVAILABLE
            
            # Продвинутые features (Unicorn НЕ поддерживает - ПАТЧИМ!)
            # 23: False,  # PF_AVX2_INSTRUCTIONS_AVAILABLE ← ВАЖНО!
            # 40: False,  # PF_AVX512F_INSTRUCTIONS_AVAILABLE
            # Для безопасности возвращаем FALSE для всех неизвестных
        }
        
        # Проверяем в виртуальном профиле
        if ProcessorFeature in VIRTUAL_CPU_FEATURES:
            result = 1 if VIRTUAL_CPU_FEATURES[ProcessorFeature] else 0
            feature_name = self._get_processor_feature_name(ProcessorFeature)
            print(f"[API] IsProcessorFeaturePresent({ProcessorFeature}:{feature_name}) -> {result} [VIRTUAL CPU]")
            self.uc.reg_write(UC_X86_REG_RAX, result)
            return result
        
        # Для неизвестных features - используем passthrough, но с осторожностью
        if self.hybrid and self.hybrid.passthrough_enabled:
            try:
                import ctypes
                kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
                result = kernel32.IsProcessorFeaturePresent(ProcessorFeature)
                
                # ПАТЧИНГ: если это продвинутая feature (> 20), возвращаем FALSE
                # чтобы программа не пыталась использовать неподдерживаемые инструкции
                if ProcessorFeature > 20 and result:
                    print(f"[API] IsProcessorFeaturePresent({ProcessorFeature}) -> 0 [PATCHED: advanced feature]")
                    self.uc.reg_write(UC_X86_REG_RAX, 0)
                    return 0
                
                print(f"[API] IsProcessorFeaturePresent({ProcessorFeature}) -> {result} [PASSTHROUGH]")
                self.uc.reg_write(UC_X86_REG_RAX, result)
                return result
            except Exception as e:
                print(f"[!] IsProcessorFeaturePresent passthrough failed: {e}")
        
        # Fallback: возвращаем 0 (feature not present)
        print(f"[API] IsProcessorFeaturePresent({ProcessorFeature}) -> 0 [STUB]")
        self.uc.reg_write(UC_X86_REG_RAX, 0)
        return 0
    
    def _get_processor_feature_name(self, feature):
        """Возвращает имя processor feature для логирования"""
        names = {
            0: "FLOATING_POINT_PRECISION_ERRATA",
            1: "FLOATING_POINT_EMULATED",
            2: "COMPARE_EXCHANGE_DOUBLE",
            3: "MMX_INSTRUCTIONS_AVAILABLE",
            6: "XMMI_INSTRUCTIONS_AVAILABLE (SSE)",
            7: "3DNOW_INSTRUCTIONS_AVAILABLE",
            10: "XMMI64_INSTRUCTIONS_AVAILABLE (SSE2)",
            13: "SSE3_INSTRUCTIONS_AVAILABLE",
            17: "COMPARE_EXCHANGE128",
            23: "SSE_DAZ_MODE_AVAILABLE",
        }
        return names.get(feature, f"UNKNOWN_{feature}")
    
    def _custom_getsysteminfo(self):
        """GetSystemInfo() - получение информации о системе"""
        lpSystemInfo = self.uc.reg_read(UC_X86_REG_RCX)
        
        print(f"[API] GetSystemInfo()")
        
        if lpSystemInfo == 0:
            return
        
        # Используем passthrough для получения РЕАЛЬНОЙ информации
        if self.hybrid and self.hybrid.passthrough_enabled:
            try:
                import ctypes
                from ctypes import wintypes, Structure, c_void_p, c_ulong, c_ushort
                
                class SYSTEM_INFO(Structure):
                    _fields_ = [
                        ("wProcessorArchitecture", c_ushort),
                        ("wReserved", c_ushort),
                        ("dwPageSize", c_ulong),
                        ("lpMinimumApplicationAddress", c_void_p),
                        ("lpMaximumApplicationAddress", c_void_p),
                        ("dwActiveProcessorMask", c_void_p),
                        ("dwNumberOfProcessors", c_ulong),
                        ("dwProcessorType", c_ulong),
                        ("dwAllocationGranularity", c_ulong),
                        ("wProcessorLevel", c_ushort),
                        ("wProcessorRevision", c_ushort),
                    ]
                
                # Вызываем РЕАЛЬНУЮ GetSystemInfo
                kernel32 = ctypes.WinDLL('kernel32')
                si = SYSTEM_INFO()
                kernel32.GetSystemInfo(ctypes.byref(si))
                
                # Записываем результат в память эмулятора
                import struct
                data = struct.pack('<HHIQQQQIIHH',
                    si.wProcessorArchitecture,
                    si.wReserved,
                    si.dwPageSize,
                    si.lpMinimumApplicationAddress or 0,
                    si.lpMaximumApplicationAddress or 0,
                    si.dwActiveProcessorMask or 0,
                    si.dwNumberOfProcessors,
                    si.dwProcessorType,
                    si.dwAllocationGranularity,
                    si.wProcessorLevel,
                    si.wProcessorRevision
                )
                
                self.uc.mem_write(lpSystemInfo, data)
                print(f"    [PASSTHROUGH] Processors: {si.dwNumberOfProcessors}, Page: {si.dwPageSize}, Arch: {si.wProcessorArchitecture}")
                return
            except Exception as e:
                print(f"    [!] Passthrough failed: {e}, using virtual data")
        
        # Fallback: виртуальные данные
        import struct
        data = struct.pack('<HHIQQQQIIHH',
            9,      # wProcessorArchitecture (PROCESSOR_ARCHITECTURE_AMD64)
            0,      # wReserved
            4096,   # dwPageSize
            0x10000,  # lpMinimumApplicationAddress
            0x7FFFFFFEFFFF,  # lpMaximumApplicationAddress
            0xFF,   # dwActiveProcessorMask (8 cores)
            8,      # dwNumberOfProcessors
            8664,   # dwProcessorType (AMD64)
            65536,  # dwAllocationGranularity
            6,      # wProcessorLevel
            0,      # wProcessorRevision
        )
        
        self.uc.mem_write(lpSystemInfo, data)
        print(f"    [VIRTUAL] Processors: 8, Page: 4096, Arch: AMD64")
    
    def _custom_loadlibrarya(self):
        """LoadLibraryA() - загрузка DLL"""
        lpLibFileName = self.uc.reg_read(UC_X86_REG_RCX)
        
        if lpLibFileName == 0:
            print(f"[API] LoadLibraryA(NULL) -> 0 [CUSTOM]")
            self.uc.reg_write(UC_X86_REG_RAX, 0)
            return 0
        
        lib_name = self._read_string(lpLibFileName)
        print(f"[API] LoadLibraryA('{lib_name}') [CUSTOM]")
        
        # Возвращаем фейковый handle для DLL
        handle = 0x70000000 + hash(lib_name.lower()) % 0x10000000
        self.uc.reg_write(UC_X86_REG_RAX, handle)
        return handle
    
    def _custom_loadlibraryw(self):
        """LoadLibraryW() - загрузка DLL (Unicode)"""
        lpLibFileName = self.uc.reg_read(UC_X86_REG_RCX)
        
        if lpLibFileName == 0:
            print(f"[API] LoadLibraryW(NULL) -> 0 [CUSTOM]")
            self.uc.reg_write(UC_X86_REG_RAX, 0)
            return 0
        
        lib_name = self._read_wstring(lpLibFileName)
        print(f"[API] LoadLibraryW('{lib_name}') [CUSTOM]")
        
        # Возвращаем фейковый handle для DLL
        handle = 0x70000000 + hash(lib_name.lower()) % 0x10000000
        self.uc.reg_write(UC_X86_REG_RAX, handle)
        return handle
    
    def _custom_getprocaddress(self):
        """GetProcAddress() - получить адрес функции в DLL"""
        hModule = self.uc.reg_read(UC_X86_REG_RCX)
        lpProcName = self.uc.reg_read(UC_X86_REG_RDX)
        
        if lpProcName == 0:
            print(f"[API] GetProcAddress(0x{hModule:x}, NULL) -> 0 [CUSTOM]")
            self.uc.reg_write(UC_X86_REG_RAX, 0)
            return 0
        
        # Проверяем, это ordinal или имя
        if lpProcName < 0x10000:
            # Это ordinal
            proc_name = f"Ordinal_{lpProcName}"
        else:
            # Это имя функции
            proc_name = self._read_string(lpProcName)
        
        print(f"[API] GetProcAddress(0x{hModule:x}, '{proc_name}') [CUSTOM]")
        
        # ХИТРОСТЬ: Для CorExitProcess возвращаем NULL, чтобы CPU-Z не использовал его
        if proc_name.lower() == 'corexitprocess':
            print(f"  -> Blocked (returning NULL to prevent early exit)")
            self.uc.reg_write(UC_X86_REG_RAX, 0)
            return 0
        
        # Проверяем, есть ли у нас stub для этой функции
        stub_addr = self.get_stub_address(proc_name)
        
        if stub_addr:
            print(f"  -> Found stub at 0x{stub_addr:x}")
            self.uc.reg_write(UC_X86_REG_RAX, stub_addr)
            return stub_addr
        
        # Нет stub - возвращаем NULL (функция не найдена)
        print(f"  -> Not found (returning NULL)")
        self.uc.reg_write(UC_X86_REG_RAX, 0)
        return 0
    
    def _custom_getprocesswindowstation(self):
        """GetProcessWindowStation() - получить handle window station"""
        handle = 0x00000100  # Фейковый handle
        print(f"[API] GetProcessWindowStation() -> 0x{handle:x} [CUSTOM]")
        self.uc.reg_write(UC_X86_REG_RAX, handle)
        return handle
    
    def _custom_getuserobjectinformationa(self):
        """GetUserObjectInformationA() - получить информацию о user object"""
        hObj = self.uc.reg_read(UC_X86_REG_RCX)
        nIndex = self.uc.reg_read(UC_X86_REG_RDX)
        pvInfo = self.uc.reg_read(UC_X86_REG_R8)
        nLength = self.uc.reg_read(UC_X86_REG_R9)
        
        print(f"[API] GetUserObjectInformationA(0x{hObj:x}, {nIndex}) [CUSTOM]")
        
        # UOI_FLAGS = 1
        if nIndex == 1 and pvInfo and nLength >= 12:
            # USEROBJECTFLAGS structure
            # dwFlags = 0x00000000 (NO GUI - WSF_VISIBLE not set)
            # Это должно сказать CPU-Z, что GUI недоступен
            self.uc.mem_write(pvInfo, b'\x00\x00\x00\x00' + b'\x00' * 8)
            self.uc.reg_write(UC_X86_REG_RAX, 1)  # TRUE
            print(f"  -> Returning NO GUI (WSF_VISIBLE=0)")
            return 1
        
        self.uc.reg_write(UC_X86_REG_RAX, 0)  # FALSE
        return 0
    
    def _custom_getuserobjectinformationw(self):
        """GetUserObjectInformationW() - получить информацию о user object (Unicode)"""
        return self._custom_getuserobjectinformationa()  # Та же логика
    
    def _custom_corexitprocess(self):
        """CorExitProcess() - .NET выход из процесса"""
        exit_code = self.uc.reg_read(UC_X86_REG_RCX)
        print(f"[API] CorExitProcess({exit_code}) [CUSTOM] - STOPPING EMULATION")
        
        # Останавливаем эмуляцию
        self.uc.emu_stop()
        
        self.uc.reg_write(UC_X86_REG_RAX, exit_code)
        return exit_code
    
    # ========================================================================
    # ВСПОМОГАТЕЛЬНЫЕ МЕТОДЫ
    # ========================================================================
    
    def _read_string(self, addr, max_len=256):
        """Читает ASCII строку из памяти"""
        try:
            data = self.uc.mem_read(addr, max_len)
            return data.split(b'\x00')[0].decode('ascii', errors='ignore')
        except:
            return ""
    
    def _read_wstring(self, addr, max_len=256):
        """Читает Unicode строку из памяти"""
        try:
            data = self.uc.mem_read(addr, max_len * 2)
            return data.decode('utf-16-le', errors='ignore').split('\x00')[0]
        except:
            return ""
    
    # ========================================================================
    # ПУБЛИЧНЫЙ API
    # ========================================================================
    
    def call_stub(self, name):
        """Вызов заглушки по имени"""
        stub = self.registry.get(name.lower())
        if stub:
            return stub()
        else:
            print(f"[!] Stub not found: {name}")
            return 0
    
    def get_stats(self):
        """Статистика по заглушкам"""
        total = len(set(self.registry.generated.keys()) | set(self.registry.custom.keys()))
        custom = len(self.registry.custom)
        generated = len(self.registry.generated)
        
        return {
            'total': total,
            'custom': custom,
            'generated': generated,
            'custom_percentage': (custom / total * 100) if total > 0 else 0
        }
    
    def get_all_stubs_info(self):
        """Получить полную информацию о всех зарегистрированных stubs"""
        info = {
            'total_addresses': len(self.stub_addresses),
            'registry_total': len(set(self.registry.generated.keys()) | set(self.registry.custom.keys())),
            'custom': len(self.registry.custom),
            'generated': len(self.registry.generated),
            'stubs_by_address': {}
        }
        
        # Проверяем stub code для каждого адреса
        for addr, name in sorted(self.stub_addresses.items()):
            try:
                code = self.uc.mem_read(addr, 2)
                has_int3 = code[0] == 0xCC
                has_ret = code[1] == 0xC3
                is_custom = name in self.registry.custom
                
                info['stubs_by_address'][addr] = {
                    'name': name,
                    'has_int3': has_int3,
                    'has_ret': has_ret,
                    'is_custom': is_custom,
                    'code_hex': code.hex()
                }
            except:
                info['stubs_by_address'][addr] = {
                    'name': name,
                    'error': 'Cannot read memory'
                }
        
        return info
    
    def get_stub_address(self, func_name):
        """Получить адрес заглушки по имени функции"""
        func_name_lower = func_name.lower()
        
        # Ищем в маппинге адресов
        for addr, name in self.stub_addresses.items():
            if name == func_name_lower:
                return addr
        
        # Если не найдено, создаём новый адрес
        if self.stub_addresses:
            max_addr = max(self.stub_addresses.keys())
            new_addr = max_addr + 0x100
        else:
            new_addr = 0x7FFF0000
        
        self.stub_addresses[new_addr] = func_name_lower
        
        # Записываем RET инструкцию
        stub_code = bytes([0xC3])  # RET
        
        try:
            self.uc.mem_write(new_addr, stub_code)
        except Exception as e:
            print(f"[!] Failed to write stub code for '{func_name_lower}' @ 0x{new_addr:x}: {e}")
        
        return new_addr
    
    def handle_stub_call(self, address):
        """Обработка вызова заглушки по адресу
        
        Returns:
            int: Адрес возврата (новый RIP)
        """
        # Находим имя функции по адресу
        func_name = self.stub_addresses.get(address)
        
        if not func_name:
            # Возможно, адрес внутри заглушки (не в начале)
            # Заглушки выровнены на 0x100, найдём начало
            stub_start = (address // 0x100) * 0x100
            func_name = self.stub_addresses.get(stub_start)
            
            if func_name:
                print(f"[STUB] Call to middle of stub '{func_name}' @ 0x{address:x} (start: 0x{stub_start:x})")
                address = stub_start  # Используем начало заглушки
            else:
                # Возможно, это dummy stub от PE Loader
                if hasattr(self.emu, 'pe_loader') and hasattr(self.emu.pe_loader, '_dummy_stub_names'):
                    dummy_name = self.emu.pe_loader._dummy_stub_names.get(address)
                    if not dummy_name:
                        # Попробуем найти по началу
                        dummy_name = self.emu.pe_loader._dummy_stub_names.get(stub_start)
                    
                    if dummy_name:
                        # Это dummy stub - просто возвращаем успех
                        rsp = self.uc.reg_read(UC_X86_REG_RSP)
                        ret_addr = int.from_bytes(self.uc.mem_read(rsp, 8), 'little')
                        print(f"[STUB] Dummy stub '{dummy_name}' @ 0x{address:x} called from 0x{ret_addr:x} -> returning success")
                        self.uc.reg_write(UC_X86_REG_RAX, 1)  # SUCCESS
                        
                        # Возвращаемся из функции
                        rsp = self.uc.reg_read(UC_X86_REG_RSP)
                        ret_addr = int.from_bytes(self.uc.mem_read(rsp, 8), 'little')
                        self.uc.reg_write(UC_X86_REG_RSP, rsp + 8)
                        self.uc.reg_write(UC_X86_REG_RIP, ret_addr)
                        return ret_addr  # ВОЗВРАЩАЕМ адрес возврата
                
                print(f"[!] Unknown stub at 0x{address:x}")
                print(f"    This address is not in stub_addresses mapping")
                print(f"    Stub region: 0x{self.STUB_BASE:x} - 0x{self.STUB_BASE + 0x40000000:x}")
                print(f"    Tried stub_start: 0x{stub_start:x}")
                
                # Всё равно делаем RET, чтобы не застрять
                rsp = self.uc.reg_read(UC_X86_REG_RSP)
                ret_addr = int.from_bytes(self.uc.mem_read(rsp, 8), 'little')
                self.uc.reg_write(UC_X86_REG_RSP, rsp + 8)
                self.uc.reg_write(UC_X86_REG_RIP, ret_addr)
                return ret_addr  # ВОЗВРАЩАЕМ адрес возврата
        
        # Получаем заглушку из registry
        stub = self.registry.get(func_name)
        
        if stub:
            # Вызываем заглушку
            stub()
            
            # Возвращаемся из функции (pop return address and jump)
            rsp = self.uc.reg_read(UC_X86_REG_RSP)
            ret_addr = int.from_bytes(self.uc.mem_read(rsp, 8), 'little')
            new_rsp = rsp + 8
            
            self.uc.reg_write(UC_X86_REG_RSP, new_rsp)
            self.uc.reg_write(UC_X86_REG_RIP, ret_addr)
            
            # print(f"[STUB] Returning to 0x{ret_addr:x}, RSP=0x{new_rsp:x}")  # Отключено
            return ret_addr  # ВОЗВРАЩАЕМ адрес возврата
        else:
            print(f"[!] No stub implementation for {func_name}")
            # Для unknown_iat_* функций - возвращаем успех
            if func_name.startswith('unknown_iat_'):
                rsp = self.uc.reg_read(UC_X86_REG_RSP)
                ret_addr = int.from_bytes(self.uc.mem_read(rsp, 8), 'little')
                print(f"[STUB] Unknown IAT function '{func_name}' called from 0x{ret_addr:x} -> returning 0")
                self.uc.reg_write(UC_X86_REG_RAX, 0)  # Return 0
            
            # Всё равно делаем RET
            rsp = self.uc.reg_read(UC_X86_REG_RSP)
            ret_addr = int.from_bytes(self.uc.mem_read(rsp, 8), 'little')
            self.uc.reg_write(UC_X86_REG_RSP, rsp + 8)
            self.uc.reg_write(UC_X86_REG_RIP, ret_addr)
            return ret_addr  # ВОЗВРАЩАЕМ адрес возврата



if __name__ == '__main__':
    print("=" * 70)
    print("WinAPI Stubs V2 - Demo")
    print("=" * 70)
    print()
    
    # Демонстрация (требует эмулятор)
    print("[*] This module requires LayeredEmulator to run")
    print("[*] Import it in your emulator code:")
    print()
    print("    from src.core.winapi_stubs_v2 import WinAPIStubsV2")
    print("    stubs = WinAPIStubsV2(emulator)")
    print("    stats = stubs.get_stats()")
    print("    print(f'Custom: {stats['custom']}/{stats['total']}')")
