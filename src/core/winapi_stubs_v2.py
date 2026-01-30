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
        
        # Загружаем автогенерированные заглушки
        self._load_generated_stubs()
        
        # Регистрируем пользовательские реализации
        self._register_custom_stubs()
        
        # Создаём маппинг адресов
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
        self.registry.register_custom('heapalloc', self._custom_heapalloc)
        self.registry.register_custom('heapfree', self._custom_heapfree)
        self.registry.register_custom('virtualalloc', self._custom_virtualalloc)
        
        # Timing (критично для анти-тампера!)
        self.registry.register_custom('gettickcount', self._custom_gettickcount)
        self.registry.register_custom('queryperformancecounter', self._custom_queryperformancecounter)
        self.registry.register_custom('queryperformancefrequency', self._custom_queryperformancefrequency)
        
        custom_count = len(self.registry.custom)
        print(f"[+] Registered {custom_count} custom implementations")
    
    def _create_stub_mapping(self):
        """Создание маппинга адресов к заглушкам"""
        self.stub_addresses = {}
        
        # Базовый адрес для заглушек
        STUB_BASE = 0x7FFF0000
        current_addr = STUB_BASE
        
        # Создаём маппинг для всех заглушек
        all_stubs = set(self.registry.generated.keys()) | set(self.registry.custom.keys())
        
        for name in sorted(all_stubs):
            self.stub_addresses[current_addr] = name
            current_addr += 0x100  # 256 байт на заглушку
    
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
    
    def _custom_heapalloc(self):
        """HeapAlloc() - с реальной аллокацией"""
        hHeap = self.uc.reg_read(UC_X86_REG_RCX)
        dwFlags = self.uc.reg_read(UC_X86_REG_RDX)
        dwBytes = self.uc.reg_read(UC_X86_REG_R8)
        
        print(f"[API] HeapAlloc(0x{hHeap:x}, {dwBytes}) [CUSTOM]")
        
        # Используем heap manager эмулятора
        if hasattr(self.emu, 'heap'):
            addr = self.emu.heap.alloc(dwBytes)
        else:
            # Fallback: простая аллокация
            addr = 0x10000000 + (dwBytes * 0x1000)
        
        self.uc.reg_write(UC_X86_REG_RAX, addr)
        return addr
    
    def _custom_heapfree(self):
        """HeapFree() - с реальным освобождением"""
        hHeap = self.uc.reg_read(UC_X86_REG_RCX)
        dwFlags = self.uc.reg_read(UC_X86_REG_RDX)
        lpMem = self.uc.reg_read(UC_X86_REG_R8)
        
        print(f"[API] HeapFree(0x{lpMem:x}) [CUSTOM]")
        
        if hasattr(self.emu, 'heap'):
            self.emu.heap.free(lpMem)
        
        self.uc.reg_write(UC_X86_REG_RAX, 1)  # TRUE
        return 1
    
    def _custom_virtualalloc(self):
        """VirtualAlloc() - с реальной аллокацией"""
        lpAddress = self.uc.reg_read(UC_X86_REG_RCX)
        dwSize = self.uc.reg_read(UC_X86_REG_RDX)
        flAllocationType = self.uc.reg_read(UC_X86_REG_R8)
        flProtect = self.uc.reg_read(UC_X86_REG_R9)
        
        print(f"[API] VirtualAlloc(0x{lpAddress:x}, {dwSize}) [CUSTOM]")
        
        # Аллоцируем память в эмуляторе
        if lpAddress == 0:
            # Выбираем адрес сами
            addr = 0x20000000
        else:
            addr = lpAddress
        
        try:
            self.uc.mem_map(addr, (dwSize + 0xFFF) & ~0xFFF)
            self.uc.reg_write(UC_X86_REG_RAX, addr)
            return addr
        except:
            self.uc.reg_write(UC_X86_REG_RAX, 0)
            return 0
    
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
