#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Детальный тест эмуляции CPU-Z с анализом вызовов

Цель: Понять, какие функции CPU-Z активно использует,
чтобы добавить недостающие заглушки.
"""

import sys
sys.path.insert(0, 'src/core')

from layered_emulator import LayeredEmulator


def test_cpuz_detailed():
    """Detailed test of CPU-Z with call counting"""
    print("=" * 70)
    print("DETAILED TEST: CPU-Z (cpuz.exe)")
    print("=" * 70)
    
    cpuz_path = "sandbox/CPU-Z/cpuz.exe"
    
    print(f"\n[*] Loading: {cpuz_path}")
    
    emu = LayeredEmulator(cpu_freq_mhz=3000)
    
    # Счётчики вызовов для ВСЕХ заглушек
    api_calls = {}
    
    # Патчим ВСЕ заглушки для подсчёта
    for stub_name, stub_info in emu.winapi.stubs.items():
        original_handler = stub_info['handler']
        
        def make_patched_handler(name, orig):
            def patched():
                if name not in api_calls:
                    api_calls[name] = 0
                api_calls[name] += 1
                return orig()
            return patched
        
        stub_info['handler'] = make_patched_handler(stub_name, original_handler)
    
    # Load and run
    entry_point = emu.load_pe(cpuz_path)
    
    print(f"\n[*] Starting emulation...")
    print(f"[*] Entry point: 0x{entry_point:x}")
    print(f"[*] Max instructions: 200,000")
    print("-" * 70)
    
    try:
        exit_code = emu.run(
            start_addr=entry_point,
            end_addr=0,
            max_instructions=200000,
            verbose=False  # Disable detailed output
        )
    except Exception as e:
        print(f"\n[!] Emulation stopped: {e}")
    
    print("-" * 70)
    print(f"\n[*] Emulation finished")
    print(f"    Instructions executed: {emu.instruction_count:,}")
    print(f"    Virtual time: {emu.clock}")
    
    # Analyze calls
    print(f"\n[*] API call statistics:")
    print(f"    Total unique functions: {len(api_calls)}")
    print(f"    Total calls: {sum(api_calls.values())}")
    
    # Top-20 most called functions
    print(f"\n[*] Top-20 most called functions:")
    sorted_calls = sorted(api_calls.items(), key=lambda x: x[1], reverse=True)
    for i, (func_name, count) in enumerate(sorted_calls[:20], 1):
        print(f"    {i:2}. {func_name:30} - {count:,} times")
    
    # Group by categories
    categories = {
        'Time': ['GetTickCount64', 'QueryPerformanceCounter', 'QueryPerformanceFrequency', 
                  'GetSystemTimeAsFileTime'],
        'Memory': ['GetProcessHeap', 'HeapAlloc', 'HeapFree', 'HeapSize', 'HeapReAlloc', 
                   'VirtualProtect'],
        'Process/Thread': ['GetCurrentProcessId', 'GetCurrentThreadId', 'GetCurrentProcess'],
        'DLL/Modules': ['LoadLibraryA', 'LoadLibraryW', 'GetProcAddress', 'GetModuleHandleW'],
        'Files': ['CreateFileA', 'CreateFileW', 'ReadFile', 'CloseHandle'],
        'System': ['GetSystemInfo', 'Sleep'],
        'CRT': ['GetCommandLineA', 'GetCommandLineW', 'GetStartupInfoW', 
                'InitializeSListHead', 'SetUnhandledExceptionFilter'],
        'GUI': ['MessageBoxA', 'MessageBoxW'],
        'Exit': ['ExitProcess'],
    }
    
    print(f"\n[*] Calls by category:")
    for category, funcs in categories.items():
        category_calls = sum(api_calls.get(func, 0) for func in funcs)
        if category_calls > 0:
            print(f"\n  {category}: {category_calls:,} calls")
            for func in funcs:
                count = api_calls.get(func, 0)
                if count > 0:
                    print(f"    - {func:30} {count:,}")
    
    # Check which functions were NOT called
    unused_stubs = [name for name in emu.winapi.stubs.keys() if name not in api_calls]
    if unused_stubs:
        print(f"\n[*] Unused stubs ({len(unused_stubs)}):")
        for func in sorted(unused_stubs):
            print(f"    - {func}")
    
    print()


if __name__ == "__main__":
    test_cpuz_detailed()
