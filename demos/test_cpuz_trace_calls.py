#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Trace all function calls in CPU-Z to find which dummy stubs are called

This will help us identify which functions need proper implementation.
"""

import sys
sys.path.insert(0, 'src/core')

from layered_emulator import LayeredEmulator
from unicorn import UC_HOOK_CODE
from unicorn.x86_const import *


def test_cpuz_trace():
    """Trace all function calls"""
    print("=" * 70)
    print("CPU-Z FUNCTION CALL TRACE")
    print("=" * 70)
    
    cpuz_path = "sandbox/CPU-Z/cpuz.exe"
    
    print(f"\n[*] Loading: {cpuz_path}")
    
    emu = LayeredEmulator(cpu_freq_mhz=3000)
    
    # Track all calls to dummy stubs
    dummy_stub_calls = {}
    
    # Get dummy stub region
    dummy_base = emu.winapi.STUB_BASE + 0xF000
    dummy_end = dummy_base + 0x10000
    
    # Hook to track calls
    def hook_code(uc, address, size, user_data):
        # Check if we're calling into dummy stub region
        if dummy_base <= address < dummy_end:
            # Find which function this is
            if hasattr(emu.pe_loader, 'pe') and hasattr(emu.pe_loader.pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in emu.pe_loader.pe.DIRECTORY_ENTRY_IMPORT:
                    dll_name = entry.dll.decode('ascii', errors='ignore')
                    for imp in entry.imports:
                        func_name = imp.name.decode('ascii', errors='ignore') if imp.name else f"Ordinal_{imp.ordinal}"
                        iat_address = imp.address
                        
                        try:
                            iat_value = int.from_bytes(uc.mem_read(iat_address, 8), 'little')
                            if iat_value == address:
                                key = f"{dll_name}::{func_name}"
                                if key not in dummy_stub_calls:
                                    dummy_stub_calls[key] = 0
                                    print(f"[DUMMY] {key}")
                                dummy_stub_calls[key] += 1
                                return
                        except:
                            pass
    
    # Add hook
    emu.uc.hook_add(UC_HOOK_CODE, hook_code)
    
    # Load PE
    entry_point = emu.load_pe(cpuz_path)
    
    print(f"\n[*] Starting emulation with call tracing...")
    print(f"[*] Entry point: 0x{entry_point:x}")
    print("-" * 70)
    
    try:
        emu.run(
            start_addr=entry_point,
            end_addr=0,
            max_instructions=10000,
            verbose=False
        )
    except Exception as e:
        print(f"\n[*] Stopped: {e}")
    
    print("-" * 70)
    print(f"\n[*] Emulation finished")
    print(f"    Instructions executed: {emu.instruction_count:,}")
    
    # Show dummy stub call statistics
    if dummy_stub_calls:
        print(f"\n[*] Dummy stub calls: {len(dummy_stub_calls)} unique functions")
        print(f"    Total calls: {sum(dummy_stub_calls.values())}")
        
        print(f"\n[*] Most called dummy stubs:")
        sorted_calls = sorted(dummy_stub_calls.items(), key=lambda x: x[1], reverse=True)
        for i, (func, count) in enumerate(sorted_calls[:20], 1):
            print(f"    {i:2}. {func:50} - {count:,} times")
        
        # Group by DLL
        print(f"\n[*] Calls by DLL:")
        dll_calls = {}
        for func, count in dummy_stub_calls.items():
            dll = func.split('::')[0]
            if dll not in dll_calls:
                dll_calls[dll] = 0
            dll_calls[dll] += count
        
        for dll, count in sorted(dll_calls.items(), key=lambda x: x[1], reverse=True):
            print(f"    {dll:30} - {count:,} calls")
    else:
        print(f"\n[*] No dummy stub calls detected")


if __name__ == "__main__":
    test_cpuz_trace()
