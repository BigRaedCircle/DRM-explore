#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Check CPU-Z IAT (Import Address Table) for NULL pointers

This will help us find which functions are not properly patched.
"""

import sys
sys.path.insert(0, 'src/core')

from layered_emulator import LayeredEmulator


def test_cpuz_iat():
    """Check IAT for NULL pointers"""
    print("=" * 70)
    print("CPU-Z IAT CHECK")
    print("=" * 70)
    
    cpuz_path = "sandbox/CPU-Z/cpuz.exe"
    
    print(f"\n[*] Loading: {cpuz_path}")
    
    emu = LayeredEmulator(cpu_freq_mhz=3000)
    entry_point = emu.load_pe(cpuz_path)
    
    print(f"\n[*] Checking IAT for NULL pointers...")
    print("-" * 70)
    
    null_count = 0
    patched_count = 0
    total_count = 0
    
    null_functions = []
    
    if hasattr(emu.pe_loader.pe, 'DIRECTORY_ENTRY_IMPORT'):
        for entry in emu.pe_loader.pe.DIRECTORY_ENTRY_IMPORT:
            dll_name = entry.dll.decode('ascii', errors='ignore')
            
            for imp in entry.imports:
                total_count += 1
                func_name = imp.name.decode('ascii', errors='ignore') if imp.name else f"Ordinal_{imp.ordinal}"
                iat_address = imp.address
                
                # Read IAT entry
                try:
                    iat_value = int.from_bytes(emu.uc.mem_read(iat_address, 8), 'little')
                    
                    if iat_value == 0:
                        null_count += 1
                        null_functions.append((dll_name, func_name, iat_address))
                        print(f"[NULL] {dll_name:20} {func_name:40} @ 0x{iat_address:x}")
                    else:
                        patched_count += 1
                        # Only show first 10 patched entries
                        if patched_count <= 10:
                            print(f"[OK]   {dll_name:20} {func_name:40} @ 0x{iat_address:x} -> 0x{iat_value:x}")
                except Exception as e:
                    print(f"[ERR]  {dll_name:20} {func_name:40} @ 0x{iat_address:x} (error: {e})")
    
    print("-" * 70)
    print(f"\n[*] IAT Statistics:")
    print(f"    Total imports: {total_count}")
    print(f"    Patched: {patched_count}")
    print(f"    NULL pointers: {null_count}")
    
    if null_count > 0:
        print(f"\n[!] Found {null_count} NULL pointers in IAT!")
        print(f"[!] These functions will cause crashes when called:")
        for dll_name, func_name, iat_addr in null_functions[:20]:  # Show first 20
            print(f"    - {dll_name}::{func_name}")
        
        if len(null_functions) > 20:
            print(f"    ... and {len(null_functions) - 20} more")
        
        return False
    else:
        print(f"\n[OK] All imports are properly patched!")
        return True


if __name__ == "__main__":
    success = test_cpuz_iat()
    exit(0 if success else 1)
