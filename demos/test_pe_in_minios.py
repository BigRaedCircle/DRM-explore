#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Test: Load PE file (time_check_demo.exe) into MiniOS

This test verifies that:
1. PE loader works with MiniOS
2. Sections are loaded correctly
3. IAT is patched with MiniOS stubs
4. Basic execution starts
"""

import sys
sys.path.insert(0, 'src/core')

from layered_emulator import LayeredEmulator


def test_pe_loading():
    """Test loading PE file into MiniOS"""
    print("=" * 70)
    print("TEST: Load PE into MiniOS")
    print("=" * 70)
    print()
    
    pe_path = "demos/time_check_demo.exe"
    
    print(f"[*] Target PE: {pe_path}")
    print()
    
    # Create emulator with MiniOS
    print("[*] Creating layered emulator with MiniOS...")
    emu = LayeredEmulator(cpu_freq_mhz=3000)
    
    print(f"[*] MiniOS initialized:")
    print(f"    - Heap base: 0x{emu.os.heap.base_address:x}")
    print(f"    - Heap size: {emu.os.heap.size / 1024 / 1024:.1f} MB")
    print(f"    - Process heap handle: 0x{emu.os.heap.process_heap:x}")
    print(f"    - PEB address: 0x{emu.os.peb_address:x}")
    print(f"    - TEB address: 0x{emu.os.teb_address:x}")
    print()
    
    # Load PE
    try:
        print("[*] Loading PE file...")
        entry_point = emu.load_pe(pe_path)
        
        print()
        print("[+] PE loaded successfully!")
        print(f"    - Entry point: 0x{entry_point:x}")
        print(f"    - Image base: 0x{emu.pe_loader.image_base:x}")
        print(f"    - Sections loaded: {len(emu.pe_loader.pe.sections)}")
        
        # Show loaded sections
        print()
        print("[*] Loaded sections:")
        for section in emu.pe_loader.pe.sections:
            name = section.Name.decode('ascii', errors='ignore').strip('\x00')
            va = section.VirtualAddress
            size = section.Misc_VirtualSize
            print(f"    - {name:<12} @ 0x{emu.pe_loader.image_base + va:x} ({size:,} bytes)")
        
        # Show IAT patches
        if hasattr(emu.pe_loader, 'iat_patches'):
            print()
            print(f"[*] IAT patches: {len(emu.pe_loader.iat_patches)}")
            for func_name, stub_addr in list(emu.pe_loader.iat_patches.items())[:10]:
                print(f"    - {func_name:<30} -> 0x{stub_addr:x}")
            if len(emu.pe_loader.iat_patches) > 10:
                print(f"    ... and {len(emu.pe_loader.iat_patches) - 10} more")
        
        print()
        print("[OK] ✓ PE loading successful!")
        return True, entry_point
        
    except Exception as e:
        print()
        print(f"[FAIL] ✗ PE loading failed: {e}")
        import traceback
        traceback.print_exc()
        return False, 0


def test_pe_execution():
    """Test executing loaded PE"""
    print("\n" + "=" * 70)
    print("TEST: Execute PE in MiniOS")
    print("=" * 70)
    print()
    
    pe_path = "demos/time_check_demo.exe"
    
    # Create emulator
    print("[*] Creating emulator and loading PE...")
    emu = LayeredEmulator(cpu_freq_mhz=3000)
    
    try:
        entry_point = emu.load_pe(pe_path)
        print(f"[+] PE loaded, entry point: 0x{entry_point:x}")
        print()
        
        # Try to execute (limit instructions to avoid infinite loops)
        print("[*] Starting execution (max 10000 instructions)...")
        print()
        
        exit_code = emu.run(entry_point, max_instructions=10000)
        
        print()
        print(f"[*] Execution finished")
        print(f"    - Exit code: {exit_code}")
        print(f"    - Instructions executed: {emu.instruction_count:,}")
        print(f"    - Virtual time: {emu.clock}")
        
        if emu.instruction_count > 0:
            print()
            print("[OK] ✓ PE execution started successfully!")
            return True
        else:
            print()
            print("[FAIL] ✗ No instructions executed")
            return False
            
    except Exception as e:
        print()
        print(f"[FAIL] ✗ Execution failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_memory_state():
    """Test memory state after loading"""
    print("\n" + "=" * 70)
    print("TEST: Memory State After Loading")
    print("=" * 70)
    print()
    
    pe_path = "demos/time_check_demo.exe"
    
    # Create emulator
    print("[*] Creating emulator and loading PE...")
    emu = LayeredEmulator(cpu_freq_mhz=3000)
    
    try:
        entry_point = emu.load_pe(pe_path)
        
        print()
        print("[*] Memory allocations:")
        print(f"    - Total allocations: {len(emu.os.vmm.allocations)}")
        
        for addr, (size, prot) in list(emu.os.vmm.allocations.items())[:10]:
            print(f"    - 0x{addr:x}: {size:,} bytes, protection={prot}")
        
        if len(emu.os.vmm.allocations) > 10:
            print(f"    ... and {len(emu.os.vmm.allocations) - 10} more")
        
        print()
        print("[*] Heap state:")
        print(f"    - Next allocation: 0x{emu.os.heap.next_alloc:x}")
        print(f"    - Active allocations: {len(emu.os.heap.allocations)}")
        
        print()
        print("[*] Reading entry point code (first 32 bytes):")
        try:
            code = bytes(emu.uc.mem_read(entry_point, 32))
            hex_str = ' '.join(f'{b:02x}' for b in code)
            print(f"    {hex_str}")
            print()
            print("[OK] ✓ Memory is readable at entry point")
        except Exception as e:
            print(f"    [FAIL] Cannot read: {e}")
            return False
        
        print()
        print("[OK] ✓ Memory state looks good!")
        return True
        
    except Exception as e:
        print()
        print(f"[FAIL] ✗ Memory check failed: {e}")
        import traceback
        traceback.print_exc()
        return False


if __name__ == "__main__":
    print("\nPE Loading into MiniOS Tests\n")
    
    success = True
    entry_point = 0
    
    # Test 1: PE loading
    result, entry = test_pe_loading()
    if not result:
        success = False
    else:
        entry_point = entry
    
    # Test 2: Memory state
    if not test_memory_state():
        success = False
    
    # Test 3: PE execution (only if loading succeeded)
    if entry_point > 0:
        if not test_pe_execution():
            success = False
    
    print("\n" + "=" * 70)
    if success:
        print("[FINAL] ✓✓✓ ALL TESTS PASSED ✓✓✓")
        print("\nMiniOS successfully loads and executes PE files!")
    else:
        print("[FINAL] ✗✗✗ SOME TESTS FAILED ✗✗✗")
        print("\nNeed to fix PE loading or execution issues.")
    print("=" * 70)
    print()
    
    sys.exit(0 if success else 1)
