#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Test: MiniOS layer - memory management and heap

Tests the minimal OS layer without full PE loading
"""

import sys
sys.path.insert(0, 'src/core')

from layered_emulator import LayeredEmulator


def test_heap_operations():
    """Test heap allocation/deallocation"""
    print("=" * 70)
    print("TEST: MiniOS Heap Operations")
    print("=" * 70)
    print()
    
    # Create emulator
    print("[*] Creating layered emulator with MiniOS...")
    emu = LayeredEmulator(cpu_freq_mhz=3000)
    
    # Test heap operations directly
    print("\n[*] Testing heap operations...")
    
    # Get process heap
    heap = emu.os.GetProcessHeap()
    print(f"[+] Process heap: 0x{heap:x}")
    
    # Allocate memory
    ptr1 = emu.os.HeapAlloc(heap, 0, 1024)
    print(f"[+] Allocated 1024 bytes at: 0x{ptr1:x}")
    
    # Write some data
    test_data = b"Hello from MiniOS!"
    emu.uc.mem_write(ptr1, test_data)
    print(f"[+] Wrote test data: {test_data}")
    
    # Read it back
    read_data = bytes(emu.uc.mem_read(ptr1, len(test_data)))
    print(f"[+] Read back: {read_data}")
    
    if read_data == test_data:
        print("[OK] ✓ Data integrity verified")
    else:
        print("[FAIL] ✗ Data mismatch!")
        return False
    
    # Allocate more memory
    ptr2 = emu.os.HeapAlloc(heap, 0, 2048)
    print(f"[+] Allocated 2048 bytes at: 0x{ptr2:x}")
    
    # Free first allocation
    result = emu.os.HeapFree(heap, 0, ptr1)
    print(f"[+] Freed ptr1: {result}")
    
    # Reallocate second pointer
    ptr3 = emu.os.HeapReAlloc(heap, 0, ptr2, 4096)
    print(f"[+] Reallocated ptr2 to 4096 bytes at: 0x{ptr3:x}")
    
    print("\n[OK] ✓ All heap operations successful!")
    return True


def test_virtual_memory():
    """Test virtual memory management"""
    print("\n" + "=" * 70)
    print("TEST: MiniOS Virtual Memory")
    print("=" * 70)
    print()
    
    # Create emulator
    print("[*] Creating layered emulator with MiniOS...")
    emu = LayeredEmulator(cpu_freq_mhz=3000)
    
    # Test virtual memory operations
    print("\n[*] Testing virtual memory operations...")
    
    # Allocate virtual memory
    addr = emu.os.VirtualAlloc(0, 0x10000, 0x1000, 0x04)  # MEM_COMMIT, PAGE_READWRITE
    print(f"[+] VirtualAlloc: 0x{addr:x}")
    
    # Write data
    test_data = b"Virtual memory test" * 100
    emu.uc.mem_write(addr, test_data)
    print(f"[+] Wrote {len(test_data)} bytes")
    
    # Read back
    read_data = bytes(emu.uc.mem_read(addr, len(test_data)))
    if read_data == test_data:
        print("[OK] ✓ Virtual memory read/write works")
    else:
        print("[FAIL] ✗ Data mismatch!")
        return False
    
    # Query memory info
    info = emu.os.VirtualQuery(addr)
    if info:
        print(f"[+] VirtualQuery: base=0x{info[0]:x}, size={info[1]}, protection={info[2]}")
    
    # Free virtual memory
    result = emu.os.VirtualFree(addr, 0, 0x8000)  # MEM_RELEASE
    print(f"[+] VirtualFree: {result}")
    
    print("\n[OK] ✓ All virtual memory operations successful!")
    return True


def test_machine_code_with_heap():
    """Test machine code that uses heap allocation"""
    print("\n" + "=" * 70)
    print("TEST: Machine Code with Heap Allocation")
    print("=" * 70)
    print()
    
    # Machine code that calls GetProcessHeap and HeapAlloc
    # This is a simplified test - in real PE, these would be IAT calls
    code = bytes([
        # Call GetProcessHeap stub
        0x48, 0xB8, 0x00, 0xF0, 0xFF, 0x7F, 0x00, 0x00, 0x00, 0x00,  # mov rax, STUB_ADDR
        0xFF, 0xD0,  # call rax
        0x48, 0x89, 0xC3,  # mov rbx, rax (save heap handle)
        
        # Call HeapAlloc(heap, 0, 1024)
        0x48, 0x89, 0xD9,  # mov rcx, rbx (heap handle)
        0x48, 0x31, 0xD2,  # xor rdx, rdx (flags = 0)
        0x49, 0xC7, 0xC0, 0x00, 0x04, 0x00, 0x00,  # mov r8, 1024
        0x48, 0xB8, 0x00, 0xF1, 0xFF, 0x7F, 0x00, 0x00, 0x00, 0x00,  # mov rax, STUB_ADDR+0x100
        0xFF, 0xD0,  # call rax
        
        # Return (RAX contains allocated pointer)
        0xC3,  # ret
    ])
    
    print(f"[*] Machine code size: {len(code)} bytes")
    print()
    
    # Create emulator
    print("[*] Creating layered emulator...")
    emu = LayeredEmulator(cpu_freq_mhz=3000)
    
    # Patch stub addresses in code
    stub_get_heap = emu.winapi.get_stub_address('GetProcessHeap')
    stub_heap_alloc = emu.winapi.get_stub_address('HeapAlloc')
    
    print(f"[*] GetProcessHeap stub: 0x{stub_get_heap:x}")
    print(f"[*] HeapAlloc stub: 0x{stub_heap_alloc:x}")
    
    # Load code
    base_addr = emu.load_code(code)
    
    # Patch addresses in code
    emu.uc.mem_write(base_addr + 2, stub_get_heap.to_bytes(8, 'little'))
    emu.uc.mem_write(base_addr + 29, stub_heap_alloc.to_bytes(8, 'little'))
    
    print()
    
    # Run
    print("[*] Running emulation...")
    result = emu.run(base_addr, max_instructions=1000)
    
    print()
    print("=" * 70)
    print(f"[*] Result (allocated pointer): 0x{result:x}")
    
    if result > 0:
        print("[OK] ✓ Heap allocation through stubs works!")
        return True
    else:
        print("[FAIL] ✗ Heap allocation failed")
        return False


if __name__ == "__main__":
    print("\nMiniOS Layer Tests\n")
    
    success = True
    
    # Test 1: Heap operations
    if not test_heap_operations():
        success = False
    
    # Test 2: Virtual memory
    if not test_virtual_memory():
        success = False
    
    # Test 3: Machine code with heap
    if not test_machine_code_with_heap():
        success = False
    
    print("\n" + "=" * 70)
    if success:
        print("[FINAL] ✓✓✓ ALL TESTS PASSED ✓✓✓")
    else:
        print("[FINAL] ✗✗✗ SOME TESTS FAILED ✗✗✗")
    print("=" * 70)
    print()
    
    sys.exit(0 if success else 1)
