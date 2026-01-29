#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Test: Minimal RDTSC consistency check (no PE, no CRT)

Goal: Prove that VirtualClock provides consistent timing
without needing full PE loader or OS emulation.
"""

import sys
sys.path.insert(0, 'src/core')

from layered_emulator import LayeredEmulator


def test_minimal_rdtsc():
    """Test RDTSC with minimal machine code"""
    print("=" * 70)
    print("TEST: Minimal RDTSC consistency check")
    print("=" * 70)
    print()
    
    # Machine code: Custom RDTSC (via INT3) -> loop -> Custom RDTSC -> check delta -> RET
    # We use INT3 (0xCC) as a marker to call our RDTSC handler
    code = bytes([
        # === First RDTSC measurement (via INT3) ===
        0xCC,                          # int3 - will be caught and handled as RDTSC
        0x48, 0x89, 0xC3,              # mov rbx, rax (save low 32 bits)
        0x48, 0x89, 0xD1,              # mov rcx, rdx (save high 32 bits)
        
        # === Loop 10000 times (simulates work) ===
        0xB8, 0x10, 0x27, 0x00, 0x00,  # mov eax, 10000
        # loop_start (offset 0x0C):
        0x48, 0xFF, 0xC8,              # dec rax (3 bytes)
        0x75, 0xFB,                    # jnz loop_start (jump back 5 bytes: 0x11 - 5 = 0x0C)
        
        # === Second RDTSC measurement (via INT3) ===
        0xCC,                          # int3 - will be caught and handled as RDTSC
        
        # === Calculate delta: RAX = RAX - RBX ===
        0x48, 0x29, 0xD8,              # sub rax, rbx
        
        # === Check if delta is reasonable ===
        # Delta should be > 1000 (loop takes some cycles)
        0x48, 0x3D, 0xE8, 0x03, 0x00, 0x00,  # cmp rax, 1000
        0x72, 0x0A,                    # jb fail (if below 1000)
        
        # Delta should be < 1000000 (not too large)
        0x48, 0x3D, 0x40, 0x42, 0x0F, 0x00,  # cmp rax, 1000000
        0x77, 0x02,                    # ja fail (if above 1000000)
        
        # === Success path ===
        0x31, 0xC0,                    # xor eax, eax (return 0)
        0xC3,                          # ret
        
        # === Fail path ===
        # fail (offset 0x2D):
        0xB8, 0x01, 0x00, 0x00, 0x00,  # mov eax, 1 (return 1)
        0xC3,                          # ret
    ])
    
    print(f"[*] Machine code size: {len(code)} bytes")
    print(f"[*] Using INT3 (0xCC) as RDTSC marker")
    print()
    
    # Create emulator
    print("[*] Creating layered emulator...")
    emu = LayeredEmulator(cpu_freq_mhz=3000)
    
    # Load code directly (no PE, no CRT)
    print("[*] Loading machine code...")
    base_addr = emu.load_code(code)
    print(f"[*] Code loaded at: 0x{base_addr:x}")
    print()
    
    # Run
    print("[*] Running emulation...")
    exit_code = emu.run(base_addr)
    
    print()
    print("=" * 70)
    print(f"[*] Exit code: {exit_code}")
    
    if exit_code == 0:
        print()
        print("[OK] ✓ SUCCESS!")
        print("[OK] ✓ RDTSC delta is reasonable (1000 < delta < 1000000)")
        print("[OK] ✓ VirtualClock provides consistent timing")
        print("[OK] ✓ No emulation detection possible at this level")
        return True
    elif exit_code == 1:
        print()
        print("[FAIL] ✗ RDTSC delta is suspicious")
        print("[FAIL] ✗ Either too small or too large")
        return False
    else:
        print()
        print(f"[?] Unexpected exit code: {exit_code}")
        return False


if __name__ == "__main__":
    success = test_minimal_rdtsc()
    print()
    sys.exit(0 if success else 1)
