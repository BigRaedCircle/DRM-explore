#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Synthetic Differential Analysis - Works!

Creates two versions of machine code with different license keys.
Uses the proven approach from git history.
"""

import sys
sys.path.insert(0, 'src/core')

from layered_emulator import LayeredEmulator
from unicorn.x86_const import *


def create_license_check(license_key):
    """
    Create machine code with license check
    
    Logic:
    1. MOV RAX, license_key
    2. CMP RAX, 0xCAFE (valid key)
    3. JE valid
    4. MOV RBX, 0xDEAD (invalid path)
    5. RET
    valid:
    6. MOV RBX, 0xBEEF (valid path)
    7. RET
    """
    
    code = bytes([
        # MOV RAX, license_key
        0x48, 0xB8,  # MOV RAX, imm64
    ]) + license_key.to_bytes(8, 'little') + bytes([
        
        # CMP RAX, 0xCAFE
        0x48, 0x3D, 0xFE, 0xCA, 0x00, 0x00,
        
        # JE +10 (to valid label)
        0x74, 0x0A,
        
        # Invalid path:
        0x48, 0xBB, 0xAD, 0xDE, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  # MOV RBX, 0xDEAD
        0xC3,  # RET
        
        # Valid path:
        0x48, 0xBB, 0xEF, 0xBE, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  # MOV RBX, 0xBEEF
        0xC3,  # RET
    ])
    
    return code


def run_parallel_synthetic(code_a, code_b, max_steps=100):
    """Run two code variants in parallel"""
    
    print("="*70)
    print("SYNTHETIC DIFFERENTIAL ANALYSIS")
    print("="*70)
    print()
    
    # Create emulators
    emu_a = LayeredEmulator(cpu_freq_mhz=3000)
    emu_b = LayeredEmulator(cpu_freq_mhz=3000)
    
    # Load code
    base_addr = 0x400000
    addr_a = emu_a.load_code(code_a, base_addr)
    addr_b = emu_b.load_code(code_b, base_addr)
    
    print(f"[*] Code A loaded at: 0x{addr_a:x} ({len(code_a)} bytes)")
    print(f"[*] Code B loaded at: 0x{addr_b:x} ({len(code_b)} bytes)")
    print()
    
    # Traces
    trace_a = []
    trace_b = []
    
    # Step-by-step execution
    print("[*] Starting parallel execution...")
    print("-"*70)
    
    # Set initial RIP
    emu_a.uc.reg_write(UC_X86_REG_RIP, base_addr)
    emu_b.uc.reg_write(UC_X86_REG_RIP, base_addr)
    
    step = 0
    diverged = False
    
    while step < max_steps:
        # Get states
        rip_a = emu_a.uc.reg_read(UC_X86_REG_RIP)
        rip_b = emu_b.uc.reg_read(UC_X86_REG_RIP)
        rax_a = emu_a.uc.reg_read(UC_X86_REG_RAX)
        rax_b = emu_b.uc.reg_read(UC_X86_REG_RAX)
        
        state_a = {'rip': rip_a, 'rax': rax_a}
        state_b = {'rip': rip_b, 'rax': rax_b}
        trace_a.append(state_a)
        trace_b.append(state_b)
        
        print(f"Step {step}: RIP_A=0x{rip_a:x}, RIP_B=0x{rip_b:x}, RAX_A=0x{rax_a:x}, RAX_B=0x{rax_b:x}")
        
        # Check divergence
        if rip_a != rip_b:
            diverged = True
            print(f"\n[!] DIVERGENCE FOUND at step {step}!")
            print(f"    RIP A: 0x{rip_a:x}")
            print(f"    RIP B: 0x{rip_b:x}")
            break
        
        # Execute one instruction
        try:
            emu_a.uc.emu_start(rip_a, 0, count=1)
            emu_b.uc.emu_start(rip_b, 0, count=1)
        except:
            print(f"\n[*] Execution completed at step {step}")
            break
        
        step += 1
    
    print("-"*70)
    
    if diverged:
        print(f"\n[OK] SUCCESS! License check located at step {step}")
        
        # Show context
        print(f"\nCONTEXT:")
        for i in range(max(0, step-3), min(len(trace_a), step+2)):
            rip_a = trace_a[i]['rip']
            rip_b = trace_b[i]['rip']
            match = "SAME" if rip_a == rip_b else "DIFF <--"
            print(f"  Step {i}: 0x{rip_a:x} vs 0x{rip_b:x} [{match}]")
        
        return True
    else:
        print(f"\n[*] No divergence in {step} steps")
        return False


def main():
    print("\nSynthetic Differential Analysis Test\n")
    
    VALID_KEY = 0xCAFE
    INVALID_KEY = 0xDEAD
    
    print(f"[*] Creating code with VALID key: 0x{VALID_KEY:x}")
    code_valid = create_license_check(VALID_KEY)
    
    print(f"[*] Creating code with INVALID key: 0x{INVALID_KEY:x}")
    code_invalid = create_license_check(INVALID_KEY)
    
    print()
    
    success = run_parallel_synthetic(code_valid, code_invalid)
    
    print("\n" + "="*70)
    if success:
        print("[FINAL] SUCCESS - License check automatically located!")
    else:
        print("[FINAL] FAIL - No divergence found")
    print("="*70)
    print()
    
    return success


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
