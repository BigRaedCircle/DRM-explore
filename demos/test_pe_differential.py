#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PE Differential Analysis - Step-by-step comparison

Loads two PE files and compares execution step-by-step
to find where they diverge (license check location).
"""

import sys
sys.path.insert(0, 'src/core')

from layered_emulator import LayeredEmulator
from unicorn.x86_const import *


def run_parallel_comparison(pe_path_a, pe_path_b, max_minutes=3):
    """Run two PE files in parallel and compare step-by-step"""
    
    import time
    
    print("="*70)
    print("PE DIFFERENTIAL ANALYSIS")
    print("="*70)
    print(f"\nPE A: {pe_path_a}")
    print(f"PE B: {pe_path_b}")
    print(f"Max time: {max_minutes} minutes\n")
    
    # Create two emulators
    print("[*] Creating emulator A...")
    emu_a = LayeredEmulator(cpu_freq_mhz=3000)
    entry_a = emu_a.load_pe(pe_path_a)
    
    print("\n[*] Creating emulator B...")
    emu_b = LayeredEmulator(cpu_freq_mhz=3000)
    entry_b = emu_b.load_pe(pe_path_b)
    
    print(f"\n[*] Entry A: 0x{entry_a:x}")
    print(f"[*] Entry B: 0x{entry_b:x}")
    
    if entry_a != entry_b:
        print("[!] WARNING: Entry points differ!")
    
    # Traces
    trace_a = []
    trace_b = []
    
    # Step-by-step execution
    print(f"\n[*] Starting parallel execution...")
    print("-"*70)
    
    start_time = time.time()
    max_seconds = max_minutes * 60
    
    step = 0
    diverged = False
    divergence_step = None
    
    while True:
        # Check timeout
        elapsed = time.time() - start_time
        if elapsed > max_seconds:
            print(f"\n[*] Timeout reached ({max_minutes} minutes)")
            break
        
        # Get current states
        rip_a = emu_a.uc.reg_read(UC_X86_REG_RIP)
        rip_b = emu_b.uc.reg_read(UC_X86_REG_RIP)
        
        rax_a = emu_a.uc.reg_read(UC_X86_REG_RAX)
        rax_b = emu_b.uc.reg_read(UC_X86_REG_RAX)
        
        # READ INSTRUCTION BYTES - this is the key!
        # Compare what instruction is ABOUT TO BE EXECUTED
        try:
            instr_a = bytes(emu_a.uc.mem_read(rip_a, 15))  # Max x86-64 instruction length
            instr_b = bytes(emu_b.uc.mem_read(rip_b, 15))
        except:
            instr_a = b''
            instr_b = b''
        
        # Save to trace
        state_a = {'rip': rip_a, 'rax': rax_a, 'instr': instr_a}
        state_b = {'rip': rip_b, 'rax': rax_b, 'instr': instr_b}
        trace_a.append(state_a)
        trace_b.append(state_b)
        
        # CRITICAL: Compare instruction bytes FIRST
        # This catches divergence at the EXACT point where code differs
        # (e.g., MOV AL, 'V' vs MOV AL, 'X')
        if instr_a[:8] != instr_b[:8]:  # Compare first 8 bytes (enough for most instructions)
            diverged = True
            divergence_step = step
            print(f"\n[!] INSTRUCTION DIVERGENCE at step {step:,} ({elapsed:.1f}s)")
            print(f"    RIP: 0x{rip_a:x} (same address, different code!)")
            print(f"    Instruction A: {instr_a[:8].hex()}")
            print(f"    Instruction B: {instr_b[:8].hex()}")
            break
        
        # Check RIP divergence (different execution paths)
        if rip_a != rip_b:
            diverged = True
            divergence_step = step
            print(f"\n[!] EXECUTION PATH DIVERGENCE at step {step:,} ({elapsed:.1f}s)")
            print(f"    RIP A: 0x{rip_a:x}")
            print(f"    RIP B: 0x{rip_b:x}")
            break
        
        # Check for conditional branch with different flags
        if len(instr_a) >= 1 and 0x70 <= instr_a[0] <= 0x7F:
            # This is a conditional jump - check flags
            from unicorn.x86_const import UC_X86_REG_EFLAGS
            flags_a = emu_a.uc.reg_read(UC_X86_REG_EFLAGS)
            flags_b = emu_b.uc.reg_read(UC_X86_REG_EFLAGS)
            
            if flags_a != flags_b:
                diverged = True
                divergence_step = step
                print(f"\n[!] CONDITIONAL BRANCH DIVERGENCE at step {step:,} ({elapsed:.1f}s)")
                print(f"    Address: 0x{rip_a:x}")
                print(f"    Instruction: 0x{instr_a[0]:02x} (conditional jump)")
                print(f"    EFLAGS A: 0x{flags_a:x}")
                print(f"    EFLAGS B: 0x{flags_b:x}")
                break
        
        # Execute one instruction in each
        try:
            emu_a.uc.emu_start(rip_a, 0, count=1)
            emu_b.uc.emu_start(rip_b, 0, count=1)
        except Exception as e:
            print(f"\n[!] Execution stopped: {e}")
            break
        
        step += 1
        
        # Progress every 10k steps
        if step % 10000 == 0:
            print(f"[*] Step {step:,} ({elapsed:.1f}s) - states identical (RIP: 0x{rip_a:x})")
    
    print("-"*70)
    
    if diverged:
        print(f"\n[OK] Found divergence at step {divergence_step:,}!")
        analyze_divergence(trace_a, trace_b, divergence_step, emu_a, emu_b)
        return True
    else:
        print(f"\n[*] Executed {step:,} steps - no divergence found")
        return False


def analyze_divergence(trace_a, trace_b, step, emu_a, emu_b):
    """Analyze divergence point"""
    
    print("\n" + "="*70)
    print("DIVERGENCE ANALYSIS")
    print("="*70)
    
    state_a = trace_a[step]
    state_b = trace_b[step]
    
    print(f"\nStep: {step:,}")
    print(f"\nEMULATOR A:")
    print(f"  RIP: 0x{state_a['rip']:x}")
    print(f"  RAX: 0x{state_a['rax']:x}")
    print(f"  Instruction: {state_a['instr'][:8].hex()}")
    
    print(f"\nEMULATOR B:")
    print(f"  RIP: 0x{state_b['rip']:x}")
    print(f"  RAX: 0x{state_b['rax']:x}")
    print(f"  Instruction: {state_b['instr'][:8].hex()}")
    
    # Show context (previous 5 steps)
    print(f"\nCONTEXT (last 5 steps):")
    print(f"{'Step':<8} {'RIP A':<18} {'Instr A':<20} {'RIP B':<18} {'Instr B':<20} {'Match':<8}")
    print("-"*100)
    
    start = max(0, step - 5)
    for i in range(start, step + 1):
        rip_a = trace_a[i]['rip']
        rip_b = trace_b[i]['rip']
        instr_a = trace_a[i]['instr'][:4].hex()
        instr_b = trace_b[i]['instr'][:4].hex()
        match = "OK" if trace_a[i]['instr'][:8] == trace_b[i]['instr'][:8] else "X DIFF"
        marker = " <--" if i == step else ""
        print(f"{i:<8} 0x{rip_a:<16x} {instr_a:<20} 0x{rip_b:<16x} {instr_b:<20} {match:<8}{marker}")
    
    # Calculate RVA
    if emu_a.pe_loader:
        image_base = emu_a.pe_loader.image_base
        rva_a = state_a['rip'] - image_base
        rva_b = state_b['rip'] - image_base
        
        print(f"\nRVA (relative to image base 0x{image_base:x}):")
        print(f"  A: 0x{rva_a:x}")
        print(f"  B: 0x{rva_b:x}")
    
    print(f"\n[!] This is likely the LICENSE CHECK location!")


def main():
    import sys
    
    if len(sys.argv) >= 3:
        pe_a = sys.argv[1]
        pe_b = sys.argv[2]
        max_minutes = int(sys.argv[3]) if len(sys.argv) > 3 else 1
    else:
        # Default
        pe_a = "demos/asm_valid.exe"
        pe_b = "demos/asm_invalid.exe"
        max_minutes = 1
    
    print(f"\nComparing:")
    print(f"  A: {pe_a}")
    print(f"  B: {pe_b}")
    print(f"  Timeout: {max_minutes} min\n")
    
    success = run_parallel_comparison(pe_a, pe_b, max_minutes=max_minutes)
    
    print("\n" + "="*70)
    if success:
        print("[FINAL] SUCCESS - License check located!")
    else:
        print("[FINAL] No divergence found")
    print("="*70)
    print()
    
    return success


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
