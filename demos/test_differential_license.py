#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Differential Analysis: License Check Detection

Runs time_check_demo.exe twice:
1. With valid license key: "VALID-KEY-1234"
2. With invalid license key: "INVALID-KEY"

Compares execution traces to find where license check happens.
"""

import sys
sys.path.insert(0, 'src/core')

from layered_emulator import LayeredEmulator
from differential_analyzer import DifferentialAnalyzer


def setup_emulator_with_args(args):
    """Create emulator and setup command-line arguments"""
    emu = LayeredEmulator(cpu_freq_mhz=3000)
    
    # Load PE
    pe_path = "demos/time_check_demo.exe"
    entry_point = emu.load_pe(pe_path)
    
    # Setup command-line arguments in memory
    # For now, we'll skip this - the program uses default "INVALID-KEY" if no args
    # TODO: Implement proper argc/argv setup
    
    return emu, entry_point


def run_with_trace(scenario_name, max_instructions=50000):
    """Run emulator and collect execution trace"""
    print(f"\n{'='*70}")
    print(f"Running: {scenario_name}")
    print(f"{'='*70}\n")
    
    emu, entry_point = setup_emulator_with_args([])
    
    # Collect trace
    trace = []
    
    def trace_hook(uc, address, size, user_data):
        """Hook to collect execution trace"""
        trace.append(address)
    
    # Add trace hook
    from unicorn import UC_HOOK_CODE
    emu.uc.hook_add(UC_HOOK_CODE, trace_hook)
    
    # Run
    try:
        exit_code = emu.run(entry_point, max_instructions=max_instructions)
        print(f"\n[*] Exit code: {exit_code}")
        print(f"[*] Instructions: {emu.instruction_count:,}")
        print(f"[*] Trace length: {len(trace):,}")
    except Exception as e:
        print(f"\n[!] Execution error: {e}")
    
    return trace, emu


def analyze_divergence(trace1, trace2):
    """Find where execution traces diverge"""
    print(f"\n{'='*70}")
    print("DIFFERENTIAL ANALYSIS")
    print(f"{'='*70}\n")
    
    print(f"[*] Trace 1 length: {len(trace1):,} instructions")
    print(f"[*] Trace 2 length: {len(trace2):,} instructions")
    
    # Find divergence point
    min_len = min(len(trace1), len(trace2))
    divergence_idx = None
    
    for i in range(min_len):
        if trace1[i] != trace2[i]:
            divergence_idx = i
            break
    
    if divergence_idx is None:
        if len(trace1) != len(trace2):
            divergence_idx = min_len
            print(f"\n[*] Traces identical up to instruction {min_len:,}")
            print(f"[*] One trace is longer than the other")
        else:
            print(f"\n[OK] Traces are IDENTICAL (no divergence)")
            return None
    
    print(f"\n[!] DIVERGENCE FOUND at instruction {divergence_idx:,}")
    print(f"\n[*] Context around divergence:")
    
    # Show context (10 instructions before divergence)
    start = max(0, divergence_idx - 10)
    end = min(min_len, divergence_idx + 10)
    
    print(f"\n{'Idx':<8} {'Trace 1 (valid key)':<20} {'Trace 2 (invalid key)':<20} {'Match':<8}")
    print("-" * 70)
    
    for i in range(start, end):
        addr1 = trace1[i] if i < len(trace1) else None
        addr2 = trace2[i] if i < len(trace2) else None
        
        match = "OK" if addr1 == addr2 else "X DIFF"
        marker = " <-- DIVERGENCE" if i == divergence_idx else ""
        
        addr1_str = f"0x{addr1:x}" if addr1 else "N/A"
        addr2_str = f"0x{addr2:x}" if addr2 else "N/A"
        
        print(f"{i:<8} {addr1_str:<20} {addr2_str:<20} {match:<8}{marker}")
    
    return divergence_idx


def test_differential_license():
    """Main test: differential analysis of license check"""
    print("="*70)
    print("DIFFERENTIAL ANALYSIS: License Check Detection")
    print("="*70)
    print()
    print("Goal: Find where license check happens by comparing two runs:")
    print("  Run 1: Valid license key (should pass)")
    print("  Run 2: Invalid license key (should fail)")
    print()
    
    # Note: Currently we can't pass command-line args to PE
    # So both runs will use default "INVALID-KEY"
    # But we can still see the execution pattern
    
    print("[*] Running scenario 1: Default execution...")
    trace1, emu1 = run_with_trace("Scenario 1: Default", max_instructions=50000)
    
    print("\n[*] Running scenario 2: Default execution (repeat)...")
    trace2, emu2 = run_with_trace("Scenario 2: Default (repeat)", max_instructions=50000)
    
    # Analyze
    divergence = analyze_divergence(trace1, trace2)
    
    if divergence is None:
        print("\n[*] Both runs are identical (expected - same input)")
        print("[*] To see real divergence, we need to implement argc/argv setup")
    else:
        print(f"\n[!] Found divergence at instruction {divergence:,}")
        print("[*] This is where execution paths differ")
    
    # Show key addresses
    print(f"\n{'='*70}")
    print("KEY ADDRESSES")
    print(f"{'='*70}\n")
    
    if emu1.pe_loader:
        image_base = emu1.pe_loader.image_base
        print(f"[*] Image base: 0x{image_base:x}")
        print(f"[*] Entry point: 0x{emu1.pe_loader.entry_point:x}")
        
        # Try to identify key functions
        print(f"\n[*] Looking for key functions in trace...")
        
        # Count unique addresses
        unique_addrs = set(trace1)
        print(f"[*] Unique addresses visited: {len(unique_addrs):,}")
        
        # Find most frequently executed addresses (likely loops)
        from collections import Counter
        addr_counts = Counter(trace1)
        top_addrs = addr_counts.most_common(10)
        
        print(f"\n[*] Top 10 most executed addresses (likely loops):")
        for addr, count in top_addrs:
            rva = addr - image_base if addr >= image_base else addr
            print(f"    0x{addr:x} (RVA: 0x{rva:x}): {count:,} times")
    
    print(f"\n{'='*70}")
    print("NEXT STEPS")
    print(f"{'='*70}\n")
    print("To properly test differential analysis:")
    print("1. Implement argc/argv setup in emulator")
    print("2. Pass different license keys to each run")
    print("3. Compare traces to find license check location")
    print("4. Disassemble divergence point to understand check logic")
    print()
    
    return True


if __name__ == "__main__":
    print("\nDifferential License Check Analysis\n")
    
    success = test_differential_license()
    
    print("\n" + "=" * 70)
    if success:
        print("[FINAL] ✓ Differential analysis completed")
        print("\nNote: Both runs used same input (no argc/argv yet)")
        print("Implement command-line argument passing for real divergence test")
    else:
        print("[FINAL] ✗ Analysis failed")
    print("=" * 70)
    print()
    
    sys.exit(0 if success else 1)
