#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Simplified Differential Analysis

Instead of passing argc/argv, we'll modify the license key string
directly in memory after loading PE but before execution.

This simulates two scenarios:
1. Valid license: "VALID-KEY-1234"
2. Invalid license: "INVALID-KEY"
"""

import sys
sys.path.insert(0, 'src/core')

from layered_emulator import LayeredEmulator


def find_string_in_memory(emu, search_str):
    """Find string in loaded PE memory"""
    search_bytes = search_str.encode('ascii')
    image_base = emu.pe_loader.image_base
    
    # Search in .rdata section (where strings usually are)
    for section in emu.pe_loader.pe.sections:
        name = section.Name.decode('ascii', errors='ignore').strip('\x00')
        if 'rdata' in name.lower() or 'data' in name.lower():
            va = section.VirtualAddress
            size = section.Misc_VirtualSize
            addr = image_base + va
            
            try:
                data = bytes(emu.uc.mem_read(addr, size))
                pos = data.find(search_bytes)
                if pos != -1:
                    return addr + pos
            except:
                pass
    
    return None


def run_scenario(scenario_name, license_key, max_instructions=200000):
    """Run one scenario with specific license key"""
    print(f"\n{'='*70}")
    print(f"SCENARIO: {scenario_name}")
    print(f"License key: {license_key}")
    print(f"{'='*70}\n")
    
    # Create emulator and load PE
    emu = LayeredEmulator(cpu_freq_mhz=3000)
    pe_path = "demos/time_check_demo.exe"
    entry_point = emu.load_pe(pe_path)
    
    # Try to patch license key in memory
    # Look for "INVALID-KEY" string and replace it
    default_key = "INVALID-KEY"
    key_addr = find_string_in_memory(emu, default_key)
    
    if key_addr:
        print(f"[*] Found default key at: 0x{key_addr:x}")
        # Patch with new key (pad to same length)
        new_key_bytes = license_key.encode('ascii').ljust(len(default_key), b'\x00')
        emu.uc.mem_write(key_addr, new_key_bytes)
        print(f"[*] Patched to: {license_key}")
    else:
        print(f"[*] Could not find default key in memory")
        print(f"[*] Will use default behavior")
    
    # Collect execution trace
    trace = []
    branch_points = []  # Track conditional branches
    
    def trace_hook(uc, address, size, user_data):
        trace.append(address)
        
        # Try to detect conditional branches
        try:
            code = bytes(uc.mem_read(address, min(size, 8)))
            # JZ, JNZ, JE, JNE, JG, JL, etc. (0x74-0x7F range)
            if len(code) >= 2 and code[0] in [0x74, 0x75, 0x7C, 0x7D, 0x7E, 0x7F]:
                branch_points.append((address, code[0]))
        except:
            pass
    
    # Add hooks
    from unicorn import UC_HOOK_CODE
    emu.uc.hook_add(UC_HOOK_CODE, trace_hook)
    
    # Run
    print(f"\n[*] Starting execution...")
    try:
        exit_code = emu.run(entry_point, max_instructions=max_instructions, verbose=False)
        print(f"\n[*] Execution finished")
        print(f"    Exit code: {exit_code}")
        print(f"    Instructions: {emu.instruction_count:,}")
        print(f"    Trace length: {len(trace):,}")
        print(f"    Branch points: {len(branch_points):,}")
        
        # Show last 10 addresses
        if len(trace) > 10:
            print(f"\n[*] Last 10 addresses in trace:")
            for addr in trace[-10:]:
                rva = addr - emu.pe_loader.image_base if emu.pe_loader else 0
                print(f"    0x{addr:x} (RVA: 0x{rva:x})")
    except Exception as e:
        print(f"\n[!] Execution error: {e}")
        import traceback
        traceback.print_exc()
    
    return trace, branch_points, emu


def compare_traces(trace1, trace2, name1, name2):
    """Compare two execution traces"""
    print(f"\n{'='*70}")
    print("TRACE COMPARISON")
    print(f"{'='*70}\n")
    
    print(f"[*] {name1}: {len(trace1):,} instructions")
    print(f"[*] {name2}: {len(trace2):,} instructions")
    
    # Find divergence
    min_len = min(len(trace1), len(trace2))
    divergence_idx = None
    
    for i in range(min_len):
        if trace1[i] != trace2[i]:
            divergence_idx = i
            break
    
    if divergence_idx is None:
        if len(trace1) == len(trace2):
            print(f"\n[*] Traces are IDENTICAL")
            return None
        else:
            divergence_idx = min_len
            print(f"\n[*] Traces identical up to {min_len:,}, then one ends")
    
    print(f"\n[!] DIVERGENCE at instruction {divergence_idx:,}")
    
    # Show context
    start = max(0, divergence_idx - 5)
    end = min(min_len, divergence_idx + 5)
    
    print(f"\n{'Idx':<10} {name1:<20} {name2:<20} {'Status':<10}")
    print("-" * 70)
    
    for i in range(start, end):
        addr1 = trace1[i] if i < len(trace1) else None
        addr2 = trace2[i] if i < len(trace2) else None
        
        addr1_str = f"0x{addr1:x}" if addr1 else "N/A"
        addr2_str = f"0x{addr2:x}" if addr2 else "N/A"
        
        if addr1 == addr2:
            status = "SAME"
        else:
            status = "DIFF <--" if i == divergence_idx else "DIFF"
        
        print(f"{i:<10} {addr1_str:<20} {addr2_str:<20} {status:<10}")
    
    return divergence_idx


def main():
    print("="*70)
    print("DIFFERENTIAL ANALYSIS: License Check Detection")
    print("="*70)
    print()
    print("Strategy: Patch license key string in memory before execution")
    print()
    
    # Run two scenarios
    trace1, branches1, emu1 = run_scenario(
        "Valid License", 
        "VALID-KEY-1234",
        max_instructions=50000
    )
    
    trace2, branches2, emu2 = run_scenario(
        "Invalid License",
        "WRONG-KEY-9999",
        max_instructions=50000
    )
    
    # Compare
    divergence = compare_traces(trace1, trace2, "Valid", "Invalid")
    
    if divergence:
        print(f"\n[!] License check likely happens around instruction {divergence:,}")
        print(f"[!] Address: 0x{trace1[divergence]:x}")
        
        # Calculate RVA
        if emu1.pe_loader:
            image_base = emu1.pe_loader.image_base
            rva = trace1[divergence] - image_base
            print(f"[!] RVA: 0x{rva:x}")
    else:
        print(f"\n[*] No divergence found")
        print(f"[*] Possible reasons:")
        print(f"    - License key not used in this execution path")
        print(f"    - Key comparison happens after max_instructions limit")
        print(f"    - Key patching didn't work")
    
    print(f"\n{'='*70}")
    print("SUMMARY")
    print(f"{'='*70}\n")
    print(f"Valid license trace:   {len(trace1):,} instructions")
    print(f"Invalid license trace: {len(trace2):,} instructions")
    print(f"Divergence point:      {divergence if divergence else 'None'}")
    print()
    
    return divergence is not None


if __name__ == "__main__":
    print("\nSimplified Differential Analysis\n")
    
    success = main()
    
    print("="*70)
    if success:
        print("[OK] Differential analysis found divergence!")
    else:
        print("[INFO] No divergence found (traces identical)")
    print("="*70)
    print()
    
    sys.exit(0)
