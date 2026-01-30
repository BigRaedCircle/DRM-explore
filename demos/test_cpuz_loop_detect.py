#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Detect infinite loops in CPU-Z execution
"""

import sys
import os
sys.path.insert(0, 'src/core')

from layered_emulator import LayeredEmulator
from collections import deque


def test_cpuz_loop_detection():
    """Detect infinite loops"""
    print("=" * 70)
    print("CPU-Z: LOOP DETECTION")
    print("=" * 70)
    
    # Change to CPU-Z directory
    os.chdir("sandbox/CPU-Z")
    
    cpuz_path = "cpuz.exe"
    
    emu = LayeredEmulator(cpu_freq_mhz=3000)
    
    # Patch GetCommandLineW
    def patched_get_command_line_w():
        cmd_line = "cpuz.exe -txt=report\x00".encode('utf-16le')
        ptr = emu.os.HeapAlloc(emu.os.heap.process_heap, 0, len(cmd_line))
        emu.uc.mem_write(ptr, cmd_line)
        emu.uc.reg_write(emu.uc.arch_const.UC_X86_REG_RAX, ptr)
        return ptr
    
    emu.winapi._stub_get_command_line_w = patched_get_command_line_w
    
    # Track instruction addresses to detect loops
    address_history = deque(maxlen=1000)
    loop_detected = False
    loop_start_insn = 0
    
    # Hook code execution
    def code_hook(uc, address, size, user_data):
        nonlocal loop_detected, loop_start_insn
        
        address_history.append(address)
        
        # Check for loops every 1000 instructions
        if len(address_history) == 1000:
            # Count address frequencies
            addr_counts = {}
            for addr in address_history:
                addr_counts[addr] = addr_counts.get(addr, 0) + 1
            
            # Find most frequent address
            max_count = max(addr_counts.values())
            max_addr = [addr for addr, count in addr_counts.items() if count == max_count][0]
            
            # If an address appears more than 50% of the time, it's a loop
            if max_count > 500:
                if not loop_detected:
                    loop_detected = True
                    loop_start_insn = emu.instruction_count
                    print(f"\n[!] LOOP DETECTED at instruction #{emu.instruction_count}")
                    print(f"[!] Address 0x{max_addr:x} executed {max_count} times in last 1000 instructions")
                    print(f"[!] This is likely an infinite loop or busy-wait")
                    
                    # Show what's happening
                    print(f"\n[*] Stopping to analyze...")
                    uc.emu_stop()
    
    from unicorn import UC_HOOK_CODE
    emu.uc.hook_add(UC_HOOK_CODE, code_hook)
    
    # Load PE
    entry_point = emu.load_pe(cpuz_path)
    
    print(f"\n[*] Running with loop detection...")
    
    try:
        emu.run(
            start_addr=entry_point,
            end_addr=0,
            max_instructions=100000,  # Reduced for faster detection
            verbose=False
        )
    except Exception as e:
        print(f"\n[!] Stopped: {e}")
    
    print(f"\n[*] Execution stopped at instruction #{emu.instruction_count}")
    
    if loop_detected:
        print(f"\n[!] INFINITE LOOP CONFIRMED")
        print(f"[!] Loop started around instruction #{loop_start_insn}")
        print(f"\n[*] Possible causes:")
        print(f"    1. CPU-Z is waiting for a GUI event that never comes")
        print(f"    2. CPU-Z is polling for hardware that doesn't exist")
        print(f"    3. CPU-Z is stuck in error handling loop")
        print(f"    4. Missing critical API stub")
        
        # Show most frequent addresses
        addr_counts = {}
        for addr in address_history:
            addr_counts[addr] = addr_counts.get(addr, 0) + 1
        
        print(f"\n[*] Most frequent addresses in loop:")
        sorted_addrs = sorted(addr_counts.items(), key=lambda x: x[1], reverse=True)
        for addr, count in sorted_addrs[:10]:
            print(f"    0x{addr:016x}: {count} times ({count*100//1000}%)")
    
    # Return to original directory
    os.chdir("../..")


if __name__ == "__main__":
    test_cpuz_loop_detection()
