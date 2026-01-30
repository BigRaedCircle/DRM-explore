#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Log all API calls before exception
"""

import sys
sys.path.insert(0, 'src/core')

from layered_emulator import LayeredEmulator
from collections import deque


def test_cpuz_api_log():
    """Log all API calls"""
    print("=" * 70)
    print("CPU-Z: API CALL LOG")
    print("=" * 70)
    
    cpuz_path = "sandbox/CPU-Z/cpuz.exe"
    
    emu = LayeredEmulator(cpu_freq_mhz=3000)
    
    # Patch GetCommandLineW
    def patched_get_command_line_w():
        cmd_line = "cpuz.exe -txt=report\x00".encode('utf-16le')
        ptr = emu.os.HeapAlloc(emu.os.heap.process_heap, 0, len(cmd_line))
        emu.uc.mem_write(ptr, cmd_line)
        emu.uc.reg_write(emu.uc.arch_const.UC_X86_REG_RAX, ptr)
        return ptr
    
    emu.winapi._stub_get_command_line_w = patched_get_command_line_w
    
    # Track last 50 API calls
    api_log = deque(maxlen=50)
    
    # Wrap handle_stub_call to log all calls
    original_handle_stub_call = emu.winapi.handle_stub_call
    
    def logged_handle_stub_call(address):
        # Find function name
        func_name = "Unknown"
        for name, stub_info in emu.winapi.stubs.items():
            if stub_info['address'] == address:
                func_name = name
                break
        
        # Check if it's a dummy stub
        if func_name == "Unknown" and hasattr(emu.pe_loader, '_dummy_stub_names'):
            if address in emu.pe_loader._dummy_stub_names:
                func_name = f"[DUMMY] {emu.pe_loader._dummy_stub_names[address]}"
        
        api_log.append({
            'name': func_name,
            'address': address,
            'insn_count': emu.instruction_count
        })
        
        return original_handle_stub_call(address)
    
    emu.winapi.handle_stub_call = logged_handle_stub_call
    
    # Load PE
    entry_point = emu.load_pe(cpuz_path)
    
    print(f"\n[*] Running...")
    
    try:
        emu.run(
            start_addr=entry_point,
            end_addr=0,
            max_instructions=100000,
            verbose=False
        )
    except Exception as e:
        print(f"\n[!] Stopped: {e}")
    
    print(f"\n[*] Execution stopped at instruction #{emu.instruction_count}")
    
    # Show last API calls
    print(f"\n[*] Last 50 API calls before stop:")
    print("-" * 70)
    for i, call in enumerate(api_log):
        marker = ">>>" if i == len(api_log) - 1 else "   "
        print(f"{marker} #{call['insn_count']:6d}  {call['name']:40} @ 0x{call['address']:x}")
    print("-" * 70)


if __name__ == "__main__":
    test_cpuz_api_log()
