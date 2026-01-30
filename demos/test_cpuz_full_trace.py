#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Full trace of CPU-Z execution with focus on file operations
"""

import sys
sys.path.insert(0, 'src/core')

from layered_emulator import LayeredEmulator


def test_cpuz_full_trace():
    """Full trace with file operation focus"""
    print("=" * 70)
    print("CPU-Z: FULL TRACE (File Operations Focus)")
    print("=" * 70)
    
    cpuz_path = "sandbox/CPU-Z/cpuz.exe"
    
    print(f"\n[*] Loading: {cpuz_path}")
    
    emu = LayeredEmulator(cpu_freq_mhz=3000)
    
    # Patch GetCommandLineW
    def patched_get_command_line_w():
        cmd_line = "cpuz.exe -txt=report\x00".encode('utf-16le')
        ptr = emu.os.HeapAlloc(emu.os.heap.process_heap, 0, len(cmd_line))
        emu.uc.mem_write(ptr, cmd_line)
        emu.uc.reg_write(emu.uc.arch_const.UC_X86_REG_RAX, ptr)
        print(f"[API] GetCommandLineW() -> \"cpuz.exe -txt=report\"")
        return ptr
    
    emu.winapi._stub_get_command_line_w = patched_get_command_line_w
    
    # Track API calls
    api_calls = []
    
    # Wrap all file I/O stubs to track calls
    original_create_file_a = emu.winapi._stub_create_file_a
    original_create_file_w = emu.winapi._stub_create_file_w
    original_write_file = emu.winapi._stub_write_file
    original_read_file = emu.winapi._stub_read_file
    original_close_handle = emu.winapi._stub_close_handle
    
    def tracked_create_file_a():
        api_calls.append(('CreateFileA', emu.instruction_count))
        return original_create_file_a()
    
    def tracked_create_file_w():
        api_calls.append(('CreateFileW', emu.instruction_count))
        return original_create_file_w()
    
    def tracked_write_file():
        api_calls.append(('WriteFile', emu.instruction_count))
        return original_write_file()
    
    def tracked_read_file():
        api_calls.append(('ReadFile', emu.instruction_count))
        return original_read_file()
    
    def tracked_close_handle():
        api_calls.append(('CloseHandle', emu.instruction_count))
        return original_close_handle()
    
    emu.winapi._stub_create_file_a = tracked_create_file_a
    emu.winapi._stub_create_file_w = tracked_create_file_w
    emu.winapi._stub_write_file = tracked_write_file
    emu.winapi._stub_read_file = tracked_read_file
    emu.winapi._stub_close_handle = tracked_close_handle
    
    # Load PE
    entry_point = emu.load_pe(cpuz_path)
    
    print(f"\n[*] Running with max 1,000,000 instructions...")
    
    try:
        emu.run(
            start_addr=entry_point,
            end_addr=0,
            max_instructions=1000000,
            verbose=False
        )
    except Exception as e:
        print(f"\n[!] Stopped: {e}")
    
    print(f"\n[*] Execution stopped at instruction #{emu.instruction_count}")
    
    # Show file I/O calls
    print(f"\n[*] File I/O API calls:")
    if api_calls:
        for func, insn_count in api_calls:
            print(f"    #{insn_count:6d}: {func}")
    else:
        print(f"    No file I/O calls detected!")
    
    # Check if report.txt was created
    import os
    if os.path.exists("report.txt"):
        size = os.path.getsize("report.txt")
        print(f"\n[✓] report.txt created! Size: {size} bytes")
        if size > 0:
            with open("report.txt", "r", encoding="utf-8", errors="ignore") as f:
                content = f.read(500)
                print(f"\n[*] First 500 bytes:")
                print(content)
    else:
        print(f"\n[✗] report.txt NOT created")


if __name__ == "__main__":
    test_cpuz_full_trace()
