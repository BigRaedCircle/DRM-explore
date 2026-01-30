#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Debug why emulation stops after unmapped read
"""

import sys
sys.path.insert(0, 'src/core')

from layered_emulator import LayeredEmulator
from capstone import *


def test_why_stops():
    """Debug stop reason"""
    print("=" * 70)
    print("DEBUG: Why does emulation stop?")
    print("=" * 70)
    
    cpuz_path = "sandbox/CPU-Z/cpuz.exe"
    
    emu = LayeredEmulator(cpu_freq_mhz=3000)
    entry_point = emu.load_pe(cpuz_path)
    
    # Patch GetCommandLineW
    def patched_get_command_line_w():
        cmd_line = "cpuz.exe -txt=report\x00".encode('utf-16le')
        ptr = emu.os.HeapAlloc(emu.os.heap.process_heap, 0, len(cmd_line))
        emu.uc.mem_write(ptr, cmd_line)
        emu.uc.reg_write(emu.uc.arch_const.UC_X86_REG_RAX, ptr)
        return ptr
    
    emu.winapi._stub_get_command_line_w = patched_get_command_line_w
    
    print(f"\n[*] Running...")
    
    try:
        from unicorn import UcError
        from unicorn.x86_const import UC_X86_REG_RIP
        emu.uc.emu_start(entry_point, 0, count=100000)
    except UcError as e:
        print(f"\n[!] Unicorn error: {e}")
        print(f"    Error code: {e.errno}")
        
        rip = emu.uc.reg_read(UC_X86_REG_RIP)
        print(f"    RIP: 0x{rip:x}")
        print(f"    Instructions executed: {emu.instruction_count}")
        
        # Show all registers
        from unicorn.x86_const import UC_X86_REG_RAX, UC_X86_REG_RBX, UC_X86_REG_RCX, UC_X86_REG_RDX
        rax = emu.uc.reg_read(UC_X86_REG_RAX)
        rbx = emu.uc.reg_read(UC_X86_REG_RBX)
        rcx = emu.uc.reg_read(UC_X86_REG_RCX)
        rdx = emu.uc.reg_read(UC_X86_REG_RDX)
        
        print(f"    RAX: 0x{rax:x}")
        print(f"    RBX: 0x{rbx:x}")
        print(f"    RCX: 0x{rcx:x}  <- This is the problem!")
        print(f"    RDX: 0x{rdx:x}")
        
        # Try to read instruction at RIP
        try:
            code = emu.uc.mem_read(rip, 15)
            md = Cs(CS_ARCH_X86, CS_MODE_64)
            insn = next(md.disasm(code, rip))
            print(f"    Next instruction: {insn.mnemonic} {insn.op_str}")
            print(f"    Will try to write to: RCX+8 = 0x{rcx+8:x}")
        except Exception as e2:
            print(f"    Cannot read instruction: {e2}")
    
    print(f"\n[*] Final instruction count: {emu.instruction_count}")


if __name__ == "__main__":
    test_why_stops()
