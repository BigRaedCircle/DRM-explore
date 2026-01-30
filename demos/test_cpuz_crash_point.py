#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Disassemble code at specific crash point
"""

import sys
sys.path.insert(0, 'src/core')

from layered_emulator import LayeredEmulator
from capstone import *


def test_crash_point():
    """Disassemble at crash point 0x14015b604"""
    print("=" * 70)
    print("CPU-Z DISASSEMBLY AT 0x14015b604")
    print("=" * 70)
    
    cpuz_path = "sandbox/CPU-Z/cpuz.exe"
    
    print(f"\n[*] Loading: {cpuz_path}")
    
    emu = LayeredEmulator(cpu_freq_mhz=3000)
    entry_point = emu.load_pe(cpuz_path)
    
    # Disassemble around 0x14015b604
    crash_rip = 0x14015b604
    
    print(f"\n[*] Disassembly around 0x{crash_rip:x}:")
    print("-" * 70)
    
    try:
        # Read 128 bytes around crash point
        start_addr = crash_rip - 32
        code = emu.uc.mem_read(start_addr, 96)
        
        # Disassemble
        md = Cs(CS_ARCH_X86, CS_MODE_64)
        md.detail = True
        
        for insn in md.disasm(code, start_addr):
            marker = " >>> " if insn.address == crash_rip else "     "
            print(f"{marker}0x{insn.address:x}:  {insn.mnemonic:8} {insn.op_str}")
    
    except Exception as e:
        print(f"[!] Cannot disassemble: {e}")
    
    print("-" * 70)


if __name__ == "__main__":
    test_crash_point()
