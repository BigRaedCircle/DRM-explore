#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Disassemble code at crash point to understand what's happening
"""

import sys
sys.path.insert(0, 'src/core')

from layered_emulator import LayeredEmulator
from capstone import *


def test_cpuz_disasm():
    """Disassemble code at crash point"""
    print("=" * 70)
    print("CPU-Z DISASSEMBLY AT CRASH POINT")
    print("=" * 70)
    
    cpuz_path = "sandbox/CPU-Z/cpuz.exe"
    
    print(f"\n[*] Loading: {cpuz_path}")
    
    emu = LayeredEmulator(cpu_freq_mhz=3000)
    entry_point = emu.load_pe(cpuz_path)
    
    # Run until crash
    print(f"\n[*] Running until crash...")
    
    try:
        emu.run(
            start_addr=entry_point,
            end_addr=0,
            max_instructions=10000,
            verbose=False
        )
    except Exception as e:
        print(f"[*] Crashed as expected: {e}")
    
    # Get crash RIP
    from unicorn.x86_const import UC_X86_REG_RIP, UC_X86_REG_RAX, UC_X86_REG_RCX, UC_X86_REG_RDX
    crash_rip = emu.uc.reg_read(UC_X86_REG_RIP)
    rax = emu.uc.reg_read(UC_X86_REG_RAX)
    rcx = emu.uc.reg_read(UC_X86_REG_RCX)
    rdx = emu.uc.reg_read(UC_X86_REG_RDX)
    
    print(f"\n[*] Crash point:")
    print(f"    RIP: 0x{crash_rip:x}")
    print(f"    RAX: 0x{rax:x}")
    print(f"    RCX: 0x{rcx:x}")
    print(f"    RDX: 0x{rdx:x}")
    
    # Disassemble around crash point
    print(f"\n[*] Disassembly around crash point:")
    print("-" * 70)
    
    try:
        # Read 64 bytes before and after crash point
        start_addr = crash_rip - 32
        code = emu.uc.mem_read(start_addr, 96)
        
        # Disassemble
        md = Cs(CS_ARCH_X86, CS_MODE_64)
        md.detail = True
        
        for insn in md.disasm(code, start_addr):
            marker = " >>> " if insn.address == crash_rip else "     "
            print(f"{marker}0x{insn.address:x}:  {insn.mnemonic:8} {insn.op_str}")
            
            # Show details for CALL instructions
            if insn.mnemonic == 'call':
                print(f"          ^ CALL instruction")
                if 'rax' in insn.op_str:
                    print(f"          ^ Indirect call through RAX (RAX=0x{rax:x})")
                elif 'rcx' in insn.op_str:
                    print(f"          ^ Indirect call through RCX (RCX=0x{rcx:x})")
    
    except Exception as e:
        print(f"[!] Cannot disassemble: {e}")
    
    print("-" * 70)
    
    # Try to find what set RAX to 0
    print(f"\n[*] Looking for instructions that set RAX...")
    
    try:
        # Disassemble more context
        start_addr = crash_rip - 128
        code = emu.uc.mem_read(start_addr, 160)
        
        md = Cs(CS_ARCH_X86, CS_MODE_64)
        
        for insn in md.disasm(code, start_addr):
            # Look for instructions that modify RAX
            if 'rax' in insn.op_str and insn.mnemonic in ['mov', 'xor', 'lea', 'call']:
                print(f"    0x{insn.address:x}:  {insn.mnemonic:8} {insn.op_str}")
    
    except Exception as e:
        print(f"[!] Cannot analyze: {e}")


if __name__ == "__main__":
    test_cpuz_disasm()
