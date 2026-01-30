#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Trace last N instructions before CPU-Z stops
"""

import sys
sys.path.insert(0, 'src/core')

from layered_emulator import LayeredEmulator
from capstone import *
from collections import deque


def test_cpuz_trace_last():
    """Trace last instructions before stop"""
    print("=" * 70)
    print("CPU-Z: TRACE LAST INSTRUCTIONS")
    print("=" * 70)
    
    cpuz_path = "sandbox/CPU-Z/cpuz.exe"
    
    print(f"\n[*] Loading: {cpuz_path}")
    
    emu = LayeredEmulator(cpu_freq_mhz=3000)
    entry_point = emu.load_pe(cpuz_path)
    
    # Create disassembler
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    
    # Keep last 50 instructions
    last_instructions = deque(maxlen=50)
    
    # Hook to trace instructions
    def trace_hook(uc, address, size, user_data):
        try:
            code = uc.mem_read(address, size)
            insn = next(md.disasm(code, address))
            
            # Get register values
            rax = uc.reg_read(uc.arch_const.UC_X86_REG_RAX)
            rcx = uc.reg_read(uc.arch_const.UC_X86_REG_RCX)
            rdx = uc.reg_read(uc.arch_const.UC_X86_REG_RDX)
            rsp = uc.reg_read(uc.arch_const.UC_X86_REG_RSP)
            
            last_instructions.append({
                'address': address,
                'mnemonic': insn.mnemonic,
                'op_str': insn.op_str,
                'rax': rax,
                'rcx': rcx,
                'rdx': rdx,
                'rsp': rsp,
                'count': emu.instruction_count
            })
        except:
            pass
    
    # Add trace hook
    from unicorn import UC_HOOK_CODE
    emu.uc.hook_add(UC_HOOK_CODE, trace_hook, begin=entry_point, end=0)
    
    print(f"\n[*] Running with instruction tracing...")
    
    try:
        emu.run(
            start_addr=entry_point,
            end_addr=0,
            max_instructions=100000,
            verbose=False
        )
    except Exception as e:
        print(f"\n[!] Stopped with error: {e}")
    
    print(f"\n[*] Execution stopped at instruction #{emu.instruction_count}")
    print(f"\n[*] Last 50 instructions:")
    print("-" * 100)
    
    for i, insn in enumerate(last_instructions):
        marker = ">>>" if i == len(last_instructions) - 1 else "   "
        print(f"{marker} #{insn['count']:6d}  0x{insn['address']:x}:  {insn['mnemonic']:10} {insn['op_str']:30}  "
              f"RAX=0x{insn['rax']:x} RCX=0x{insn['rcx']:x} RDX=0x{insn['rdx']:x}")
    
    print("-" * 100)
    
    # Show final register state
    print(f"\n[*] Final register state:")
    from unicorn.x86_const import *
    rip = emu.uc.reg_read(UC_X86_REG_RIP)
    rax = emu.uc.reg_read(UC_X86_REG_RAX)
    rbx = emu.uc.reg_read(UC_X86_REG_RBX)
    rcx = emu.uc.reg_read(UC_X86_REG_RCX)
    rdx = emu.uc.reg_read(UC_X86_REG_RDX)
    rsi = emu.uc.reg_read(UC_X86_REG_RSI)
    rdi = emu.uc.reg_read(UC_X86_REG_RDI)
    rsp = emu.uc.reg_read(UC_X86_REG_RSP)
    rbp = emu.uc.reg_read(UC_X86_REG_RBP)
    
    print(f"  RIP: 0x{rip:016x}")
    print(f"  RAX: 0x{rax:016x}  RBX: 0x{rbx:016x}")
    print(f"  RCX: 0x{rcx:016x}  RDX: 0x{rdx:016x}")
    print(f"  RSI: 0x{rsi:016x}  RDI: 0x{rdi:016x}")
    print(f"  RSP: 0x{rsp:016x}  RBP: 0x{rbp:016x}")
    
    # Try to disassemble next instruction
    print(f"\n[*] Next instruction at RIP:")
    try:
        code = emu.uc.mem_read(rip, 15)
        insn = next(md.disasm(code, rip))
        print(f"  0x{insn.address:x}:  {insn.mnemonic:10} {insn.op_str}")
    except Exception as e:
        print(f"  Cannot read: {e}")


if __name__ == "__main__":
    test_cpuz_trace_last()
