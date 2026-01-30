#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Show last instructions before crash
"""

import sys
sys.path.insert(0, 'src/core')

from layered_emulator import LayeredEmulator
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from collections import deque
from unicorn.x86_const import *


def test_cpuz_last_instructions():
    """Show last instructions before crash"""
    print("=" * 70)
    print("CPU-Z: LAST INSTRUCTIONS BEFORE CRASH")
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
    
    # Track last 20 instructions
    insn_log = deque(maxlen=20)
    
    # Disassembler
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    
    # Hook code execution
    def code_hook(uc, address, size, user_data):
        try:
            code = uc.mem_read(address, size)
            disasm = list(md.disasm(code, address))
            if disasm:
                insn = disasm[0]
                insn_log.append({
                    'address': address,
                    'mnemonic': insn.mnemonic,
                    'op_str': insn.op_str,
                    'bytes': code.hex()
                })
        except:
            insn_log.append({
                'address': address,
                'mnemonic': '???',
                'op_str': '',
                'bytes': ''
            })
    
    from unicorn import UC_HOOK_CODE
    
    emu.uc.hook_add(UC_HOOK_CODE, code_hook)
    
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
    
    # Show last instructions
    print(f"\n[*] Last 20 instructions before crash:")
    print("-" * 70)
    for i, insn in enumerate(insn_log):
        marker = ">>>" if i == len(insn_log) - 1 else "   "
        print(f"{marker} 0x{insn['address']:016x}  {insn['mnemonic']:8} {insn['op_str']:30}")
    print("-" * 70)
    
    # Show registers
    print(f"\n[*] Final register state:")
    print(f"    RAX: 0x{emu.uc.reg_read(UC_X86_REG_RAX):016x}")
    print(f"    RBX: 0x{emu.uc.reg_read(UC_X86_REG_RBX):016x}")
    print(f"    RCX: 0x{emu.uc.reg_read(UC_X86_REG_RCX):016x}")
    print(f"    RDX: 0x{emu.uc.reg_read(UC_X86_REG_RDX):016x}")
    print(f"    RSI: 0x{emu.uc.reg_read(UC_X86_REG_RSI):016x}")
    print(f"    RDI: 0x{emu.uc.reg_read(UC_X86_REG_RDI):016x}")
    print(f"    RBP: 0x{emu.uc.reg_read(UC_X86_REG_RBP):016x}")
    print(f"    RSP: 0x{emu.uc.reg_read(UC_X86_REG_RSP):016x}")
    print(f"    RIP: 0x{emu.uc.reg_read(UC_X86_REG_RIP):016x}")
    
    # Check what's at the call target
    call_target_addr = 0x14033d282
    try:
        call_target_bytes = emu.uc.mem_read(call_target_addr, 8)
        call_target = int.from_bytes(call_target_bytes, 'little')
        print(f"\n[*] Call target:")
        print(f"    Address: 0x{call_target_addr:016x}")
        print(f"    Value: 0x{call_target:016x}")
        
        # Check if it's a dummy stub
        if hasattr(emu.pe_loader, '_dummy_stub_names') and call_target in emu.pe_loader._dummy_stub_names:
            print(f"    Function: [DUMMY] {emu.pe_loader._dummy_stub_names[call_target]}")
    except Exception as e:
        print(f"\n[!] Cannot read call target: {e}")


if __name__ == "__main__":
    test_cpuz_last_instructions()
