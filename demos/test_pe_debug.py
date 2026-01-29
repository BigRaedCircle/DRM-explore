#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Test: PE loading debug with detailed logging
"""

import sys
sys.path.insert(0, 'src/core')

from layered_emulator import LayeredEmulator
from unicorn import UcError


def test_pe_debug():
    """Test with detailed debugging"""
    print("=" * 70)
    print("DEBUG: PE loading with detailed logging")
    print("=" * 70)
    print()
    
    # Create emulator
    emu = LayeredEmulator(cpu_freq_mhz=3000)
    
    # Load PE
    pe_path = "demos/time_check_demo.exe"
    try:
        entry_point = emu.load_pe(pe_path)
    except Exception as e:
        print(f"\n[!] Loading error: {e}")
        import traceback
        traceback.print_exc()
        return False
    
    # Add hook for debugging each instruction
    instruction_log = []
    
    def debug_hook(uc, address, size, user_data):
        # Log last 50 instructions
        try:
            code = uc.mem_read(address, min(size, 15))
            rip = uc.reg_read(0x21)  # UC_X86_REG_RIP
            rsp = uc.reg_read(0x2c)  # UC_X86_REG_RSP
            rax = uc.reg_read(0x23)  # UC_X86_REG_RAX
            rcx = uc.reg_read(0x19)  # UC_X86_REG_RCX
            
            instruction_log.append({
                'addr': address,
                'code': code.hex(),
                'rip': rip,
                'rsp': rsp,
                'rax': rax,
                'rcx': rcx
            })
            
            # Keep only last 50
            if len(instruction_log) > 50:
                instruction_log.pop(0)
            
            # Print every 50th instruction
            if len(instruction_log) % 50 == 0:
                print(f"[{len(instruction_log):4d}] RIP=0x{rip:016x} RSP=0x{rsp:016x}")
        except:
            pass
    
    from unicorn import UC_HOOK_CODE
    emu.uc.hook_add(UC_HOOK_CODE, debug_hook)
    
    # Run
    print(f"\n[*] Starting from entry point: 0x{entry_point:x}")
    
    # Check what's at entry point
    try:
        entry_code = emu.uc.mem_read(entry_point, 16)
        print(f"[*] Code at entry point: {entry_code.hex()}")
        
        # Try to disassemble
        try:
            from capstone import Cs, CS_ARCH_X86, CS_MODE_64
            md = Cs(CS_ARCH_X86, CS_MODE_64)
            print(f"[*] Disassembly at entry:")
            for insn in md.disasm(entry_code, entry_point):
                print(f"    0x{insn.address:x}: {insn.mnemonic} {insn.op_str}")
                if len(list(md.disasm(entry_code, entry_point))) >= 5:
                    break
        except:
            pass
    except Exception as e:
        print(f"[!] Cannot read entry point: {e}")
    
    print("-" * 70)
    
    try:
        emu.uc.emu_start(entry_point, 0, count=1000)
        print("\n[OK] Emulation completed successfully")
        return True
    except Exception as e:
        print(f"\n[!] Error: {e}")
        rip = emu.uc.reg_read(0x21)
        print(f"[!] RIP: 0x{rip:x}")
        print(f"[!] Total instructions: {len(instruction_log)}")
        
        # Show last 10 instructions
        if instruction_log:
            print("\n[*] Last 10 instructions before crash:")
            for i, entry in enumerate(instruction_log[-10:]):
                print(f"  [{i-9:3d}] 0x{entry['addr']:016x}: {entry['code'][:16]:<16} "
                      f"RAX=0x{entry['rax']:016x} RCX=0x{entry['rcx']:016x}")
        
        # Try to disassemble crash location
        try:
            from capstone import Cs, CS_ARCH_X86, CS_MODE_64
            md = Cs(CS_ARCH_X86, CS_MODE_64)
            crash_code = emu.uc.mem_read(rip, 16)
            print(f"\n[*] Instruction at crash (0x{rip:x}):")
            for insn in md.disasm(crash_code, rip):
                print(f"    {insn.mnemonic} {insn.op_str}")
                break
            
            # Also disassemble last few instructions
            if instruction_log and len(instruction_log) >= 3:
                print(f"\n[*] Last 3 instructions disassembled:")
                for entry in instruction_log[-3:]:
                    try:
                        code_bytes = bytes.fromhex(entry['code'][:16])
                        for insn in md.disasm(code_bytes, entry['addr']):
                            print(f"    0x{insn.address:x}: {insn.mnemonic} {insn.op_str}")
                            break
                    except:
                        pass
        except:
            pass
        
        return False


if __name__ == "__main__":
    success = test_pe_debug()
    sys.exit(0 if success else 1)
