#!/usr/bin/env python3
"""
Check what's at 0x14003a510 during emulation
"""

import sys
import os
sys.path.insert(0, 'src/core')

from unicorn import Uc, UC_ARCH_X86, UC_MODE_64
from unicorn.x86_const import *
from virtual_clock import VirtualClock
from mini_os import MiniOS
from winapi_stubs_v2 import WinAPIStubsV2
from pe_loader import PELoader


# Quick test - just load PE and check memory
uc = Uc(UC_ARCH_X86, UC_MODE_64)
clock = VirtualClock(3000)
os_mini = MiniOS(uc, clock)

# Stub memory
STUB_BASE = 0x7FFF0000
STUB_SIZE = 0x40000000
uc.mem_map(STUB_BASE, STUB_SIZE)

# Stack
STACK_BASE = 0x00100000
STACK_SIZE = 0x00100000
uc.mem_map(STACK_BASE, STACK_SIZE)
uc.reg_write(UC_X86_REG_RSP, STACK_BASE + STACK_SIZE - 0x1000)

# TIB
TIB_BASE = 0x00030000
TIB_SIZE = 0x2000
uc.mem_map(TIB_BASE, TIB_SIZE)

# Create minimal emulator
class MinimalEmu:
    def __init__(self):
        self.uc = uc
        self.clock = clock
        self.os = os_mini
        self.STACK_BASE = STACK_BASE
        self.STACK_SIZE = STACK_SIZE
        self.TIB_BASE = TIB_BASE
        self.TIB_SIZE = TIB_SIZE

emu = MinimalEmu()
winapi = WinAPIStubsV2(emu)
emu.winapi = winapi

# Load PE
pe_loader = PELoader(emu)
emu.pe_loader = pe_loader

os.chdir("sandbox/CoreInfo")
entry_point = pe_loader.load("Coreinfo64.exe")

# Check what's at 0x14003a510
addr = 0x14003a510
data = uc.mem_read(addr, 8)
value = int.from_bytes(data, 'little')

print(f"Value at 0x{addr:x}: 0x{value:016x}")
print(f"Bytes: {data.hex()}")

# Check if it's a valid address
PE_BASE = 0x140000000
PE_SIZE = 0x00100000

if PE_BASE <= value < PE_BASE + PE_SIZE:
    print(f"-> Points to RVA 0x{value - PE_BASE:x} (inside image)")
else:
    print(f"-> Not a valid image address")

# Check nearby addresses too
print(f"\nNearby addresses:")
for offset in range(-16, 24, 8):
    check_addr = addr + offset
    data = uc.mem_read(check_addr, 8)
    value = int.from_bytes(data, 'little')
    print(f"  0x{check_addr:x}: 0x{value:016x}")
