#!/usr/bin/env python3
import sys
sys.path.insert(0, 'src/core')

from unicorn import Uc, UC_ARCH_X86, UC_MODE_64
from pe_loader import PELoader
from winapi_stubs_v2 import WinAPIStubsV2
from mini_os import MiniOS
from virtual_clock import VirtualClock

# Создаём минимальный эмулятор
uc = Uc(UC_ARCH_X86, UC_MODE_64)
clock = VirtualClock(3000)
os_obj = MiniOS(uc, clock)

# Stub memory
STUB_BASE = 0x7FFF0000
STUB_SIZE = 0x40000000
uc.mem_map(STUB_BASE, STUB_SIZE)

# Создаём эмулятор-обёртку
class DummyEmu:
    def __init__(self):
        self.uc = uc
        self.clock = clock
        self.os = os_obj
        self.winapi = None

emu = DummyEmu()
emu.winapi = WinAPIStubsV2(emu)

# Загружаем PE
loader = PELoader(emu)
entry = loader.load('sandbox/CoreInfo/Coreinfo64.exe')

# Проверяем IAT entry для GetSystemTimeAsFileTime
iat_addr = 0x14003a2d8
stub_addr = int.from_bytes(uc.mem_read(iat_addr, 8), 'little')

print(f"IAT entry @ 0x{iat_addr:x}: 0x{stub_addr:x}")
print(f"Expected: 0x7fffbb00")
print(f"Match: {stub_addr == 0x7fffbb00}")

# Читаем код по адресу stub
print(f"\nCode at stub address 0x{stub_addr:x}:")
code = uc.mem_read(stub_addr, 16)
print(" ".join(f"{b:02x}" for b in code))

# Дизассемблируем
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
md = Cs(CS_ARCH_X86, CS_MODE_64)
for insn in md.disasm(code, stub_addr):
    print(f"  0x{insn.address:x}: {insn.mnemonic} {insn.op_str}")
