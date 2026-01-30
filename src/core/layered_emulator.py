#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Layered Emulator — расслоенная эмуляция с поддержкой WinAPI

Объединяет:
- VirtualClock (единый источник времени)
- SimpleEmulator (эмуляция CPU)
- WinAPIStubs (заглушки системных вызовов)
- PELoader (загрузка PE-файлов)
"""

import sys
sys.path.insert(0, '.')

from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UcError
from unicorn import UC_HOOK_CODE, UC_HOOK_INSN
from unicorn.x86_const import *
from virtual_clock import VirtualClock
from mini_os import MiniOS
from winapi_stubs import WinAPIStubs
from pe_loader import PELoader
from realistic_stubs import SystemInfo, VirtualFileSystem, DirectXStubs, NetworkStubs


class LayeredEmulator:
    """Расслоенный эмулятор с поддержкой PE и WinAPI"""
    
    def __init__(self, cpu_freq_mhz=3000):
        # Инициализация Unicorn
        self.uc = Uc(UC_ARCH_X86, UC_MODE_64)
        
        # Виртуальные часы
        self.clock = VirtualClock(cpu_freq_mhz)
        
        # Реалистичные заглушки для периферии
        self.system_info = SystemInfo()
        self.vfs = VirtualFileSystem(base_path=".")
        self.directx = DirectXStubs(self.system_info, self.clock)
        self.network = NetworkStubs(self.clock)
        
        # Минимальный OS-слой
        self.os = MiniOS(self.uc, self.clock)
        
        # Счётчики
        self.instruction_count = 0
        self.syscall_count = 0
        
        # Выделение памяти для стека
        self.STACK_BASE = 0x00100000
        self.STACK_SIZE = 0x00100000  # 1 МБ
        self.uc.mem_map(self.STACK_BASE, self.STACK_SIZE)
        self.uc.reg_write(UC_X86_REG_RSP, self.STACK_BASE + self.STACK_SIZE - 0x1000)
        
        # Настройка TIB (Thread Information Block) для GS segment
        self.TIB_BASE = 0x00030000
        self.TIB_SIZE = 0x2000  # 8 KB
        self.uc.mem_map(self.TIB_BASE, self.TIB_SIZE)
        self._setup_tib()
        
        # Map GS segment memory (low addresses 0x0-0x2000) to TIB
        # This allows GS:[offset] to work directly
        try:
            self.uc.mem_map(0x0, 0x3000)  # Map first 12KB for GS segment
            # Copy TIB data to GS segment area
            tib_data = self.uc.mem_read(self.TIB_BASE, self.TIB_SIZE)
            self.uc.mem_write(0x0, tib_data)
            print(f"[TIB] Mapped GS segment at 0x0-0x3000")
        except Exception as e:
            print(f"[TIB] Warning: Could not map GS segment: {e}")
        
        # Map additional memory for RDTSC-based addressing
        # Some programs use RDTSC values as pointers (weird but happens)
        try:
            # Map 1MB at 0x3b9b0000 (where RDTSC values point)
            self.uc.mem_map(0x3b9b0000, 0x100000)
            self.uc.mem_write(0x3b9b0000, b'\x00' * 0x100000)
            print(f"[MEM] Mapped 1MB at 0x3b9b0000 for RDTSC-based addressing")
        except Exception as e:
            print(f"[MEM] Warning: Could not map RDTSC memory: {e}")
        
        # Выделение памяти для заглушек WinAPI (ПЕРЕД созданием WinAPIStubs!)
        STUB_BASE = 0x7FFF0000
        self.uc.mem_map(STUB_BASE, 0x10000)
        
        # WinAPI заглушки (теперь используют MiniOS)
        self.winapi = WinAPIStubs(self)
        
        # PE Loader
        self.pe_loader = None
        
        # Настройка хуков
        self._setup_hooks()
    
    def _setup_tib(self):
        """Настройка Thread Information Block (TIB) для x64"""
        import struct
        
        # TIB structure (упрощённая версия)
        # Offset 0x00: ExceptionList
        # Offset 0x08: StackBase
        # Offset 0x10: StackLimit
        # Offset 0x18: SubSystemTib
        # Offset 0x20: FiberData / Version
        # Offset 0x28: ArbitraryUserPointer
        # Offset 0x30: Self (pointer to TIB itself)
        
        tib_data = bytearray(self.TIB_SIZE)
        
        # Stack Base (0x08)
        struct.pack_into('<Q', tib_data, 0x08, self.STACK_BASE + self.STACK_SIZE)
        
        # Stack Limit (0x10) - важно для __chkstk!
        struct.pack_into('<Q', tib_data, 0x10, self.STACK_BASE)
        
        # Self pointer (0x30)
        struct.pack_into('<Q', tib_data, 0x30, self.TIB_BASE)
        
        # Записываем TIB в память
        self.uc.mem_write(self.TIB_BASE, bytes(tib_data))
        
        # Настраиваем GS segment register для указания на TIB
        # В x64 Windows GS указывает на TIB
        # Unicorn не поддерживает полноценные segment descriptors,
        # но мы можем использовать MSR для GS_BASE
        try:
            # IA32_GS_BASE MSR (0xC0000101)
            from unicorn.x86_const import UC_X86_REG_MSR
            # Unicorn использует специальный способ для установки GS_BASE
            # Попробуем через прямую запись в GS
            self.uc.reg_write(UC_X86_REG_GS, self.TIB_BASE)
        except:
            # Если не получилось, попробуем альтернативный способ
            pass
        
        print(f"[TIB] Initialized at 0x{self.TIB_BASE:x}")
        print(f"[TIB] Stack Base: 0x{self.STACK_BASE + self.STACK_SIZE:x}")
        print(f"[TIB] Stack Limit: 0x{self.STACK_BASE:x}")
    
    def _setup_hooks(self):
        """Setup hooks for instruction interception"""
        # Hook on every instruction (for cycle counting and RDTSC)
        self.uc.hook_add(UC_HOOK_CODE, self._hook_instruction)
        
        # Hook for INT instructions (system calls)
        from unicorn import UC_HOOK_INTR
        self.uc.hook_add(UC_HOOK_INTR, self._hook_interrupt)
        
        # Hook for memory reads to emulate GS segment access
        from unicorn import UC_HOOK_MEM_READ_UNMAPPED, UC_HOOK_MEM_WRITE_UNMAPPED, UC_HOOK_MEM_FETCH_UNMAPPED
        self.uc.hook_add(UC_HOOK_MEM_READ_UNMAPPED, self._hook_mem_read_unmapped)
        self.uc.hook_add(UC_HOOK_MEM_WRITE_UNMAPPED, self._hook_mem_write_unmapped)
        self.uc.hook_add(UC_HOOK_MEM_FETCH_UNMAPPED, self._hook_mem_fetch_unmapped)
    
    def _hook_instruction(self, uc, address, size, user_data):
        """Hook on every instruction - advance virtual time"""
        # Modern CPUs have high IPC (Instructions Per Cycle)
        # Advance clock by a small fraction per instruction
        # This gives us realistic timing without huge jumps
        self.instruction_count += 1
        
        # Advance 1 tick every 10 instructions (simulates IPC ≈ 10)
        # This gives us realistic RDTSC deltas
        if self.instruction_count % 10 == 0:
            self.clock.advance(1)
        
        # Check if we're executing in stub area - handle it immediately
        if self.winapi.STUB_BASE <= address < self.winapi.STUB_BASE + 0x10000:
            # We're in a stub - handle it
            self.winapi.handle_stub_call(address)
            # Pop return address and jump there
            rsp = uc.reg_read(UC_X86_REG_RSP)
            ret_addr = int.from_bytes(uc.mem_read(rsp, 8), 'little')
            uc.reg_write(UC_X86_REG_RSP, rsp + 8)
            uc.reg_write(UC_X86_REG_RIP, ret_addr)
            print(f"  <- returning to 0x{ret_addr:x}")
            return
        
        # Read instruction to check for RDTSC and CPUID
        try:
            code = uc.mem_read(address, min(size, 15))
            
            # RDTSC = 0x0F 0x31
            if len(code) >= 2 and code[0] == 0x0F and code[1] == 0x31:
                # Handle RDTSC
                ticks = self.clock.rdtsc()
                eax = ticks & 0xFFFFFFFF
                edx = (ticks >> 32) & 0xFFFFFFFF
                uc.reg_write(UC_X86_REG_RAX, eax)
                uc.reg_write(UC_X86_REG_RDX, edx)
                print(f"[RDTSC] @ 0x{address:x} -> {ticks} ticks")
                # Skip the RDTSC instruction (2 bytes)
                uc.reg_write(UC_X86_REG_RIP, address + 2)
                return
            
            # CPUID = 0x0F 0xA2
            elif len(code) >= 2 and code[0] == 0x0F and code[1] == 0xA2:
                # Handle CPUID
                self._handle_cpuid(uc, address)
            
            # Check for indirect JMP/CALL through memory (0xFF opcode)
            elif len(code) >= 2 and code[0] == 0xFF:
                modrm = code[1]
                # Check if it's JMP [mem] (opcode /4) or CALL [mem] (opcode /2)
                reg = (modrm >> 3) & 0x7
                if reg == 4 or reg == 2:  # JMP or CALL
                    # This might be IAT call - log it only if verbose
                    rax = uc.reg_read(UC_X86_REG_RAX)
                    if rax == 0 and False:  # Disabled warning
                        print(f"[WARN] Indirect {'CALL' if reg == 2 else 'JMP'} @ 0x{address:x} with RAX=0")
        except:
            pass
    
    def _handle_cpuid(self, uc, address):
        """Handle CPUID instruction - return fake CPU information"""
        eax = uc.reg_read(UC_X86_REG_EAX)
        ecx = uc.reg_read(UC_X86_REG_ECX)
        
        print(f"[CPUID] @ 0x{address:x} EAX=0x{eax:x}, ECX=0x{ecx:x}")
        
        if eax == 0:
            # CPUID Function 0: Get Vendor ID
            # Return "GenuineIntel"
            uc.reg_write(UC_X86_REG_EAX, 0x16)  # Max basic CPUID function
            uc.reg_write(UC_X86_REG_EBX, 0x756e6547)  # "Genu"
            uc.reg_write(UC_X86_REG_EDX, 0x49656e69)  # "ineI"
            uc.reg_write(UC_X86_REG_ECX, 0x6c65746e)  # "ntel"
            print(f"  -> Vendor: GenuineIntel, Max Function: 0x16")
        
        elif eax == 1:
            # CPUID Function 1: Processor Info and Feature Bits
            # Intel Core i7-9700K (Coffee Lake)
            uc.reg_write(UC_X86_REG_EAX, 0x000906ED)  # Family 6, Model 158, Stepping 13
            uc.reg_write(UC_X86_REG_EBX, 0x08100800)  # Brand Index, CLFLUSH, Max CPUs, APIC ID
            uc.reg_write(UC_X86_REG_ECX, 0x7FFAFBBF)  # Feature flags (SSE3, SSSE3, SSE4.1, SSE4.2, AVX, etc.)
            uc.reg_write(UC_X86_REG_EDX, 0xBFEBFBFF)  # Feature flags (FPU, VME, DE, PSE, TSC, MSR, PAE, etc.)
            print(f"  -> CPU: Intel Core i7-9700K (Family 6, Model 158)")
        
        elif eax == 2:
            # CPUID Function 2: Cache and TLB Descriptor
            uc.reg_write(UC_X86_REG_EAX, 0x76036301)
            uc.reg_write(UC_X86_REG_EBX, 0x00F0B5FF)
            uc.reg_write(UC_X86_REG_ECX, 0x00000000)
            uc.reg_write(UC_X86_REG_EDX, 0x00C30000)
            print(f"  -> Cache/TLB descriptors")
        
        elif eax == 4:
            # CPUID Function 4: Deterministic Cache Parameters
            if ecx == 0:  # L1 Data Cache
                uc.reg_write(UC_X86_REG_EAX, 0x1C004121)
                uc.reg_write(UC_X86_REG_EBX, 0x01C0003F)
                uc.reg_write(UC_X86_REG_ECX, 0x0000003F)
                uc.reg_write(UC_X86_REG_EDX, 0x00000000)
                print(f"  -> L1 Data Cache: 32KB")
            elif ecx == 1:  # L1 Instruction Cache
                uc.reg_write(UC_X86_REG_EAX, 0x1C004122)
                uc.reg_write(UC_X86_REG_EBX, 0x01C0003F)
                uc.reg_write(UC_X86_REG_ECX, 0x0000003F)
                uc.reg_write(UC_X86_REG_EDX, 0x00000000)
                print(f"  -> L1 Instruction Cache: 32KB")
            elif ecx == 2:  # L2 Cache
                uc.reg_write(UC_X86_REG_EAX, 0x1C004143)
                uc.reg_write(UC_X86_REG_EBX, 0x01C0003F)
                uc.reg_write(UC_X86_REG_ECX, 0x000001FF)
                uc.reg_write(UC_X86_REG_EDX, 0x00000000)
                print(f"  -> L2 Cache: 256KB")
            elif ecx == 3:  # L3 Cache
                uc.reg_write(UC_X86_REG_EAX, 0x1C03C163)
                uc.reg_write(UC_X86_REG_EBX, 0x02C0003F)
                uc.reg_write(UC_X86_REG_ECX, 0x00001FFF)
                uc.reg_write(UC_X86_REG_EDX, 0x00000006)
                print(f"  -> L3 Cache: 12MB")
            else:  # No more caches
                uc.reg_write(UC_X86_REG_EAX, 0)
                uc.reg_write(UC_X86_REG_EBX, 0)
                uc.reg_write(UC_X86_REG_ECX, 0)
                uc.reg_write(UC_X86_REG_EDX, 0)
        
        elif eax == 7:
            # CPUID Function 7: Extended Features
            if ecx == 0:
                uc.reg_write(UC_X86_REG_EAX, 0)  # Max sub-leaf
                uc.reg_write(UC_X86_REG_EBX, 0xD39FFFFB)  # AVX2, BMI1, BMI2, etc.
                uc.reg_write(UC_X86_REG_ECX, 0x00000004)
                uc.reg_write(UC_X86_REG_EDX, 0xBC000400)
                print(f"  -> Extended Features: AVX2, BMI1, BMI2")
        
        elif eax == 0x80000000:
            # CPUID Function 0x80000000: Get Highest Extended Function
            uc.reg_write(UC_X86_REG_EAX, 0x80000008)  # Max extended function
            uc.reg_write(UC_X86_REG_EBX, 0)
            uc.reg_write(UC_X86_REG_ECX, 0)
            uc.reg_write(UC_X86_REG_EDX, 0)
            print(f"  -> Max Extended Function: 0x80000008")
        
        elif eax == 0x80000001:
            # CPUID Function 0x80000001: Extended Processor Info
            uc.reg_write(UC_X86_REG_EAX, 0)
            uc.reg_write(UC_X86_REG_EBX, 0)
            uc.reg_write(UC_X86_REG_ECX, 0x00000121)  # LAHF/SAHF, LZCNT
            uc.reg_write(UC_X86_REG_EDX, 0x2C100800)  # SYSCALL, NX, RDTSCP
            print(f"  -> Extended Features")
        
        elif eax == 0x80000002:
            # CPUID Function 0x80000002-0x80000004: Processor Brand String
            # "Intel(R) Core(TM) i7-9700K CPU @ 3.60GHz"
            uc.reg_write(UC_X86_REG_EAX, 0x65746E49)  # "Inte"
            uc.reg_write(UC_X86_REG_EBX, 0x2952286C)  # "l(R)"
            uc.reg_write(UC_X86_REG_ECX, 0x726F4320)  # " Cor"
            uc.reg_write(UC_X86_REG_EDX, 0x4D542865)  # "e(TM"
            print(f"  -> Brand String Part 1")
        
        elif eax == 0x80000003:
            uc.reg_write(UC_X86_REG_EAX, 0x37692029)  # ") i7"
            uc.reg_write(UC_X86_REG_EBX, 0x3030372D)  # "-970"
            uc.reg_write(UC_X86_REG_ECX, 0x43204B30)  # "0K C"
            uc.reg_write(UC_X86_REG_EDX, 0x40205550)  # "PU @"
            print(f"  -> Brand String Part 2")
        
        elif eax == 0x80000004:
            uc.reg_write(UC_X86_REG_EAX, 0x30362E33)  # " 3.6"
            uc.reg_write(UC_X86_REG_EBX, 0x7A484730)  # "0GHz"
            uc.reg_write(UC_X86_REG_ECX, 0x00000000)
            uc.reg_write(UC_X86_REG_EDX, 0x00000000)
            print(f"  -> Brand String Part 3: Intel Core i7-9700K @ 3.60GHz")
        
        elif eax == 0x80000006:
            # CPUID Function 0x80000006: Extended L2 Cache Features
            uc.reg_write(UC_X86_REG_EAX, 0)
            uc.reg_write(UC_X86_REG_EBX, 0)
            uc.reg_write(UC_X86_REG_ECX, 0x01006040)  # L2 Cache: 256KB, 8-way, 64B line
            uc.reg_write(UC_X86_REG_EDX, 0)
            print(f"  -> L2 Cache Info")
        
        elif eax == 0x80000008:
            # CPUID Function 0x80000008: Virtual/Physical Address Sizes
            uc.reg_write(UC_X86_REG_EAX, 0x00003027)  # 48-bit physical, 48-bit virtual
            uc.reg_write(UC_X86_REG_EBX, 0)
            uc.reg_write(UC_X86_REG_ECX, 0)
            uc.reg_write(UC_X86_REG_EDX, 0)
            print(f"  -> Address Sizes: 48-bit physical, 48-bit virtual")
        
        else:
            # Unknown CPUID function - return zeros
            uc.reg_write(UC_X86_REG_EAX, 0)
            uc.reg_write(UC_X86_REG_EBX, 0)
            uc.reg_write(UC_X86_REG_ECX, 0)
            uc.reg_write(UC_X86_REG_EDX, 0)
            print(f"  -> Unknown function, returning zeros")
    
    def _hook_interrupt(self, uc, intno, user_data):
        """Handle INT instructions (system calls)"""
        rip = uc.reg_read(UC_X86_REG_RIP)
        
        if intno == 0x03:
            # INT 0x03 - Breakpoint / Our stub marker
            # Check if this is our stub
            if rip >= self.winapi.STUB_BASE and rip < self.winapi.STUB_BASE + 0x10000:
                # This is our stub - call handler
                self.winapi.handle_stub_call(rip)
                # Emulate RET: pop return address from stack
                rsp = uc.reg_read(UC_X86_REG_RSP)
                ret_addr = int.from_bytes(uc.mem_read(rsp, 8), 'little')
                uc.reg_write(UC_X86_REG_RSP, rsp + 8)
                uc.reg_write(UC_X86_REG_RIP, ret_addr)
                print(f"  <- returning to 0x{ret_addr:x}")
            else:
                # INT3 in user code - use as RDTSC marker
                ticks = self.clock.rdtsc()
                eax = ticks & 0xFFFFFFFF
                edx = (ticks >> 32) & 0xFFFFFFFF
                uc.reg_write(UC_X86_REG_RAX, eax)
                uc.reg_write(UC_X86_REG_RDX, edx)
                print(f"[RDTSC via INT3] @ 0x{rip:x} -> {ticks} ticks (EAX=0x{eax:x}, EDX=0x{edx:x})")
                # Advance RIP past INT3 (1 byte)
                uc.reg_write(UC_X86_REG_RIP, rip + 1)
        elif intno == 0x29:
            # INT 0x29 - Windows fast debug output
            # Just skip it - advance RIP by 2 bytes (CD 29)
            print(f"[INT 0x29] @ 0x{rip:x} - Windows debug output (skipped)")
            uc.reg_write(UC_X86_REG_RIP, rip + 2)
        elif intno == 0x2E:
            # INT 0x2E - Windows system call (old method)
            print(f"[INT 0x2E] @ 0x{rip:x} - Windows syscall (skipped)")
            uc.reg_write(UC_X86_REG_RIP, rip + 2)
        else:
            print(f"[INT 0x{intno:02x}] @ 0x{rip:x} - Unknown interrupt")
            # Let it crash for debugging
    
    def _hook_mem_read_unmapped(self, uc, access, address, size, value, user_data):
        """Handle unmapped memory reads - emulate GS segment access"""
        rip = uc.reg_read(UC_X86_REG_RIP)
        
        # Check if this is a GS segment read
        # GS segment reads in x64 Windows typically access TIB
        # The address will be the offset, not the full address
        # We need to check if the instruction is reading from GS segment
        
        try:
            # Read the instruction bytes
            code = uc.mem_read(rip, 15)
            
            # Check for GS segment prefix (0x65)
            if code[0] == 0x65:
                # This is a GS segment read!
                # The address parameter is the offset within GS segment
                tib_address = self.TIB_BASE + address
                
                print(f"[GS] Read from GS:[0x{address:x}] @ RIP=0x{rip:x}")
                
                # Read the value from TIB
                try:
                    data = uc.mem_read(tib_address, size)
                    result = int.from_bytes(data, 'little')
                    print(f"[GS] -> 0x{result:x} (from TIB @ 0x{tib_address:x})")
                    
                    # Map the memory temporarily so Unicorn can read it
                    # This is a hack: we map the GS segment offset as real memory
                    # Round down to page boundary
                    page_start = (address // 0x1000) * 0x1000
                    page_size = 0x1000
                    
                    try:
                        # Try to map the page
                        uc.mem_map(page_start, page_size)
                        # Write the TIB data to this location
                        uc.mem_write(address, data)
                        print(f"[GS] Mapped page at 0x{page_start:x} for GS segment emulation")
                        return True
                    except:
                        # Page already mapped or other error
                        try:
                            uc.mem_write(address, data)
                            return True
                        except:
                            pass
                    
                except Exception as e:
                    print(f"[GS] Error reading from TIB: {e}")
        except:
            pass
        
        # Not a GS segment read - check if it's a small address (likely invalid pointer)
        if address < 0x10000:
            # This is likely a NULL or near-NULL pointer dereference
            # Common in anti-emulation checks or bugs
            print(f"[MEM] NULL pointer read @ 0x{address:x}, size={size}, RIP=0x{rip:x}")
            print(f"[MEM] Mapping zero page and continuing...")
            
            # Map a zero page at address 0 to handle NULL pointer reads
            try:
                page_start = (address // 0x1000) * 0x1000
                if page_start < 0x3000:  # Don't remap GS segment
                    page_start = 0x3000
                uc.mem_map(page_start, 0x1000)
                # Fill with zeros
                uc.mem_write(page_start, b'\x00' * 0x1000)
                print(f"[MEM] Mapped zero page at 0x{page_start:x}, continuing execution")
                return True
            except Exception as e:
                print(f"[MEM] Failed to map zero page: {e}")
                # Try to continue anyway
                return True
        
        # Not a GS segment read - let it crash
        print(f"[MEM] Unmapped read @ 0x{address:x}, size={size}, RIP=0x{rip:x}")
        return False
    
    def _hook_mem_write_unmapped(self, uc, access, address, size, value, user_data):
        """Handle unmapped memory writes"""
        rip = uc.reg_read(UC_X86_REG_RIP)
        
        # Check if this is C++ exception (RCX = 0xE06D7363)
        from unicorn.x86_const import UC_X86_REG_RCX
        rcx = uc.reg_read(UC_X86_REG_RCX)
        
        if rcx == 0xE06D7363:
            # This is a C++ exception being thrown
            print(f"[EXCEPTION] C++ exception at RIP=0x{rip:x}")
            print(f"[EXCEPTION] Stopping emulation - something went wrong in CPU-Z")
            # Stop emulation
            uc.emu_stop()
            return False
        
        # Try to map memory for the write
        if address < 0x10000:
            print(f"[MEM] NULL pointer write @ 0x{address:x}, size={size}, RIP=0x{rip:x}")
            print(f"[MEM] Mapping zero page for write...")
            try:
                page_start = (address // 0x1000) * 0x1000
                if page_start < 0x3000:
                    page_start = 0x3000
                uc.mem_map(page_start, 0x1000)
                uc.mem_write(page_start, b'\x00' * 0x1000)
                print(f"[MEM] Mapped zero page at 0x{page_start:x}")
                return True
            except Exception as e:
                print(f"[MEM] Failed to map: {e}")
                return True
        
        print(f"[MEM] Unmapped write @ 0x{address:x}, size={size}, value={value}, RIP=0x{rip:x}")
        return False
    
    def _hook_mem_fetch_unmapped(self, uc, access, address, size, value, user_data):
        """Handle unmapped code execution - skip invalid function calls"""
        rip = uc.reg_read(UC_X86_REG_RIP)
        rsp = uc.reg_read(UC_X86_REG_RSP)
        
        print(f"[MEM] Unmapped code fetch @ 0x{address:x}, called from RIP=0x{rip:x}")
        
        # Map a page at this address with a simple RET instruction
        try:
            page_start = (address // 0x1000) * 0x1000
            page_size = 0x1000
            uc.mem_map(page_start, page_size)
            
            # Write RET instruction (0xC3) at the address
            # Also set RAX to 1 (success): MOV RAX, 1; RET
            stub_code = bytes([
                0x48, 0xC7, 0xC0, 0x01, 0x00, 0x00, 0x00,  # MOV RAX, 1
                0xC3,              # RET
            ])
            uc.mem_write(address, stub_code)
            
            print(f"[MEM] Mapped page at 0x{page_start:x} with RET stub")
            return True
        except Exception as e:
            print(f"[MEM] Failed to map page: {e}")
            return False
    
    def load_pe(self, pe_path):
        """Load PE file"""
        print(f"\n[*] Loading PE: {pe_path}")
        
        self.pe_loader = PELoader(self)
        entry_point = self.pe_loader.load(pe_path)
        
        print(f"[*] Entry point: 0x{entry_point:x}")
        print(f"[*] Image base: 0x{self.pe_loader.image_base:x}")

        
        return entry_point
    
    def load_code(self, code, base_addr=0x400000):
        """Load machine code directly"""
        # Allocate memory (at least 4KB, aligned)
        code_size = max(((len(code) + 0xFFF) // 0x1000) * 0x1000, 0x1000)
        self.uc.mem_map(base_addr, code_size)
        
        # Write code
        self.uc.mem_write(base_addr, code)
        
        print(f"[*] Allocated {code_size} bytes at 0x{base_addr:x}")
        
        return base_addr
    
    def run(self, start_addr, end_addr=0, max_instructions=100000, verbose=True):
        """Run emulation"""
        if verbose:
            print(f"\n[*] Starting emulation from address 0x{start_addr:x}")
            print(f"[*] Initial state: {self.clock}")
            print("-" * 70)
        
        try:
            # Set RIP
            self.uc.reg_write(UC_X86_REG_RIP, start_addr)
            
            # Start emulation
            self.uc.emu_start(start_addr, end_addr, count=max_instructions)
            
        except UcError as e:
            if verbose:
                print(f"\n[!] Emulation error: {e}")
                print(f"[!] RIP: 0x{self.uc.reg_read(UC_X86_REG_RIP):x}")
        
        if verbose:
            print("-" * 70)
            print(f"\n[*] Emulation finished")
            print(f"[*] Final state: {self.clock}")
            print(f"[*] Instructions executed: {self.instruction_count:,}")
            print(f"[*] System calls: {self.syscall_count}")
        
        # Return RAX (exit code)
        return self.uc.reg_read(UC_X86_REG_RAX)


if __name__ == "__main__":
    print("Layered Emulator — расслоенная эмуляция с WinAPI")
    print("\nИспользование:")
    print("  from layered_emulator import LayeredEmulator")
    print("  emu = LayeredEmulator()")
    print("  entry = emu.load_pe('demo.exe')")
    print("  emu.run(entry)")
