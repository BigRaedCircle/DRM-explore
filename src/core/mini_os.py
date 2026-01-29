#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MiniOS - Minimal OS layer for PE emulation

Provides:
- Virtual memory management (pages, protection)
- Heap management (for HeapAlloc/HeapFree)
- Basic OS structures (PEB, TEB)
- Minimal WinAPI implementation for CRT support
"""

import struct
from collections import defaultdict


class MemoryPage:
    """Single memory page (4KB)"""
    PAGE_SIZE = 0x1000
    
    # Protection flags
    PAGE_NOACCESS = 0x01
    PAGE_READONLY = 0x02
    PAGE_READWRITE = 0x04
    PAGE_EXECUTE = 0x10
    PAGE_EXECUTE_READ = 0x20
    PAGE_EXECUTE_READWRITE = 0x40
    
    def __init__(self, address, size, protection):
        self.address = address
        self.size = size
        self.protection = protection
        self.allocated = True


class VirtualMemoryManager:
    """Virtual memory manager - tracks allocations and protections"""
    
    def __init__(self, uc):
        self.uc = uc
        self.pages = {}  # address -> MemoryPage
        self.allocations = {}  # base_address -> (size, protection)
        
    def allocate(self, address, size, protection):
        """Allocate virtual memory region"""
        # Align to page boundary
        aligned_addr = address & ~0xFFF
        aligned_size = ((size + 0xFFF) // 0x1000) * 0x1000
        
        # Map in Unicorn
        try:
            self.uc.mem_map(aligned_addr, aligned_size)
        except Exception as e:
            # Already mapped - that's ok
            pass
        
        # Track allocation
        self.allocations[aligned_addr] = (aligned_size, protection)
        
        # Track pages
        for offset in range(0, aligned_size, 0x1000):
            page_addr = aligned_addr + offset
            self.pages[page_addr] = MemoryPage(page_addr, 0x1000, protection)
        
        return aligned_addr
    
    def free(self, address):
        """Free virtual memory region"""
        if address not in self.allocations:
            return False
        
        size, _ = self.allocations[address]
        
        # Remove pages
        for offset in range(0, size, 0x1000):
            page_addr = address + offset
            if page_addr in self.pages:
                del self.pages[page_addr]
        
        # Remove allocation
        del self.allocations[address]
        return True
    
    def protect(self, address, size, new_protection):
        """Change memory protection"""
        aligned_addr = address & ~0xFFF
        aligned_size = ((size + 0xFFF) // 0x1000) * 0x1000
        
        for offset in range(0, aligned_size, 0x1000):
            page_addr = aligned_addr + offset
            if page_addr in self.pages:
                self.pages[page_addr].protection = new_protection
        
        return True
    
    def query(self, address):
        """Query memory information"""
        page_addr = address & ~0xFFF
        if page_addr in self.pages:
            page = self.pages[page_addr]
            return (page.address, page.size, page.protection)
        return None


class HeapManager:
    """Simple heap manager for HeapAlloc/HeapFree"""
    
    def __init__(self, uc, vmm, base_address=0x10000000, size=0x10000000):
        self.uc = uc
        self.vmm = vmm
        self.base_address = base_address
        self.size = size
        self.next_alloc = base_address
        
        # Allocate heap region
        self.vmm.allocate(base_address, size, MemoryPage.PAGE_READWRITE)
        
        # Track allocations: address -> size
        self.allocations = {}
        
        # Default process heap handle
        self.process_heap = 0x00010000
    
    def alloc(self, size, flags=0):
        """Allocate memory from heap"""
        # Align to 16 bytes
        aligned_size = ((size + 15) // 16) * 16
        
        # Check if we have space
        if self.next_alloc + aligned_size > self.base_address + self.size:
            return 0  # Out of memory
        
        # Allocate
        address = self.next_alloc
        self.next_alloc += aligned_size
        self.allocations[address] = aligned_size
        
        # Zero memory if requested
        if flags & 0x00000008:  # HEAP_ZERO_MEMORY
            self.uc.mem_write(address, b'\x00' * aligned_size)
        
        return address
    
    def free(self, address):
        """Free heap memory"""
        if address not in self.allocations:
            return False
        
        # Simple implementation - just mark as freed
        # (no coalescing or reuse for now)
        del self.allocations[address]
        return True
    
    def realloc(self, address, new_size):
        """Reallocate heap memory"""
        if address == 0:
            return self.alloc(new_size)
        
        if address not in self.allocations:
            return 0
        
        old_size = self.allocations[address]
        
        # Allocate new block
        new_address = self.alloc(new_size)
        if new_address == 0:
            return 0
        
        # Copy old data
        copy_size = min(old_size, new_size)
        data = self.uc.mem_read(address, copy_size)
        self.uc.mem_write(new_address, bytes(data))
        
        # Free old block
        self.free(address)
        
        return new_address


class MiniOS:
    """Minimal OS layer for PE emulation"""
    
    def __init__(self, uc, clock):
        self.uc = uc
        self.clock = clock
        
        # Memory management
        self.vmm = VirtualMemoryManager(uc)
        self.heap = HeapManager(uc, self.vmm)
        
        # OS structures
        self.peb_address = 0x7FFE0000
        self.teb_address = 0x7FFE1000
        
        self._setup_os_structures()
    
    def _setup_os_structures(self):
        """Setup basic OS structures (PEB, TEB)"""
        # Allocate PEB
        self.vmm.allocate(self.peb_address, 0x1000, MemoryPage.PAGE_READONLY)
        
        # Allocate TEB
        self.vmm.allocate(self.teb_address, 0x1000, MemoryPage.PAGE_READWRITE)
        
        # Write minimal PEB structure
        peb_data = struct.pack('<Q', self.heap.process_heap)  # ProcessHeap at offset 0x30
        self.uc.mem_write(self.peb_address + 0x30, peb_data)
        
        # Write minimal TEB structure
        teb_data = struct.pack('<Q', self.peb_address)  # PEB pointer at offset 0x60
        self.uc.mem_write(self.teb_address + 0x60, teb_data)
    
    # === WinAPI implementations ===
    
    def GetProcessHeap(self):
        """Get process heap handle"""
        return self.heap.process_heap
    
    def HeapAlloc(self, heap_handle, flags, size):
        """Allocate memory from heap"""
        return self.heap.alloc(size, flags)
    
    def HeapFree(self, heap_handle, flags, address):
        """Free heap memory"""
        return 1 if self.heap.free(address) else 0
    
    def HeapReAlloc(self, heap_handle, flags, address, size):
        """Reallocate heap memory"""
        return self.heap.realloc(address, size)
    
    def VirtualAlloc(self, address, size, allocation_type, protect):
        """Allocate virtual memory"""
        if address == 0:
            # Let system choose address
            address = 0x20000000 + len(self.vmm.allocations) * 0x100000
        
        return self.vmm.allocate(address, size, protect)
    
    def VirtualFree(self, address, size, free_type):
        """Free virtual memory"""
        return 1 if self.vmm.free(address) else 0
    
    def VirtualProtect(self, address, size, new_protect):
        """Change memory protection"""
        old_protect = 0
        if self.vmm.protect(address, size, new_protect):
            # Return old protection (simplified - just return PAGE_READWRITE)
            old_protect = MemoryPage.PAGE_READWRITE
        return old_protect
    
    def VirtualQuery(self, address):
        """Query virtual memory information"""
        return self.vmm.query(address)
    
    def GetTickCount64(self):
        """Get milliseconds since start"""
        return self.clock.get_tick_count()
    
    def QueryPerformanceCounter(self):
        """Get high-resolution counter"""
        return self.clock.query_performance_counter()
    
    def QueryPerformanceFrequency(self):
        """Get counter frequency"""
        return self.clock.query_performance_frequency()
    
    def GetSystemTimeAsFileTime(self):
        """Get system time as FILETIME"""
        return self.clock.get_system_time_as_file_time()
    
    def OutputDebugStringA(self, string_ptr):
        """Output debug string"""
        try:
            # Read null-terminated string
            data = b''
            addr = string_ptr
            while True:
                byte = self.uc.mem_read(addr, 1)[0]
                if byte == 0:
                    break
                data += bytes([byte])
                addr += 1
            
            msg = data.decode('ascii', errors='ignore')
            print(f"[DEBUG] {msg}")
        except:
            pass
    
    def GetLastError(self):
        """Get last error code"""
        # Simplified - always return success
        return 0
    
    def SetLastError(self, error_code):
        """Set last error code"""
        # Simplified - ignore for now
        pass


if __name__ == "__main__":
    print("MiniOS - Minimal OS layer for PE emulation")
    print("\nProvides:")
    print("  - Virtual memory management")
    print("  - Heap management")
    print("  - Basic OS structures (PEB, TEB)")
    print("  - Minimal WinAPI for CRT support")
