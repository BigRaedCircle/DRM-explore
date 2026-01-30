#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PE Loader — загрузка PE-файлов в эмулятор

Минимальная реализация для загрузки учебного анти-тампера.
"""

import pefile
from unicorn.x86_const import *


class PELoader:
    """Загрузчик PE-файлов для эмулятора"""
    
    def __init__(self, emulator):
        self.emu = emulator
        self.pe = None
        self.image_base = 0
        self.entry_point = 0
    
    def load(self, filepath):
        """Load PE file into emulator memory"""
        print(f"[*] Loading PE: {filepath}")
        
        # Parse PE
        self.pe = pefile.PE(filepath)
        
        # Get base address and entry point
        self.image_base = self.pe.OPTIONAL_HEADER.ImageBase
        self.entry_point = self.image_base + self.pe.OPTIONAL_HEADER.AddressOfEntryPoint
        
        print(f"[*] ImageBase: 0x{self.image_base:x}")
        print(f"[*] EntryPoint: 0x{self.entry_point:x}")
        print(f"[*] Sections: {self.pe.FILE_HEADER.NumberOfSections}")
        
        # Allocate memory for image
        image_size = self.pe.OPTIONAL_HEADER.SizeOfImage
        try:
            self.emu.uc.mem_map(self.image_base, image_size)
            print(f"[*] Allocated memory: {image_size:,} bytes")
        except:
            print(f"[*] Memory already allocated")
        
        # Load sections
        self._load_sections()
        
        # Process imports (patch IAT)
        self._process_imports()
        
        # Setup stack
        self._setup_stack()
        
        print(f"[OK] PE loaded successfully\n")
        return self.entry_point
    
    def _load_sections(self):
        """Load all sections into memory"""
        print(f"\n[*] Loading sections:")
        
        from unicorn import UC_PROT_ALL
        
        for section in self.pe.sections:
            name = section.Name.decode('ascii', errors='ignore').strip('\x00')
            va = self.image_base + section.VirtualAddress
            size = section.Misc_VirtualSize
            data = section.get_data()
            
            if data:
                # Write section data
                # Use UC_PROT_ALL to allow IAT patching
                self.emu.uc.mem_write(va, data)
                print(f"    {name:<12} 0x{va:x}  {len(data):,} bytes")
    
    def _process_imports(self):
        """Process imports and patch IAT"""
        print(f"\n[*] Processing imports:")
        
        if not hasattr(self.pe, 'DIRECTORY_ENTRY_IMPORT'):
            print("    [!] No imports")
            return
        
        import_count = 0
        patched_count = 0
        
        # IAT is already loaded in sections (.rdata or .idata)
        # No need to allocate additional memory
        
        for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
            dll_name = entry.dll.decode('ascii', errors='ignore')
            print(f"    DLL: {dll_name}")
            
            for imp in entry.imports:
                import_count += 1
                func_name = imp.name.decode('ascii', errors='ignore') if imp.name else f"Ordinal_{imp.ordinal}"
                
                # imp.address already contains absolute address (not RVA!)
                iat_address = imp.address
                
                # Check if we have a stub for this function
                stub_addr = self.emu.winapi.get_stub_address(func_name)
                
                if stub_addr:
                    # Patch IAT - write stub address
                    try:
                        self.emu.uc.mem_write(iat_address, stub_addr.to_bytes(8, 'little'))
                        patched_count += 1
                        print(f"      [+] {func_name:<30} @ 0x{iat_address:x} -> 0x{stub_addr:x}")
                    except Exception as e:
                        print(f"      [-] {func_name:<30} @ 0x{iat_address:x} (patch error: {e})")
                else:
                    # No stub - create dummy stub
                    dummy_stub = self._create_dummy_stub(func_name)
                    try:
                        self.emu.uc.mem_write(iat_address, dummy_stub.to_bytes(8, 'little'))
                        print(f"      [?] {func_name:<30} @ 0x{iat_address:x} -> dummy")
                    except Exception as e:
                        print(f"      [-] {func_name:<30} @ 0x{iat_address:x} (error: {e})")
        
        print(f"\n    [*] Imports: {import_count}, patched: {patched_count}")
    
    def _create_dummy_stub(self, func_name):
        """Create dummy stub for unknown function"""
        # Allocate unique address for each stub
        # Use counter to create unique addresses
        if not hasattr(self, '_dummy_stub_counter'):
            self._dummy_stub_counter = 0
            self._dummy_stub_names = {}  # Map address -> function name
            # Выделяем память для dummy stubs (64KB должно хватить)
            try:
                dummy_region_base = self.emu.winapi.STUB_BASE + 0xF000
                dummy_region_size = 0x10000  # 64KB
                self.emu.uc.mem_map(dummy_region_base, dummy_region_size)
                print(f"      [*] Allocated dummy stub region: 0x{dummy_region_base:x} ({dummy_region_size} bytes)")
            except Exception as e:
                # Память уже выделена или ошибка
                pass
        
        dummy_base = self.emu.winapi.STUB_BASE + 0xF000 + (self._dummy_stub_counter * 16)
        self._dummy_stub_counter += 1
        
        # Save function name for this stub
        self._dummy_stub_names[dummy_base] = func_name
        
        # Write smarter stub: MOV RAX, 1; RET (возвращаем SUCCESS вместо NULL)
        # Большинство WinAPI функций возвращают TRUE (1) при успехе
        stub_code = bytes([
            0x48, 0xC7, 0xC0, 0x01, 0x00, 0x00, 0x00,  # MOV RAX, 1
            0xC3,              # RET
        ])
        
        try:
            self.emu.uc.mem_write(dummy_base, stub_code)
        except Exception as e:
            print(f"      [!] Error writing dummy stub: {e}")
        
        return dummy_base
    
    def _setup_stack(self):
        """Setup stack"""
        # Stack already allocated in SimpleEmulator
        # Just set pointers
        stack_top = self.emu.STACK_BASE + self.emu.STACK_SIZE - 0x1000
        
        self.emu.uc.reg_write(UC_X86_REG_RSP, stack_top)
        self.emu.uc.reg_write(UC_X86_REG_RBP, stack_top)
        
        print(f"\n[*] Stack: 0x{stack_top:x}")


if __name__ == "__main__":
    # Тест загрузчика
    import sys
    from simple_emulator import SimpleEmulator
    
    if len(sys.argv) < 2:
        print("Использование: python pe_loader.py <файл.exe>")
        sys.exit(1)
    
    emu = SimpleEmulator()
    loader = PELoader(emu)
    
    try:
        entry = loader.load(sys.argv[1])
        print(f"[OK] Готов к запуску с адреса 0x{entry:x}")
    except Exception as e:
        print(f"[!] Ошибка загрузки: {e}")
        import traceback
        traceback.print_exc()
