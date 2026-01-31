#!/usr/bin/env python3
"""
Analyze what's in the memory region 0x14003a4f8-0x14003a550
"""

import pefile

def analyze_memory_region():
    pe_path = "sandbox/CoreInfo/Coreinfo64.exe"
    
    print("=" * 70)
    print("CoreInfo Memory Region Analysis")
    print("=" * 70)
    
    pe = pefile.PE(pe_path)
    
    image_base = pe.OPTIONAL_HEADER.ImageBase
    
    # Адреса, которые нас интересуют
    problem_addresses = [
        0x14003a4f8,
        0x14003a500,
        0x14003a508,
        0x14003a510,  # Вызывается чаще всего
        0x14003a518,
        0x14003a528,
        0x14003a538,
        0x14003a540,
        0x14003a548,
        0x14003a550,
    ]
    
    print(f"\nImage Base: 0x{image_base:x}")
    print(f"\nChecking addresses 0x14003a4f8 - 0x14003a550:")
    print("-" * 70)
    
    # Найдем, в какой секции находятся эти адреса
    for addr in problem_addresses:
        rva = addr - image_base
        
        # Найдем секцию
        section = None
        for sec in pe.sections:
            sec_start = sec.VirtualAddress
            sec_end = sec.VirtualAddress + sec.Misc_VirtualSize
            
            if sec_start <= rva < sec_end:
                section = sec
                break
        
        if section:
            sec_name = section.Name.decode('utf-8').rstrip('\x00')
            offset_in_section = rva - section.VirtualAddress
            file_offset = section.PointerToRawData + offset_in_section
            
            # Читаем 8 байт по этому адресу
            data = pe.get_data(rva, 8)
            value = int.from_bytes(data, 'little')
            
            print(f"\n0x{addr:x} (RVA: 0x{rva:x}):")
            print(f"  Section: {sec_name}")
            print(f"  File offset: 0x{file_offset:x}")
            print(f"  Value: 0x{value:016x}")
            print(f"  Bytes: {data.hex()}")
            
            # Проверим, является ли это адресом в образе
            if image_base <= value < image_base + pe.OPTIONAL_HEADER.SizeOfImage:
                target_rva = value - image_base
                print(f"  -> Points to RVA 0x{target_rva:x} (inside image)")
                
                # Найдем секцию цели
                for sec in pe.sections:
                    sec_start = sec.VirtualAddress
                    sec_end = sec.VirtualAddress + sec.Misc_VirtualSize
                    
                    if sec_start <= target_rva < sec_end:
                        target_sec_name = sec.Name.decode('utf-8').rstrip('\x00')
                        print(f"  -> Target section: {target_sec_name}")
                        break
            else:
                print(f"  -> Not a valid image address")
        else:
            print(f"\n0x{addr:x}: NOT IN ANY SECTION")
    
    # Проверим delay-load imports
    print(f"\n{'='*70}")
    print("DELAY-LOAD IMPORTS")
    print(f"{'='*70}")
    
    if hasattr(pe, 'DIRECTORY_ENTRY_DELAY_IMPORT'):
        for entry in pe.DIRECTORY_ENTRY_DELAY_IMPORT:
            dll_name = entry.dll.decode('utf-8')
            print(f"\nDLL: {dll_name}")
            print("-" * 70)
            
            for imp in entry.imports:
                if imp.address:
                    func_name = imp.name.decode('utf-8') if imp.name else f"Ordinal_{imp.ordinal}"
                    print(f"  {func_name:40s} @ 0x{imp.address:x}")
                    
                    # Проверим, совпадает ли с нашими адресами
                    if imp.address in problem_addresses:
                        print(f"    *** MATCH! This is {func_name} from {dll_name} ***")
    else:
        print("\nNo delay-load imports found")
    
    # Проверим bound imports
    print(f"\n{'='*70}")
    print("BOUND IMPORTS")
    print(f"{'='*70}")
    
    if hasattr(pe, 'DIRECTORY_ENTRY_BOUND_IMPORT'):
        for entry in pe.DIRECTORY_ENTRY_BOUND_IMPORT:
            print(f"\nDLL: {entry.name.decode('utf-8')}")
    else:
        print("\nNo bound imports found")


if __name__ == '__main__':
    analyze_memory_region()
