#!/usr/bin/env python3
"""
Analyze CoreInfo IAT in detail to identify unknown functions
"""

import pefile
import sys

def analyze_iat():
    pe_path = "sandbox/CoreInfo/Coreinfo64.exe"
    
    print("=" * 70)
    print("CoreInfo IAT Analysis - Detailed")
    print("=" * 70)
    
    pe = pefile.PE(pe_path)
    
    print(f"\nImage Base: 0x{pe.OPTIONAL_HEADER.ImageBase:x}")
    print(f"Entry Point: 0x{pe.OPTIONAL_HEADER.AddressOfEntryPoint:x}")
    
    # Найдем IAT
    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        print(f"\n{'='*70}")
        print("IMPORT ADDRESS TABLE (IAT)")
        print(f"{'='*70}")
        
        iat_start = None
        iat_end = None
        
        all_imports = []
        
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll_name = entry.dll.decode('utf-8')
            print(f"\nDLL: {dll_name}")
            print("-" * 70)
            
            for imp in entry.imports:
                if imp.address:
                    if iat_start is None or imp.address < iat_start:
                        iat_start = imp.address
                    if iat_end is None or imp.address > iat_end:
                        iat_end = imp.address
                    
                    func_name = imp.name.decode('utf-8') if imp.name else f"Ordinal_{imp.ordinal}"
                    
                    all_imports.append({
                        'dll': dll_name,
                        'name': func_name,
                        'address': imp.address,
                        'ordinal': imp.ordinal
                    })
                    
                    print(f"  {func_name:40s} @ 0x{imp.address:x}")
        
        print(f"\n{'='*70}")
        print(f"IAT Range: 0x{iat_start:x} - 0x{iat_end:x} ({iat_end - iat_start} bytes)")
        print(f"Total imports: {len(all_imports)}")
        print(f"{'='*70}")
        
        # Теперь проверим, какие адреса в диапазоне IAT НЕ имеют импортов
        print(f"\n{'='*70}")
        print("CHECKING FOR GAPS IN IAT")
        print(f"{'='*70}")
        
        # Сортируем импорты по адресу
        all_imports.sort(key=lambda x: x['address'])
        
        # Проверяем пробелы
        gaps = []
        for i in range(len(all_imports) - 1):
            current_addr = all_imports[i]['address']
            next_addr = all_imports[i + 1]['address']
            
            expected_next = current_addr + 8  # 64-bit pointer
            
            if next_addr > expected_next:
                # Есть пробел!
                gap_start = expected_next
                gap_end = next_addr
                gap_size = (gap_end - gap_start) // 8
                
                gaps.append({
                    'start': gap_start,
                    'end': gap_end,
                    'count': gap_size,
                    'after': all_imports[i]['name'],
                    'before': all_imports[i + 1]['name']
                })
        
        if gaps:
            print(f"\nFound {len(gaps)} gaps in IAT:")
            for gap in gaps:
                print(f"\n  Gap: 0x{gap['start']:x} - 0x{gap['end']:x} ({gap['count']} entries)")
                print(f"    After:  {gap['after']}")
                print(f"    Before: {gap['before']}")
                
                # Показываем адреса в пробеле
                for addr in range(gap['start'], gap['end'], 8):
                    print(f"      0x{addr:x}")
        else:
            print("\nNo gaps found in IAT")
        
        # Проверим конкретные адреса, которые нас интересуют
        print(f"\n{'='*70}")
        print("CHECKING SPECIFIC ADDRESSES")
        print(f"{'='*70}")
        
        problem_addresses = [
            0x14003a4f8,
            0x14003a500,
            0x14003a508,
            0x14003a510,  # Этот вызывается чаще всего
            0x14003a518,
            0x14003a528,
            0x14003a538,
            0x14003a540,
            0x14003a548,
            0x14003a550,
        ]
        
        for addr in problem_addresses:
            # Ищем в импортах
            found = None
            for imp in all_imports:
                if imp['address'] == addr:
                    found = imp
                    break
            
            if found:
                print(f"\n0x{addr:x}: {found['dll']}!{found['name']}")
            else:
                print(f"\n0x{addr:x}: NOT FOUND IN IMPORTS")
                
                # Проверим, в каком пробеле это находится
                for gap in gaps:
                    if gap['start'] <= addr < gap['end']:
                        print(f"  -> In gap between {gap['after']} and {gap['before']}")
                        break
    
    else:
        print("\nNo imports found!")


if __name__ == '__main__':
    analyze_iat()
