#!/usr/bin/env python3
"""Анализ IAT CoreInfo для определения неизвестных функций"""

import pefile
import sys

def analyze_iat(pe_path):
    """Анализирует IAT и показывает все импорты"""
    pe = pefile.PE(pe_path)
    
    print(f"[*] Analyzing: {pe_path}")
    print(f"[*] ImageBase: 0x{pe.OPTIONAL_HEADER.ImageBase:x}")
    print()
    
    # Собираем все импорты
    if not hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        print("[!] No imports found")
        return
    
    print("[*] Import Address Table (IAT):")
    print()
    
    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        dll_name = entry.dll.decode('utf-8')
        print(f"DLL: {dll_name}")
        
        for imp in entry.imports:
            if imp.name:
                func_name = imp.name.decode('utf-8')
            else:
                func_name = f"Ordinal_{imp.ordinal}"
            
            # IAT адрес (где хранится указатель на функцию)
            iat_addr = imp.address
            
            print(f"  {func_name:40s} @ 0x{iat_addr:x}")
        
        print()
    
    # Проверяем delay-load imports
    if hasattr(pe, 'DIRECTORY_ENTRY_DELAY_IMPORT'):
        print("[*] Delay-Load Imports:")
        print()
        
        for entry in pe.DIRECTORY_ENTRY_DELAY_IMPORT:
            dll_name = entry.dll.decode('utf-8')
            print(f"DLL: {dll_name} (delay-load)")
            
            for imp in entry.imports:
                if imp.name:
                    func_name = imp.name.decode('utf-8')
                else:
                    func_name = f"Ordinal_{imp.ordinal}"
                
                iat_addr = imp.address
                print(f"  {func_name:40s} @ 0x{iat_addr:x}")
            
            print()
    
    # Проверяем bound imports
    if hasattr(pe, 'DIRECTORY_ENTRY_BOUND_IMPORT'):
        print("[*] Bound Imports:")
        print()
        
        for entry in pe.DIRECTORY_ENTRY_BOUND_IMPORT:
            dll_name = entry.name.decode('utf-8')
            print(f"DLL: {dll_name} (bound)")
            print()

if __name__ == '__main__':
    analyze_iat('sandbox/CoreInfo/Coreinfo64.exe')
