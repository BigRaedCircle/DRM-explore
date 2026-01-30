#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Analyze CPU-Z PE structure using pefile
"""

import pefile
import sys


def analyze_cpuz():
    """Analyze CPU-Z executable"""
    cpuz_path = "sandbox/CPU-Z/cpuz.exe"
    
    print("=" * 80)
    print("CPU-Z PE ANALYSIS")
    print("=" * 80)
    
    pe = pefile.PE(cpuz_path)
    
    # Basic info
    print(f"\n[*] Basic Information:")
    print(f"    Machine: {hex(pe.FILE_HEADER.Machine)}")
    print(f"    Number of Sections: {pe.FILE_HEADER.NumberOfSections}")
    print(f"    Time Date Stamp: {pe.FILE_HEADER.TimeDateStamp}")
    print(f"    Image Base: 0x{pe.OPTIONAL_HEADER.ImageBase:x}")
    print(f"    Entry Point: 0x{pe.OPTIONAL_HEADER.AddressOfEntryPoint:x}")
    print(f"    Entry Point (absolute): 0x{pe.OPTIONAL_HEADER.ImageBase + pe.OPTIONAL_HEADER.AddressOfEntryPoint:x}")
    
    # Sections
    print(f"\n[*] Sections:")
    for section in pe.sections:
        name = section.Name.decode('utf-8').rstrip('\x00')
        print(f"    {name:10} VirtAddr: 0x{section.VirtualAddress:08x}  "
              f"VirtSize: 0x{section.Misc_VirtualSize:08x}  "
              f"RawSize: 0x{section.SizeOfRawData:08x}  "
              f"Characteristics: 0x{section.Characteristics:08x}")
    
    # Imports
    print(f"\n[*] Import Summary:")
    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        dll_count = len(pe.DIRECTORY_ENTRY_IMPORT)
        print(f"    Total DLLs: {dll_count}")
        
        total_imports = 0
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll_name = entry.dll.decode('utf-8')
            import_count = len(entry.imports)
            total_imports += import_count
            print(f"    {dll_name:30} - {import_count:3} imports")
        
        print(f"\n    Total imports: {total_imports}")
    
    # Find specific imports we care about
    print(f"\n[*] File I/O Functions:")
    file_io_funcs = ['CreateFileA', 'CreateFileW', 'ReadFile', 'WriteFile', 
                     'CloseHandle', 'GetFileSize', 'SetFilePointer']
    
    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll_name = entry.dll.decode('utf-8')
            for imp in entry.imports:
                if imp.name:
                    func_name = imp.name.decode('utf-8')
                    if func_name in file_io_funcs:
                        print(f"    {dll_name:20} -> {func_name:30} @ 0x{imp.address:x}")
    
    # Exports (if any)
    print(f"\n[*] Exports:")
    if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            print(f"    {exp.name.decode('utf-8'):40} @ 0x{exp.address:x}")
    else:
        print(f"    No exports")
    
    # Resources
    print(f"\n[*] Resources:")
    if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
        def print_resources(entry, level=0):
            indent = "    " * level
            if hasattr(entry, 'id'):
                if entry.id:
                    print(f"{indent}ID: {entry.id.name if hasattr(entry.id, 'name') else entry.id}")
            if hasattr(entry, 'directory'):
                for e in entry.directory.entries:
                    print_resources(e, level + 1)
        
        for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries:
            print_resources(entry, 1)
    else:
        print(f"    No resources")
    
    # TLS (Thread Local Storage)
    print(f"\n[*] TLS:")
    if hasattr(pe, 'DIRECTORY_ENTRY_TLS'):
        tls = pe.DIRECTORY_ENTRY_TLS.struct
        print(f"    Start Address: 0x{tls.StartAddressOfRawData:x}")
        print(f"    End Address: 0x{tls.EndAddressOfRawData:x}")
        print(f"    Index Address: 0x{tls.AddressOfIndex:x}")
        print(f"    Callbacks: 0x{tls.AddressOfCallBacks:x}")
    else:
        print(f"    No TLS")
    
    # Look for strings in .rdata section
    print(f"\n[*] Interesting strings in .rdata:")
    for section in pe.sections:
        if b'.rdata' in section.Name:
            data = section.get_data()
            # Find ASCII strings
            strings = []
            current = b''
            for byte in data:
                if 32 <= byte <= 126:  # Printable ASCII
                    current += bytes([byte])
                else:
                    if len(current) >= 10:  # At least 10 chars
                        try:
                            s = current.decode('ascii')
                            if 'report' in s.lower() or 'txt' in s.lower() or 'file' in s.lower():
                                strings.append(s)
                        except:
                            pass
                    current = b''
            
            print(f"    Found {len(strings)} interesting strings:")
            for s in strings[:20]:  # Show first 20
                print(f"      {s}")
    
    pe.close()


if __name__ == "__main__":
    analyze_cpuz()
