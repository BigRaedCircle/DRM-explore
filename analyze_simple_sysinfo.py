#!/usr/bin/env python3
"""
Analyze simple_sysinfo.exe imports
"""

import pefile

pe = pefile.PE('demos/simple_sysinfo.exe')

print("=" * 70)
print("simple_sysinfo.exe - Import Analysis")
print("=" * 70)

if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        dll_name = entry.dll.decode('utf-8')
        print(f"\n{dll_name}:")
        for imp in entry.imports:
            if imp.name:
                func_name = imp.name.decode('utf-8')
                print(f"  - {func_name}")
            else:
                print(f"  - Ordinal_{imp.ordinal}")

print("\n" + "=" * 70)
