#!/usr/bin/env python3
import pefile

pe = pefile.PE('sandbox/CoreInfo/Coreinfo64.exe')

print("CoreInfo Imports:")
print("=" * 70)

for entry in pe.DIRECTORY_ENTRY_IMPORT:
    dll_name = entry.dll.decode('ascii', errors='ignore')
    print(f"\n{dll_name}:")
    
    for imp in entry.imports:
        func_name = imp.name.decode('ascii', errors='ignore') if imp.name else f"Ordinal_{imp.ordinal}"
        print(f"  - {func_name}")
