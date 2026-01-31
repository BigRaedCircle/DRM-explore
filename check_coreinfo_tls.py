#!/usr/bin/env python3
"""
Check if CoreInfo has TLS callbacks
"""

import pefile

pe_path = "sandbox/CoreInfo/Coreinfo64.exe"
pe = pefile.PE(pe_path)

print("=" * 70)
print("CoreInfo TLS Callback Check")
print("=" * 70)

# Check for TLS directory
if hasattr(pe, 'DIRECTORY_ENTRY_TLS'):
    print("\n[+] TLS Directory found!")
    tls = pe.DIRECTORY_ENTRY_TLS.struct
    
    print(f"\nTLS Directory:")
    print(f"  StartAddressOfRawData: 0x{tls.StartAddressOfRawData:x}")
    print(f"  EndAddressOfRawData: 0x{tls.EndAddressOfRawData:x}")
    print(f"  AddressOfIndex: 0x{tls.AddressOfIndex:x}")
    print(f"  AddressOfCallBacks: 0x{tls.AddressOfCallBacks:x}")
    print(f"  SizeOfZeroFill: {tls.SizeOfZeroFill}")
    print(f"  Characteristics: 0x{tls.Characteristics:x}")
    
    # Check if there are callbacks
    if tls.AddressOfCallBacks:
        print(f"\n[+] TLS Callbacks found at 0x{tls.AddressOfCallBacks:x}")
        
        # Try to read callbacks (this is tricky because they're in memory layout)
        # AddressOfCallBacks points to an array of function pointers
        # We need to convert VA to file offset
        
        callbacks_va = tls.AddressOfCallBacks
        callbacks_rva = callbacks_va - pe.OPTIONAL_HEADER.ImageBase
        
        print(f"    RVA: 0x{callbacks_rva:x}")
        
        # Find section containing this RVA
        for section in pe.sections:
            sec_start = section.VirtualAddress
            sec_end = section.VirtualAddress + section.Misc_VirtualSize
            
            if sec_start <= callbacks_rva < sec_end:
                sec_name = section.Name.decode('utf-8').rstrip('\x00')
                offset_in_section = callbacks_rva - section.VirtualAddress
                file_offset = section.PointerToRawData + offset_in_section
                
                print(f"    Section: {sec_name}")
                print(f"    File offset: 0x{file_offset:x}")
                
                # Read callback pointers (array of QWORDs, terminated by NULL)
                callback_num = 0
                while True:
                    data = pe.get_data(callbacks_rva + callback_num * 8, 8)
                    callback_ptr = int.from_bytes(data, 'little')
                    
                    if callback_ptr == 0:
                        break
                    
                    callback_rva = callback_ptr - pe.OPTIONAL_HEADER.ImageBase
                    print(f"\n    Callback #{callback_num + 1}:")
                    print(f"      VA: 0x{callback_ptr:x}")
                    print(f"      RVA: 0x{callback_rva:x}")
                    
                    callback_num += 1
                    
                    if callback_num > 10:  # Safety limit
                        print("      (stopping after 10 callbacks)")
                        break
                
                if callback_num == 0:
                    print("\n    [!] No callbacks found (array is empty)")
                else:
                    print(f"\n    [+] Found {callback_num} TLS callback(s)")
                
                break
    else:
        print("\n[-] No TLS callbacks (AddressOfCallBacks is NULL)")
else:
    print("\n[-] No TLS Directory found")
    print("    CoreInfo does not use TLS callbacks")

print("\n" + "=" * 70)
