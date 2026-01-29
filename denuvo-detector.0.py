#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Denuvo Detector — детальный анализ PE-файла на признаки защиты Denuvo Anti-Tamper
Важно: используйте ТОЛЬКО для анализа законно приобретённых копий игр
"""

import pefile
import sys
import hashlib
import binascii
from datetime import datetime

def format_timestamp(ts):
    try:
        return datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
    except:
        return "invalid"

def section_rights(section):
    rights = []
    if section.Characteristics & 0x20000000: rights.append('Execute')
    if section.Characteristics & 0x40000000: rights.append('Read')
    if section.Characteristics & 0x80000000: rights.append('Write')
    if section.Characteristics & 0x00000200: rights.append('Discardable')
    if section.Characteristics & 0x02000000: rights.append('NotCached')
    return ','.join(rights) if rights else 'None'

def detect_denuvo(filepath):
    print(f"[+] Анализ файла: {filepath}")
    print("=" * 80)
    
    try:
        pe = pefile.PE(filepath, fast_load=False)
    except Exception as e:
        print(f"[!] Ошибка загрузки PE: {e}")
        return False

    # Базовая информация
    print(f"\n[БАЗОВАЯ ИНФОРМАЦИЯ]")
    print(f"  Архитектура: {pe.FILE_HEADER.Machine:x} ({pefile.MACHINE_TYPE[pe.FILE_HEADER.Machine].name})")
    print(f"  Временная метка: {format_timestamp(pe.FILE_HEADER.TimeDateStamp)} (0x{pe.FILE_HEADER.TimeDateStamp:x})")
    print(f"  Количество секций: {pe.FILE_HEADER.NumberOfSections}")
    print(f"  Размер образа: {pe.OPTIONAL_HEADER.SizeOfImage:,} байт")
    print(f"  EntryPoint: 0x{pe.OPTIONAL_HEADER.AddressOfEntryPoint:x}")
    
    # Анализ секций
    print(f"\n[СЕКЦИИ PE-ФАЙЛА]")
    print(f"{'Имя':<12} {'Вирт.Адрес':<14} {'Размер':<12} {'Права':<25} {'Хеш (MD5)':<32}")
    print("-" * 80)
    
    denuvo_candidates = []
    suspicious_sections = []
    
    for i, section in enumerate(pe.sections):
        name = section.Name.decode(errors='ignore').strip('\x00')
        va = section.VirtualAddress
        size = section.Misc_VirtualSize
        rights = section_rights(section)
        data = section.get_data()
        md5 = hashlib.md5(data[:min(65536, len(data))]).hexdigest()  # хеш первых 64КБ
        
        # Детекция признаков Denuvo
        is_denuvo = False
        reasons = []
        
        if '.vm' in name.lower() or '.denuvo' in name.lower():
            is_denuvo = True
            reasons.append('имя секции')
        
        # Подозрительные комбинации прав (например, исполняемые данные)
        if 'Execute' in rights and 'Write' in rights:
            reasons.append('RWX права')
            suspicious_sections.append((name, va, size, rights))
        
        # Аномально большой размер кода
        if name.strip() == '.text' and size > 0x1000000:  # >16 МБ
            reasons.append('огромный .text')
        
        if is_denuvo:
            denuvo_candidates.append((name, va, size, rights, reasons))
        
        print(f"{name:<12} 0x{va:<12x} {size:<12,} {rights:<25} {md5}")
    
    # Детальный анализ секций Denuvo
    if denuvo_candidates:
        print(f"\n[!] ОБНАРУЖЕНЫ СЕКЦИИ DENUVO ({len(denuvo_candidates)})")
        for name, va, size, rights, reasons in denuvo_candidates:
            print(f"\n  Секция: {name}")
            print(f"    Виртуальный адрес: 0x{va:x}")
            print(f"    Размер: {size:,} байт ({size/1024/1024:.2f} МБ)")
            print(f"    Права доступа: {rights}")
            print(f"    Признаки: {', '.join(reasons)}")
            
            # Пример данных из секции (первые 64 байта)
            data = pe.get_data(va, min(64, size))
            print(f"    Первые 64 байта (hex): {binascii.hexlify(data).decode()}")
    
    # Подозрительные секции с необычными правами
    if suspicious_sections:
        print(f"\n[!] ПОДОЗРИТЕЛЬНЫЕ СЕКЦИИ (необычные права доступа)")
        for name, va, size, rights in suspicious_sections:
            print(f"  {name:<12} 0x{va:x}  {size:<10,}  {rights}")
    
    # Поиск строковых сигнатур в ресурсах и секциях
    print(f"\n[ПОИСК СТРОКОВЫХ СИГНАТУР]")
    signatures = [b'denuvo', b'vmprotect', b'anti_tamper', b'securom']
    found = False
    
    # Поиск в секциях
    for section in pe.sections:
        data = section.get_data()
        for sig in signatures:
            pos = data.lower().find(sig)
            if pos != -1:
                context_start = max(0, pos - 30)
                context_end = min(len(data), pos + 30)
                context = data[context_start:context_end]
                print(f"  [+] Найдено '{sig.decode()}' в секции '{section.Name.decode().strip(chr(0))}'")
                print(f"      Позиция: +0x{pos:x} (от начала секции)")
                print(f"      Контекст: {context}")
                found = True
    
    # Поиск в ресурсах (если есть)
    if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
        print(f"\n  Анализ ресурсов...")
        # Упрощённый поиск — полный анализ требует рекурсивного обхода дерева ресурсов
    
    if not found:
        print("  Строковые сигнатуры не обнаружены")
    
    # Анализ импортов (косвенные признаки)
    print(f"\n[ИМПОРТЫ — косвенные признаки]")
    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        kernel32_imports = [imp.name for entry in pe.DIRECTORY_ENTRY_IMPORT 
                           for imp in entry.imports if b'kernel32' in entry.dll.lower()]
        suspicious_apis = ['VirtualProtect', 'VirtualAlloc', 'CreateThread', 'IsDebuggerPresent']
        for api in suspicious_apis:
            if any(api.lower().encode() in (imp or b'') for imp in kernel32_imports):
                print(f"  [!] Подозрительный API: {api}")
    else:
        print("  Таблица импортов отсутствует или повреждена")
    
    print("\n" + "=" * 80)
    return bool(denuvo_candidates)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Использование: python denuvo_detector.py <путь_к_exe>")
        sys.exit(1)
    
    filepath = sys.argv[1]
    has_denuvo = detect_denuvo(filepath)
    
    print(f"\n[РЕЗУЛЬТАТ] {'✓ Denuvo обнаружен' if has_denuvo else '✗ Denuvo не обнаружен (статически)'}")
    sys.exit(0 if has_denuvo else 1)
