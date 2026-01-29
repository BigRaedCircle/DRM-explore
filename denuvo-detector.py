#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Denuvo Detector — детальный анализ PE-файла на признаки защиты Denuvo Anti-Tamper
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
        return f"invalid (0x{ts:x})"

def section_rights(section):
    rights = []
    if section.Characteristics & 0x20000000: rights.append('X')
    if section.Characteristics & 0x40000000: rights.append('R')
    if section.Characteristics & 0x80000000: rights.append('W')
    if section.Characteristics & 0x02000000: rights.append('NC')
    return ''.join(rights) if rights else '-'

def detect_denuvo(filepath):
    print(f"[+] Анализ файла: {filepath}")
    print("=" * 90)
    
    try:
        pe = pefile.PE(filepath, fast_load=False)
    except Exception as e:
        print(f"[!] Ошибка загрузки PE: {e}")
        return False

    # Базовая информация
    print(f"\n[БАЗОВАЯ ИНФОРМАЦИЯ]")
    try:
        machine = pe.FILE_HEADER.Machine
        machine_str = pefile.MACHINE_TYPE.get(machine, f"Unknown (0x{machine:x})")
        print(f"  Архитектура: 0x{machine:04x} ({machine_str})")
    except Exception as e:
        print(f"  Архитектура: ошибка ({e})")
    
    print(f"  Временная метка: {format_timestamp(pe.FILE_HEADER.TimeDateStamp)}")
    print(f"  Секций: {pe.FILE_HEADER.NumberOfSections}")
    print(f"  EntryPoint RVA: 0x{pe.OPTIONAL_HEADER.AddressOfEntryPoint:x}")
    print(f"  ImageBase: 0x{pe.OPTIONAL_HEADER.ImageBase:x}")
    print(f"  SizeOfImage: {pe.OPTIONAL_HEADER.SizeOfImage:,} байт ({pe.OPTIONAL_HEADER.SizeOfImage/1024/1024:.2f} МБ)")

    # Анализ секций
    print(f"\n[СЕКЦИИ PE-ФАЙЛА]")
    print(f"{'#':<3} {'Имя':<12} {'RVA':<12} {'Размер':<10} {'Права':<8} {'Энтропия':<10} {'Хеш (MD5 первых 64КБ)':<32}")
    print("-" * 90)
    
    denuvo_candidates = []
    suspicious_sections = []
    
    for i, section in enumerate(pe.sections):
        try:
            name = section.Name.decode('ascii', errors='ignore').strip('\x00')
        except:
            name = repr(section.Name)
        
        va = section.VirtualAddress
        size = section.Misc_VirtualSize or section.SizeOfRawData
        rights = section_rights(section)
        
        # Энтропия (высокая энтропия ≈ шифрование/упаковка)
        data = section.get_data()
        entropy = calculate_entropy(data[:min(1024, len(data))]) if data else 0.0
        
        # Хеш первых 64КБ
        md5 = hashlib.md5(data[:min(65536, len(data))]).hexdigest() if data else 'N/A'
        
        # Детекция признаков Denuvo
        is_denuvo = False
        reasons = []
        
        if any(marker in name.lower() for marker in ['.vm', '.denuvo', 'denuvo', 'vmcode']):
            is_denuvo = True
            reasons.append('имя секции')
        
        # Подозрительные права
        if 'W' in rights and 'X' in rights:
            reasons.append('WX права')
            suspicious_sections.append((name, va, size, rights))
        
        # Высокая энтропия + большой размер
        if entropy > 7.0 and size > 0x10000:
            reasons.append(f'высокая энтропия ({entropy:.2f})')
        
        if is_denuvo:
            denuvo_candidates.append((name, va, size, rights, entropy, reasons, data[:64] if data else b''))
        
        print(f"{i:<3} {name:<12} 0x{va:<10x} {size:<10,} {rights:<8} {entropy:<10.2f} {md5}")

    # Детальный анализ секций Denuvo
    if denuvo_candidates:
        print(f"\n[!] ОБНАРУЖЕНЫ СЕКЦИИ DENUVO ({len(denuvo_candidates)})")
        for name, va, size, rights, entropy, reasons, sample in denuvo_candidates:
            print(f"\n  → Секция #{i}: {name}")
            print(f"     RVA: 0x{va:x} | Размер: {size:,} байт ({size/1024/1024:.2f} МБ)")
            print(f"     Права: {rights} | Энтропия: {entropy:.2f}")
            print(f"     Признаки: {', '.join(reasons)}")
            if sample:
                hex_str = binascii.hexlify(sample).decode()
                ascii_str = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in sample)
                print(f"     Первые 64 байта:")
                print(f"        HEX : {hex_str}")
                print(f"        ASCII: {ascii_str}")
    else:
        print(f"\n[?] Секции с явными именами Denuvo (.vm/.denuvo) НЕ НАЙДЕНЫ")

    # Поиск строковых сигнатур во ВСЕХ секциях
    print(f"\n[ПОИСК СТРОКОВЫХ СИГНАТУР ВО ВСЕХ СЕКЦИЯХ]")
    signatures = [
        b'denuvo', b'Denuvo', b'DENUVO',
        b'anti_tamper', b'antitamper',
        b'vmprotect', b'VMProtect',
        b'secureregion'
    ]
    found_any = False
    
    for section in pe.sections:
        try:
            name = section.Name.decode('ascii', errors='ignore').strip('\x00')
            data = section.get_data()
            if not data:
                continue
            
            for sig in signatures:
                pos = data.lower().find(sig.lower())
                if pos != -1:
                    if not found_any:
                        print("")
                    found_any = True
                    context_start = max(0, pos - 40)
                    context_end = min(len(data), pos + 40)
                    context = data[context_start:context_end]
                    
                    # Попытка декодировать контекст как ASCII для читаемости
                    try:
                        ascii_ctx = context.decode('ascii', errors='ignore')
                        printable = ''.join(c if 32 <= ord(c) <= 126 else '.' for c in ascii_ctx)
                    except:
                        printable = binascii.hexlify(context[:20]).decode() + '...'
                    
                    print(f"  [+] '{sig.decode()}' в секции '{name}'")
                    print(f"      Смещение в секции: +0x{pos:x} | Общий сдвиг: +0x{section.PointerToRawData + pos:x}")
                    print(f"      Контекст: {printable}")
        except Exception as e:
            continue  # Пропускаем проблемные секции
    
    if not found_any:
        print("  Строковые сигнатуры не обнаружены в данных секций")

    # Анализ импортов
    print(f"\n[ИМПОРТЫ — косвенные признаки защиты]")
    suspicious_apis = {
        'kernel32.dll': ['VirtualProtect', 'VirtualAlloc', 'VirtualQuery', 'IsDebuggerPresent', 
                        'CheckRemoteDebuggerPresent', 'OutputDebugStringA', 'GetTickCount'],
        'ntdll.dll': ['NtQueryInformationProcess', 'NtSetInformationThread', 'RtlAdjustPrivilege']
    }
    found_imports = []
    
    try:
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode('ascii', errors='ignore').lower()
                for imp in entry.imports:
                    if imp.name:
                        api_name = imp.name.decode('ascii', errors='ignore')
                        for suspicious_dll, apis in suspicious_apis.items():
                            if suspicious_dll in dll_name:
                                if any(api.lower() in api_name.lower() for api in apis):
                                    found_imports.append(f"{dll_name}!{api_name}")
    except:
        pass
    
    if found_imports:
        print(f"  Найдено подозрительных API: {len(found_imports)}")
        for i, api in enumerate(found_imports[:10], 1):  # Первые 10
            print(f"    {i}. {api}")
        if len(found_imports) > 10:
            print(f"    ... и ещё {len(found_imports) - 10}")
    else:
        print("  Подозрительные API не найдены (или таблица импортов отсутствует)")

    print("\n" + "=" * 90)
    return bool(denuvo_candidates) or found_any

def calculate_entropy(data):
    """Расчёт энтропии Шеннона для байтового блока (0.0–8.0)"""
    if not data:
        return 0.0
    import math
    from collections import Counter
    entropy = 0
    counter = Counter(data)
    length = len(data)
    for count in counter.values():
        p_x = count / length
        entropy += -p_x * math.log2(p_x)
    return entropy

def scan_directory(directory, recursive=False, extensions=('.exe', '.dll')):
    """Сканирование директории на наличие исполняемых файлов"""
    import os
    from pathlib import Path
    
    path = Path(directory)
    if not path.exists():
        print(f"[!] Путь не существует: {directory}")
        return []
    
    files = []
    if recursive:
        for ext in extensions:
            files.extend(path.rglob(f'*{ext}'))
    else:
        for ext in extensions:
            files.extend(path.glob(f'*{ext}'))
    
    return [str(f) for f in files]

def batch_scan(files, output_format='text'):
    """Пакетное сканирование файлов"""
    results = []
    total = len(files)
    
    print(f"\n[BATCH SCAN] Сканирование {total} файлов...\n")
    
    for idx, filepath in enumerate(files, 1):
        print(f"[{idx}/{total}] {filepath}")
        try:
            # Быстрая проверка без детального вывода
            pe = pefile.PE(filepath, fast_load=True)
            
            has_denuvo = False
            evidence = []
            
            # Проверка секций
            for section in pe.sections:
                name = section.Name.decode('ascii', errors='ignore').strip('\x00')
                if any(marker in name.lower() for marker in ['.vm', '.denuvo', 'denuvo']):
                    has_denuvo = True
                    evidence.append(f"section:{name}")
                    break
            
            # Быстрый поиск сигнатур только в .ecode/.text
            if not has_denuvo:
                for section in pe.sections:
                    name = section.Name.decode('ascii', errors='ignore').strip('\x00')
                    if name in ['.ecode', '.text', '.data']:
                        data = section.get_data()
                        if b'denuvo' in data.lower():
                            has_denuvo = True
                            evidence.append(f"signature:{name}")
                            break
            
            results.append({
                'file': filepath,
                'protected': has_denuvo,
                'evidence': evidence
            })
            
            status = "✓ DENUVO" if has_denuvo else "✗ Clean"
            print(f"    → {status}\n")
            
        except Exception as e:
            results.append({
                'file': filepath,
                'protected': None,
                'error': str(e)
            })
            print(f"    → ERROR: {e}\n")
    
    return results

def export_results(results, format='json', output_file=None):
    """Экспорт результатов в JSON/CSV"""
    if format == 'json':
        import json
        data = json.dumps(results, indent=2, ensure_ascii=False)
        if output_file:
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(data)
            print(f"[+] Результаты сохранены: {output_file}")
        else:
            print(data)
    
    elif format == 'csv':
        import csv
        if not output_file:
            output_file = 'scan_results.csv'
        
        with open(output_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=['file', 'protected', 'evidence', 'error'])
            writer.writeheader()
            for r in results:
                writer.writerow({
                    'file': r.get('file', ''),
                    'protected': r.get('protected', ''),
                    'evidence': ';'.join(r.get('evidence', [])),
                    'error': r.get('error', '')
                })
        print(f"[+] Результаты сохранены: {output_file}")

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Denuvo Anti-Tamper Detector',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Примеры использования:
  python denuvo-detector.py game.exe                    # Детальный анализ одного файла
  python denuvo-detector.py -d "C:/Games" -r            # Рекурсивное сканирование папки
  python denuvo-detector.py -d . -o results.json        # Экспорт в JSON
  python denuvo-detector.py -d . -o results.csv -f csv  # Экспорт в CSV
        """
    )
    
    parser.add_argument('file', nargs='?', help='Путь к EXE/DLL файлу для анализа')
    parser.add_argument('-d', '--directory', help='Сканировать директорию')
    parser.add_argument('-r', '--recursive', action='store_true', help='Рекурсивное сканирование')
    parser.add_argument('-o', '--output', help='Файл для сохранения результатов')
    parser.add_argument('-f', '--format', choices=['json', 'csv'], default='json', help='Формат экспорта')
    parser.add_argument('-q', '--quiet', action='store_true', help='Тихий режим (только результат)')
    
    args = parser.parse_args()
    
    try:
        # Режим пакетного сканирования
        if args.directory:
            files = scan_directory(args.directory, args.recursive)
            if not files:
                print("[!] Исполняемые файлы не найдены")
                sys.exit(1)
            
            results = batch_scan(files)
            
            if args.output:
                export_results(results, args.format, args.output)
            
            # Статистика
            protected = sum(1 for r in results if r.get('protected'))
            clean = sum(1 for r in results if r.get('protected') == False)
            errors = sum(1 for r in results if 'error' in r)
            
            print(f"\n{'='*50}")
            print(f"[СТАТИСТИКА]")
            print(f"  Всего файлов: {len(results)}")
            print(f"  С Denuvo: {protected}")
            print(f"  Без защиты: {clean}")
            print(f"  Ошибок: {errors}")
            print(f"{'='*50}\n")
            
            sys.exit(0)
        
        # Режим детального анализа одного файла
        elif args.file:
            if args.quiet:
                # Быстрая проверка без детального вывода
                pe = pefile.PE(args.file, fast_load=True)
                has_denuvo = False
                
                for section in pe.sections:
                    data = section.get_data()
                    if b'denuvo' in data.lower():
                        has_denuvo = True
                        break
                
                print("DENUVO" if has_denuvo else "CLEAN")
                sys.exit(0 if has_denuvo else 1)
            else:
                print(f"\nЗапуск анализа: {args.file}\n")
                has_denuvo = detect_denuvo(args.file)
                print(f"\n[ИТОГ] {'✓✓✓ DENUVO ОБНАРУЖЕН ✓✓✓' if has_denuvo else '✗✗✗ Denuvo не обнаружен статически ✗✗✗'}\n")
                sys.exit(0 if has_denuvo else 1)
        
        else:
            parser.print_help()
            sys.exit(1)
            
    except KeyboardInterrupt:
        print("\n[!] Анализ прерван пользователем")
        sys.exit(2)
    except Exception as e:
        print(f"\n[!] Критическая ошибка: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(3)
