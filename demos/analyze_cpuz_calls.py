#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Анализ вызовов WinAPI в CPU-Z

Определяет, какие функции вызываются чаще всего
и какие нужно реализовать в custom
"""

import sys
sys.path.insert(0, 'src/core')
sys.path.insert(0, 'tools')

import pefile
from collections import Counter


def analyze_cpuz_imports():
    """Анализ импортов CPU-Z"""
    print("=" * 70)
    print("АНАЛИЗ: Импорты CPU-Z")
    print("=" * 70)
    
    pe_path = "sandbox/CPU-Z/cpuz.exe"
    
    try:
        pe = pefile.PE(pe_path)
    except Exception as e:
        print(f"[!] Ошибка загрузки PE: {e}")
        return
    
    # Собираем все импорты
    imports_by_dll = {}
    total_imports = 0
    
    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll_name = entry.dll.decode('utf-8').lower()
            
            if dll_name not in imports_by_dll:
                imports_by_dll[dll_name] = []
            
            for imp in entry.imports:
                if imp.name:
                    func_name = imp.name.decode('utf-8')
                    imports_by_dll[dll_name].append(func_name)
                    total_imports += 1
    
    print(f"\n[*] Всего импортов: {total_imports}")
    print(f"[*] DLL библиотек: {len(imports_by_dll)}")
    
    # Показываем по DLL
    print(f"\n{'DLL':<30} {'Функций':<10}")
    print("-" * 70)
    
    for dll_name in sorted(imports_by_dll.keys(), key=lambda x: len(imports_by_dll[x]), reverse=True):
        count = len(imports_by_dll[dll_name])
        print(f"{dll_name:<30} {count:<10}")
    
    # Проверяем покрытие автогенерированными заглушками
    print(f"\n" + "=" * 70)
    print("ПОКРЫТИЕ: Автогенерированные заглушки")
    print("=" * 70)
    
    try:
        from generated import winapi_stubs_generated
        
        # Собираем все сгенерированные функции
        generated_funcs = set()
        for name in dir(winapi_stubs_generated):
            if name.startswith('_stub_'):
                func_name = name[6:]  # Убираем _stub_
                generated_funcs.add(func_name.lower())
        
        print(f"\n[*] Автогенерированных заглушек: {len(generated_funcs)}")
        
        # Проверяем покрытие для каждой DLL
        for dll_name in sorted(imports_by_dll.keys()):
            funcs = imports_by_dll[dll_name]
            covered = 0
            missing = []
            
            for func in funcs:
                if func.lower() in generated_funcs:
                    covered += 1
                else:
                    missing.append(func)
            
            coverage = (covered / len(funcs) * 100) if funcs else 0
            
            print(f"\n{dll_name}:")
            print(f"  Покрытие: {covered}/{len(funcs)} ({coverage:.1f}%)")
            
            if missing and len(missing) <= 10:
                print(f"  Отсутствуют:")
                for func in missing[:10]:
                    print(f"    - {func}")
            elif missing:
                print(f"  Отсутствуют: {len(missing)} функций")
                print(f"  Топ-10:")
                for func in missing[:10]:
                    print(f"    - {func}")
    
    except ImportError:
        print(f"\n[!] Не найдены автогенерированные заглушки")
        print(f"    Запустите: python tools/header_parser.py")
    
    # Рекомендации
    print(f"\n" + "=" * 70)
    print("РЕКОМЕНДАЦИИ")
    print("=" * 70)
    
    critical_dlls = ['kernel32.dll', 'ntdll.dll', 'user32.dll', 'advapi32.dll']
    
    print(f"\n[*] Критичные DLL для CPU-Z:")
    for dll in critical_dlls:
        if dll in imports_by_dll:
            count = len(imports_by_dll[dll])
            print(f"    - {dll}: {count} функций")
    
    print(f"\n[*] Следующие шаги:")
    print(f"    1. Добавить отсутствующие функции в header_parser.py")
    print(f"    2. Регенерировать заглушки")
    print(f"    3. Реализовать критичные функции в custom")
    print(f"    4. Запустить test_cpuz_with_v2_stubs.py")


def analyze_most_common_patterns():
    """Анализ наиболее частых паттернов функций"""
    print("\n" + "=" * 70)
    print("АНАЛИЗ: Частые паттерны функций")
    print("=" * 70)
    
    pe_path = "sandbox/CPU-Z/cpuz.exe"
    
    try:
        pe = pefile.PE(pe_path)
    except:
        return
    
    # Собираем все функции
    all_funcs = []
    
    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            for imp in entry.imports:
                if imp.name:
                    func_name = imp.name.decode('utf-8')
                    all_funcs.append(func_name)
    
    # Анализируем префиксы
    prefixes = Counter()
    for func in all_funcs:
        # Берём первые 3-4 символа как префикс
        if len(func) >= 3:
            prefix = func[:3]
            prefixes[prefix] += 1
    
    print(f"\n[*] Топ-10 префиксов функций:")
    for prefix, count in prefixes.most_common(10):
        print(f"    {prefix}*: {count} функций")
    
    # Анализируем категории
    categories = {
        'File I/O': ['CreateFile', 'ReadFile', 'WriteFile', 'CloseHandle', 'GetFileSize'],
        'Memory': ['VirtualAlloc', 'VirtualFree', 'HeapAlloc', 'HeapFree'],
        'Registry': ['RegOpenKey', 'RegQueryValue', 'RegCloseKey'],
        'Process': ['CreateProcess', 'GetCurrentProcess', 'OpenProcess'],
        'Thread': ['CreateThread', 'GetCurrentThread', 'SuspendThread'],
        'Module': ['LoadLibrary', 'GetProcAddress', 'GetModuleHandle'],
        'System Info': ['GetSystemInfo', 'GetVersionEx', 'GetComputerName'],
        'Timing': ['GetTickCount', 'QueryPerformanceCounter', 'Sleep'],
    }
    
    print(f"\n[*] Функции по категориям:")
    for category, keywords in categories.items():
        found = []
        for func in all_funcs:
            for keyword in keywords:
                if keyword.lower() in func.lower():
                    found.append(func)
                    break
        
        if found:
            print(f"\n  {category}: {len(found)} функций")
            for func in found[:5]:
                print(f"    - {func}")
            if len(found) > 5:
                print(f"    ... и ещё {len(found) - 5}")


if __name__ == '__main__':
    print("\n")
    print("╔" + "═" * 68 + "╗")
    print("║" + " " * 20 + "Анализ CPU-Z вызовов" + " " * 28 + "║")
    print("╚" + "═" * 68 + "╝")
    print()
    
    analyze_cpuz_imports()
    analyze_most_common_patterns()
    
    print("\n")
