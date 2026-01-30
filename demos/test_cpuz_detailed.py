#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Детальный тест эмуляции CPU-Z с анализом вызовов

Цель: Понять, какие функции CPU-Z активно использует,
чтобы добавить недостающие заглушки.
"""

import sys
sys.path.insert(0, 'src/core')

from layered_emulator import LayeredEmulator


def test_cpuz_detailed():
    """Детальный тест CPU-Z с подсчётом всех вызовов"""
    print("=" * 70)
    print("ДЕТАЛЬНЫЙ ТЕСТ: CPU-Z (cpuz.exe)")
    print("=" * 70)
    
    cpuz_path = "sandbox/CPU-Z/cpuz.exe"
    
    print(f"\n[*] Загружаем: {cpuz_path}")
    
    emu = LayeredEmulator(cpu_freq_mhz=3000)
    
    # Счётчики вызовов для ВСЕХ заглушек
    api_calls = {}
    
    # Патчим ВСЕ заглушки для подсчёта
    for stub_name, stub_info in emu.winapi.stubs.items():
        original_handler = stub_info['handler']
        
        def make_patched_handler(name, orig):
            def patched():
                if name not in api_calls:
                    api_calls[name] = 0
                api_calls[name] += 1
                return orig()
            return patched
        
        stub_info['handler'] = make_patched_handler(stub_name, original_handler)
    
    # Загружаем и запускаем
    entry_point = emu.load_pe(cpuz_path)
    
    print(f"\n[*] Начинаем эмуляцию...")
    print(f"[*] Entry point: 0x{entry_point:x}")
    print(f"[*] Максимум инструкций: 200,000")
    print("-" * 70)
    
    try:
        exit_code = emu.run(
            start_addr=entry_point,
            end_addr=0,
            max_instructions=200000,
            verbose=False  # Отключаем детальный вывод
        )
    except Exception as e:
        print(f"\n[!] Эмуляция остановлена: {e}")
    
    print("-" * 70)
    print(f"\n[*] Эмуляция завершена")
    print(f"    Инструкций выполнено: {emu.instruction_count:,}")
    print(f"    Виртуальное время: {emu.clock}")
    
    # Анализируем вызовы
    print(f"\n[*] Статистика API вызовов:")
    print(f"    Всего уникальных функций: {len(api_calls)}")
    print(f"    Всего вызовов: {sum(api_calls.values())}")
    
    # Топ-20 самых вызываемых функций
    print(f"\n[*] Топ-20 самых вызываемых функций:")
    sorted_calls = sorted(api_calls.items(), key=lambda x: x[1], reverse=True)
    for i, (func_name, count) in enumerate(sorted_calls[:20], 1):
        print(f"    {i:2}. {func_name:30} - {count:,} раз")
    
    # Группируем по категориям
    categories = {
        'Время': ['GetTickCount64', 'QueryPerformanceCounter', 'QueryPerformanceFrequency', 
                  'GetSystemTimeAsFileTime'],
        'Память': ['GetProcessHeap', 'HeapAlloc', 'HeapFree', 'HeapSize', 'HeapReAlloc', 
                   'VirtualProtect'],
        'Процесс/Поток': ['GetCurrentProcessId', 'GetCurrentThreadId', 'GetCurrentProcess'],
        'DLL/Модули': ['LoadLibraryA', 'LoadLibraryW', 'GetProcAddress', 'GetModuleHandleW'],
        'Файлы': ['CreateFileA', 'CreateFileW', 'ReadFile', 'CloseHandle'],
        'Система': ['GetSystemInfo', 'Sleep'],
        'CRT': ['GetCommandLineA', 'GetCommandLineW', 'GetStartupInfoW', 
                'InitializeSListHead', 'SetUnhandledExceptionFilter'],
        'GUI': ['MessageBoxA', 'MessageBoxW'],
        'Выход': ['ExitProcess'],
    }
    
    print(f"\n[*] Вызовы по категориям:")
    for category, funcs in categories.items():
        category_calls = sum(api_calls.get(func, 0) for func in funcs)
        if category_calls > 0:
            print(f"\n  {category}: {category_calls:,} вызовов")
            for func in funcs:
                count = api_calls.get(func, 0)
                if count > 0:
                    print(f"    - {func:30} {count:,}")
    
    # Проверяем, какие функции НЕ вызывались
    unused_stubs = [name for name in emu.winapi.stubs.keys() if name not in api_calls]
    if unused_stubs:
        print(f"\n[*] Неиспользованные заглушки ({len(unused_stubs)}):")
        for func in sorted(unused_stubs):
            print(f"    - {func}")
    
    print()


if __name__ == "__main__":
    test_cpuz_detailed()
