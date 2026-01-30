#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Тест реального выполнения CPU-Z с генерацией отчёта

Запускаем: cpuz.exe -txt=report
Ожидаем: создание файла report.txt с информацией о системе
"""

import sys
import os
sys.path.insert(0, 'src/core')

from layered_emulator import LayeredEmulator


def test_cpuz_report_generation():
    """Тест генерации отчёта CPU-Z"""
    print("=" * 70)
    print("ТЕСТ: CPU-Z генерация отчёта (cpuz.exe -txt=report)")
    print("=" * 70)
    
    # Сохраняем текущую директорию
    original_dir = os.getcwd()
    
    # Переходим в папку CPU-Z
    os.chdir("sandbox/CPU-Z")
    
    cpuz_path = "cpuz.exe"
    report_path = "report.txt"
    
    # Удаляем старый отчёт если есть
    if os.path.exists(report_path):
        os.remove(report_path)
        print(f"\n[*] Удалён старый отчёт: {report_path}")
    
    print(f"\n[*] Загружаем: {cpuz_path}")
    print(f"[*] Аргументы: -txt=report")
    print(f"[*] Рабочая директория: {os.getcwd()}")
    
    try:
        emu = LayeredEmulator(cpu_freq_mhz=3000)
        
        # Модифицируем GetCommandLineW для возврата правильных аргументов
        original_get_command_line_w = emu.winapi._stub_get_command_line_w
        
        def patched_get_command_line_w():
            """Возвращаем командную строку с аргументами"""
            # Создаём командную строку: "cpuz.exe -txt=report"
            cmd_line = "cpuz.exe -txt=report\x00".encode('utf-16le')
            
            # Выделяем память для командной строки
            ptr = emu.os.HeapAlloc(emu.os.heap.process_heap, 0, len(cmd_line))
            emu.uc.mem_write(ptr, cmd_line)
            emu.uc.reg_write(emu.uc.arch_const.UC_X86_REG_RAX, ptr)
            
            print(f"[API] GetCommandLineW()")
            print(f"  -> 0x{ptr:x} (\"cpuz.exe -txt=report\")")
            print(f"  <- returning to 0x{emu.uc.reg_read(emu.uc.arch_const.UC_X86_REG_RIP):x}")
            
            return ptr
        
        emu.winapi._stub_get_command_line_w = patched_get_command_line_w
        
        # Загружаем PE файл
        entry_point = emu.load_pe(cpuz_path)
        
        print(f"\n[*] Начинаем эмуляцию...")
        print(f"[*] Entry point: 0x{entry_point:x}")
        print(f"[*] Максимум инструкций: 10,000,000")
        print("-" * 70)
        
        # Запускаем эмуляцию с большим лимитом
        exit_code = emu.run(
            start_addr=entry_point,
            end_addr=0,
            max_instructions=10000000,  # 10 миллионов инструкций
            verbose=False  # Отключаем детальный вывод
        )
        
        print("-" * 70)
        print(f"\n[*] Эмуляция завершена")
        print(f"    Exit code: {exit_code}")
        print(f"    Инструкций выполнено: {emu.instruction_count:,}")
        print(f"    Виртуальное время: {emu.clock}")
        
        # Проверяем, создался ли файл отчёта
        print(f"\n[*] Проверяем наличие отчёта...")
        
        if os.path.exists(report_path):
            file_size = os.path.getsize(report_path)
            print(f"[✓] Файл отчёта создан: {report_path}")
            print(f"[✓] Размер файла: {file_size} байт")
            
            # Читаем и показываем содержимое
            print(f"\n[*] Содержимое отчёта:")
            print("-" * 70)
            with open(report_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                print(content[:1000])  # Первые 1000 символов
                if len(content) > 1000:
                    print(f"\n... (всего {len(content)} символов)")
            print("-" * 70)
            
            return True
        else:
            print(f"[✗] Файл отчёта НЕ создан: {report_path}")
            print(f"\n[!] Возможные причины:")
            print(f"    1. CPU-Z не дошёл до кода генерации отчёта")
            print(f"    2. Отсутствует заглушка для WriteFile")
            print(f"    3. Недостаточно инструкций для выполнения")
            print(f"    4. Ошибка при парсинге аргументов командной строки")
            
            # Проверяем, какие файловые операции были вызваны
            print(f"\n[*] Проверяем вызовы файловых операций...")
            
            # Проверяем VirtualFileSystem
            if hasattr(emu, 'vfs') and emu.vfs:
                print(f"    VirtualFileSystem:")
                print(f"      Открытых файлов: {len(emu.vfs.open_files)}")
                for handle, file_info in emu.vfs.open_files.items():
                    print(f"        Handle 0x{handle:x}: {file_info.get('path', 'unknown')}")
            
            return False
        
    except Exception as e:
        print(f"\n[✗] Ошибка при выполнении: {e}")
        import traceback
        traceback.print_exc()
        return False
    finally:
        # Возвращаемся в исходную директорию
        os.chdir(original_dir)


def main():
    print("=" * 70)
    print("ТЕСТИРОВАНИЕ РЕАЛЬНОГО ВЫПОЛНЕНИЯ CPU-Z")
    print("=" * 70)
    print("\nЗапускаем CPU-Z с параметром -txt=report")
    print("Ожидаем создание файла report.txt с информацией о системе")
    print()
    
    success = test_cpuz_report_generation()
    
    print("\n" + "=" * 70)
    print("ИТОГИ")
    print("=" * 70)
    
    if success:
        print("\n[✓✓✓] ТЕСТ ПРОЙДЕН!")
        print("\nCPU-Z успешно выполнен в эмуляторе!")
        print("Отчёт создан, программа работает корректно.")
    else:
        print("\n[✗] ТЕСТ НЕ ПРОЙДЕН")
        print("\nCPU-Z не смог создать отчёт.")
        print("Нужно добавить недостающие заглушки или увеличить лимит инструкций.")
    
    print()
    
    return 0 if success else 1


if __name__ == "__main__":
    exit(main())
