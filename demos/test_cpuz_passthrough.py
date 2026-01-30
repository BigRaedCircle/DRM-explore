#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CPU-Z с passthrough режимом - вызываем реальные Windows API

Стратегия: минимум эмуляции, максимум реальных вызовов
"""

import sys
import os
sys.path.insert(0, 'src/core')

from layered_emulator import LayeredEmulator


def test_cpuz_passthrough():
    """Тест CPU-Z с реальными API вызовами"""
    print("=" * 70)
    print("CPU-Z: PASSTHROUGH MODE (Real Windows API)")
    print("=" * 70)
    
    # Change to CPU-Z directory
    os.chdir("sandbox/CPU-Z")
    
    cpuz_path = "cpuz.exe"
    
    print(f"\n[*] Стратегия: вызываем РЕАЛЬНЫЕ Windows API")
    print(f"[*] Логирование: winapi_calls.log")
    print(f"[*] Цель: получить полный лог для создания заглушек\n")
    
    try:
        emu = LayeredEmulator(cpu_freq_mhz=3000)
        
        # Patch GetCommandLineW для правильных аргументов
        original_get_cmd = emu.winapi._stub_get_command_line_w
        
        def patched_get_command_line_w():
            cmd_line = "cpuz.exe -txt=report\x00".encode('utf-16le')
            ptr = emu.os.HeapAlloc(emu.os.heap.process_heap, 0, len(cmd_line))
            emu.uc.mem_write(ptr, cmd_line)
            emu.uc.reg_write(emu.uc.arch_const.UC_X86_REG_RAX, ptr)
            print(f"[API] GetCommandLineW() -> \"cpuz.exe -txt=report\"")
            return ptr
        
        emu.winapi._stub_get_command_line_w = patched_get_command_line_w
        
        # Load PE
        entry_point = emu.load_pe(cpuz_path)
        
        print(f"\n[*] Запускаем CPU-Z...")
        print(f"[*] Entry point: 0x{entry_point:x}")
        print(f"[*] Максимум инструкций: 10,000,000")
        print("-" * 70)
        
        # Run with increased limit
        exit_code = emu.run(
            start_addr=entry_point,
            end_addr=0,
            max_instructions=10000000,
            verbose=False
        )
        
        print("-" * 70)
        print(f"\n[*] Эмуляция завершена")
        print(f"    Exit code: {exit_code}")
        print(f"    Инструкций: {emu.instruction_count:,}")
        print(f"    Виртуальное время: {emu.clock}")
        
        # Check for report file
        print(f"\n[*] Проверяем результат...")
        
        if os.path.exists("report.txt"):
            file_size = os.path.getsize("report.txt")
            print(f"[✓] УСПЕХ! Файл report.txt создан ({file_size} байт)")
            
            # Show first lines
            with open("report.txt", 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read(500)
                print(f"\n[*] Первые строки отчёта:")
                print("-" * 70)
                print(content)
                print("-" * 70)
            
            return True
        else:
            print(f"[✗] Файл report.txt НЕ создан")
            print(f"\n[*] Возможные причины:")
            print(f"    1. CPU-Z не дошёл до генерации отчёта")
            print(f"    2. Нужно больше инструкций")
            print(f"    3. Отсутствует критичная функция")
            
            return False
        
    except Exception as e:
        print(f"\n[✗] Ошибка: {e}")
        import traceback
        traceback.print_exc()
        return False
    finally:
        # Return to original directory
        os.chdir("../..")


def main():
    print("=" * 70)
    print("ТЕСТ: CPU-Z с реальными Windows API (Passthrough Mode)")
    print("=" * 70)
    print()
    
    success = test_cpuz_passthrough()
    
    print("\n" + "=" * 70)
    print("ИТОГИ")
    print("=" * 70)
    
    if success:
        print("\n[✓✓✓] ТЕСТ ПРОЙДЕН!")
        print("\nCPU-Z успешно создал отчёт!")
        print("Лог вызовов сохранён в winapi_calls.log")
    else:
        print("\n[✗] ТЕСТ НЕ ПРОЙДЕН")
        print("\nCPU-Z не смог создать отчёт")
        print("Проверьте лог для анализа")
    
    print()
    
    return 0 if success else 1


if __name__ == "__main__":
    exit(main())
