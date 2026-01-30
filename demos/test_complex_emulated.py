#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Тест комплексного анти-тампера в эмуляторе
"""

import sys
sys.path.insert(0, 'src/core')

from layered_emulator import LayeredEmulator


def test_complex_antitamper_emulated():
    """Тест комплексного анти-тампера в эмуляторе"""
    print("╔" + "═" * 68 + "╗")
    print("║" + " " * 68 + "║")
    print("║" + "  КОМПЛЕКСНЫЙ АНТИ-ТАМПЕР В ЭМУЛЯТОРЕ".center(68) + "║")
    print("║" + " " * 68 + "║")
    print("╚" + "═" * 68 + "╝")
    print()
    
    exe_path = "demos/complex_antitamper.exe"
    
    print(f"[*] Программа: {exe_path}")
    print(f"[*] Тесты:")
    print(f"    1. RDTSC проверка")
    print(f"    2. GetTickCount проверка")
    print(f"    3. QueryPerformanceCounter проверка")
    print(f"    4. Валидация лицензии (валидный ключ)")
    print(f"    5. Обфускация и проверки целостности")
    print(f"    6. Валидация лицензии (невалидный ключ)")
    print()
    
    try:
        print("[*] Инициализация эмулятора...")
        emu = LayeredEmulator(cpu_freq_mhz=3000)
        
        print("[*] Загрузка PE файла...")
        entry_point = emu.load_pe(exe_path)
        
        print(f"[*] Entry point: 0x{entry_point:x}")
        print(f"[*] Image base: 0x{emu.pe_loader.image_base:x}")
        print()
        print("=" * 70)
        print("ЗАПУСК ЭМУЛЯЦИИ")
        print("=" * 70)
        print()
        
        # Run emulation
        exit_code = emu.run(
            start_addr=entry_point,
            end_addr=0,
            max_instructions=500000,  # Увеличили лимит
            verbose=False  # Отключили детальный вывод для скорости
        )
        
        print()
        print("=" * 70)
        print("РЕЗУЛЬТАТЫ ЭМУЛЯЦИИ")
        print("=" * 70)
        print(f"Exit code:    {exit_code}")
        print(f"Инструкций:   {emu.instruction_count:,}")
        print(f"Время:        {emu.clock}")
        print(f"Тики RDTSC:   {emu.clock.rdtsc():,}")
        print("=" * 70)
        print()
        
        if exit_code == 0:
            print("╔" + "═" * 68 + "╗")
            print("║" + " " * 68 + "║")
            print("║" + "  🎉 ВСЕ ТЕСТЫ ПРОЙДЕНЫ!".center(68) + "║")
            print("║" + " " * 68 + "║")
            print("║" + "  Эмулятор корректно обрабатывает:".center(68) + "║")
            print("║" + "    ✓ RDTSC инструкции".center(68) + "║")
            print("║" + "    ✓ Проверки времени (GetTickCount, QPC)".center(68) + "║")
            print("║" + "    ✓ Лицензионные проверки".center(68) + "║")
            print("║" + "    ✓ Обфускацию и проверки целостности".center(68) + "║")
            print("║" + "    ✓ Множественные уровни валидации".center(68) + "║")
            print("║" + " " * 68 + "║")
            print("╚" + "═" * 68 + "╝")
            return True
        else:
            print("╔" + "═" * 68 + "╗")
            print("║" + " " * 68 + "║")
            print("║" + "  ⚠️  ТЕСТЫ НЕ ПРОЙДЕНЫ".center(68) + "║")
            print("║" + " " * 68 + "║")
            print("║" + f"  Exit code: {exit_code}".center(68) + "║")
            print("║" + " " * 68 + "║")
            print("╚" + "═" * 68 + "╝")
            return False
        
    except Exception as e:
        print()
        print("╔" + "═" * 68 + "╗")
        print("║" + " " * 68 + "║")
        print("║" + "  ❌ ОШИБКА ЭМУЛЯЦИИ".center(68) + "║")
        print("║" + " " * 68 + "║")
        print("║" + f"  {str(e)[:60]}".center(68) + "║")
        print("║" + " " * 68 + "║")
        print("╚" + "═" * 68 + "╝")
        
        import traceback
        print("\nПодробности:")
        traceback.print_exc()
        
        return False


if __name__ == "__main__":
    success = test_complex_antitamper_emulated()
    exit(0 if success else 1)
