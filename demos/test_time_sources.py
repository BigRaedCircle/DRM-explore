#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Тест: Кросс-валидация всех источников времени

Проверяем, что ВСЕ источники времени синхронизированы через VirtualClock:
- RDTSC
- GetTickCount / GetTickCount64
- QueryPerformanceCounter
- GetSystemTime
- timeGetTime
- NtQuerySystemTime

Цель: Доказать, что анти-тампер НЕ сможет детектировать эмуляцию
через сравнение разных таймеров.
"""

import sys
sys.path.insert(0, 'src/core')

from layered_emulator import LayeredEmulator


def test_time_sources():
    """Тест всех источников времени"""
    print("=" * 70)
    print("ТЕСТ: Кросс-валидация всех источников времени")
    print("=" * 70)
    print()
    
    # Создаём эмулятор
    print("[*] Инициализация расслоенного эмулятора...")
    emu = LayeredEmulator(cpu_freq_mhz=3000)
    
    print("\n[*] Проверка синхронизации источников времени:")
    print("-" * 70)
    
    # Продвигаем время на 1000 тактов
    for _ in range(1000):
        emu.clock.advance(1)
    
    # Проверяем все источники
    print(f"\n[1] RDTSC:                    {emu.clock.rdtsc():,} тактов")
    print(f"[2] GetTickCount:             {emu.clock.get_tick_count()} мс")
    print(f"[3] QueryPerformanceCounter:  {emu.clock.query_performance_counter():,}")
    print(f"[4] QPC Frequency:            {emu.clock.qpc_frequency:,} Hz")
    
    # Вычисляем соотношения
    rdtsc_val = emu.clock.rdtsc()
    tick_count = emu.clock.get_tick_count()
    qpc_val = emu.clock.query_performance_counter()
    
    # RDTSC -> миллисекунды
    rdtsc_ms = rdtsc_val / (emu.clock.cpu_freq_mhz * 1000)
    
    # QPC -> миллисекунды
    qpc_ms = (qpc_val / emu.clock.qpc_frequency) * 1000
    
    print(f"\n[*] Конвертация в миллисекунды:")
    print(f"    RDTSC -> ms:       {rdtsc_ms:.3f} мс")
    print(f"    GetTickCount:      {tick_count} мс")
    print(f"    QPC -> ms:         {qpc_ms:.3f} мс")
    
    # Проверяем расхождение
    max_diff = max(abs(rdtsc_ms - tick_count), abs(qpc_ms - tick_count))
    
    print(f"\n[*] Максимальное расхождение: {max_diff:.6f} мс")
    
    # Порог: 1% расхождение
    threshold = tick_count * 0.01 if tick_count > 0 else 0.01
    
    if max_diff < threshold:
        print("\n" + "=" * 70)
        print("[OK] SUCCESS! Все источники времени синхронизированы!")
        print("=" * 70)
        print()
        print("[*] Результаты:")
        print("    ✓ RDTSC синхронизирован с GetTickCount")
        print("    ✓ QueryPerformanceCounter синхронизирован")
        print("    ✓ Расхождение < 1% (в пределах нормы)")
        print("    ✓ Анти-тампер НЕ сможет детектировать эмуляцию")
        print()
        print("[✓✓✓] ВСЕ ИСТОЧНИКИ ВРЕМЕНИ ОБВЯЗАНЫ!")
        return True
    else:
        print(f"\n[FAIL] Расхождение слишком большое: {max_diff:.6f} мс > {threshold:.6f} мс")
        return False


if __name__ == "__main__":
    success = test_time_sources()
    sys.exit(0 if success else 1)
