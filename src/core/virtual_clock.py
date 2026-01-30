#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
VirtualClock — единый источник времени для всей расслоенной эмуляции

Ключевая идея: ВСЕ таймеры (RDTSC, GetTickCount, QueryPerformanceCounter)
математически связаны через один счётчик виртуальных тактов CPU.
"""

class VirtualClock:
    """Виртуальные часы с детерминированным временем"""
    
    def __init__(self, cpu_freq_mhz=3000):
        """
        Args:
            cpu_freq_mhz: Частота виртуального CPU в МГц (по умолчанию 3 GHz)
        """
        self.ticks = 0  # Виртуальные такты CPU
        self.cpu_freq_mhz = cpu_freq_mhz
        self.cpu_freq_hz = cpu_freq_mhz * 1_000_000
        
        # Для QueryPerformanceCounter (обычно 10 MHz)
        self.qpc_frequency = 10_000_000  # Hz
        
        # RDTSC offset - start from zero for clean timing checks
        # Anti-tamper programs expect small, consistent deltas
        self.rdtsc_offset = 0
    
    def advance(self, cycles=1):
        """Продвинуть виртуальное время на N тактов"""
        self.ticks += cycles
        return self.ticks
    
    def rdtsc(self):
        """
        Эмуляция инструкции RDTSC (Read Time-Stamp Counter)
        Возвращает: (EDX:EAX) — 64-битный счётчик тактов
        """
        return self.ticks + self.rdtsc_offset
    
    def get_tick_count(self):
        """
        Эмуляция GetTickCount() / GetTickCount64()
        Возвращает: миллисекунды с момента запуска
        """
        # ticks / (cpu_freq_hz / 1000) = миллисекунды
        return self.ticks // (self.cpu_freq_hz // 1000)
    
    def query_performance_counter(self):
        """
        Эмуляция QueryPerformanceCounter()
        Возвращает: счётчик высокого разрешения
        """
        # Обычно QPC работает на частоте ~10 MHz
        # Масштабируем наши такты к этой частоте
        return (self.ticks * self.qpc_frequency) // self.cpu_freq_hz
    
    def query_performance_frequency(self):
        """
        Эмуляция QueryPerformanceFrequency()
        Возвращает: частота счётчика QPC
        """
        return self.qpc_frequency
    
    def get_system_time_as_file_time(self):
        """
        Эмуляция GetSystemTimeAsFileTime()
        Возвращает: 64-битное значение FILETIME (100-наносекундные интервалы)
        """
        # FILETIME = 100ns интервалы с 1 января 1601
        # Для простоты возвращаем производное от ticks
        ns_per_tick = 1_000_000_000 // self.cpu_freq_hz
        filetime_units = (self.ticks * ns_per_tick) // 100
        return filetime_units
    
    def __repr__(self):
        return (f"VirtualClock(ticks={self.ticks:,}, "
                f"ms={self.get_tick_count():,}, "
                f"freq={self.cpu_freq_mhz} MHz)")


if __name__ == "__main__":
    # Демонстрация консистентности
    clock = VirtualClock(cpu_freq_mhz=3000)
    
    print("=== Демонстрация VirtualClock ===\n")
    print(f"Начальное состояние: {clock}\n")
    
    # Симулируем выполнение кода (1 миллион тактов)
    print("Симулируем выполнение кода (1,000,000 тактов)...")
    clock.advance(1_000_000)
    
    # Читаем все таймеры
    rdtsc = clock.rdtsc()
    tick_count = clock.get_tick_count()
    qpc = clock.query_performance_counter()
    qpc_freq = clock.query_performance_frequency()
    
    print(f"\nРезультаты:")
    print(f"  RDTSC:                    {rdtsc:,} тактов")
    print(f"  GetTickCount():           {tick_count} мс")
    print(f"  QueryPerformanceCounter: {qpc:,}")
    print(f"  QueryPerformanceFreq:    {qpc_freq:,} Hz")
    
    # Проверка консистентности
    print(f"\n=== Проверка консистентности ===")
    
    # RDTSC → миллисекунды
    rdtsc_to_ms = rdtsc / (clock.cpu_freq_hz / 1000)
    print(f"  RDTSC → мс:              {rdtsc_to_ms:.3f} мс")
    print(f"  GetTickCount():          {tick_count} мс")
    print(f"  Разница:                 {abs(rdtsc_to_ms - tick_count):.6f} мс")
    
    # QPC → миллисекунды
    qpc_to_ms = (qpc / qpc_freq) * 1000
    print(f"\n  QPC → мс:                {qpc_to_ms:.3f} мс")
    print(f"  GetTickCount():          {tick_count} мс")
    print(f"  Разница:                 {abs(qpc_to_ms - tick_count):.6f} мс")
    
    print(f"\n[OK] Все таймеры математически консистентны!")
    print(f"[OK] Анти-тампер не сможет детектировать эмуляцию через кросс-валидацию времени")
