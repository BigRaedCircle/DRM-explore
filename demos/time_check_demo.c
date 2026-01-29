/*
 * time_check_demo.c — Учебный анти-тампер с кросс-валидацией времени
 * 
 * Проверяет консистентность между RDTSC и GetTickCount64.
 * Если расхождение > 20% — детектирует эмуляцию/отладку.
 * 
 * Компиляция:
 *   gcc -O2 time_check_demo.c -o time_check_demo.exe
 *   cl /O2 time_check_demo.c (MSVC)
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <math.h>
#include <windows.h>
#include <intrin.h>

// Частота CPU (примерно, для расчётов)
#define CPU_FREQ_MHZ 3000

/**
 * Проверка на эмуляцию через кросс-валидацию времени
 * Возвращает: 1 если эмуляция детектирована, 0 если нет
 */
int detect_emulation() {
    // Замеряем время ДО критичного блока
    uint64_t t1_rdtsc = __rdtsc();
    uint64_t t1_tick = GetTickCount64();
    
    // Критичный блок кода (занимает ~1000-10000 тактов)
    volatile uint64_t sum = 0;
    for (int i = 0; i < 10000; i++) {
        sum += i * i;
    }
    
    // Замеряем время ПОСЛЕ критичного блока
    uint64_t t2_rdtsc = __rdtsc();
    uint64_t t2_tick = GetTickCount64();
    
    // Вычисляем дельты
    uint64_t delta_rdtsc = t2_rdtsc - t1_rdtsc;
    uint64_t delta_tick = t2_tick - t1_tick;
    
    // Конвертируем RDTSC в миллисекунды
    // delta_rdtsc / (CPU_FREQ_MHZ * 1000) = миллисекунды
    double rdtsc_ms = (double)delta_rdtsc / (CPU_FREQ_MHZ * 1000.0);
    
    // Вычисляем расхождение
    double diff_ms = rdtsc_ms - (double)delta_tick;
    double diff_percent = (diff_ms / rdtsc_ms) * 100.0;
    
    printf("[DEBUG] RDTSC delta:     %llu тактов\n", delta_rdtsc);
    printf("[DEBUG] RDTSC -> ms:     %.3f мс\n", rdtsc_ms);
    printf("[DEBUG] GetTickCount:    %llu мс\n", delta_tick);
    printf("[DEBUG] Расхождение:     %.3f мс (%.1f%%)\n", diff_ms, diff_percent);
    
    // Порог детектирования: 20% расхождение
    if (fabs(diff_percent) > 20.0) {
        printf("[!] ЭМУЛЯЦИЯ ДЕТЕКТИРОВАНА! Расхождение > 20%%\n");
        return 1;
    }
    
    printf("[✓] Эмуляция НЕ детектирована (расхождение в пределах нормы)\n");
    return 0;
}

/**
 * Проверка лицензии (заглушка)
 */
int check_license(const char* key) {
    printf("\n[*] Проверка лицензии: %s\n", key);
    
    // Простая проверка для демонстрации
    if (strcmp(key, "VALID-KEY-1234") == 0) {
        printf("[✓] Лицензия валидна!\n");
        return 1;
    } else {
        printf("[✗] Лицензия невалидна!\n");
        return 0;
    }
}

int main(int argc, char* argv[]) {
    printf("=== Учебный анти-тампер с кросс-валидацией времени ===\n\n");
    
    // Шаг 1: Проверка на эмуляцию
    printf("[*] Шаг 1: Проверка на эмуляцию/отладку...\n");
    if (detect_emulation()) {
        printf("\n[!] ЗАЩИТА СРАБОТАЛА: Эмуляция детектирована!\n");
        printf("[!] Программа завершается.\n");
        return 1;
    }
    
    // Шаг 2: Проверка лицензии
    const char* license_key = (argc > 1) ? argv[1] : "INVALID-KEY";
    if (!check_license(license_key)) {
        printf("\n[!] ЗАЩИТА СРАБОТАЛА: Невалидная лицензия!\n");
        return 2;
    }
    
    // Успех
    printf("\n[✓✓✓] ВСЕ ПРОВЕРКИ ПРОЙДЕНЫ!\n");
    printf("[✓✓✓] Программа запущена успешно.\n");
    return 0;
}
