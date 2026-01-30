/*
 * Учебный анти-тампер с кросс-валидацией времени
 * 
 * Демонстрирует ключевую технику детектирования эмуляции:
 * - RDTSC vs GetTickCount должны быть синхронизированы
 * - Если расхождение > порога → эмулятор обнаружен
 * 
 * В расслоенной эмуляции оба таймера производные от VirtualClock,
 * поэтому математически консистентны → детекция не срабатывает.
 */

#include <stdio.h>
#include <stdint.h>
#include <windows.h>

// Симуляция частоты CPU (3 GHz)
#define CPU_FREQ_MHZ 3000
#define THRESHOLD_TICKS (CPU_FREQ_MHZ * 100)  // 100 мс допуск

// Inline assembly для RDTSC
static inline uint64_t rdtsc(void) {
    uint32_t lo, hi;
    __asm__ volatile ("rdtsc" : "=a"(lo), "=d"(hi));
    return ((uint64_t)hi << 32) | lo;
}

// Проверка лицензии с кросс-валидацией времени
int check_license_with_timing(uint32_t license_key) {
    printf("[*] Проверка лицензии: 0x%08x\n", license_key);
    
    // Замер 1: RDTSC
    uint64_t t1_rdtsc = rdtsc();
    DWORD t1_tick = GetTickCount();
    
    printf("[*] T1: RDTSC=%llu, GetTickCount=%lu\n", t1_rdtsc, t1_tick);
    
    // Критичный блок: проверка лицензии
    int valid = 0;
    if (license_key == 0xCAFEBABE) {
        // Валидный ключ
        valid = 1;
        
        // Имитация сложных вычислений
        volatile uint64_t hash = license_key;
        for (int i = 0; i < 1000; i++) {
            hash = (hash * 1103515245 + 12345) & 0x7FFFFFFF;
        }
        
        if (hash == 0) valid = 0;  // Никогда не сработает, но компилятор не оптимизирует
    }
    
    // Замер 2: RDTSC
    uint64_t t2_rdtsc = rdtsc();
    DWORD t2_tick = GetTickCount();
    
    printf("[*] T2: RDTSC=%llu, GetTickCount=%lu\n", t2_rdtsc, t2_tick);
    
    // Кросс-валидация времени
    uint64_t delta_rdtsc = t2_rdtsc - t1_rdtsc;
    uint64_t delta_tick = (uint64_t)(t2_tick - t1_tick);
    
    // Конвертируем GetTickCount (мс) в такты CPU
    uint64_t delta_tick_in_ticks = delta_tick * CPU_FREQ_MHZ * 1000;
    
    printf("[*] Delta RDTSC: %llu тактов\n", delta_rdtsc);
    printf("[*] Delta GetTickCount: %llu мс (%llu тактов)\n", delta_tick, delta_tick_in_ticks);
    
    // Проверка консистентности
    int64_t diff = (int64_t)(delta_rdtsc - delta_tick_in_ticks);
    if (diff < 0) diff = -diff;
    
    printf("[*] Расхождение: %lld тактов\n", diff);
    
    if (diff > THRESHOLD_TICKS) {
        printf("[!] ЭМУЛЯТОР ОБНАРУЖЕН! Таймеры рассинхронизированы!\n");
        return 0;  // Блокируем выполнение
    }
    
    printf("[OK] Таймеры синхронизированы - реальное железо\n");
    return valid;
}

int main(int argc, char *argv[]) {
    printf("======================================================================\n");
    printf("УЧЕБНЫЙ АНТИ-ТАМПЕР: Кросс-валидация времени\n");
    printf("======================================================================\n\n");
    
    uint32_t license_key = 0xCAFEBABE;  // Валидный ключ по умолчанию
    
    if (argc > 1) {
        sscanf(argv[1], "%x", &license_key);
    }
    
    int result = check_license_with_timing(license_key);
    
    printf("\n======================================================================\n");
    if (result) {
        printf("[✓] ЛИЦЕНЗИЯ ВАЛИДНА\n");
    } else {
        printf("[✗] ЛИЦЕНЗИЯ НЕВАЛИДНА или ЭМУЛЯТОР ОБНАРУЖЕН\n");
    }
    printf("======================================================================\n");
    
    return result ? 0 : 1;
}
