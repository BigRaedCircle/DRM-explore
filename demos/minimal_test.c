/*
 * minimal_test.c — Минимальный тест без CRT
 * 
 * Компиляция без CRT:
 *   gcc -nostdlib -e mainCRTStartup minimal_test.c -o minimal_test.exe -lkernel32
 */

#include <windows.h>

// Прототипы WinAPI функций
__declspec(dllimport) ULONGLONG __stdcall GetTickCount64(void);
__declspec(dllimport) void __stdcall ExitProcess(UINT uExitCode);

// Inline RDTSC
static inline unsigned long long rdtsc() {
    unsigned int lo, hi;
    __asm__ volatile ("rdtsc" : "=a" (lo), "=d" (hi));
    return ((unsigned long long)hi << 32) | lo;
}

// Entry point
void mainCRTStartup() {
    // Замеряем RDTSC
    unsigned long long t1 = rdtsc();
    
    // Простой цикл
    volatile int sum = 0;
    for (int i = 0; i < 1000; i++) {
        sum += i;
    }
    
    // Замеряем снова
    unsigned long long t2 = rdtsc();
    
    // Вычисляем дельту
    unsigned long long delta = t2 - t1;
    
    // Если дельта разумная (> 0 и < 1000000) — успех
    if (delta > 0 && delta < 1000000) {
        ExitProcess(0);  // SUCCESS
    } else {
        ExitProcess(1);  // FAIL
    }
}
