/*
 * minimal_test.c — Минимальный тест для эмулятора
 * 
 * Без зависимостей от WinAPI, только чистый код.
 * Компиляция: gcc -nostdlib -e main minimal_test.c -o minimal_test.exe
 */

// Простая функция для тестирования RDTSC
unsigned long long test_rdtsc() {
    unsigned long long result;
    __asm__ volatile ("rdtsc" : "=A" (result));
    return result;
}

// Простая функция для тестирования времени
int test_timing() {
    unsigned long long t1 = test_rdtsc();
    
    // Критичный блок (простой цикл)
    volatile int sum = 0;
    for (int i = 0; i < 1000; i++) {
        sum += i;
    }
    
    unsigned long long t2 = test_rdtsc();
    
    // Проверка: прошло ли время?
    if (t2 > t1) {
        return 0;  // SUCCESS
    } else {
        return 1;  // FAIL
    }
}

// Entry point
int main() {
    return test_timing();
}
