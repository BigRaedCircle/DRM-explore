/*
 * Комплексный Анти-Тампер Тест
 * 
 * Включает:
 * - RDTSC проверки (timing attacks)
 * - Множественные проверки времени
 * - Обфускация через указатели
 * - Проверка целостности кода
 * - Лицензионные проверки
 * - Криптографические операции
 * - Многоуровневая валидация
 */

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Глобальные переменные для анти-тампера
static DWORD g_license_key = 0;
static BOOL g_is_valid = FALSE;
static ULONGLONG g_start_time = 0;

// === RDTSC ПРОВЕРКИ ===

__forceinline ULONGLONG rdtsc_inline() {
    return __rdtsc();
}

BOOL check_timing_rdtsc() {
    ULONGLONG start = rdtsc_inline();
    
    // Простая операция
    volatile int sum = 0;
    for (int i = 0; i < 1000; i++) {
        sum += i;
    }
    
    ULONGLONG end = rdtsc_inline();
    ULONGLONG delta = end - start;
    
    // Проверка: операция должна занять разумное время
    // В эмуляторе: ~1000 тиков
    // В реальности: ~3000-10000 тиков
    printf("[RDTSC] Delta: %llu ticks\n", delta);
    
    if (delta < 100 || delta > 1000000) {
        printf("[RDTSC] SUSPICIOUS: Timing anomaly detected!\n");
        return FALSE;
    }
    
    return TRUE;
}

// === ПРОВЕРКИ ВРЕМЕНИ ===

BOOL check_timing_gettickcount() {
    DWORD start = GetTickCount();
    
    // Имитация работы
    Sleep(10);
    
    DWORD end = GetTickCount();
    DWORD delta = end - start;
    
    printf("[GetTickCount] Delta: %lu ms\n", delta);
    
    // Должно быть около 10 мс
    if (delta < 5 || delta > 50) {
        printf("[GetTickCount] SUSPICIOUS: Time manipulation detected!\n");
        return FALSE;
    }
    
    return TRUE;
}

BOOL check_timing_qpc() {
    LARGE_INTEGER freq, start, end;
    
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&start);
    
    // Имитация работы
    volatile int sum = 0;
    for (int i = 0; i < 10000; i++) {
        sum += i * i;
    }
    
    QueryPerformanceCounter(&end);
    
    ULONGLONG delta = end.QuadPart - start.QuadPart;
    double ms = (delta * 1000.0) / freq.QuadPart;
    
    printf("[QPC] Delta: %.3f ms (freq: %lld Hz)\n", ms, freq.QuadPart);
    
    // Проверка разумности
    if (ms < 0.001 || ms > 100.0) {
        printf("[QPC] SUSPICIOUS: Performance counter anomaly!\n");
        return FALSE;
    }
    
    return TRUE;
}

// === ЛИЦЕНЗИОННЫЕ ПРОВЕРКИ ===

DWORD calculate_license_hash(const char* key) {
    DWORD hash = 0x12345678;
    
    for (int i = 0; key[i] != '\0'; i++) {
        hash = ((hash << 5) + hash) + key[i];
        hash ^= (hash >> 16);
    }
    
    return hash;
}

BOOL validate_license_simple(const char* key) {
    printf("[LICENSE] Validating key: %s\n", key);
    
    DWORD hash = calculate_license_hash(key);
    
    // Правильный ключ: "VALID-KEY-2026"
    // Hash: 0x8B4E2A1C (примерный)
    DWORD expected = calculate_license_hash("VALID-KEY-2026");
    
    printf("[LICENSE] Hash: 0x%08X (expected: 0x%08X)\n", hash, expected);
    
    if (hash == expected) {
        printf("[LICENSE] ✓ Valid license!\n");
        g_license_key = hash;
        return TRUE;
    } else {
        printf("[LICENSE] ✗ Invalid license!\n");
        return FALSE;
    }
}

// === ОБФУСКАЦИЯ И ПРОВЕРКА ЦЕЛОСТНОСТИ ===

typedef BOOL (*ValidationFunc)(void);

BOOL obfuscated_check_1() {
    // Проверка через указатели
    volatile DWORD* ptr = &g_license_key;
    DWORD value = *ptr;
    
    if (value == 0) {
        printf("[OBFUSCATED-1] ✗ License not initialized!\n");
        return FALSE;
    }
    
    printf("[OBFUSCATED-1] ✓ License key present\n");
    return TRUE;
}

BOOL obfuscated_check_2() {
    // Проверка через XOR
    DWORD xor_key = 0xDEADBEEF;
    DWORD encoded = g_license_key ^ xor_key;
    DWORD decoded = encoded ^ xor_key;
    
    if (decoded != g_license_key) {
        printf("[OBFUSCATED-2] ✗ Memory corruption detected!\n");
        return FALSE;
    }
    
    printf("[OBFUSCATED-2] ✓ Memory integrity OK\n");
    return TRUE;
}

BOOL obfuscated_check_3() {
    // Проверка через арифметику
    DWORD temp = g_license_key;
    temp = (temp * 0x1234) + 0x5678;
    temp = (temp >> 8) & 0xFFFFFF;
    
    if (temp == 0) {
        printf("[OBFUSCATED-3] ✗ Arithmetic check failed!\n");
        return FALSE;
    }
    
    printf("[OBFUSCATED-3] ✓ Arithmetic check passed\n");
    return TRUE;
}

// === МНОГОУРОВНЕВАЯ ВАЛИДАЦИЯ ===

BOOL multi_level_validation() {
    printf("\n=== MULTI-LEVEL VALIDATION ===\n");
    
    ValidationFunc checks[] = {
        obfuscated_check_1,
        obfuscated_check_2,
        obfuscated_check_3,
    };
    
    int passed = 0;
    int total = sizeof(checks) / sizeof(checks[0]);
    
    for (int i = 0; i < total; i++) {
        if (checks[i]()) {
            passed++;
        }
    }
    
    printf("[VALIDATION] Passed: %d/%d\n", passed, total);
    
    return (passed == total);
}

// === ПРОВЕРКА ЦЕЛОСТНОСТИ КОДА ===

DWORD calculate_code_checksum() {
    // Вычисляем контрольную сумму функции validate_license_simple
    BYTE* code = (BYTE*)validate_license_simple;
    DWORD checksum = 0;
    
    // Читаем первые 64 байта функции
    for (int i = 0; i < 64; i++) {
        checksum += code[i];
        checksum = (checksum << 1) | (checksum >> 31);
    }
    
    return checksum;
}

BOOL check_code_integrity() {
    printf("\n=== CODE INTEGRITY CHECK ===\n");
    
    DWORD checksum = calculate_code_checksum();
    printf("[INTEGRITY] Code checksum: 0x%08X\n", checksum);
    
    // В реальности здесь была бы проверка с эталонным значением
    // Для демо просто проверяем, что checksum не нулевой
    if (checksum == 0) {
        printf("[INTEGRITY] ✗ Code corruption detected!\n");
        return FALSE;
    }
    
    printf("[INTEGRITY] ✓ Code integrity OK\n");
    return TRUE;
}

// === КОМБИНИРОВАННАЯ ПРОВЕРКА ===

BOOL combined_timing_check() {
    printf("\n=== COMBINED TIMING CHECK ===\n");
    
    ULONGLONG rdtsc_start = rdtsc_inline();
    DWORD tick_start = GetTickCount();
    LARGE_INTEGER qpc_start;
    QueryPerformanceCounter(&qpc_start);
    
    // Имитация работы
    Sleep(50);
    
    ULONGLONG rdtsc_end = rdtsc_inline();
    DWORD tick_end = GetTickCount();
    LARGE_INTEGER qpc_end;
    QueryPerformanceCounter(&qpc_end);
    
    ULONGLONG rdtsc_delta = rdtsc_end - rdtsc_start;
    DWORD tick_delta = tick_end - tick_start;
    ULONGLONG qpc_delta = qpc_end.QuadPart - qpc_start.QuadPart;
    
    printf("[COMBINED] RDTSC: %llu ticks\n", rdtsc_delta);
    printf("[COMBINED] GetTickCount: %lu ms\n", tick_delta);
    printf("[COMBINED] QPC: %llu counts\n", qpc_delta);
    
    // Проверка корреляции между источниками времени
    // RDTSC должен быть пропорционален другим источникам
    
    // Для 3 GHz CPU: 50 ms = 150,000,000 тиков RDTSC
    // Допустим диапазон: 100M - 200M тиков
    if (rdtsc_delta < 100000000 || rdtsc_delta > 200000000) {
        printf("[COMBINED] ✗ RDTSC correlation failed!\n");
        return FALSE;
    }
    
    // GetTickCount должен быть около 50 мс
    if (tick_delta < 40 || tick_delta > 100) {
        printf("[COMBINED] ✗ GetTickCount correlation failed!\n");
        return FALSE;
    }
    
    printf("[COMBINED] ✓ All timing sources correlated\n");
    return TRUE;
}

// === ГЛАВНАЯ ФУНКЦИЯ ===

int main(int argc, char* argv[]) {
    printf("╔════════════════════════════════════════════════════════════╗\n");
    printf("║         COMPLEX ANTI-TAMPER TEST SUITE                    ║\n");
    printf("║         Testing Emulator Capabilities                     ║\n");
    printf("╚════════════════════════════════════════════════════════════╝\n\n");
    
    g_start_time = rdtsc_inline();
    
    int total_checks = 0;
    int passed_checks = 0;
    
    // === ТЕСТ 1: RDTSC ===
    printf("\n[TEST 1] RDTSC Timing Check\n");
    printf("─────────────────────────────────────────────────────────────\n");
    total_checks++;
    if (check_timing_rdtsc()) {
        passed_checks++;
        printf("✓ PASSED\n");
    } else {
        printf("✗ FAILED\n");
    }
    
    // === ТЕСТ 2: GetTickCount ===
    printf("\n[TEST 2] GetTickCount Timing Check\n");
    printf("─────────────────────────────────────────────────────────────\n");
    total_checks++;
    if (check_timing_gettickcount()) {
        passed_checks++;
        printf("✓ PASSED\n");
    } else {
        printf("✗ FAILED\n");
    }
    
    // === ТЕСТ 3: QueryPerformanceCounter ===
    printf("\n[TEST 3] QueryPerformanceCounter Check\n");
    printf("─────────────────────────────────────────────────────────────\n");
    total_checks++;
    if (check_timing_qpc()) {
        passed_checks++;
        printf("✓ PASSED\n");
    } else {
        printf("✗ FAILED\n");
    }
    
    // === ТЕСТ 4: Лицензия (VALID) ===
    printf("\n[TEST 4] License Validation (Valid Key)\n");
    printf("─────────────────────────────────────────────────────────────\n");
    total_checks++;
    if (validate_license_simple("VALID-KEY-2026")) {
        passed_checks++;
        printf("✓ PASSED\n");
    } else {
        printf("✗ FAILED\n");
    }
    
    // === ТЕСТ 5: Многоуровневая валидация ===
    printf("\n[TEST 5] Multi-Level Validation\n");
    printf("─────────────────────────────────────────────────────────────\n");
    total_checks++;
    if (multi_level_validation()) {
        passed_checks++;
        printf("✓ PASSED\n");
    } else {
        printf("✗ FAILED\n");
    }
    
    // === ТЕСТ 6: Целостность кода ===
    printf("\n[TEST 6] Code Integrity Check\n");
    printf("─────────────────────────────────────────────────────────────\n");
    total_checks++;
    if (check_code_integrity()) {
        passed_checks++;
        printf("✓ PASSED\n");
    } else {
        printf("✗ FAILED\n");
    }
    
    // === ТЕСТ 7: Комбинированная проверка времени ===
    printf("\n[TEST 7] Combined Timing Check\n");
    printf("─────────────────────────────────────────────────────────────\n");
    total_checks++;
    if (combined_timing_check()) {
        passed_checks++;
        printf("✓ PASSED\n");
    } else {
        printf("✗ FAILED\n");
    }
    
    // === ТЕСТ 8: Лицензия (INVALID) ===
    printf("\n[TEST 8] License Validation (Invalid Key)\n");
    printf("─────────────────────────────────────────────────────────────\n");
    total_checks++;
    if (!validate_license_simple("INVALID-KEY-XXX")) {
        passed_checks++;
        printf("✓ PASSED (correctly rejected)\n");
    } else {
        printf("✗ FAILED (should have rejected)\n");
    }
    
    // === ИТОГИ ===
    ULONGLONG end_time = rdtsc_inline();
    ULONGLONG total_time = end_time - g_start_time;
    
    printf("\n╔════════════════════════════════════════════════════════════╗\n");
    printf("║                      FINAL RESULTS                         ║\n");
    printf("╠════════════════════════════════════════════════════════════╣\n");
    printf("║  Total Tests:  %2d                                          ║\n", total_checks);
    printf("║  Passed:       %2d                                          ║\n", passed_checks);
    printf("║  Failed:       %2d                                          ║\n", total_checks - passed_checks);
    printf("║  Success Rate: %3d%%                                        ║\n", (passed_checks * 100) / total_checks);
    printf("║  Total Time:   %llu ticks                            ║\n", total_time);
    printf("╚════════════════════════════════════════════════════════════╝\n");
    
    if (passed_checks == total_checks) {
        printf("\n🎉 ALL TESTS PASSED! Emulator is working perfectly!\n");
        return 0;
    } else {
        printf("\n⚠️  SOME TESTS FAILED! Check emulator implementation.\n");
        return 1;
    }
}
