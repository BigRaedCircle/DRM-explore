/*
 * Комплексный Анти-Тампер Тест (Упрощённая версия)
 * Компилируется любым компилятором
 */

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <intrin.h>

// Глобальные переменные
static DWORD g_license_key = 0;
static unsigned __int64 g_start_time = 0;

// RDTSC через intrinsic
unsigned __int64 get_rdtsc() {
    return __rdtsc();
}

// === ПРОВЕРКИ ВРЕМЕНИ ===

int check_timing_rdtsc() {
    unsigned __int64 start = get_rdtsc();
    
    volatile int sum = 0;
    for (int i = 0; i < 1000; i++) {
        sum += i;
    }
    
    unsigned __int64 end = get_rdtsc();
    unsigned __int64 delta = end - start;
    
    printf("[RDTSC] Delta: %llu ticks\n", delta);
    
    if (delta < 100 || delta > 1000000) {
        printf("[RDTSC] SUSPICIOUS!\n");
        return 0;
    }
    
    return 1;
}

int check_timing_gettickcount() {
    DWORD start = GetTickCount();
    Sleep(10);
    DWORD end = GetTickCount();
    DWORD delta = end - start;
    
    printf("[GetTickCount] Delta: %lu ms\n", delta);
    
    if (delta < 5 || delta > 50) {
        printf("[GetTickCount] SUSPICIOUS!\n");
        return 0;
    }
    
    return 1;
}

int check_timing_qpc() {
    LARGE_INTEGER freq, start, end;
    
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&start);
    
    volatile int sum = 0;
    for (int i = 0; i < 10000; i++) {
        sum += i * i;
    }
    
    QueryPerformanceCounter(&end);
    
    unsigned __int64 delta = end.QuadPart - start.QuadPart;
    double ms = (delta * 1000.0) / freq.QuadPart;
    
    printf("[QPC] Delta: %.3f ms\n", ms);
    
    if (ms < 0.001 || ms > 100.0) {
        printf("[QPC] SUSPICIOUS!\n");
        return 0;
    }
    
    return 1;
}

// === ЛИЦЕНЗИЯ ===

DWORD calculate_hash(const char* key) {
    DWORD hash = 0x12345678;
    
    for (int i = 0; key[i] != '\0'; i++) {
        hash = ((hash << 5) + hash) + key[i];
        hash ^= (hash >> 16);
    }
    
    return hash;
}

int validate_license(const char* key) {
    printf("[LICENSE] Validating: %s\n", key);
    
    DWORD hash = calculate_hash(key);
    DWORD expected = calculate_hash("VALID-KEY-2026");
    
    printf("[LICENSE] Hash: 0x%08X\n", hash);
    
    if (hash == expected) {
        printf("[LICENSE] VALID!\n");
        g_license_key = hash;
        return 1;
    } else {
        printf("[LICENSE] INVALID!\n");
        return 0;
    }
}

// === ОБФУСКАЦИЯ ===

int obfuscated_check_1() {
    volatile DWORD* ptr = &g_license_key;
    DWORD value = *ptr;
    
    if (value == 0) {
        printf("[CHECK-1] FAILED!\n");
        return 0;
    }
    
    printf("[CHECK-1] OK\n");
    return 1;
}

int obfuscated_check_2() {
    DWORD xor_key = 0xDEADBEEF;
    DWORD encoded = g_license_key ^ xor_key;
    DWORD decoded = encoded ^ xor_key;
    
    if (decoded != g_license_key) {
        printf("[CHECK-2] FAILED!\n");
        return 0;
    }
    
    printf("[CHECK-2] OK\n");
    return 1;
}

int obfuscated_check_3() {
    DWORD temp = g_license_key;
    temp = (temp * 0x1234) + 0x5678;
    temp = (temp >> 8) & 0xFFFFFF;
    
    if (temp == 0) {
        printf("[CHECK-3] FAILED!\n");
        return 0;
    }
    
    printf("[CHECK-3] OK\n");
    return 1;
}

// === MAIN ===

int main() {
    printf("========================================\n");
    printf("  COMPLEX ANTI-TAMPER TEST SUITE\n");
    printf("========================================\n\n");
    
    g_start_time = get_rdtsc();
    
    int total = 0;
    int passed = 0;
    
    // Test 1: RDTSC
    printf("\n[TEST 1] RDTSC Check\n");
    total++;
    if (check_timing_rdtsc()) {
        passed++;
        printf("PASSED\n");
    } else {
        printf("FAILED\n");
    }
    
    // Test 2: GetTickCount
    printf("\n[TEST 2] GetTickCount Check\n");
    total++;
    if (check_timing_gettickcount()) {
        passed++;
        printf("PASSED\n");
    } else {
        printf("FAILED\n");
    }
    
    // Test 3: QPC
    printf("\n[TEST 3] QPC Check\n");
    total++;
    if (check_timing_qpc()) {
        passed++;
        printf("PASSED\n");
    } else {
        printf("FAILED\n");
    }
    
    // Test 4: Valid License
    printf("\n[TEST 4] Valid License\n");
    total++;
    if (validate_license("VALID-KEY-2026")) {
        passed++;
        printf("PASSED\n");
    } else {
        printf("FAILED\n");
    }
    
    // Test 5: Obfuscated checks
    printf("\n[TEST 5] Obfuscated Checks\n");
    total++;
    if (obfuscated_check_1() && obfuscated_check_2() && obfuscated_check_3()) {
        passed++;
        printf("PASSED\n");
    } else {
        printf("FAILED\n");
    }
    
    // Test 6: Invalid License
    printf("\n[TEST 6] Invalid License\n");
    total++;
    if (!validate_license("INVALID-KEY")) {
        passed++;
        printf("PASSED (correctly rejected)\n");
    } else {
        printf("FAILED\n");
    }
    
    // Results
    unsigned __int64 end_time = get_rdtsc();
    unsigned __int64 total_time = end_time - g_start_time;
    
    printf("\n========================================\n");
    printf("  RESULTS\n");
    printf("========================================\n");
    printf("Total:   %d\n", total);
    printf("Passed:  %d\n", passed);
    printf("Failed:  %d\n", total - passed);
    printf("Rate:    %d%%\n", (passed * 100) / total);
    printf("Time:    %llu ticks\n", total_time);
    printf("========================================\n");
    
    if (passed == total) {
        printf("\nALL TESTS PASSED!\n");
        return 0;
    } else {
        printf("\nSOME TESTS FAILED!\n");
        return 1;
    }
}
