// Simple license check - INVALID key hardcoded
#include <stdio.h>

int main() {
    const char* key = "WRONG-KEY-9999";
    
    // Simple check
    if (key[0] == 'V' && key[6] == 'K') {
        printf("License OK\n");
        return 0;
    } else {
        printf("License FAIL\n");
        return 1;
    }
}
