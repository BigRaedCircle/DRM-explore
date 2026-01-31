/*
 * Simple System Information Tool - NO CRT VERSION
 * Uses only Windows API, no C runtime
 */

#include <windows.h>

// Helper to write string to console
void WriteString(const WCHAR* str) {
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD written;
    DWORD len = 0;
    while (str[len]) len++;
    WriteConsoleW(hConsole, str, len, &written, NULL);
}

// Helper to write number
void WriteNumber(DWORD num) {
    WCHAR buf[32];
    int i = 0;
    
    if (num == 0) {
        buf[i++] = L'0';
    } else {
        WCHAR temp[32];
        int j = 0;
        while (num > 0) {
            temp[j++] = L'0' + (num % 10);
            num /= 10;
        }
        while (j > 0) {
            buf[i++] = temp[--j];
        }
    }
    buf[i] = 0;
    
    WriteString(buf);
}

void mainCRTStartup(void) {
    SYSTEM_INFO si;
    
    WriteString(L"=================================================\r\n");
    WriteString(L"Simple System Information Tool (No CRT)\r\n");
    WriteString(L"=================================================\r\n\r\n");
    
    // Get system information
    GetSystemInfo(&si);
    
    WriteString(L"Hardware Information:\r\n");
    WriteString(L"---------------------\r\n");
    WriteString(L"  Number of processors: ");
    WriteNumber(si.dwNumberOfProcessors);
    WriteString(L"\r\n");
    
    WriteString(L"  Page size: ");
    WriteNumber(si.dwPageSize);
    WriteString(L" bytes\r\n");
    
    WriteString(L"  Processor architecture: ");
    switch (si.wProcessorArchitecture) {
        case PROCESSOR_ARCHITECTURE_AMD64:
            WriteString(L"x64 (AMD or Intel)\r\n");
            break;
        case PROCESSOR_ARCHITECTURE_INTEL:
            WriteString(L"x86\r\n");
            break;
        default:
            WriteString(L"Unknown\r\n");
    }
    
    WriteString(L"\r\nProcessor Features:\r\n");
    WriteString(L"-------------------\r\n");
    
    int count = 0;
    if (IsProcessorFeaturePresent(PF_MMX_INSTRUCTIONS_AVAILABLE)) {
        WriteString(L"  [+] MMX instructions\r\n");
        count++;
    }
    if (IsProcessorFeaturePresent(PF_XMMI_INSTRUCTIONS_AVAILABLE)) {
        WriteString(L"  [+] SSE instructions\r\n");
        count++;
    }
    if (IsProcessorFeaturePresent(PF_XMMI64_INSTRUCTIONS_AVAILABLE)) {
        WriteString(L"  [+] SSE2 instructions\r\n");
        count++;
    }
    if (IsProcessorFeaturePresent(PF_SSE3_INSTRUCTIONS_AVAILABLE)) {
        WriteString(L"  [+] SSE3 instructions\r\n");
        count++;
    }
    if (IsProcessorFeaturePresent(PF_RDTSC_INSTRUCTION_AVAILABLE)) {
        WriteString(L"  [+] RDTSC instruction\r\n");
        count++;
    }
    
    WriteString(L"\r\nTotal: ");
    WriteNumber(count);
    WriteString(L" features supported\r\n");
    
    WriteString(L"\r\n=================================================\r\n");
    WriteString(L"Test completed successfully!\r\n");
    WriteString(L"=================================================\r\n");
    
    ExitProcess(0);
}
