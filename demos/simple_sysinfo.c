/*
 * Simple System Information Tool
 * Demonstrates GetSystemInfo and IsProcessorFeaturePresent APIs
 * Perfect for testing hybrid passthrough emulation
 */

#include <windows.h>
#include <stdio.h>

int main(int argc, char* argv[])
{
    SYSTEM_INFO si;
    
    printf("=================================================\n");
    printf("Simple System Information Tool\n");
    printf("=================================================\n\n");
    
    // Get system information
    GetSystemInfo(&si);
    
    printf("Hardware Information:\n");
    printf("---------------------\n");
    printf("  Number of processors: %u\n", si.dwNumberOfProcessors);
    printf("  Page size: %u bytes\n", si.dwPageSize);
    printf("  Processor architecture: ");
    
    switch (si.wProcessorArchitecture) {
        case PROCESSOR_ARCHITECTURE_AMD64:
            printf("x64 (AMD or Intel)\n");
            break;
        case PROCESSOR_ARCHITECTURE_ARM:
            printf("ARM\n");
            break;
        case PROCESSOR_ARCHITECTURE_ARM64:
            printf("ARM64\n");
            break;
        case PROCESSOR_ARCHITECTURE_INTEL:
            printf("x86\n");
            break;
        case PROCESSOR_ARCHITECTURE_IA64:
            printf("Intel Itanium\n");
            break;
        default:
            printf("Unknown (%u)\n", si.wProcessorArchitecture);
    }
    
    printf("  Processor level: %u\n", si.wProcessorLevel);
    printf("  Processor revision: %u\n", si.wProcessorRevision);
    printf("  Active processor mask: 0x%IX\n", si.dwActiveProcessorMask);
    printf("  Allocation granularity: %u bytes\n", si.dwAllocationGranularity);
    
    printf("\nMemory Information:\n");
    printf("-------------------\n");
    printf("  Minimum application address: 0x%p\n", si.lpMinimumApplicationAddress);
    printf("  Maximum application address: 0x%p\n", si.lpMaximumApplicationAddress);
    
    printf("\nProcessor Features:\n");
    printf("-------------------\n");
    
    // Check various processor features
    struct {
        DWORD feature;
        const char* name;
    } features[] = {
        {PF_FLOATING_POINT_PRECISION_ERRATA, "Floating point precision errata"},
        {PF_FLOATING_POINT_EMULATED, "Floating point emulated"},
        {PF_COMPARE_EXCHANGE_DOUBLE, "Compare exchange double"},
        {PF_MMX_INSTRUCTIONS_AVAILABLE, "MMX instructions"},
        {PF_XMMI_INSTRUCTIONS_AVAILABLE, "SSE instructions"},
        {PF_3DNOW_INSTRUCTIONS_AVAILABLE, "3DNow instructions"},
        {PF_RDTSC_INSTRUCTION_AVAILABLE, "RDTSC instruction"},
        {PF_PAE_ENABLED, "PAE enabled"},
        {PF_XMMI64_INSTRUCTIONS_AVAILABLE, "SSE2 instructions"},
        {PF_SSE3_INSTRUCTIONS_AVAILABLE, "SSE3 instructions"},
        {PF_COMPARE_EXCHANGE128, "Compare exchange 128"},
        {PF_COMPARE64_EXCHANGE128, "Compare 64 exchange 128"},
        {PF_CHANNELS_ENABLED, "Channels enabled"},
        {PF_XSAVE_ENABLED, "XSAVE enabled"},
        {PF_ARM_VFP_32_REGISTERS_AVAILABLE, "ARM VFP 32 registers"},
        {PF_ARM_NEON_INSTRUCTIONS_AVAILABLE, "ARM NEON instructions"},
        {PF_SECOND_LEVEL_ADDRESS_TRANSLATION, "Second level address translation"},
        {PF_VIRT_FIRMWARE_ENABLED, "Virtualization firmware enabled"},
        {PF_RDWRFSGSBASE_AVAILABLE, "RDWRFSGSBASE available"},
        {PF_FASTFAIL_AVAILABLE, "Fast fail available"},
        {PF_ARM_DIVIDE_INSTRUCTION_AVAILABLE, "ARM divide instruction"},
        {PF_ARM_64BIT_LOADSTORE_ATOMIC, "ARM 64-bit load/store atomic"},
        {PF_ARM_EXTERNAL_CACHE_AVAILABLE, "ARM external cache"},
        {PF_ARM_FMAC_INSTRUCTIONS_AVAILABLE, "ARM FMAC instructions"},
        {PF_RDRAND_INSTRUCTION_AVAILABLE, "RDRAND instruction"},
        {PF_ARM_V8_INSTRUCTIONS_AVAILABLE, "ARM v8 instructions"},
        {PF_ARM_V8_CRYPTO_INSTRUCTIONS_AVAILABLE, "ARM v8 crypto instructions"},
        {PF_ARM_V8_CRC32_INSTRUCTIONS_AVAILABLE, "ARM v8 CRC32 instructions"},
        {PF_RDTSCP_INSTRUCTION_AVAILABLE, "RDTSCP instruction"},
        {PF_RDPID_INSTRUCTION_AVAILABLE, "RDPID instruction"},
        {PF_ARM_V81_ATOMIC_INSTRUCTIONS_AVAILABLE, "ARM v8.1 atomic instructions"},
        {PF_MONITORX_INSTRUCTION_AVAILABLE, "MONITORX instruction"},
        {PF_SSSE3_INSTRUCTIONS_AVAILABLE, "SSSE3 instructions"},
        {PF_SSE4_1_INSTRUCTIONS_AVAILABLE, "SSE4.1 instructions"},
        {PF_SSE4_2_INSTRUCTIONS_AVAILABLE, "SSE4.2 instructions"},
        {PF_AVX_INSTRUCTIONS_AVAILABLE, "AVX instructions"},
        {PF_AVX2_INSTRUCTIONS_AVAILABLE, "AVX2 instructions"},
        {PF_AVX512F_INSTRUCTIONS_AVAILABLE, "AVX-512F instructions"},
    };
    
    int feature_count = sizeof(features) / sizeof(features[0]);
    int supported_count = 0;
    
    for (int i = 0; i < feature_count; i++) {
        if (IsProcessorFeaturePresent(features[i].feature)) {
            printf("  [+] %s\n", features[i].name);
            supported_count++;
        }
    }
    
    printf("\nTotal: %d features supported\n", supported_count);
    
    printf("\n=================================================\n");
    printf("Test completed successfully!\n");
    printf("=================================================\n");
    
    return 0;
}
