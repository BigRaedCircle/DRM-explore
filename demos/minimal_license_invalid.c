// Minimal PE without CRT - Invalid license
// Compile: cl /c /O1 minimal_license_invalid.c
// Link: link /SUBSYSTEM:CONSOLE /ENTRY:check_license /NODEFAULTLIB kernel32.lib minimal_license_invalid.obj

// Import ExitProcess
__declspec(dllimport) void __stdcall ExitProcess(unsigned int uExitCode);

void check_license(void) {
    // Simple license check - invalid key
    char key = 'X';
    
    if (key == 'V') {
        // Valid - exit with 0
        ExitProcess(0);
    } else {
        // Invalid - exit with 1
        ExitProcess(1);
    }
}
