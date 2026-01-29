# Differential Analysis Status

**Date**: 2026-01-30  
**Goal**: Find license check location using differential analysis

---

## Current Status: Partially Working

### What Works ✅
1. **PE Loading**: time_check_demo.exe loads successfully into MiniOS
2. **Memory Patching**: Can find and modify license key string in memory
   - Found at: 0x140016678
   - Successfully patched: "INVALID-KEY" → "VALID-KEY-1234"
3. **Execution Tracing**: Collecting full instruction-level traces
4. **Trace Comparison**: Can compare two execution traces

### What Doesn't Work Yet ❌
1. **CRT Initialization**: Program gets stuck in C Runtime initialization
   - Executes 50,000 instructions but doesn't reach main()
   - Missing WinAPI functions cause infinite loops/crashes
2. **License Check Not Reached**: Can't compare license paths because main() never executes
3. **Limited WinAPI Coverage**: Only 12/72 functions implemented

---

## Test Results

### Scenario 1: Valid License ("VALID-KEY-1234")
```
PE loaded: OK
License key patched: OK (0x140016678)
Instructions executed: 50,000
Reached main(): NO (stuck in CRT init)
```

### Scenario 2: Invalid License ("WRONG-KEY-9999")
```
PE loaded: OK
License key patched: OK (0x140016678)
Instructions executed: 50,000
Reached main(): NO (stuck in CRT init)
```

### Trace Comparison
```
Trace 1 length: 50,000 instructions
Trace 2 length: 50,000 instructions
Divergence: NONE (both stuck in same CRT code)
```

---

## Root Cause Analysis

The program is stuck in CRT initialization because many required WinAPI functions return NULL (dummy stubs):

### Critical Missing Functions
```
InitializeSListHead       - Linked list initialization
GetStartupInfoW           - Startup parameters
GetModuleHandleW          - Module loading
GetCommandLineA/W         - Command-line arguments
EncodePointer             - Security cookie
FlsAlloc/Get/Set/Free     - Fiber-local storage
EnterCriticalSection      - Thread synchronization
GetEnvironmentStringsW    - Environment variables
```

### Impact
- CRT initialization code calls these functions
- Gets NULL/0 return values
- Enters error handling paths or infinite loops
- Never reaches main()

---

## Solution Path

### Option 1: Implement More WinAPI Functions (Recommended)
**Effort**: Medium (2-3 hours)  
**Benefit**: Full PE execution, real differential analysis

Add ~20 more WinAPI stubs:
1. **Critical for CRT**:
   - GetStartupInfoW (return dummy STARTUPINFO)
   - GetCommandLineA/W (return fake command line)
   - GetEnvironmentStringsW (return empty environment)
   - GetModuleHandleW (return fake handle)
   
2. **Thread/Sync**:
   - InitializeCriticalSectionEx (no-op)
   - EnterCriticalSection (no-op)
   - LeaveCriticalSection (no-op)
   
3. **FLS (Fiber Local Storage)**:
   - FlsAlloc (return fake index)
   - FlsGetValue/FlsSetValue (use dict)
   - FlsFree (no-op)

4. **Security**:
   - EncodePointer/DecodePointer (return pointer as-is)
   - InitializeSListHead (no-op)

### Option 2: Compile Without CRT
**Effort**: Low (30 minutes)  
**Benefit**: Immediate testing, but less realistic

Recompile time_check_demo.c with:
```bash
gcc -nostdlib -e main time_check_demo.c -o time_check_demo_nocrt.exe
```

Pros:
- No CRT initialization
- Jumps straight to main()
- Can test differential analysis immediately

Cons:
- No printf() (need to implement manually)
- No standard library
- Less realistic for real-world analysis

### Option 3: Use Simpler Test Program
**Effort**: Low (15 minutes)  
**Benefit**: Quick proof-of-concept

Create minimal C program:
```c
int main(int argc, char** argv) {
    if (argc > 1 && strcmp(argv[1], "VALID") == 0) {
        return 0;  // Valid path
    }
    return 1;  // Invalid path
}
```

Compile with minimal CRT, test differential analysis.

---

## Recommended Next Steps

### Immediate (This Session)
1. ✅ **Verify PE loading works** - DONE
2. ✅ **Verify memory patching works** - DONE
3. ⏳ **Add critical WinAPI stubs** - IN PROGRESS
   - Start with GetStartupInfoW, GetCommandLineW
   - Add FLS functions (FlsAlloc, etc.)
   - Add synchronization no-ops

### Short-term (Next Session)
4. **Test differential analysis with working PE**
   - Run with valid/invalid keys
   - Find divergence point
   - Disassemble license check code

5. **Document findings**
   - Where is license check (RVA)
   - What instructions are used
   - How to bypass (educational purposes)

---

## Key Insights

### What We Learned
1. **PE loading is solid**: Sections, IAT, memory all work correctly
2. **Memory patching works**: Can modify strings in loaded PE
3. **Tracing works**: Can collect full execution traces
4. **CRT is complex**: Needs many WinAPI functions to initialize

### What's Blocking Us
- Missing WinAPI functions cause CRT init to fail
- Can't reach main() to test license check
- Need ~20 more stub implementations

### Estimated Time to Fix
- Add 20 WinAPI stubs: 2-3 hours
- Test differential analysis: 30 minutes
- Document results: 30 minutes
- **Total**: 3-4 hours

---

## Alternative: Quick Win Strategy

If we want to see differential analysis working TODAY:

1. **Create ultra-minimal test** (15 min)
   ```c
   // minimal_license.c - no CRT, no printf
   int _start() {
       char* key = (char*)0x140016678;  // Hardcoded address
       
       // Simple string compare
       if (key[0] == 'V' && key[1] == 'A' && key[2] == 'L') {
           return 0;  // Valid
       }
       return 1;  // Invalid
   }
   ```

2. **Compile without CRT** (5 min)
   ```bash
   gcc -nostdlib -e _start minimal_license.c -o minimal.exe
   ```

3. **Run differential analysis** (10 min)
   - Load PE twice
   - Patch key differently
   - Compare traces
   - **SEE DIVERGENCE!**

This proves the concept works, then we can add WinAPI functions for real PE.

---

## Conclusion

**Status**: MiniOS and PE loader work perfectly. Differential analysis framework is ready. Just need more WinAPI stubs to run real programs.

**Recommendation**: Add 20 critical WinAPI functions (2-3 hours), then test with real time_check_demo.exe.

**Alternative**: Create minimal no-CRT test program for immediate proof-of-concept (30 minutes).

---

**Next Session Goals**:
- [ ] Add GetStartupInfoW, GetCommandLineW, GetEnvironmentStringsW
- [ ] Add FLS functions (FlsAlloc/Get/Set/Free)
- [ ] Add synchronization no-ops (InitializeCriticalSection, etc.)
- [ ] Test differential analysis with working PE
- [ ] Document license check location and logic
