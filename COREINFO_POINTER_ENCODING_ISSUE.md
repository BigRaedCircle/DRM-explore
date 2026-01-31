# CoreInfo Pointer Encoding Issue

## Date: 2026-02-01

## Summary

CoreInfo crashes after 899 instructions due to encoded function pointer decoding failure.

## Problem

CoreInfo uses encoded function pointers as an anti-tampering mechanism. During execution, it tries to decode a pointer using XOR/ROR operations, but the decoded value is garbage (0x531c5800024c1ad5), causing a crash when it tries to jump to that address.

## Technical Details

### Crash Location
- **Instruction**: 899
- **Address**: 0x1400183b9
- **Operation**: `call qword ptr [rip + 0x22151]` → calls 0x14003a510
- **Target**: 0x1400362e0 → `jmp qword ptr [rip + 0x4222]`
- **Final**: 0x1400362c0 → `jmp rax` where RAX=0x531c5800024c1ad5 (garbage)

### Decoding Sequence
```assembly
[885] mov rax, qword ptr [rip + 0x41caf]  ; Load encoded pointer from 0x14005a03f
[886] mov rdx, qword ptr [rip + 0x43ae8]  ; Load XOR key from 0x14005be79
[887] cmp rdx, rax                         ; Compare
[888] je 0x1400183bf                       ; If equal, skip decoding
[889] mov ecx, eax
[890] and ecx, 0x3f
[891] xor rax, rdx                         ; XOR with key
[892] ror rax, cl                          ; Rotate right by (rax & 0x3f)
...
[897] call qword ptr [rip + 0x22151]      ; Call decoded pointer
```

### Root Cause

The pointer at 0x14005a03f is supposed to be ENCODED, but it's not. CoreInfo likely encodes these pointers during initialization (possibly in code before the entry point, or in TLS callbacks), but we're not running that initialization code.

When CoreInfo tries to decode the raw pointer, it produces garbage.

## Memory Layout

- **0x14003a510**: Function pointer in .rdata section (value: 0x00000001400362e0)
  - This is AFTER the IAT (IAT ends at 0x14003a4e8)
  - Points to internal function in .text section
  - Should be encoded but isn't

- **0x14005a03f**: Encoded pointer storage (.data section)
  - Should contain encoded version of function pointer
  - Currently contains raw/unencoded value

- **0x14005be79**: XOR key (.data section)
  - Used for pointer encoding/decoding
  - Part of CoreInfo's anti-tampering system

## Previous Working State

According to the context transfer summary, CoreInfo previously executed 1,672 instructions and exited cleanly with ExitProcess(0). This was BEFORE we fixed the IAT patching logic.

The difference:
- **Before**: We were patching 0x14003a510 (and other addresses) as if they were IAT entries, replacing them with stub addresses
- **After**: We correctly identify these as internal pointers and don't patch them

The "working" state was actually broken - we were replacing internal function pointers with stubs, which prevented CoreInfo from reaching this encoded pointer check.

## Solutions

### Option 1: Pre-encode Pointers
Identify all encoded pointers in the .data section and encode them using CoreInfo's encoding scheme before starting emulation.

**Pros**: Proper solution
**Cons**: Requires reverse engineering CoreInfo's encoding scheme

### Option 2: Skip Decoding
Patch memory so that the comparison at instruction 888 succeeds (make encoded pointer == XOR key), causing CoreInfo to skip the decoding.

**Pros**: Simple workaround
**Cons**: Might break other functionality

### Option 3: Find Initialization Code
Locate and execute CoreInfo's initialization code that encodes these pointers (possibly TLS callbacks or pre-entry-point code).

**Pros**: Proper solution
**Cons**: Requires finding and emulating initialization code

### Option 4: Use Different Test Program
Switch to a simpler test program without encoded pointers.

**Pros**: Avoids the problem entirely
**Cons**: Doesn't solve the underlying issue

## Recommendation

For demonstration purposes, **Option 4** (use a different test program) is recommended. CoreInfo's anti-tampering mechanisms are too complex for a simple emulator demo.

For production use, **Option 3** (find initialization code) is the proper solution, as many real-world applications use similar techniques.

## Alternative Test Programs

Consider testing with:
1. **Simple console apps** - Hello World, basic file I/O
2. **WinAPI test programs** - Custom programs that test specific APIs
3. **Open-source utilities** - Programs with available source code for verification

## Status

🔴 **BLOCKED**: CoreInfo requires proper pointer encoding support

**Next Steps**:
1. Document this as a known limitation
2. Switch to simpler test program for demo
3. Consider implementing TLS callback support for future work

---

**Related Files**:
- `demos/test_coreinfo.py` - Test harness
- `src/core/winapi_stubs_v2.py` - Stub implementations
- `COREINFO_IAT_FIX.md` - Previous IAT patching fix
- `analyze_coreinfo_memory.py` - Memory analysis tool
