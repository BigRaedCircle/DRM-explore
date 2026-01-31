# Memory Fetch Hook Issue

**Date:** 2026-02-01  
**Problem:** Fetch hook returns True but Unicorn doesn't continue with new RIP

---

## Problem

After handling stub call in `_hook_mem_fetch_unmapped()` and setting RIP to return address, Unicorn stops with `UC_ERR_MAP` instead of continuing execution.

## Evidence

```
[FETCH] Stub call @ 0x7fffbc00
[API] GetSystemTimeAsFileTime(0x1fefd8) -> 134143712505890124 [CUSTOM]
[STUB] Returning to 0x14000ffb9, RSP=0x1fef98
[!] Эмуляция остановлена: Invalid memory mapping (UC_ERR_MAP)
```

## Root Cause

Fetch hook behavior:
1. Unmapped fetch at 0x7fffbc00 triggers hook
2. Hook calls `handle_stub_call()` which sets RIP to 0x14000ffb9
3. Hook returns `True` (meaning "I handled it")
4. **Unicorn tries to continue fetching from ORIGINAL address** (0x7fffbc00)
5. Memory still unmapped → UC_ERR_MAP

**Key insight:** Returning `True` from fetch hook means "I provided the code", NOT "continue from new RIP"!

## Solutions Attempted

### ❌ Option 1: INT3 hook
- Problem: INT hook doesn't respect RIP changes

### ❌ Option 2: Fetch hook with unmapped memory
- Problem: Fetch hook doesn't respect RIP changes either!

### ✅ Option 3: Map stub memory and write RET instruction
- Write actual executable code (RET) at stub address
- Let CPU execute RET naturally
- This WILL work!

---

## Final Solution

**Write RET instruction at each stub address:**

```python
def _write_all_stub_code(self):
    # Map stub memory
    # (already done in LayeredEmulatorV2.__init__)
    
    for address, func_name in self.stub_addresses.items():
        # Write RET instruction
        stub_code = bytes([0xC3])  # RET
        self.uc.mem_write(address, stub_code)
```

**In fetch hook: DON'T handle stubs!**
```python
def _hook_mem_fetch_unmapped(self, uc, access, address, size, value, user_data):
    # Stubs are now MAPPED, so this won't trigger for them
    # Only handle truly unmapped addresses
    return False
```

**In code hook: Detect stub entry and handle**
```python
def _hook_code(self, uc, address, size, user_data):
    STUB_BASE = 0x7FFF0000
    STUB_SIZE = 0x40000000
    
    if STUB_BASE <= address < STUB_BASE + STUB_SIZE:
        # This is stub entry!
        self.winapi.handle_stub_call(address)
        # RIP now points to return address
        # Next instruction will be at return address
```

---

## Why This Works

1. Stub memory is MAPPED with RET instruction
2. When code calls stub, CPU executes to stub address
3. Code hook detects stub entry (before RET executes)
4. We handle stub call and set RIP to return address
5. Code hook returns
6. **Unicorn continues from NEW RIP** (return address)
7. RET instruction never executes

This works because **code hook DOES respect RIP changes**!

---

## Implementation

Need to:
1. Re-enable stub memory mapping in `LayeredEmulatorV2.__init__()`
2. Write RET (0xC3) at each stub address in `_write_all_stub_code()`
3. Remove fetch hook stub handling
4. Add code hook stub detection

This is the CORRECT solution!
