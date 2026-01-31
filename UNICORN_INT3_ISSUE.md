# Unicorn INT3 Hook Issue

**Date:** 2026-02-01  
**Problem:** RIP modification in INT3 hook is ignored by Unicorn

---

## Problem Description

When we modify RIP in Unicorn's INT hook (for INT3), Unicorn **ignores** the new RIP value and continues execution from an incorrect address.

## Evidence

```
[INT3] @ 0x7fff4101, return to 0x140018344
[STUB] Call to middle of stub 'entercriticalsection' @ 0x7fff4101
[API] EnterCriticalSection()
[STUB] Returning to 0x140018344, RSP=0x1fef38
  ← RIP set to 0x140018344, RSP set to 0x1fef38

[!] UNMAPPED FETCH @ 0xfdeec17634000, RIP=0x92fdeec17634000
  ← Next instruction: RIP is CORRUPTED!
```

## Root Cause

Unicorn's INT hook behavior:
1. INT3 instruction triggers hook
2. Hook modifies RIP to return address (0x140018344)
3. Hook returns
4. **Unicorn continues from RIP+1** (next byte after INT3) instead of new RIP
5. Executes garbage bytes, leading to corrupted RIP

## Verification

- RIP verification in `handle_stub_call()`: **PASSED** (RIP correctly set to 0x140018344)
- _hook_code called for 0x140018344: **FAILED** (never called)
- Next instruction: **UNMAPPED FETCH** with corrupted RIP

## Solutions

### Option 1: Use emu_stop() + restart pattern ❌
```python
def _hook_interrupt(self, uc, intno, user_data):
    if intno == 0x03:
        self.winapi.handle_stub_call(rip)
        # Stop emulation
        uc.emu_stop()
        # Need to restart from new RIP - COMPLEX!
```
**Problem:** Need to manage emulation restart, complex state management

### Option 2: Use memory fetch hook instead of INT3 ✅
```python
# Instead of INT3 (0xCC), use invalid opcode or special marker
# Catch in memory fetch unmapped hook
def _hook_mem_fetch_unmapped(self, uc, access, address, size, value, user_data):
    if is_stub_address(address):
        self.winapi.handle_stub_call(address)
        return True  # Continue execution
```
**Advantage:** Memory hooks respect RIP changes!

### Option 3: Use UD2 (invalid instruction) instead of INT3 ✅
```python
# Stub code: UD2 (0x0F 0x0B) instead of INT3 (0xCC)
stub_code = bytes([0x0F, 0x0B])  # UD2 - invalid instruction

# Hook invalid instruction
uc.hook_add(UC_HOOK_INSN_INVALID, self._hook_invalid_insn)
```
**Advantage:** Invalid instruction hooks may handle RIP better

### Option 4: Don't modify RIP in hook, use callback ✅
```python
# In INT3 hook: just save return address
def _hook_interrupt(self, uc, intno, user_data):
    if intno == 0x03:
        rsp = uc.reg_read(UC_X86_REG_RSP)
        ret_addr = int.from_bytes(uc.mem_read(rsp, 8), 'little')
        
        # Save for next instruction
        self.pending_return = ret_addr
        
        # Let RET execute naturally
        return

# In _hook_code: check if we have pending return
def _hook_code(self, uc, address, size, user_data):
    if self.pending_return and address == self.pending_return:
        self.pending_return = None
        # Continue normally
```
**Problem:** Still need RET to execute, but we're in INT3, not at RET

---

## Recommended Solution

**Use memory fetch unmapped hook** instead of INT3:

1. Stub code: Write **NOP** (0x90) instead of INT3+RET
2. Don't map stub memory initially
3. Catch unmapped fetch in `_hook_mem_fetch_unmapped()`
4. Call `handle_stub_call()` there
5. Memory hooks **respect RIP changes**!

```python
# In WinAPIStubsV2:
def _write_all_stub_code(self):
    # DON'T write stub code!
    # Leave memory unmapped
    # Catch in fetch hook
    pass

# In LayeredEmulatorV2:
def _hook_mem_fetch_unmapped(self, uc, access, address, size, value, user_data):
    STUB_BASE = 0x7FFF0000
    STUB_SIZE = 0x40000000
    
    if STUB_BASE <= address < STUB_BASE + STUB_SIZE:
        # This is a stub call!
        self.winapi.handle_stub_call(address)
        
        # RIP is now set to return address
        # Unicorn will continue from new RIP
        return True
    
    return False
```

---

## Next Steps

1. Implement memory fetch hook solution
2. Remove INT3-based stub code
3. Test with CoreInfo
4. Verify RIP is correctly restored after stub calls

---

## Conclusion

Unicorn's INT hook does NOT respect RIP modifications. We must use **memory fetch unmapped hook** instead, which DOES respect RIP changes.

This is a fundamental limitation of Unicorn's INT hook implementation.
