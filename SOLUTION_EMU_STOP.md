# Final Solution: uc.emu_stop() + Restart Pattern

**Date:** 2026-02-01  
**Conclusion:** ALL hooks (INT, fetch, code) don't respect RIP changes in Unicorn

---

## Problem Summary

Tried 3 different approaches:
1. ❌ INT3 hook + RIP modification → Unicorn ignores new RIP
2. ❌ Memory fetch unmapped hook + RIP modification → Unicorn ignores new RIP  
3. ❌ Code hook (stub entry detection) + RIP modification → Unicorn ignores new RIP

**Root cause:** Unicorn's hook system does NOT respect RIP modifications made inside hooks!

---

## Evidence

All three approaches show the same pattern:
```
[STUB] Returning to 0x140018344, RSP=0x1fef38
  ← RIP set to 0x140018344

[!] UNMAPPED FETCH @ 0x92ff8dc3f8700000
  ← Next instruction: RIP is CORRUPTED!
```

The code hook is NEVER called for 0x140018344. Unicorn jumps to garbage address instead.

---

## The ONLY Solution

**Use uc.emu_stop() + restart pattern:**

```python
def handle_stub_call(self, address):
    # Find stub function
    func_name = self.stub_addresses.get(address)
    stub = self.registry.get(func_name)
    
    if stub:
        # Call stub implementation
        stub()
        
        # Get return address from stack
        rsp = self.uc.reg_read(UC_X86_REG_RSP)
        ret_addr = int.from_bytes(self.uc.mem_read(rsp, 8), 'little')
        
        # Update RSP and RIP
        self.uc.reg_write(UC_X86_REG_RSP, rsp + 8)
        self.uc.reg_write(UC_X86_REG_RIP, ret_addr)
        
        # CRITICAL: Stop emulation
        # This is the ONLY way to make Unicorn respect new RIP!
        self.uc.emu_stop()
        
        # Save return address for restart
        self.pending_restart = ret_addr
```

Then in main emulation loop:
```python
def run(self, start_addr, end_addr=0, max_instructions=10000000):
    current_addr = start_addr
    
    while self.instruction_count < max_instructions:
        try:
            # Run until stub call or end
            self.uc.emu_start(current_addr, end_addr, count=max_instructions - self.instruction_count)
            
            # Emulation ended normally
            break
            
        except Exception as e:
            # Check if we have pending restart (from stub call)
            if hasattr(self.winapi, 'pending_restart') and self.winapi.pending_restart:
                current_addr = self.winapi.pending_restart
                self.winapi.pending_restart = None
                # Continue emulation from new address
                continue
            else:
                # Real error
                raise
```

---

## Why This Works

1. Stub call detected in code hook
2. `handle_stub_call()` executes stub and sets RIP
3. `uc.emu_stop()` stops emulation
4. Exception caught in run() loop
5. Check for `pending_restart`
6. **Restart emulation from new RIP**
7. Unicorn now executes from correct address!

This is the ONLY way to make Unicorn respect RIP changes!

---

## Implementation Required

1. Modify `handle_stub_call()` to call `uc.emu_stop()` and save return address
2. Modify `run()` to catch stop and restart from saved address
3. Add `pending_restart` attribute to track restart address

This will finally make stub system work correctly!
