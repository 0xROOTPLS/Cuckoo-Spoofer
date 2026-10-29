# Cuckoo: Call Stack Spoofing Without Module Tampering

Cuckoo is a Win64 call-stack spoofing technique that hides the consumer module from a thread's reconstructed call tree without modifying any DLL memory. It descends directly from SilentMoonwalk by Klez, shares its goal (zero EXE frames in the observed chain), and reaches that goal through a different primitive to avoid fragile gadgets.

What follows is the design, the mechanism, the IOC profile, and the limits.

## The call tree and what makes it readable

Every running thread has a call tree. Each function call is a node, and each return address links a node to its parent. Stack walkers reconstruct that tree by reading frame sizes from `.pdata` unwind metadata, hopping from saved return address to saved return address until they hit the thread's entry point.

For a defender inspecting an unfamiliar process, that tree is the most direct artefact of "what is this code actually doing." A `CreateRemoteThread` whose chain ends in `consumer.exe!shellcode_loader+0x42` is a different observable than one whose chain ends in `kernel32!BaseThreadInitThunk+0x14`. Stack spoofing is the practice of presenting the second when the first is true.

## The wall

The original SilentMoonwalk technique chained `call <reg>; <epilog>` gadgets in system DLLs to plant pseudo return addresses whose unwind metadata happened to match the desired hidden frame size. Control Flow Guard dispatch, body-after-call layouts, and a general scarcity of the exact `call reg` followed by a clean ret epilog mean those gadgets are essentially gone from `kernel32`, `kernelbase`, and `ntdll` on Windows 11 24H2.

Klez's response to the same wall was [BYOUD](https://klezvirus.github.io/posts/Byoud/). The insight: the stack walker does not validate exact return addresses, it validates that frame sizes add up. Tamper with the unwind metadata of a proxy function so that one frame of unwind data swallows the entire hidden subtree, and the unwinder reconstructs a tree that diverges from the one actually executed.

BYOUD is excellent. It is also "loud" in a specific way. It requires changing the contents of `.pdata`, `.rdata`, or `.xdata` in a system DLL's memory image. Those sections normally carry `PAGE_READONLY`, so tampering requires a `VirtualProtect` flip. The byte content also diverges from the on-disk reference. EDR running an UnwindInspector-style integrity diff against any clean copy of the same module catches every variant of the family.

That is the gap cuckoo addresses. The goal is the same call tree result (zero EXE frames, plausible thread chain) using a mechanism that touches no DLL memory at all.

## Design

Two observations make this possible.

First, `RtlVirtualUnwind` only reads what is on the regular stack at the moment the walker observes it. Whatever was on the stack a microsecond earlier and got overwritten before the walker arrived is invisible.

Second, hardware breakpoints are per-thread debug-register state, settable by the thread itself via `SetThreadContext` on its own handle. A breakpoint placed on the address that the spoofed return chain claims as the parent will fire as `EXCEPTION_SINGLE_STEP` the moment the target API tries to return through it.

Combine the two. Set a hardware execute breakpoint on the address the fabricated chain will claim as its parent, plant the chain on the regular stack, then pivot into the target API. Catch the trap in a vectored exception handler. Redirect execution back into a continuation labelled inside the dispatcher's own frame. Unwind through the dispatcher's truthful UNWIND_INFO.

Nothing in the unwind data lies. Nothing in any DLL's memory has been written.

## The dispatcher

The whole mechanism lives in one assembly procedure, `cu_dispatch`, with truthful `FRAME` annotations:

```asm
cu_dispatch PROC FRAME
    push    r15
    .pushreg r15
    push    r14
    .pushreg r14
    ; ... six more pushes for nonvol GPRs ...
    sub     rsp, 108h
    .allocstack 108h
    .endprolog
```

The 0x108 byte allocation is the planting region. Three slots inside it carry the fabricated chain:

```
planted_top + 0x00 : SlotA (fires the HW BP: BTITN+0x14)
planted_top + 0x08 : SlotB (next walked frame: RtlUTS+0x21)
planted_top + 0x10 : SlotC (terminator: 0)
```

The remaining bytes serve as scratch space and to keep the alignment honest. After the prologue completes, the dispatcher's own frame is 16-byte aligned; the pivot then sets RSP to `planted_top`, which is congruent to 8 modulo 16, exactly what the target API expects on entry.

The shape of the planted region is the only delicate arithmetic in the technique. Win64 ABI requires that the callee see RSP congruent to 8 modulo 16 when its first instruction executes, with a 32 byte shadow space and arguments five and onward at `[rsp+0x28]` upward. Cuckoo's pivot must land RSP exactly there relative to the SlotA/B/C plant, which is why the argument count is capped at five. The sixth argument slot would collide with SlotB.

## Arming the breakpoint

`cu_arm_hwbp` is a thin C helper called from `cu_dispatch` before the chain is planted. It does four things in sequence.

1. Reject the call if the thread's TLS already holds an armed `CU_SPOOFER` (a nested or overlapping call on the same thread); `cuckoo_call` then returns NULL.
2. `GetThreadContext` on the calling thread's pseudo-handle, then scan DR7 for the lowest free `L_n` enable bit. A free slot is one whose enable bit is zero, regardless of what content sits in the corresponding DRn register.
3. Stash the active `CU_SPOOFER` pointer in a TLS slot. The vectored handler needs it to find the saved RSP and the continuation address; it is released when the call completes.
4. Write the L1 value (BTITN+0x14) into the chosen DRn, set its `L_n` bit in DR7, and clear the R/W and LEN fields for that slot to encode an execute breakpoint (R/W = 00, LEN = 00). `SetThreadContext` commits the change.

The free-slot scan exists for a specific reason. Hardcoding DR0 collides with EDR runtimes that own one or more debug-register slots for their own hooks. Stomping a slot that the EDR is actively using produces both a missed hook on the EDR side and a guaranteed alert on the spoofer's side. Picking the lowest free slot avoids that vector entirely as long as at least one of the four slots is still available, which is the common case.

The chosen slot index goes back into the `CU_SPOOFER` struct so the handler later knows which DR6 hit bit to test and which `L_n` bit to clear on disarm.

## The pivot

After `cu_arm_hwbp` returns successfully, `cu_dispatch` plants the three slots, loads the target function pointer into RAX, the up-to-five arguments into RCX/RDX/R8/R9 plus the fifth into the appropriate stack slot, then:

```asm
mov     rsp, r10        ; r10 was loaded with the planted top
jmp     rax
```

Note the `jmp`, not `call`. A CALL would push the post-call return address inside `cu_dispatch` (a real EXE address) onto both the regular stack and the shadow stack, defeating the entire point. A JMP transfers control without touching either stack. From the target API's perspective on entry, the regular stack reads exactly as if the thread had started inside `BaseThreadInitThunk`, run for a while, and called the API normally.

## The handler

The vectored exception handler `cu_veh` receives every exception in the process. It only acts when all of these hold:

1. The exception code is `EXCEPTION_SINGLE_STEP` (`0x80000004`).
2. `ExceptionAddress` is the armed L1 address.
3. The TLS slot for the active `CU_SPOOFER` is non-null and its slot index is valid.
4. The DR6 hit bit corresponding to `s->DrSlot` is set.

Failing any of these, the handler returns `EXCEPTION_CONTINUE_SEARCH` and the exception flows to whatever the process or system would have done with it normally. The handler is a strict filter, not a swallower.

When all conditions hold, the handler performs these steps.

1. Save the thread's last-error value around the TLS accesses, and copy the target API's return value (currently in RAX of the exception context) into `s->ReturnValue`.
2. Release the TLS owner so the thread can arm another call.
3. Disarm the chosen DR slot by clearing its `L_n` bit in DR7 and its hit bit in DR6.
4. Restore RSP from `s->SavedRsp`, the value `cu_dispatch` saved before pivoting.
5. Set RCX to the active `CU_SPOOFER` and `Rip` to `cu_dispatch_continuation`, a public label inside `cu_dispatch` that sits between the JMP and the truthful epilog.
6. Return `EXCEPTION_CONTINUE_EXECUTION`.

The CPU resumes at the continuation. RAX is reloaded from `s->ReturnValue`, the `add rsp, 108h` reverses the prologue's allocation, the eight `pop` instructions reverse the nonvol saves, and `ret` pops the original caller's return address off the regular stack and returns. From the outside, `cu_dispatch` is a normal Win64 function that took some arguments and returned a value. Its UNWIND_INFO matches its actual prologue exactly.

## What the call tree looks like

While the target API is running, an external observer that calls `OpenThread`, `SuspendThread`, then walks via `RtlVirtualUnwind` sees:

```
[0]  user32!MessageBoxA+0x1f
[1]  KERNEL32!BaseThreadInitThunk+0x14
[2]  ntdll!RtlUserThreadStart+0x21
[end]
```

The exact same chain a thread that had been started directly with `CreateThread(MessageBoxA, ...)` would produce. Nothing in `cuckoo.exe` or whatever the consumer module is named appears anywhere.

After the API returns and the handler redirects execution back into `cu_dispatch`, the chain transitions to its truthful form during the dispatcher's epilog. The window of plausibility is exactly the duration of the target API call, which is the only window that matters.

## Threading

Each thread that calls into cuckoo arms its own DR slot via its own TLS-stored `CU_SPOOFER`. Slots are picked independently per thread; threads do not coordinate, and the slot is released when the call completes. A thread whose TLS already holds an armed call rejects a second, overlapping call (nested callback, APC, or fiber) and `cuckoo_call` returns NULL instead of corrupting the TLS pointer. A thread whose slots are held elsewhere (for example by an EDR) picks the lowest free slot; if all four are taken, `cu_arm_hwbp` returns failure and `cu_dispatch` unwinds without calling the target.

The vectored handler is process-wide, registered once at `cuckoo_init()`. It distinguishes its own traps from anyone else's via the L1 address, TLS slot, and DR6 hit-bit tests, all per-thread state. An EDR or another library that uses hardware breakpoints in unrelated threads is not interfered with.

`cuckoo_clear()` drains in-flight calls (blocking for the target's duration) before removing the handler and freeing the TLS index. Calls that start during teardown fail fast, and a clear issued from inside a spoofed call on the same thread is a no-op so that call's handler remains available.

## Why the unwind data does not lie

This is the piece that distinguishes cuckoo from BYOUD and from anything that fakes UNWIND_INFO.

`cu_dispatch` is a real function. Its `.pushreg`, `.allocstack`, and `.endprolog` directives describe its prologue accurately. A walker that lands inside `cu_dispatch` (during the epilog or at the continuation label) gets a perfectly accurate frame. The helper that arms the breakpoint is called at the prologue's stack pointer (the allocation's first 0x20 bytes serve as its shadow space) and the slots are planted afterwards, so no unrecorded RSP adjustment exists during arming either. A walker that lands inside the target API at any point during the spoofed-chain window does not see `cu_dispatch` at all, because the planted frame above the target API claims `BTITN+0x14` as the parent, and `BaseThreadInitThunk`'s own truthful UNWIND_INFO carries the walker the rest of the way to `RtlUserThreadStart`.

Every UNWIND_INFO consulted along the spoofed chain is the genuine, on-disk, byte-identical UNWIND_INFO of a Microsoft-shipped function. None of them have been touched. The lie is in execution flow (the target API was called from cu_dispatch, not from BTITN), not in metadata.

**This is the dual of BYOUD's path. BYOUD leaves execution honest and lies in metadata. Cuckoo leaves metadata honest and lies in execution. Each pays a different IOC cost..**

## CET

Hardware Stack Protection (CET shadow stack) only applies to processes linked with `/CETCOMPAT:Yes`. That set is small at the time of writing and includes essentially no third-party userland software. Within that set, cuckoo's target-API `ret` pops the planted `BTITN+0x14` off the regular stack and pops `caller_RA` (whatever called `cu_dispatch`) off the shadow stack. The mismatch raises `#CP` and the process terminates.

This is a hard limit, not a tunable. Making cuckoo CET-clean for `/CETCOMPAT` processes requires the kind of state-driven dispatcher architecture that BYOUD's unreleased SDIE prototype reaches for, where each transition is a real CALL/RET pair and the regular and shadow stacks stay in sync at all times. Reaching that property in cuckoo would be a meaningful research direction if `/CETCOMPAT` ever becomes mandatory in a future Windows revision.

For the overwhelming majority of processes today, cuckoo is safe.

## IOC profile

Cuckoo produces, per call:

* One `EXCEPTION_SINGLE_STEP` trap, captured in the process's own VEH and not propagated. Visible in the ETW Threat Intelligence provider, which logs exception dispatch events.
* One pair of `GetThreadContext` and `SetThreadContext` on the calling thread's pseudo-handle.
* Use of one DR slot for the duration of the call. Released on return.

Cuckoo does not produce:

* Any write to a DLL's `.text`, `.pdata`, `.rdata`, or `.xdata` section.
* Any `VirtualProtect` change on a system DLL's mapping.
* Any modification of `RUNTIME_FUNCTION` tables, static or dynamic.
* Any unwind-metadata divergence from the on-disk image.
* Any thread-pool dispatch event.
* Any spawned thread.

The asymmetry against BYOUD is direct. BYOUD avoids the exception-trap signal, paid for with module-memory tampering. Cuckoo avoids the module-memory signal, paid for with a single trap.

## Detection

### Empirical results

A worker thread was placed in `DelayExecution` via `cuckoo_call(Sleep, 120000)` and scanned by four publicly available tools: Moneta (Forrest Orr), PE-Sieve (hasherezade), Hunt-Sleeping-Beacons (theFLink), and Get-InjectedThreadEx. A naive control (worker thread starting in `VirtualAlloc(PAGE_EXECUTE_READWRITE)` private memory) was scanned alongside to confirm the toolchain was firing on something it should.

Control results, abbreviated:

```
Moneta:   private +X region; thread origin off-image
PE-Sieve: 1/4 -- implanted_shc=1 | thread: SUS_START, SUS_CALLSTACK_SHC
HSB:      Thread N | Abnormal Page in Callstack | private memory regions | MID
GIT-Ex:   TID N -> PRIVATE
```

Cuckoo results:

```
Moneta:   no anomaly markers
PE-Sieve: modified=0/5 (errors=0)
HSB:      Thread N | Identified enabled hardware-breakpoints
GIT-Ex:   TID N -> hw_breakpoint
```

The chain inspection itself was clean across all four. Specifically, the following did not fire on cuckoo:

* Moneta's `Abnormal private executable memory` and `Thread within non-image memory region`.
* PE-Sieve's `SUS_START`, `SUS_CALLSTACK_SHC`, and `implanted_shc` indicators (with `/shellc 3 /threads`).
* HSB's `return_address_spoofing.cpp`, `abnormal_intermodular_call.cpp`, `private_memory.cpp`, and `non_executable_memory.cpp` modules.
* Get-InjectedThreadEx's `proxy_call`, `prolog`, `private_image`, and `PRIVATE` rules.

Get-InjectedThreadEx logged `Win32StartAddress: sleeper.exe!worker` for the cuckoo'd thread and did not cross-check that against the spoofed chain (which contains no `worker` frame). HSB did the same. The Win32-start vs chain mismatch identified earlier as the cleanest theoretical detection against cuckoo is not implemented in any of the four tools at the time of writing.

The spoof itself, in other words, holds.

### What did fire

Both HSB and Get-InjectedThreadEx caught on the same orthogonal signal: an enabled hardware breakpoint sitting in a debug register during the call window. HSB labelled it `Identified enabled hardware-breakpoints`. Get-InjectedThreadEx flagged it as `hw_breakpoint`.

Two properties of this detection are worth noting.

It is generic, not cuckoo-specific. Both rules flag any thread with an enabled `L_n` bit in DR7. The same pattern fires on EDR hooks themselves, anti-cheat, debuggers, and a number of legitimate runtimes. The signal-to-noise ratio on "DR enabled" is poor, which is why EDRs that ingest it generally treat it as an enrichment factor rather than a standalone alert.

It is structural to the redirect mechanism. The target API's `ret` consumes the planted `BTITN+0x14` and would execute the real bytes at that address (which dispatch into thread-exit code) unless something catches the transition first. The realistic alternatives are page guards on `kernel32.dll` (much louder), invalid-VA + access-violation handlers (heavier ETW exception telemetry than `#DB`), or inline-patching the system DLL itself (defeats "no DLL tampering" property). HWBP is the quietest available primitive for this redirect.

### Detection vectors that remain theoretically open

The following are not implemented in any of the four scanners but would catch cuckoo if a defender added them.

ETW Threat Intelligence `#DB` correlation. A composite rule of (self-DR-arm) followed by (`#DB`) followed by (RIP redirect to a non-instruction-following address inside the same EXE/DLL as the arming code) pattern-matches cuckoo specifically rather than HWBPs in general.

`Win32StartAddress` versus call chain cross-check. The thread's recorded start address is set by the kernel at thread creation and not modifiable from user mode. Cuckoo's chain elides the start-address frame. A scanner that checks "does `Win32StartAddress` appear anywhere in the reconstructed chain" finds the inconsistency on cuckoo'd threads.

Plausibility of (parent_function, child_API) pairs. `BaseThreadInitThunk+0x14` as a parent of `MessageBoxA` is fully plausible (a thread genuinely started on `MessageBoxA` would produce that). `BaseThreadInitThunk+0x14` as a parent of, say, `RtlAcquireSRWLockExclusive` strains plausibility, because no realistic thread is started on that function.

## Limitations

* Five argument cap. On current builds the sixth argument slot (`planted_top+0x30`) collides with SlotB. Fixable by enlarging the plant and shifting the slot offsets, at the cost of a wider plant footprint.
* One in-flight call per thread. Overlapping calls are detected and rejected: the inner `cuckoo_call` returns NULL. A call that never returns through the planted frame (for example `ExitThread`/`TerminateThread`, or a VEH that redirects instead of unwinding) leaks the in-flight count, so `cuckoo_clear` can block; if the thread survives, its DR slot and TLS stay armed and later calls on it fail.
* `/CETCOMPAT` processes are unsupported.
* The DR slot must be available. Four slots total per thread, and EDRs commonly hold one or two of them. Three coexisting EDRs holding all four leaves cuckoo no room.
* Exceptions raised inside the target cannot be caught by SEH frames around `cuckoo_call`; the fabricated chain omits the real caller frames. Only a process-wide VEH (or a handler inside the target) can intercept them.
* Init requires the L1 symbol's unwind frame (`BaseThreadInitThunk` by default) to be at least 0x28 bytes so SlotB clears the target's shadow space and the fifth-argument slot. Current builds use 0x28; a build with a smaller frame fails init cleanly.
* No support yet for varargs APIs whose stack-arg layout depends on runtime types (the `printf` family). The fixed five-arg ABI handles every standard Win32 API.

## Status

The technique is the result of pivoting away from the SilentMoonwalk gadget approach. BYOUD by Klez is the closest published technique by intent and the proximate inspiration for thinking about the unwind apparatus as the spoofing surface. The path cuckoo takes is the dual of BYOUD's path, with a different IOC profile and a different detection envelope.

Neither dominates the other. A defender that builds for one is not automatically equipped to detect the other, which is the most useful property of having two such different mechanisms aiming at the same outcome.
