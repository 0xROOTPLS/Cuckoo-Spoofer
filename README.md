# Cuckoo

Win64 call-stack spoofing that hides the consumer module from a thread's reconstructed call tree without writing to any DLL memory or relying on gadgets.

## Motivation

A defender reading a call tree sees what the code **claims** to be doing. A `CreateRemoteThread` chain ending in `consumer.exe!loader+0x42` is an obvious red flag. The same call ending in `kernel32!BaseThreadInitThunk+0x14` is not. Stack spoofing presents the second when the first is true.

SilentMoonwalk chained `call <reg>; <epilog>` gadgets in system DLLs to match desired frame sizes. Those gadgets are gone on Windows 11 24H2. In response, Klez's BYOUD instead tampers with the unwind metadata of a proxy function so the unwinder reconstructs a different tree. It works, but it requires writes to `.pdata`/`.xdata`/`.rdata`, a `VirtualProtect` call, and it diverges from disk.

Cuckoo targets the same outcome with no module writes.

## Design

Two things make Cuckoo work:

1. `RtlVirtualUnwind` only sees what is on the regular stack at the moment it walks.
2. Debug registers are per-thread state, and a thread can set its own via `SetThreadContext` on its pseudo-handle.

Combine the two and you get... magic! (jk)
if you set a hardware execute breakpoint on the address the fabricated chain claims as its parent, then plant the chain, and JMP into the target API. A VEH catches the `#DB` and redirects execution to a labelled continuation inside the dispatcher. The dispatcher then unwinds through its own truthful UNWIND_INFO.

No unwind table is falsely claimed and no DLL memory is written. The spoof is in execution flow, not metadata. (This is the dual of BYOUD)

## Observed Chain

```
[0] user32!MessageBoxA+0x1f
[1] KERNEL32!BaseThreadInitThunk+0x14
[2] ntdll!RtlUserThreadStart+0x21
```

This matches a thread created with `CreateThread(MessageBoxA)`. The window of plausibility is the duration of the target call.

`cu_dispatch`'s `.pushreg`/`.allocstack`/`.endprolog` accurately describe its prologue, so a walker inside it gets a correct frame. A walker inside the target sees the planted frame claiming `BTITN+0x14`, and that function's own UNWIND_INFO carries it to `RtlUserThreadStart`.

## Detection

**Test setup:** worker thread in `cuckoo_call(Sleep, 120000)`, scanned with Moneta, PE-Sieve, Hunt-Sleeping-Beacons (HSB), and Get-InjectedThreadEx (GIT-Ex). Control: a thread starting in `VirtualAlloc`'d RWX private memory.

| Tool | Control | Cuckoo |
|---|---|---|
| Moneta | Private +X region, off-image origin | No anomaly markers |
| PE-Sieve | 1/4, `implanted_shc`, `SUS_START`, `SUS_CALLSTACK_SHC` | `modified=0/5` |
| HSB | Abnormal page in callstack, private memory | Enabled hardware breakpoints |
| GIT-Ex | `PRIVATE` | `hw_breakpoint` |

Chain inspection was clean across all four. The only hit was the enabled DR slot, flagged by HSB and GIT-Ex. That signal is generic though.

## Limitations

- **Five args max.** On current builds the sixth slot collides with SlotB. Fixable with a larger plant footprint.
- **One in-flight call per thread.** A call that never returns through the plant leaks the in-flight count and DR slot, and `cuckoo_clear` can block.
- **`/CETCOMPAT` unsupported.** The target's `ret` mismatches the shadow stack and raises `#CP`. 
- **Needs a free DR slot.** Four per thread, and EDRs often hold one or two (sometimes)
- **SEH around `cuckoo_call` won't catch exceptions from inside the target.** Only a process-wide VEH sees them.
- **Init requires an L1 frame ≥ 0x28 bytes** so SlotB clears shadow space and the fifth-arg slot. Smaller frames fail cleanly.
- **No varargs.** The `printf` family's stack layout depends on runtime types. The fixed five-arg ABI covers standard Win32 APIs.

## Status

Cuckoo replaces the SilentMoonwalk approach. BYOUD is the closest published technique. Neither dominates.
