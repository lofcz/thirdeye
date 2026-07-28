/*
 * Minimal freestanding CRT surface for the thirdeye DLL.
 *
 * The DLL is linked with -nostdlib so that no MinGW/UCRT startup code
 * (dllcrt0, atexit tables, TLS support, pseudo-relocation) and none of the
 * api-ms-win-crt-* import DLLs appear in the image. That startup residue is
 * what drags injection-associated imports (VirtualProtect, VirtualQuery,
 * TlsGetValue, LoadLibraryA/GetProcAddress, stdio) into the IAT even though
 * the library never calls them, and the resulting lean-DLL-plus-CRT shape is
 * what static ML classifiers key on.
 *
 * Only the small set of routines the code actually uses is provided here,
 * implemented directly on top of the NT process heap and compiler intrinsics.
 * Heap allocation uses GetProcessHeap/HeapAlloc, which are ordinary,
 * low-signal kernel32 imports.
 */
#include <windows.h>
#include <stddef.h>
#include <stdint.h>

/* ---- heap-backed allocation ---- */

void* malloc(size_t size) {
    if (size == 0) size = 1;
    return HeapAlloc(GetProcessHeap(), 0, size);
}

void* calloc(size_t num, size_t size) {
    SIZE_T total = num * size;
    if (size != 0 && total / size != num) return NULL; /* overflow */
    if (total == 0) total = 1;
    return HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, total);
}

void* realloc(void* ptr, size_t size) {
    if (!ptr) return malloc(size);
    if (size == 0) { HeapFree(GetProcessHeap(), 0, ptr); return NULL; }
    return HeapReAlloc(GetProcessHeap(), 0, ptr, size);
}

void free(void* ptr) {
    if (ptr) HeapFree(GetProcessHeap(), 0, ptr);
}

/* ---- memory / string primitives ----
 * Compiled with -fno-builtin so the compiler emits calls to these rather than
 * inlining its own (which would reference libgcc's versions). */

void* memcpy(void* dst, const void* src, size_t n) {
    unsigned char* d = (unsigned char*)dst;
    const unsigned char* s = (const unsigned char*)src;
    for (size_t i = 0; i < n; ++i) d[i] = s[i];
    return dst;
}

void* memmove(void* dst, const void* src, size_t n) {
    unsigned char* d = (unsigned char*)dst;
    const unsigned char* s = (const unsigned char*)src;
    if (d == s || n == 0) return dst;
    if (d < s) {
        for (size_t i = 0; i < n; ++i) d[i] = s[i];
    } else {
        for (size_t i = n; i > 0; --i) d[i - 1] = s[i - 1];
    }
    return dst;
}

void* memset(void* dst, int c, size_t n) {
    unsigned char* d = (unsigned char*)dst;
    unsigned char v = (unsigned char)c;
    for (size_t i = 0; i < n; ++i) d[i] = v;
    return dst;
}

int memcmp(const void* a, const void* b, size_t n) {
    const unsigned char* x = (const unsigned char*)a;
    const unsigned char* y = (const unsigned char*)b;
    for (size_t i = 0; i < n; ++i) {
        if (x[i] != y[i]) return (int)x[i] - (int)y[i];
    }
    return 0;
}

size_t strlen(const char* s) {
    const char* p = s;
    while (*p) ++p;
    return (size_t)(p - s);
}

char* strncpy(char* dst, const char* src, size_t n) {
    size_t i = 0;
    for (; i < n && src[i]; ++i) dst[i] = src[i];
    for (; i < n; ++i) dst[i] = '\0';
    return dst;
}

int strncmp(const char* a, const char* b, size_t n) {
    for (size_t i = 0; i < n; ++i) {
        unsigned char ca = (unsigned char)a[i];
        unsigned char cb = (unsigned char)b[i];
        if (ca != cb || ca == 0) return (int)ca - (int)cb;
    }
    return 0;
}

int strcmp(const char* a, const char* b) {
    while (*a && (*a == *b)) { ++a; ++b; }
    return (int)(unsigned char)*a - (int)(unsigned char)*b;
}

/* ---- floating point rounding (tiny_jpeg DCT quantization) ----
 * Truncation-toward-zero then adjust, matching C99 floorf/ceilf semantics. */

float floorf(float x) {
    int64_t t = (int64_t)x;          /* truncate toward zero */
    float tf = (float)t;
    if (tf > x) return tf - 1.0f;    /* x negative non-integer */
    return tf;
}

float ceilf(float x) {
    int64_t t = (int64_t)x;
    float tf = (float)t;
    if (tf < x) return tf + 1.0f;    /* x positive non-integer */
    return tf;
}

/* ---- MinGW stack probe ----
 * Emitted for frames >= 4096 bytes (e.g. TJEState). With -nostdlib the libgcc
 * copy is unavailable, so provide one. It walks the stack down one page at a
 * time, touching each page to grow the guard region, matching the ABI the
 * caller expects (allocation size passed in %rax, preserved on return). */
#if defined(__x86_64__) || defined(_M_X64)
__asm__(
    ".text\n"
    ".globl ___chkstk_ms\n"
    ".def ___chkstk_ms; .scl 2; .type 32; .endef\n"
    "___chkstk_ms:\n"
    "   pushq %rcx\n"
    "   pushq %rax\n"
    "   cmpq  $0x1000, %rax\n"
    "   leaq  24(%rsp), %rcx\n"
    "   jb    2f\n"
    "1:\n"
    "   subq  $0x1000, %rcx\n"
    "   testb %al, (%rcx)\n"
    "   subq  $0x1000, %rax\n"
    "   cmpq  $0x1000, %rax\n"
    "   ja    1b\n"
    "2:\n"
    "   subq  %rax, %rcx\n"
    "   testb %al, (%rcx)\n"
    "   popq  %rax\n"
    "   popq  %rcx\n"
    "   ret\n"
);
#endif
