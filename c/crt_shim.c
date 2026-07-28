#include <windows.h>
#include <stddef.h>
#include <stdint.h>
#include <stdarg.h>
#include <wchar.h>

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

#if defined(__GNUC__)
/* MinGW -nostdlib freestanding build: supply the wide-string helpers the
 * elevation/capture paths use. MSVC links these from its CRT, so only define
 * them under GCC to avoid redefinition. */
size_t wcslen(const wchar_t* s) {
    const wchar_t* p = s;
    while (*p) ++p;
    return (size_t)(p - s);
}

// Minimal wide swprintf supporting only %ls (wide string), %hs (narrow
// string), %d/%u, and %% used by the elevation/capture paths. No floating
// point. MinGW's headers redirect swprintf -> __mingw_swprintf, so define that
// symbol to satisfy the compiler-generated references under -nostdlib.
int __mingw_swprintf(wchar_t* buf, size_t /*count*/, const wchar_t* fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    wchar_t* out = buf;
    for (const wchar_t* f = fmt; *f; ++f) {
        if (*f != L'%') { *out++ = *f; continue; }
        ++f;
        if (*f == L'%') { *out++ = L'%'; continue; }
        wchar_t spec = *f;
        int wide = 0;
        if (spec == L'l') { wide = 1; spec = *++f; }
        else if (spec == L'h') { wide = 0; spec = *++f; }
        if (spec == L's') {
            if (wide) {
                const wchar_t* s = va_arg(ap, const wchar_t*);
                while (s && *s) *out++ = *s++;
            } else {
                const char* s = va_arg(ap, const char*);
                while (s && *s) *out++ = (wchar_t)*s++;
            }
        } else if (spec == L'd' || spec == L'u') {
            long v = va_arg(ap, long);
            wchar_t tmp[24];
            int i = 0, neg = 0;
            unsigned long uv;
            if (spec == L'd' && v < 0) { neg = 1; uv = (unsigned long)(-v); }
            else uv = (unsigned long)v;
            if (uv == 0) tmp[i++] = L'0';
            while (uv) { tmp[i++] = (wchar_t)(L'0' + (uv % 10)); uv /= 10; }
            if (neg) *out++ = L'-';
            while (i) *out++ = tmp[--i];
        }
    }
    *out = 0;
    va_end(ap);
    return (int)(out - buf);
}
#endif /* __GNUC__ */

float floorf(float x) {
    int64_t t = (int64_t)x;
    float tf = (float)t;
    if (tf > x) return tf - 1.0f;
    return tf;
}

float ceilf(float x) {
    int64_t t = (int64_t)x;
    float tf = (float)t;
    if (tf < x) return tf + 1.0f;
    return tf;
}

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
