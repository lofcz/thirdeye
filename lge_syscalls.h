#ifndef THIRDEYE_LGE_SYSCALLS_H
#define THIRDEYE_LGE_SYSCALLS_H

#include "internal.h"

#ifdef __cplusplus
extern "C" {
#endif

bool LgeInitialize();

NTSTATUS LgeInvoke(DWORD ssn,
    void* a1, void* a2, void* a3, void* a4,
    void* a5, void* a6, void* a7, void* a8,
    void* a9, void* a10, void* a11, void* a12);

#ifdef __cplusplus
}
#endif

#endif
