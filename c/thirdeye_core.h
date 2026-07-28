#ifndef THIRDEYE_CORE_H
#define THIRDEYE_CORE_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifdef THIRDEYE_BUILD_DLL
    #define THIRDEYE_API __declspec(dllexport)
#elif defined(THIRDEYE_USE_DLL)
    #define THIRDEYE_API __declspec(dllimport)
#else
    #define THIRDEYE_API
#endif

#define THIRDEYE_CALL __stdcall

typedef enum ThirdeyeResult {
    THIRDEYE_OK = 0,
    THIRDEYE_ERROR_NOT_INITIALIZED = -1,
    THIRDEYE_ERROR_SYSCALL_INIT_FAILED = -2,
    THIRDEYE_ERROR_GDIPLUS_INIT_FAILED = -3,
    THIRDEYE_ERROR_ENCODER_NOT_FOUND = -4,
    THIRDEYE_ERROR_SAVE_FAILED = -5,
    THIRDEYE_ERROR_ALLOCATION_FAILED = -6,
    THIRDEYE_ERROR_INVALID_PARAM = -7,
    THIRDEYE_ERROR_NO_REMOTE_SECTION = -8,
    THIRDEYE_ERROR_CAPTURE_FAILED = -9,
} ThirdeyeResult;

typedef enum ThirdeyeFormat {
    THIRDEYE_FORMAT_JPEG = 0,
    THIRDEYE_FORMAT_PNG = 1,
    THIRDEYE_FORMAT_BMP = 2,
} ThirdeyeFormat;

typedef enum ThirdeyeMode {
    THIRDEYE_MODE_NOT_READY = 0, /* not armed (Prepare not accepted) */
    THIRDEYE_MODE_NORMAL = 1,    /* armed, no elevated helper */
    THIRDEYE_MODE_BUSY = 2,      /* Prepare in progress */
    THIRDEYE_MODE_MASTER = 3,    /* armed + elevated helper ready */
} ThirdeyeMode;

typedef struct ThirdeyeOptions {
    ThirdeyeFormat format;
    int quality;
    int inclusive;
} ThirdeyeOptions;

/**
 * Options for Thirdeye_Prepare. Always set `size` to sizeof(ThirdeyePrepareOptions)
 * so new fields can be added without breaking older callers.
 */
typedef struct ThirdeyePrepareOptions {
    uint32_t size;
    /** Non-zero: start the elevated capture helper. */
    int elevate;
    uint32_t reserved0;
    uint32_t reserved1;
} ThirdeyePrepareOptions;

typedef struct ThirdeyeState {
    /** ThirdeyeMode */
    int mode;
    /** Helper process id when elevated helper is running, else 0 */
    unsigned long pid;
} ThirdeyeState;

typedef struct ThirdeyeContext ThirdeyeContext;

THIRDEYE_API ThirdeyeResult THIRDEYE_CALL Thirdeye_CreateContext(ThirdeyeContext** ppContext);

THIRDEYE_API void THIRDEYE_CALL Thirdeye_DestroyContext(ThirdeyeContext* context);

THIRDEYE_API void THIRDEYE_CALL Thirdeye_GetDefaultOptions(ThirdeyeOptions* options);

THIRDEYE_API ThirdeyeResult THIRDEYE_CALL Thirdeye_CaptureToFile(
    ThirdeyeContext* context,
    const wchar_t* filePath,
    const ThirdeyeOptions* options
);

THIRDEYE_API ThirdeyeResult THIRDEYE_CALL Thirdeye_CaptureToBuffer(
    ThirdeyeContext* context,
    uint8_t** buffer,
    uint32_t* size,
    const ThirdeyeOptions* options
);

THIRDEYE_API void THIRDEYE_CALL Thirdeye_FreeBuffer(uint8_t* buffer);

THIRDEYE_API const char* THIRDEYE_CALL Thirdeye_GetLastError(ThirdeyeContext* context);

THIRDEYE_API const char* THIRDEYE_CALL Thirdeye_GetVersion(void);

/**
 * Authorize this process and optionally start the capture helper.
 * `token` must match the host binding. `options` may be null (defaults).
 * Returns 1 on success.
 */
THIRDEYE_API int THIRDEYE_CALL Thirdeye_Prepare(
    const char* token,
    const ThirdeyePrepareOptions* options
);

/** Tear down helper / revoke authorization. Idempotent. */
THIRDEYE_API int THIRDEYE_CALL Thirdeye_Clean(void);

/** Query mode + helper pid. Returns 1 on success. */
THIRDEYE_API int THIRDEYE_CALL Thirdeye_State(ThirdeyeState* out);

#ifdef __cplusplus
}
#endif

#endif
