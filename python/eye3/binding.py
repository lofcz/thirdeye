"""ctypes binding to the bundled thirdeye.dll (Windows x64)."""

import ctypes
import os
import sys
from enum import IntEnum

_DLL_NAME = "thirdeye.dll"


def get_library_path() -> str:
    """Absolute path to the bundled thirdeye.dll."""
    path = os.path.join(os.path.dirname(__file__), _DLL_NAME)
    if not os.path.exists(path):
        raise ThirdEyeError(
            f"thirdeye native library not found at {path}. "
            "This wheel ships a Windows x64 binary only."
        )
    return path


class ThirdeyeResult(IntEnum):
    OK = 0
    ERROR_NOT_INITIALIZED = -1
    ERROR_SYSCALL_INIT_FAILED = -2
    ERROR_GDIPLUS_INIT_FAILED = -3
    ERROR_ENCODER_NOT_FOUND = -4
    ERROR_SAVE_FAILED = -5
    ERROR_ALLOCATION_FAILED = -6
    ERROR_INVALID_PARAM = -7
    ERROR_NO_REMOTE_SECTION = -8
    ERROR_CAPTURE_FAILED = -9


class ThirdeyeFormat(IntEnum):
    JPEG = 0
    PNG = 1
    BMP = 2


class ThirdEyeError(RuntimeError):
    """Raised when a thirdeye call returns a non-OK result."""

    def __init__(self, result, message: str):
        self.result = result
        super().__init__(f"{message} (result={int(result)})")


class ThirdEyeOptions(ctypes.Structure):
    _fields_ = [
        ("format", ctypes.c_int),
        ("quality", ctypes.c_int),
        ("inclusive", ctypes.c_int),
    ]

    def __init__(self, format=ThirdeyeFormat.JPEG, quality=90, inclusive=True):
        super().__init__(int(format), int(quality), 1 if inclusive else 0)


class ThirdEyeState(ctypes.Structure):
    _fields_ = [
        ("mode", ctypes.c_int),
        ("pid", ctypes.c_ulong),
    ]


class ThirdEyePrepareOptions(ctypes.Structure):
    _fields_ = [
        ("size", ctypes.c_uint32),
        ("elevate", ctypes.c_int),
        ("reserved0", ctypes.c_uint32),
        ("reserved1", ctypes.c_uint32),
    ]

    def __init__(self, elevate=True):
        super().__init__(ctypes.sizeof(ThirdEyePrepareOptions), 1 if elevate else 0, 0, 0)


# Must match the native Prepare token.
_PREPARE_TOKEN = "third_eye_token"


def _load():
    if sys.platform != "win32":
        raise ThirdEyeError(
            ThirdeyeResult.ERROR_NOT_INITIALIZED,
            "thirdeye is supported on Windows x64 only",
        )
    lib = ctypes.WinDLL(get_library_path())

    lib.Thirdeye_CreateContext.argtypes = [ctypes.POINTER(ctypes.c_void_p)]
    lib.Thirdeye_CreateContext.restype = ctypes.c_int

    lib.Thirdeye_DestroyContext.argtypes = [ctypes.c_void_p]
    lib.Thirdeye_DestroyContext.restype = None

    lib.Thirdeye_GetDefaultOptions.argtypes = [ctypes.POINTER(ThirdEyeOptions)]
    lib.Thirdeye_GetDefaultOptions.restype = None

    lib.Thirdeye_CaptureToFile.argtypes = [
        ctypes.c_void_p,
        ctypes.c_wchar_p,
        ctypes.POINTER(ThirdEyeOptions),
    ]
    lib.Thirdeye_CaptureToFile.restype = ctypes.c_int

    lib.Thirdeye_CaptureToBuffer.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.POINTER(ctypes.c_uint8)),
        ctypes.POINTER(ctypes.c_uint32),
        ctypes.POINTER(ThirdEyeOptions),
    ]
    lib.Thirdeye_CaptureToBuffer.restype = ctypes.c_int

    lib.Thirdeye_FreeBuffer.argtypes = [ctypes.POINTER(ctypes.c_uint8)]
    lib.Thirdeye_FreeBuffer.restype = None

    lib.Thirdeye_GetLastError.argtypes = [ctypes.c_void_p]
    lib.Thirdeye_GetLastError.restype = ctypes.c_char_p

    lib.Thirdeye_GetVersion.argtypes = []
    lib.Thirdeye_GetVersion.restype = ctypes.c_char_p

    lib.Thirdeye_Prepare.argtypes = [ctypes.c_char_p, ctypes.POINTER(ThirdEyePrepareOptions)]
    lib.Thirdeye_Prepare.restype = ctypes.c_int

    lib.Thirdeye_Clean.argtypes = []
    lib.Thirdeye_Clean.restype = ctypes.c_int

    lib.Thirdeye_State.argtypes = [ctypes.POINTER(ThirdEyeState)]
    lib.Thirdeye_State.restype = ctypes.c_int

    return lib


class ThirdEyeSession:
    """Thread-safe-ish capture session. Use as a context manager."""

    def __init__(self):
        self._lib = _load()
        self._ctx = ctypes.c_void_p()
        rc = ThirdeyeResult(self._lib.Thirdeye_CreateContext(ctypes.byref(self._ctx)))
        if rc != ThirdeyeResult.OK or not self._ctx:
            raise ThirdEyeError(rc, "Thirdeye_CreateContext failed")

    def default_options(self) -> ThirdEyeOptions:
        opts = ThirdEyeOptions()
        self._lib.Thirdeye_GetDefaultOptions(ctypes.byref(opts))
        return opts

    def capture_to_file(self, file_path: str, options: ThirdEyeOptions = None) -> None:
        opts = options or self.default_options()
        rc = ThirdeyeResult(
            self._lib.Thirdeye_CaptureToFile(self._ctx, file_path, ctypes.byref(opts))
        )
        if rc != ThirdeyeResult.OK:
            raise ThirdEyeError(rc, f"Thirdeye_CaptureToFile failed: {self.last_error()}")

    def capture_to_buffer(self, options: ThirdEyeOptions = None) -> bytes:
        opts = options or self.default_options()
        buf = ctypes.POINTER(ctypes.c_uint8)()
        size = ctypes.c_uint32(0)
        rc = ThirdeyeResult(
            self._lib.Thirdeye_CaptureToBuffer(
                self._ctx, ctypes.byref(buf), ctypes.byref(size), ctypes.byref(opts)
            )
        )
        if rc != ThirdeyeResult.OK or not buf or size.value == 0:
            raise ThirdEyeError(rc, f"Thirdeye_CaptureToBuffer failed: {self.last_error()}")
        try:
            return ctypes.string_at(buf, size.value)
        finally:
            self._lib.Thirdeye_FreeBuffer(buf)

    def last_error(self) -> str:
        err = self._lib.Thirdeye_GetLastError(self._ctx)
        return err.decode("utf-8", "replace") if err else ""

    def version(self) -> str:
        v = self._lib.Thirdeye_GetVersion()
        return v.decode("utf-8", "replace") if v else ""

    def prepare(self, elevate: bool = True) -> bool:
        """
        Authorize the library.

        Capture options `inclusive`:
        - includes hidden / capture-excluded windows
        - when state is ``master`` and elevate was True, also elevated processes

        state is ``normal`` | ``busy`` | ``master``.
        """
        opts = ThirdEyePrepareOptions(elevate=elevate)
        return bool(
            self._lib.Thirdeye_Prepare(_PREPARE_TOKEN.encode("ascii"), ctypes.byref(opts))
        )

    def clean(self) -> bool:
        return bool(self._lib.Thirdeye_Clean())

    def state(self) -> dict:
        # mode: 0 NotReady (until armed), 1 Normal, 2 Busy, 3 Master
        st = ThirdEyeState()
        if not self._lib.Thirdeye_State(ctypes.byref(st)):
            return {"mode": 0, "pid": 0}
        return {"mode": int(st.mode), "pid": int(st.pid)}

    def close(self) -> None:
        try:
            self.clean()
        except Exception:
            pass
        if self._ctx:
            self._lib.Thirdeye_DestroyContext(self._ctx)
            self._ctx = ctypes.c_void_p()

    def __enter__(self) -> "ThirdEyeSession":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def __del__(self):
        try:
            self.close()
        except Exception:
            pass
