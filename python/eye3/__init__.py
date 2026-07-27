"""eye3 - screen capture bypassing WDA_MONITOR/WDA_EXCLUDEFROMCAPTURE.

Windows x64 native binary bundled in the wheel.
"""

from .binding import (
    ThirdEyeError,
    ThirdEyeOptions,
    ThirdEyeSession,
    ThirdeyeFormat,
    ThirdeyeResult,
    get_library_path,
)

__version__ = "1.0.0"

__all__ = [
    "ThirdEyeError",
    "ThirdEyeOptions",
    "ThirdEyeSession",
    "ThirdeyeFormat",
    "ThirdeyeResult",
    "get_library_path",
    "__version__",
]
