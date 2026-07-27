import re
import sys
from pathlib import Path

GENERIC_PATTERNS = [
    (re.compile(rb"\.\./\.\./\.\./mingw-w64-libraries/winpthreads/src/[^ \x00]+\.c"), b"runtime.c"),
]

EXACT_PATCHES = {
    b"Mingw-w64 runtime failure:": b"Runtime failure:",
}

def patch_binary(path: Path) -> None:
    data = bytearray(path.read_bytes())
    for old, new in EXACT_PATCHES.items():
        if len(new) > len(old):
            raise ValueError(f"replacement longer than original for {old!r}")
        new = new.ljust(len(old), b"\x00")
        idx = 0
        while True:
            idx = data.find(old, idx)
            if idx == -1:
                break
            data[idx:idx + len(old)] = new
            idx += len(old)
    for pattern, replacement in GENERIC_PATTERNS:
        def repl(m):
            return replacement.ljust(len(m.group(0)), b"\x00")
        data[:] = pattern.sub(repl, bytes(data))
    path.write_bytes(data)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("usage: patch_toolchain.py <binary> [<binary> ...]", file=sys.stderr)
        sys.exit(1)
    for arg in sys.argv[1:]:
        patch_binary(Path(arg))
