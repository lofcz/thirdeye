[![ThirdEye](https://shields.io/nuget/v/ThirdEye?v=302&icon=nuget&label=ThirdEye)](https://www.nuget.org/packages/ThirdEye)

# Third Eye

Usermode `WDA_MONITOR`/`WDA_EXCLUDEFROMCAPTURE` bypasser written in C++ with C# bindings.

Starring:
- PEB walking
- Tartarus Gate
- Custom PE sections
- `Zw*` Windows functions
- EDR/AV evasion ([0/69 on VirusTotal](https://www.virustotal.com/gui/file/c7df1ab62ee8f5785623630add373f3883ad135b5207e2c66f08731d384531ba))
- No `0F 05` via `ntdll.dll` indirection
- `constexpr` AES-like literals shredding, clean `.rodata`

## Getting Started

Install the package:

```
dotnet add thirdeye
```

### Usage (C#)

Take screenshots unmasking any hidden windows:

```cs
using ThirdEye;

using var session = new ThirdEyeSession()
session.CaptureToFile("screenshot.png");
```

Options are available:

```cs
using var session = new ThirdEyeSession();
var options = new ThirdEyeOptions(
    format: ThirdeyeFormat.Jpeg,
    quality: 90,
    bypassProtection: true
);
    
session.CaptureToFile("screenshot.jpeg", options);
```

If needed, screenshots can be stored in memory:

```cs
using var session = new ThirdEyeSession()
byte[] bufferData = session.CaptureToBuffer();
```

### Usage (C/C++)

```cpp
#include "thirdeye_core.h"

ThirdeyeContext* ctx = nullptr;
if (Thirdeye_CreateContext(&ctx) == THIRDEYE_OK) {
    Thirdeye_CaptureToFile(ctx, L"screenshot.jpg", nullptr);
    Thirdeye_DestroyContext(ctx);
}
```
