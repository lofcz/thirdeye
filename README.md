[![ThirdEye](https://shields.io/nuget/v/ThirdEye?v=302&icon=nuget&label=ThirdEye)](https://www.nuget.org/packages/ThirdEye)

# Third Eye

Usermode `WDA_MONITOR`/`WDA_EXCLUDEFROMCAPTURE` bypasser using undocumented Windows functions with C# bindings.

Starring:
- PEB walking
- Halo's Gate
- Custom PE sections
- Undocumented Windows functions
- Quick and dirty EDR/AV evasion ([2/72 on VirusTotal](https://www.virustotal.com/gui/file/db1de8681fd4b86870bf6b1af50703a17f7997791387bb5d56b3d5130fe3f789?nocache=1))
- Direct syscalls

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
