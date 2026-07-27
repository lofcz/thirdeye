[![ThirdEye](https://img.shields.io/nuget/v/ThirdEye?logo=nuget&label=ThirdEye)](https://www.nuget.org/packages/ThirdEye)
[![npm](https://img.shields.io/npm/v/@lofcz/thirdeye?logo=npm&label=@lofcz/thirdeye)](https://www.npmjs.com/package/@lofcz/thirdeye)
[![PyPI](https://img.shields.io/pypi/v/eye3?logo=pypi&label=eye3)](https://pypi.org/project/eye3/)

# Third Eye

Usermode `WDA_MONITOR`/`WDA_EXCLUDEFROMCAPTURE` bypasser written in C++ with bindings for several popular languages.

Starring:
- PEB walking
- Tartarus Gate
- Custom PE sections
- `Zw*` Windows functions
- EDR/AV evasion ([0/70 on VirusTotal](https://www.virustotal.com/gui/file/c7df1ab62ee8f5785623630add373f3883ad135b5207e2c66f08731d384531ba))
- No `0F 05` via `ntdll.dll` indirection
- `constexpr` AES-like literals shredding, clean `.rodata`

## Getting Started

<details>
<summary>TS</summary>

Install:

```
npm i @lofcz/thirdeye
```

Use:

```ts
import { ThirdEyeSession, ThirdeyeFormat } from '@lofcz/thirdeye';

const session = new ThirdEyeSession();
session.captureToFile('screenshot.jpg');
session.close();
```

With options:

```ts
session.captureToFile('screenshot.jpeg', {
  format: ThirdeyeFormat.Jpeg,
  quality: 90,
  bypassProtection: true,
});
```

Capture to memory:

```ts
const buffer: Buffer = session.captureToBuffer();
```

</details>

<details>
<summary>C#</summary>

Install:

```
dotnet add package ThirdEye
```

Use:

```cs
using ThirdEye;

using var session = new ThirdEyeSession();
session.CaptureToFile("screenshot.jpg");
```

With options:

```cs
var options = new ThirdEyeOptions(
    format: ThirdeyeFormat.Jpeg,
    quality: 90,
    bypassProtection: true
);
session.CaptureToFile("screenshot.jpeg", options);
```

Capture to memory:

```cs
byte[] buffer = session.CaptureToBuffer();
```

</details>

<details>
<summary>Python</summary>

Install:

```
pip install eye3
```

Use:

```python
from eye3 import ThirdEyeSession, ThirdEyeOptions, ThirdeyeFormat

with ThirdEyeSession() as session:
    session.capture_to_file("screenshot.jpg")
```

With options:

```python
options = ThirdEyeOptions(
    format=ThirdeyeFormat.JPEG,
    quality=90,
    bypass_protection=True,
)
session.capture_to_file("screenshot.jpeg", options)
```

Capture to memory:

```python
buffer: bytes = session.capture_to_buffer()
```

</details>

<details>
<summary>C/C++</summary>

Install: download `thirdeye.dll` + `thirdeye_core.h` from the [latest release](https://github.com/lofcz/thirdeye/releases) (or build from `c/`).

Use:

```cpp
#include "thirdeye_core.h"

ThirdeyeContext* ctx = nullptr;
if (Thirdeye_CreateContext(&ctx) == THIRDEYE_OK) {
    Thirdeye_CaptureToFile(ctx, L"screenshot.jpg", nullptr);
    Thirdeye_DestroyContext(ctx);
}
```

With options:

```cpp
ThirdeyeOptions options;
Thirdeye_GetDefaultOptions(&options);
options.format = THIRDEYE_FORMAT_JPEG;
options.quality = 90;
Thirdeye_CaptureToFile(ctx, L"screenshot.jpeg", &options);
```

Capture to memory:

```cpp
uint8_t* buffer = nullptr;
uint32_t size = 0;
Thirdeye_CaptureToBuffer(ctx, &buffer, &size, nullptr);
Thirdeye_FreeBuffer(buffer);
```

</details>
