# eye3

Screen capture library bypassing `WDA_MONITOR` / `WDA_EXCLUDEFROMCAPTURE` (Windows x64 native binary).

```python
from eye3 import ThirdEyeSession

with ThirdEyeSession() as session:
    session.capture_to_file("screenshot.png")
```

Options:

```python
from eye3 import ThirdEyeSession, ThirdEyeOptions, ThirdeyeFormat

with ThirdEyeSession() as session:
    opts = ThirdEyeOptions(format=ThirdeyeFormat.JPEG, quality=90, bypass_protection=True)
    session.capture_to_file("screenshot.jpeg", opts)

    data: bytes = session.capture_to_buffer()
```

Windows x64 only. Ships the native `thirdeye.dll` inside the wheel.
