[![ThirdEye](https://shields.io/nuget/v/ThirdEye?v=302&icon=nuget&label=ThirdEye)](https://www.nuget.org/packages/ThirdEye)

# Third Eye

Usermode `WDA_MONITOR`/`WDA_EXCLUDEFROMCAPTURE` bypasser using undocumented Windows functions with C# bindings.

Starring:
- PEB walking
- Halo's Gate
- Custom PE sections
- Undocumented Windows functions
- Somewhat memetic synchronization model
- Quick and dirty EDR/AV evasion ([2/72 on VirusTotal](https://www.virustotal.com/gui/file/db1de8681fd4b86870bf6b1af50703a17f7997791387bb5d56b3d5130fe3f789?nocache=1))
- Direct syscalls

## Getting Started

Install the package:

```
dotnet add thirdeye
```

Take screenshots unmasking any hidden windows:

```cs
ThirdEye.CaptureToFile("screenshot.png");
```

Options are available:

```cs
var bypassOptions = new ThirdEyeOptions(format: ThirdeyeFormat.Jpeg, quality: 90, bypassProtection: true);
ThirdEye.CaptureToFile("screenshot.jpeg", bypassOptions);
```

If needed, screenshots can be stored in memory:

```cs
byte[] bufferData = ThirdEye.CaptureToBuffer();
```
