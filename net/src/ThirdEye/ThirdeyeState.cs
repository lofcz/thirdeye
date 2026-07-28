using System.Runtime.InteropServices;

namespace ThirdEye;

/// <summary>
/// Session mode. NotReady until armed; Normal when armed; Busy during Prepare;
/// Master when elevated helper is ready.
/// </summary>
public enum ThirdeyeMode
{
    NotReady = 0,
    Normal = 1,
    Busy = 2,
    Master = 3,
}

[StructLayout(LayoutKind.Sequential)]
public struct ThirdeyeState
{
    public int Mode;
    public uint Pid;

    public ThirdeyeMode SessionMode => (ThirdeyeMode)Mode;
    public bool IsMaster => Mode == (int)ThirdeyeMode.Master;
    public bool IsReady => Mode != (int)ThirdeyeMode.NotReady;
}
