using System.Runtime.InteropServices;

namespace ThirdEye;

/// <summary>
/// Options for <see cref="ThirdEyeSession.Prepare"/>.
/// Set <see cref="Size"/> to <c>Marshal.SizeOf&lt;ThirdeyePrepareOptions&gt;()</c>
/// so new fields can be added later without breaking callers.
/// </summary>
/// <remarks>
/// Capture option <c>Inclusive</c>:
/// includes hidden / capture-excluded windows; when state is Master and
/// <see cref="Elevate"/> was true, also includes elevated processes.
/// State is Normal | Busy | Master.
/// </remarks>
[StructLayout(LayoutKind.Sequential)]
public struct ThirdeyePrepareOptions
{
    public uint Size;
    /// <summary>Non-zero: start the elevated capture helper.</summary>
    public int Elevate;
    public uint Reserved0;
    public uint Reserved1;

    public static ThirdeyePrepareOptions Create(bool elevate = true) => new()
    {
        Size = (uint)Marshal.SizeOf<ThirdeyePrepareOptions>(),
        Elevate = elevate ? 1 : 0,
    };
}
