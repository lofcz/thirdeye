using System.Runtime.InteropServices;

namespace ThirdEye;

/// <summary>
/// Options for configuring screen capture behavior.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public struct ThirdEyeOptions
{
    /// <summary>
    /// Output image format.
    /// </summary>
    public ThirdeyeFormat Format;

    /// <summary>
    /// Image quality (1-100). Only applicable to JPEG format.
    /// </summary>
    public int Quality;

    /// <summary>
    /// Include windows that opt out of normal screen capture (1 = yes, 0 = no).
    /// </summary>
    public int Inclusive;

    /// <summary>
    /// Creates options with specified values.
    /// </summary>
    public ThirdEyeOptions(ThirdeyeFormat format, int quality = 90, bool inclusive = true)
    {
        Format = format;
        Quality = quality;
        Inclusive = inclusive ? 1 : 0;
    }

    /// <summary>
    /// Gets or sets whether inclusive capture is enabled.
    /// </summary>
    public bool IsInclusive
    {
        get => Inclusive != 0;
        set => Inclusive = value ? 1 : 0;
    }
}
