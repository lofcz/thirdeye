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
    /// Whether to bypass WDA_MONITOR/WDA_EXCLUDEFROMCAPTURE protection.
    /// Set to 1 to enable bypass, 0 to disable.
    /// </summary>
    public int BypassProtection;

    /// <summary>
    /// Creates options with specified values.
    /// </summary>
    public ThirdEyeOptions(ThirdeyeFormat format, int quality = 90, bool bypassProtection = true)
    {
        Format = format;
        Quality = quality;
        BypassProtection = bypassProtection ? 1 : 0;
    }

    /// <summary>
    /// Gets or sets whether bypass protection is enabled.
    /// </summary>
    public bool IsBypassEnabled
    {
        get => BypassProtection != 0;
        set => BypassProtection = value ? 1 : 0;
    }
}

