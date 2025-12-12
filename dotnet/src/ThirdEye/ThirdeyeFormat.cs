namespace ThirdEye;

/// <summary>
/// Image formats supported by ThirdEye for screen capture.
/// </summary>
public enum ThirdeyeFormat
{
    /// <summary>JPEG format (lossy compression, smaller file size).</summary>
    Jpeg = 0,
    
    /// <summary>PNG format (lossless compression, larger file size).</summary>
    Png = 1,
    
    /// <summary>BMP format (uncompressed bitmap).</summary>
    Bmp = 2,
}

