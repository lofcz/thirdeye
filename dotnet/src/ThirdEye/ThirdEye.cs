using System;
using System.Runtime.InteropServices;
using System.Threading;

namespace ThirdEye;

/// <summary>
/// Main entry point for ThirdEye screen capture functionality.
/// Provides methods to capture screenshots with optional bypass of display protection.
/// This class is thread-safe.
/// </summary>
public class ThirdEyeSession : IDisposable
{
    private const string DllName = "thirdeye_native.dll";
    private IntPtr _context;
    private bool _disposed;

    /// <summary>
    /// Initialize a new ThirdEye session.
    /// </summary>
    /// <exception cref="ThirdEyeException">Thrown if initialization fails.</exception>
    public ThirdEyeSession()
    {
        var result = Native_CreateContext(out _context);
        if (result != ThirdeyeResult.Ok)
        {
            throw new ThirdEyeException(result, "Failed to create context");
        }
    }

    ~ThirdEyeSession()
    {
        Dispose(false);
    }

    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }

    protected virtual void Dispose(bool disposing)
    {
        if (!_disposed)
        {
            if (_context != IntPtr.Zero)
            {
                Native_DestroyContext(_context);
                _context = IntPtr.Zero;
            }
            _disposed = true;
        }
    }

    #region Native Imports

    [DllImport(DllName, CallingConvention = CallingConvention.StdCall, EntryPoint = "Thirdeye_CreateContext")]
    private static extern ThirdeyeResult Native_CreateContext(out IntPtr ppContext);

    [DllImport(DllName, CallingConvention = CallingConvention.StdCall, EntryPoint = "Thirdeye_DestroyContext")]
    private static extern void Native_DestroyContext(IntPtr context);

    [DllImport(DllName, CallingConvention = CallingConvention.StdCall, EntryPoint = "Thirdeye_GetDefaultOptions")]
    private static extern void Native_GetDefaultOptions(ref ThirdEyeOptions options);

    [DllImport(DllName, CallingConvention = CallingConvention.StdCall, CharSet = CharSet.Unicode, EntryPoint = "Thirdeye_CaptureToFile")]
    private static extern ThirdeyeResult Native_CaptureToFile(
        IntPtr context,
        [MarshalAs(UnmanagedType.LPWStr)] string filePath,
        ref ThirdEyeOptions options
    );

    [DllImport(DllName, CallingConvention = CallingConvention.StdCall, CharSet = CharSet.Unicode, EntryPoint = "Thirdeye_CaptureToFile")]
    private static extern ThirdeyeResult Native_CaptureToFileDefault(
        IntPtr context,
        [MarshalAs(UnmanagedType.LPWStr)] string filePath,
        IntPtr options
    );

    [DllImport(DllName, CallingConvention = CallingConvention.StdCall, EntryPoint = "Thirdeye_CaptureToBuffer")]
    private static extern ThirdeyeResult Native_CaptureToBuffer(
        IntPtr context,
        out IntPtr buffer,
        out uint size,
        ref ThirdEyeOptions options
    );

    [DllImport(DllName, CallingConvention = CallingConvention.StdCall, EntryPoint = "Thirdeye_CaptureToBuffer")]
    private static extern ThirdeyeResult Native_CaptureToBufferDefault(
        IntPtr context,
        out IntPtr buffer,
        out uint size,
        IntPtr options
    );

    [DllImport(DllName, CallingConvention = CallingConvention.StdCall, EntryPoint = "Thirdeye_FreeBuffer")]
    private static extern void Native_FreeBuffer(IntPtr buffer);

    [DllImport(DllName, CallingConvention = CallingConvention.StdCall, EntryPoint = "Thirdeye_GetLastError")]
    private static extern IntPtr Native_GetLastError(IntPtr context);

    [DllImport(DllName, CallingConvention = CallingConvention.StdCall, EntryPoint = "Thirdeye_GetVersion")]
    private static extern IntPtr Native_GetVersion();

    #endregion

    #region Public API

    /// <summary>
    /// Get the default capture options.
    /// </summary>
    /// <returns>Default options (JPEG, quality 90, bypass enabled).</returns>
    public static ThirdEyeOptions GetDefaultOptions()
    {
        var options = new ThirdEyeOptions();
        Native_GetDefaultOptions(ref options);
        return options;
    }

    /// <summary>
    /// Capture a screenshot and save it to a file using default options.
    /// </summary>
    /// <param name="filePath">Path to save the screenshot.</param>
    /// <exception cref="ThirdEyeException">Thrown if capture fails.</exception>
    public void CaptureToFile(string filePath)
    {
        if (_disposed) throw new ObjectDisposedException(nameof(ThirdEyeSession));

        var result = Native_CaptureToFileDefault(_context, filePath, IntPtr.Zero);
        if (result != ThirdeyeResult.Ok)
        {
            throw new ThirdEyeException(result, GetLastError());
        }
    }

    /// <summary>
    /// Capture a screenshot and save it to a file with custom options.
    /// </summary>
    /// <param name="filePath">Path to save the screenshot.</param>
    /// <param name="options">Capture options.</param>
    /// <exception cref="ThirdEyeException">Thrown if capture fails.</exception>
    public void CaptureToFile(string filePath, ThirdEyeOptions options)
    {
        if (_disposed) throw new ObjectDisposedException(nameof(ThirdEyeSession));

        var result = Native_CaptureToFile(_context, filePath, ref options);
        if (result != ThirdeyeResult.Ok)
        {
            throw new ThirdEyeException(result, GetLastError());
        }
    }

    /// <summary>
    /// Capture a screenshot to a memory buffer using default options.
    /// </summary>
    /// <returns>Byte array containing the image data.</returns>
    /// <exception cref="ThirdEyeException">Thrown if capture fails.</exception>
    public byte[] CaptureToBuffer()
    {
        if (_disposed) throw new ObjectDisposedException(nameof(ThirdEyeSession));

        var result = Native_CaptureToBufferDefault(_context, out IntPtr buffer, out uint size, IntPtr.Zero);
        if (result != ThirdeyeResult.Ok)
        {
            throw new ThirdEyeException(result, GetLastError());
        }

        try
        {
            var data = new byte[size];
            Marshal.Copy(buffer, data, 0, (int)size);
            return data;
        }
        finally
        {
            Native_FreeBuffer(buffer);
        }
    }

    /// <summary>
    /// Capture a screenshot to a memory buffer with custom options.
    /// </summary>
    /// <param name="options">Capture options.</param>
    /// <returns>Byte array containing the image data.</returns>
    /// <exception cref="ThirdEyeException">Thrown if capture fails.</exception>
    public byte[] CaptureToBuffer(ThirdEyeOptions options)
    {
        if (_disposed) throw new ObjectDisposedException(nameof(ThirdEyeSession));

        var result = Native_CaptureToBuffer(_context, out IntPtr buffer, out uint size, ref options);
        if (result != ThirdeyeResult.Ok)
        {
            throw new ThirdEyeException(result, GetLastError());
        }

        try
        {
            var data = new byte[size];
            Marshal.Copy(buffer, data, 0, (int)size);
            return data;
        }
        finally
        {
            Native_FreeBuffer(buffer);
        }
    }

    /// <summary>
    /// Get the last error message from the native library.
    /// </summary>
    /// <returns>Error message string, or empty string if no error.</returns>
    public string GetLastError()
    {
        if (_context == IntPtr.Zero) return string.Empty;
        var ptr = Native_GetLastError(_context);
        return ptr != IntPtr.Zero ? Marshal.PtrToStringAnsi(ptr) ?? string.Empty : string.Empty;
    }

    /// <summary>
    /// Get the version string of the native library.
    /// </summary>
    /// <returns>Version string.</returns>
    public static string GetVersion()
    {
        var ptr = Native_GetVersion();
        return ptr != IntPtr.Zero ? Marshal.PtrToStringAnsi(ptr) ?? "unknown" : "unknown";
    }

    #endregion
}
