using System;
using System.Runtime.InteropServices;
using System.Threading;

namespace ThirdEye;

/// <summary>
/// Main entry point for ThirdEye screen capture functionality.
/// Provides methods to capture screenshots with optional bypass of display protection.
/// </summary>
public static class ThirdEye
{
    private const string DllName = "thirdeye_native.dll";
    private static readonly object InitLock = new();
    private static int _managedInitialized; // 0 = no, 1 = yes
    private static int _processExitHooked;  // 0 = no, 1 = yes

    private static void EnsureInitialized()
    {
        if (Volatile.Read(ref _managedInitialized) == 1)
        {
            return;
        }

        lock (InitLock)
        {
            if (_managedInitialized == 1)
            {
                return;
            }

            var result = Native_Initialize();
            if (result != ThirdeyeResult.Ok)
            {
                throw new ThirdEyeException(result, GetLastError());
            }

            _managedInitialized = 1;

            // Best-effort cleanup so users don't have to remember calling Shutdown().
            if (Interlocked.Exchange(ref _processExitHooked, 1) == 0)
            {
                AppDomain.CurrentDomain.ProcessExit += (_, _) =>
                {
                    try
                    {
                        if (Volatile.Read(ref _managedInitialized) == 1)
                        {
                            Native_Shutdown();
                            Volatile.Write(ref _managedInitialized, 0);
                        }
                    }
                    catch
                    {
                        // Ignore shutdown failures on process exit.
                    }
                };
            }
        }
    }

    #region Native Imports

    [DllImport(DllName, CallingConvention = CallingConvention.StdCall, EntryPoint = "Thirdeye_Initialize")]
    private static extern ThirdeyeResult Native_Initialize();

    [DllImport(DllName, CallingConvention = CallingConvention.StdCall, EntryPoint = "Thirdeye_Shutdown")]
    private static extern void Native_Shutdown();

    [DllImport(DllName, CallingConvention = CallingConvention.StdCall, EntryPoint = "Thirdeye_IsInitialized")]
    private static extern int Native_IsInitialized();

    [DllImport(DllName, CallingConvention = CallingConvention.StdCall, EntryPoint = "Thirdeye_GetDefaultOptions")]
    private static extern void Native_GetDefaultOptions(ref ThirdEyeOptions options);

    [DllImport(DllName, CallingConvention = CallingConvention.StdCall, CharSet = CharSet.Unicode, EntryPoint = "Thirdeye_CaptureToFile")]
    private static extern ThirdeyeResult Native_CaptureToFile(
        [MarshalAs(UnmanagedType.LPWStr)] string filePath,
        ref ThirdEyeOptions options
    );

    [DllImport(DllName, CallingConvention = CallingConvention.StdCall, CharSet = CharSet.Unicode, EntryPoint = "Thirdeye_CaptureToFile")]
    private static extern ThirdeyeResult Native_CaptureToFileDefault(
        [MarshalAs(UnmanagedType.LPWStr)] string filePath,
        IntPtr options
    );

    [DllImport(DllName, CallingConvention = CallingConvention.StdCall, EntryPoint = "Thirdeye_CaptureToBuffer")]
    private static extern ThirdeyeResult Native_CaptureToBuffer(
        out IntPtr buffer,
        out uint size,
        ref ThirdEyeOptions options
    );

    [DllImport(DllName, CallingConvention = CallingConvention.StdCall, EntryPoint = "Thirdeye_CaptureToBuffer")]
    private static extern ThirdeyeResult Native_CaptureToBufferDefault(
        out IntPtr buffer,
        out uint size,
        IntPtr options
    );

    [DllImport(DllName, CallingConvention = CallingConvention.StdCall, EntryPoint = "Thirdeye_FreeBuffer")]
    private static extern void Native_FreeBuffer(IntPtr buffer);

    [DllImport(DllName, CallingConvention = CallingConvention.StdCall, EntryPoint = "Thirdeye_GetLastError")]
    private static extern IntPtr Native_GetLastError();

    [DllImport(DllName, CallingConvention = CallingConvention.StdCall, EntryPoint = "Thirdeye_GetVersion")]
    private static extern IntPtr Native_GetVersion();

    #endregion

    #region Public API

    /// <summary>
    /// Gets whether the library has been initialized.
    /// </summary>
    public static bool IsInitialized
    {
        get
        {
            if (Volatile.Read(ref _managedInitialized) == 1)
            {
                return true;
            }

            try
            {
                return Native_IsInitialized() != 0;
            }
            catch (DllNotFoundException)
            {
                return false;
            }
            catch (EntryPointNotFoundException)
            {
                return false;
            }
        }
    }

    /// <summary>
    /// Initialize the ThirdEye library.
    /// capture operations auto-initialize on first use.
    /// </summary>
    /// <exception cref="ThirdEyeException">Thrown if initialization fails.</exception>
    public static void Initialize()
    {
        EnsureInitialized();
    }

    /// <summary>
    /// Shutdown the ThirdEye library and release all resources.
    /// </summary>
    public static void Shutdown()
    {
        lock (InitLock)
        {
            if (_managedInitialized == 1)
            {
                Native_Shutdown();
                _managedInitialized = 0;
            }
        }
    }

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
    public static void CaptureToFile(string filePath)
    {
        EnsureInitialized();
        var result = Native_CaptureToFileDefault(filePath, IntPtr.Zero);
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
    public static void CaptureToFile(string filePath, ThirdEyeOptions options)
    {
        EnsureInitialized();
        var result = Native_CaptureToFile(filePath, ref options);
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
    public static byte[] CaptureToBuffer()
    {
        EnsureInitialized();
        var result = Native_CaptureToBufferDefault(out IntPtr buffer, out uint size, IntPtr.Zero);
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
    public static byte[] CaptureToBuffer(ThirdEyeOptions options)
    {
        EnsureInitialized();
        var result = Native_CaptureToBuffer(out IntPtr buffer, out uint size, ref options);
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
    public static string GetLastError()
    {
        var ptr = Native_GetLastError();
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

