using System;

namespace ThirdEye;

/// <summary>
/// Exception thrown when a ThirdEye operation fails.
/// </summary>
public class ThirdEyeException : Exception
{
    /// <summary>
    /// Gets the result code from the native library.
    /// </summary>
    public ThirdeyeResult ResultCode { get; }

    /// <summary>
    /// Creates a new ThirdEyeException with the specified result code and message.
    /// </summary>
    public ThirdEyeException(ThirdeyeResult result, string? nativeMessage)
        : base(FormatMessage(result, nativeMessage))
    {
        ResultCode = result;
    }

    /// <summary>
    /// Creates a new ThirdEyeException with the specified result code.
    /// </summary>
    public ThirdEyeException(ThirdeyeResult result)
        : this(result, null)
    {
    }

    private static string FormatMessage(ThirdeyeResult result, string? nativeMessage)
    {
        var baseMessage = result switch
        {
            ThirdeyeResult.ErrorNotInitialized => "ThirdEye has not been initialized",
            ThirdeyeResult.ErrorSyscallInitFailed => "Failed to initialize syscall stubs",
            ThirdeyeResult.ErrorGdiplusInitFailed => "Failed to initialize GDI+",
            ThirdeyeResult.ErrorEncoderNotFound => "Image encoder not found",
            ThirdeyeResult.ErrorSaveFailed => "Failed to save image",
            ThirdeyeResult.ErrorAllocationFailed => "Memory allocation failed",
            ThirdeyeResult.ErrorInvalidParam => "Invalid parameter",
            ThirdeyeResult.ErrorNoRemoteSection => "No remote section available",
            _ => $"Unknown error ({(int)result})"
        };

        return string.IsNullOrEmpty(nativeMessage) 
            ? baseMessage 
            : $"{baseMessage}: {nativeMessage}";
    }
}

