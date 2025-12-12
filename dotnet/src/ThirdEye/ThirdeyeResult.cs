namespace ThirdEye;

/// <summary>
/// Result codes returned by ThirdEye native functions.
/// </summary>
public enum ThirdeyeResult
{
    /// <summary>Operation completed successfully.</summary>
    Ok = 0,
    
    /// <summary>Library has not been initialized. Call Initialize() first.</summary>
    ErrorNotInitialized = -1,
    
    /// <summary>Failed to initialize syscall stubs.</summary>
    ErrorSyscallInitFailed = -2,
    
    /// <summary>Failed to initialize GDI+.</summary>
    ErrorGdiplusInitFailed = -3,
    
    /// <summary>Image encoder not found for the specified format.</summary>
    ErrorEncoderNotFound = -4,
    
    /// <summary>Failed to save the captured image.</summary>
    ErrorSaveFailed = -5,
    
    /// <summary>Memory allocation failed.</summary>
    ErrorAllocationFailed = -6,
    
    /// <summary>Invalid parameter provided.</summary>
    ErrorInvalidParam = -7,
    
    /// <summary>No remote section available for bypass.</summary>
    ErrorNoRemoteSection = -8,
}

