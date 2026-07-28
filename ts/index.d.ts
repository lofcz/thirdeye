declare module '@lofcz/thirdeye' {
  /** Result codes returned by the native thirdeye API. */
  export enum ThirdeyeResult {
    Ok = 0,
    NotInitialized = -1,
    SyscallInitFailed = -2,
    GdiplusInitFailed = -3,
    EncoderNotFound = -4,
    SaveFailed = -5,
    AllocationFailed = -6,
    InvalidParam = -7,
    NoRemoteSection = -8,
    CaptureFailed = -9,
  }

  /** Pixel/encoder formats supported for captures. */
  export enum ThirdeyeFormat {
    Jpeg = 0,
    Png = 1,
    Bmp = 2,
  }

  /** Alias for {@link ThirdeyeResult.Ok}. */
  export const THIRDEYE_OK: ThirdeyeResult.Ok;

  /** Capture options. Plain JS object; converted to the native struct internally. */
  export interface ThirdEyeOptions {
    /** Output format. Defaults to the library default (JPEG). */
    format: ThirdeyeFormat;
    /** Encoder quality 1-100 (JPEG only). */
    quality: number;
    /** Bypass WDA_MONITOR / WDA_EXCLUDEFROMCAPTURE when capturing. */
    bypassProtection: boolean;
  }

  /** Absolute path to the bundled thirdeye.dll (Windows x64). */
  export function getLibraryPath(): string;

  /**
   * Low-level FFI binding (requires the optional dependency "koffi").
   * Exposes the raw native functions plus the koffi struct constructor.
   * Most consumers should prefer {@link ThirdEyeSession}.
   */
  export interface ThirdEyeBinding {
    /** The koffi module, for advanced struct/pointer handling. */
    koffi: unknown;
    /** koffi struct constructor for the native ThirdeyeOptions. */
    ThirdeyeOptionsStruct: new () => {
      format: number;
      quality: number;
      bypassProtection: number;
    };
    CreateContext(out: unknown[]): ThirdeyeResult;
    DestroyContext(ctx: unknown): void;
    GetDefaultOptions(opts: unknown): void;
    CaptureToFile(ctx: unknown, filePath: string, options: unknown): ThirdeyeResult;
    CaptureToBuffer(ctx: unknown, buffer: unknown[], size: number[], options: unknown): ThirdeyeResult;
    FreeBuffer(buffer: unknown): void;
    GetLastError(ctx: unknown): string;
    GetVersion(): string;
  }

  /** Create the low-level FFI binding (requires optional dependency "koffi"). */
  export function createBinding(): ThirdEyeBinding;

  /**
   * High-level capture session. Wraps a native context; call {@link close}
   * (or rely on process exit) to release it.
   */
  export class ThirdEyeSession {
    constructor();

    /** Library-default capture options. */
    defaultOptions(): ThirdEyeOptions;

    /** Capture the screen to a file. Throws on failure. */
    captureToFile(filePath: string, options?: ThirdEyeOptions): void;

    /** Capture the screen to an in-memory buffer. Throws on failure. */
    captureToBuffer(options?: ThirdEyeOptions): Buffer;

    /** Last native error message for this session's context. */
    lastError(): string;

    /** Native library version string. */
    version(): string;

    /** Destroy the native context. Idempotent. */
    close(): void;
  }
}
