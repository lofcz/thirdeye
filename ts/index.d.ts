declare module '@lofcz/thirdeye' {
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

  export enum ThirdeyeFormat {
    Jpeg = 0,
    Png = 1,
    Bmp = 2,
  }

  /**
   * Session mode (native ThirdeyeMode).
   * NotReady until armed; Normal when armed; Busy during Prepare;
   * Master when elevated helper is ready.
   */
  export enum ThirdeyeMode {
    NotReady = 0,
    Normal = 1,
    Busy = 2,
    Master = 3,
  }

  export const THIRDEYE_OK: ThirdeyeResult.Ok;

  /**
   * Capture options.
   *
   * `inclusive`:
   * - includes hidden / capture-excluded windows
   * - when {@link state}`.mode === ThirdeyeMode.Master`, also elevated processes
   */
  export interface ThirdEyeOptions {
    format: ThirdeyeFormat;
    quality: number;
    inclusive: boolean;
  }

  /** Prepare options (extensible). `elevate` starts the elevated helper. */
  export interface ThirdEyePrepareOptions {
    elevate?: boolean;
  }

  export interface ThirdEyeStateInfo {
    mode: ThirdeyeMode;
    pid: number;
  }

  export function getLibraryPath(): string;

  export interface ThirdEyeBinding {
    koffi: unknown;
    Prepare(token: string, options: unknown): number;
    Clean(): number;
    State(out: unknown): number;
    CreateContext(out: unknown[]): ThirdeyeResult;
    DestroyContext(ctx: unknown): void;
    GetDefaultOptions(opts: unknown): void;
    CaptureToFile(ctx: unknown, filePath: string, options: unknown): ThirdeyeResult;
    CaptureToBuffer(ctx: unknown, buffer: unknown[], size: number[], options: unknown): ThirdeyeResult;
    FreeBuffer(buffer: unknown): void;
    GetLastError(ctx: unknown): string;
    GetVersion(): string;
  }

  export function createBinding(): ThirdEyeBinding;
  export function prepareAsync(options?: ThirdEyePrepareOptions): Promise<boolean>;
  export function clean(): boolean;
  export function state(): ThirdEyeStateInfo;

  export class ThirdEyeSession {
    constructor();
    defaultOptions(): ThirdEyeOptions;
    captureToFile(filePath: string, options?: ThirdEyeOptions): void;
    captureToFileAsync(filePath: string, options?: ThirdEyeOptions): Promise<void>;
    captureToBuffer(options?: ThirdEyeOptions): Buffer;
    lastError(): string;
    version(): string;
    prepare(options?: ThirdEyePrepareOptions): boolean;
    prepareAsync(options?: ThirdEyePrepareOptions): Promise<boolean>;
    clean(): boolean;
    state(): ThirdEyeStateInfo;
    close(): void;
  }
}
