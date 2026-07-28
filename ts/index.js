'use strict';

const path = require('path');
const fs = require('fs');

const DLL_NAME = 'thirdeye.dll';
const bundled = path.join(__dirname, 'bin', DLL_NAME);

function getLibraryPath() {
  if (!fs.existsSync(bundled)) {
    throw new Error(
      `thirdeye native library not found at ${bundled}. ` +
      `This package ships a Windows x64 binary only (os=win32, cpu=x64).`
    );
  }
  return bundled;
}

let _lib = null;
function _load() {
  if (_lib) return _lib;
  let koffi;
  try {
    koffi = require('koffi');
  } catch {
    throw new Error(
      'thirdeye: the high-level API requires the optional "koffi" package. ' +
      'Install it (npm i koffi) or use getLibraryPath() with your own FFI.'
    );
  }
  _lib = koffi.load(getLibraryPath());
  return _lib;
}

const ThirdeyeResult = Object.freeze({
  Ok: 0,
  NotInitialized: -1,
  SyscallInitFailed: -2,
  GdiplusInitFailed: -3,
  EncoderNotFound: -4,
  SaveFailed: -5,
  AllocationFailed: -6,
  InvalidParam: -7,
  NoRemoteSection: -8,
  CaptureFailed: -9,
});

const ThirdeyeFormat = Object.freeze({
  Jpeg: 0,
  Png: 1,
  Bmp: 2,
});

const THIRDEYE_OK = ThirdeyeResult.Ok;

function createBinding() {
  const lib = _load();
  const koffi = require('koffi');

  const ThirdeyeOptionsStruct = koffi.struct('ThirdeyeOptions', {
    format: 'int',
    quality: 'int',
    bypassProtection: 'int',
  });

  const CreateContext = lib.func('int __stdcall Thirdeye_CreateContext(_Out_ void **ppContext)');
  const DestroyContext = lib.func('void __stdcall Thirdeye_DestroyContext(void *context)');
  const GetDefaultOptions = lib.func('void __stdcall Thirdeye_GetDefaultOptions(_Out_ ThirdeyeOptions *options)');
  const CaptureToFile = lib.func('int __stdcall Thirdeye_CaptureToFile(void *context, const char16_t *filePath, const ThirdeyeOptions *options)');
  const CaptureToBuffer = lib.func('int __stdcall Thirdeye_CaptureToBuffer(void *context, _Out_ uint8_t **buffer, _Out_ uint32_t *size, const ThirdeyeOptions *options)');
  const FreeBuffer = lib.func('void __stdcall Thirdeye_FreeBuffer(uint8_t *buffer)');
  const GetLastError = lib.func('const char * __stdcall Thirdeye_GetLastError(void *context)');
  const GetVersion = lib.func('const char * __stdcall Thirdeye_GetVersion(void)');

  return {
    koffi,
    ThirdeyeOptionsStruct,
    CreateContext,
    DestroyContext,
    GetDefaultOptions,
    CaptureToFile,
    CaptureToBuffer,
    FreeBuffer,
    GetLastError,
    GetVersion,
  };
}

function toStruct(b, options) {
  return {
    format: options.format,
    quality: options.quality,
    bypassProtection: options.bypassProtection ? 1 : 0,
  };
}

class ThirdEyeSession {
  constructor() {
    const b = createBinding();
    this._b = b;
    const out = [null];
    const rc = b.CreateContext(out);
    if (rc !== THIRDEYE_OK || !out[0]) {
      throw new Error(`Thirdeye_CreateContext failed (rc=${rc})`);
    }
    this._ctx = out[0];
  }

  defaultOptions() {
    const s = this._b.koffi.alloc(this._b.ThirdeyeOptionsStruct, 1);
    this._b.GetDefaultOptions(s);
    const d = this._b.koffi.decode(s, this._b.ThirdeyeOptionsStruct);
    return {
      format: d.format,
      quality: d.quality,
      bypassProtection: !!d.bypassProtection,
    };
  }

  captureToFile(filePath, options) {
    const opts = options || this.defaultOptions();
    const rc = this._b.CaptureToFile(this._ctx, String(filePath), toStruct(this._b, opts));
    if (rc !== THIRDEYE_OK) {
      throw new Error(`Thirdeye_CaptureToFile failed (rc=${rc}): ${this.lastError()}`);
    }
  }

  captureToBuffer(options) {
    const opts = options || this.defaultOptions();
    const bufOut = [null];
    const sizeOut = [0];
    const rc = this._b.CaptureToBuffer(this._ctx, bufOut, sizeOut, toStruct(this._b, opts));
    if (rc !== THIRDEYE_OK || !bufOut[0] || !sizeOut[0]) {
      throw new Error(`Thirdeye_CaptureToBuffer failed (rc=${rc}): ${this.lastError()}`);
    }
    try {
      return Buffer.from(this._b.koffi.decode(bufOut[0], 'uint8_t', sizeOut[0]));
    } finally {
      this._b.FreeBuffer(bufOut[0]);
    }
  }

  lastError() {
    return this._b.GetLastError(this._ctx);
  }

  version() {
    return this._b.GetVersion();
  }

  close() {
    if (this._ctx) {
      this._b.DestroyContext(this._ctx);
      this._ctx = null;
    }
  }
}

module.exports = {
  getLibraryPath,
  createBinding,
  ThirdEyeSession,
  ThirdeyeResult,
  ThirdeyeFormat,
  THIRDEYE_OK,
};
