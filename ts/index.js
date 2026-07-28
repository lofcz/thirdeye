'use strict';

const path = require('path');
const fs = require('fs');
const { Worker } = require('worker_threads');

const DLL_NAME = 'thirdeye.dll';
const bundled = path.join(__dirname, 'bin', DLL_NAME);
const WORKER_SCRIPT = path.join(__dirname, 'worker-thread.js');

const PREPARE_TOKEN = 'third_eye_token';

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

/**
 * Session mode (matches native ThirdeyeMode).
 * NotReady — until armed; Normal — armed; Busy — Prepare; Master — elevated helper.
 */
const ThirdeyeMode = Object.freeze({
  NotReady: 0,
  Normal: 1,
  Busy: 2,
  Master: 3,
});

const THIRDEYE_OK = ThirdeyeResult.Ok;

let _binding = null;
function createBinding() {
  if (_binding) return _binding;
  const lib = _load();
  const koffi = require('koffi');

  const ThirdeyeOptionsStruct = koffi.struct('ThirdeyeOptions', {
    format: 'int',
    quality: 'int',
    inclusive: 'int',
  });

  const ThirdeyePrepareOptionsStruct = koffi.struct('ThirdeyePrepareOptions', {
    size: 'uint32',
    elevate: 'int',
    reserved0: 'uint32',
    reserved1: 'uint32',
  });

  const ThirdeyeStateStruct = koffi.struct('ThirdeyeState', {
    mode: 'int',
    pid: 'uint32',
  });

  const CreateContext = lib.func('int __stdcall Thirdeye_CreateContext(_Out_ void **ppContext)');
  const DestroyContext = lib.func('void __stdcall Thirdeye_DestroyContext(void *context)');
  const GetDefaultOptions = lib.func('void __stdcall Thirdeye_GetDefaultOptions(_Out_ ThirdeyeOptions *options)');
  const CaptureToFile = lib.func('int __stdcall Thirdeye_CaptureToFile(void *context, const char16_t *filePath, const ThirdeyeOptions *options)');
  const CaptureToBuffer = lib.func('int __stdcall Thirdeye_CaptureToBuffer(void *context, _Out_ uint8_t **buffer, _Out_ uint32_t *size, const ThirdeyeOptions *options)');
  const FreeBuffer = lib.func('void __stdcall Thirdeye_FreeBuffer(uint8_t *buffer)');
  const GetLastError = lib.func('const char * __stdcall Thirdeye_GetLastError(void *context)');
  const GetVersion = lib.func('const char * __stdcall Thirdeye_GetVersion(void)');
  const Prepare = lib.func(
    'int __stdcall Thirdeye_Prepare(const char *token, const ThirdeyePrepareOptions *options)',
  );
  const Clean = lib.func('int __stdcall Thirdeye_Clean(void)');
  const State = lib.func('int __stdcall Thirdeye_State(_Out_ ThirdeyeState *out)');

  _binding = {
    koffi,
    ThirdeyeOptionsStruct,
    ThirdeyePrepareOptionsStruct,
    ThirdeyeStateStruct,
    CreateContext,
    DestroyContext,
    GetDefaultOptions,
    CaptureToFile,
    CaptureToBuffer,
    FreeBuffer,
    GetLastError,
    GetVersion,
    Prepare,
    Clean,
    State,
  };
  return _binding;
}

function toStruct(options) {
  return {
    format: options.format,
    quality: options.quality,
    inclusive: options.inclusive ? 1 : 0,
  };
}

function prepareOptionsStruct(elevate) {
  return {
    size: 16,
    elevate: elevate ? 1 : 0,
    reserved0: 0,
    reserved1: 0,
  };
}

function resolveKoffiPath() {
  try {
    return require.resolve('koffi');
  } catch {
    throw new Error(
      'thirdeye: the high-level API requires the optional "koffi" package. ' +
      'Install it (npm i koffi) or use getLibraryPath() with your own FFI.'
    );
  }
}

function runNativeWorker(op, args) {
  return new Promise((resolve, reject) => {
    const worker = new Worker(WORKER_SCRIPT, {
      workerData: {
        dllPath: getLibraryPath(),
        koffiPath: resolveKoffiPath(),
        token: PREPARE_TOKEN,
        op,
        args: args || null,
      },
    });
    let settled = false;
    const finish = (err, value) => {
      if (settled) return;
      settled = true;
      worker.terminate().catch(() => {});
      if (err) reject(err);
      else resolve(value);
    };
    worker.on('message', (msg) => {
      if (!msg || !msg.ok) {
        finish(new Error((msg && msg.error) || 'native worker failed'));
        return;
      }
      finish(null, msg.result);
    });
    worker.on('error', (err) => finish(err));
    worker.on('exit', (code) => {
      if (!settled && code !== 0) {
        finish(new Error(`native worker exited with code ${code}`));
      }
    });
  });
}

let _preparePromise = null;

/**
 * Authorize the native library and optionally start the elevated helper.
 *
 * @param {{ elevate?: boolean }} [options]
 *
 * Capture options.inclusive:
 * - includes hidden / capture-excluded windows
 * - when state().mode === ThirdeyeMode.Master, also elevated processes
 *
 * state().mode: ThirdeyeMode.NotReady | Normal | Busy | Master
 * - NotReady until armed; Normal when armed; Busy during Prepare; Master with helper
 */
function prepareAsync(options) {
  const elevate = !options || options.elevate !== false;
  if (_preparePromise) return _preparePromise;
  _preparePromise = runNativeWorker('prepare', { elevate }).then(
    (ok) => !!ok,
    (err) => {
      _preparePromise = null;
      throw err;
    },
  );
  return _preparePromise;
}

function clean() {
  _preparePromise = null;
  try {
    return !!createBinding().Clean();
  } catch {
    return false;
  }
}

/** @returns {{ mode: number, pid: number }} */
function state() {
  const b = createBinding();
  const s = b.koffi.alloc(b.ThirdeyeStateStruct, 1);
  if (!b.State(s)) return { mode: ThirdeyeMode.NotReady, pid: 0 };
  const d = b.koffi.decode(s, b.ThirdeyeStateStruct);
  return { mode: d.mode | 0, pid: d.pid >>> 0 };
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
      /**
       * inclusive:
       * - includes hidden / capture-excluded windows
       * - when state().mode === ThirdeyeMode.Master, also elevated processes
       */
      inclusive: !!d.inclusive,
    };
  }

  captureToFile(filePath, options) {
    const opts = options || this.defaultOptions();
    const rc = this._b.CaptureToFile(this._ctx, String(filePath), toStruct(opts));
    if (rc !== THIRDEYE_OK) {
      throw new Error(`Thirdeye_CaptureToFile failed (rc=${rc}): ${this.lastError()}`);
    }
  }

  async captureToFileAsync(filePath, options) {
    const opts = options || this.defaultOptions();
    if (opts.inclusive) {
      await prepareAsync({ elevate: true });
    }
    await runNativeWorker('captureToFile', { filePath: String(filePath), options: opts });
  }

  captureToBuffer(options) {
    const opts = options || this.defaultOptions();
    const bufOut = [null];
    const sizeOut = [0];
    const rc = this._b.CaptureToBuffer(this._ctx, bufOut, sizeOut, toStruct(opts));
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

  /** @param {{ elevate?: boolean }} [options] */
  prepare(options) {
    const elevate = !options || options.elevate !== false;
    return !!this._b.Prepare(PREPARE_TOKEN, prepareOptionsStruct(elevate));
  }

  prepareAsync(options) {
    return prepareAsync(options);
  }

  clean() {
    return clean();
  }

  state() {
    return state();
  }

  close() {
    clean();
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
  prepareAsync,
  clean,
  state,
  ThirdeyeResult,
  ThirdeyeFormat,
  ThirdeyeMode,
  THIRDEYE_OK,
};
