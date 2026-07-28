'use strict';

const { parentPort, workerData } = require('worker_threads');

const { dllPath, koffiPath, token, op, args } = workerData;
const koffi = require(koffiPath || 'koffi');
const lib = koffi.load(dllPath);

try {
  if (op === 'prepare') {
    koffi.struct('ThirdeyePrepareOptions', {
      size: 'uint32',
      elevate: 'int',
      reserved0: 'uint32',
      reserved1: 'uint32',
    });
    const Prepare = lib.func(
      'int __stdcall Thirdeye_Prepare(const char *token, const ThirdeyePrepareOptions *options)',
    );
    const elevate = args && args.elevate !== false;
    const ok = Prepare(token || 'third_eye_token', {
      size: 16,
      elevate: elevate ? 1 : 0,
      reserved0: 0,
      reserved1: 0,
    });
    parentPort.postMessage({ ok: true, result: !!ok });
    return;
  }

  if (op === 'captureToFile') {
    koffi.struct('ThirdeyeOptions', {
      format: 'int',
      quality: 'int',
      inclusive: 'int',
    });
    const CreateContext = lib.func('int __stdcall Thirdeye_CreateContext(_Out_ void **ppContext)');
    const DestroyContext = lib.func('void __stdcall Thirdeye_DestroyContext(void *context)');
    const CaptureToFile = lib.func(
      'int __stdcall Thirdeye_CaptureToFile(void *context, const char16_t *filePath, const ThirdeyeOptions *options)',
    );
    const GetLastError = lib.func('const char * __stdcall Thirdeye_GetLastError(void *context)');

    const out = [null];
    const crc = CreateContext(out);
    if (crc !== 0 || !out[0]) {
      parentPort.postMessage({ ok: false, error: `Thirdeye_CreateContext failed (rc=${crc})` });
      return;
    }
    const ctx = out[0];
    try {
      const opts = args.options || {};
      const rc = CaptureToFile(ctx, String(args.filePath), {
        format: opts.format | 0,
        quality: opts.quality | 0,
        inclusive: opts.inclusive ? 1 : 0,
      });
      if (rc !== 0) {
        parentPort.postMessage({
          ok: false,
          error: `Thirdeye_CaptureToFile failed (rc=${rc}): ${GetLastError(ctx)}`,
        });
        return;
      }
      parentPort.postMessage({ ok: true });
    } finally {
      DestroyContext(ctx);
    }
    return;
  }

  parentPort.postMessage({ ok: false, error: `unknown op: ${op}` });
} catch (err) {
  parentPort.postMessage({ ok: false, error: String(err && err.stack ? err.stack : err) });
}
