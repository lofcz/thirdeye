'use strict';

// Direct koffi harness: load an arbitrary thirdeye.dll and capture to file.
// Usage: node test-dll.js <path-to-dll> <out.jpg>

const path = require('path');
const fs = require('fs');
const koffi = require('koffi');

const dllPath = path.resolve(process.argv[2]);
const outPath = path.resolve(process.argv[3] || 'dll_test_out.jpg');

if (!fs.existsSync(dllPath)) {
  console.error('DLL not found:', dllPath);
  process.exit(2);
}

const lib = koffi.load(dllPath);

const CreateContext = lib.func('int __stdcall Thirdeye_CreateContext(_Out_ void **ppContext)');
const DestroyContext = lib.func('void __stdcall Thirdeye_DestroyContext(void *context)');
const GetDefaultOptions = lib.func('void __stdcall Thirdeye_GetDefaultOptions(_Out_ void *options)');
const GetLastError = lib.func('const char * __stdcall Thirdeye_GetLastError(void *context)');
const GetVersion = lib.func('const char * __stdcall Thirdeye_GetVersion(void)');

const ThirdeyeOptions = koffi.struct('ThirdeyeOptions', {
  format: 'int',
  quality: 'int',
  bypassProtection: 'int',
});

const CaptureToFile = lib.func('int __stdcall Thirdeye_CaptureToFile(void *context, const char16_t *filePath, const ThirdeyeOptions *options)');

console.log('DLL:', dllPath);
console.log('size:', fs.statSync(dllPath).Length || fs.statSync(dllPath).size, 'bytes');
console.log('version:', GetVersion());

const out = [null];
const rc = CreateContext(out);
if (rc !== 0 || !out[0]) {
  console.error('CreateContext failed rc=', rc);
  process.exit(1);
}
const ctx = out[0];

// default options -> bypassProtection should be 1
const optsBuf = koffi.alloc(ThirdeyeOptions, 1);
GetDefaultOptions(optsBuf);
const def = koffi.decode(optsBuf, ThirdeyeOptions);
console.log('default options:', def);

const opts = { format: 0, quality: 90, bypassProtection: 1 };
const crc = CaptureToFile(ctx, outPath, opts);
console.log('CaptureToFile rc=', crc, crc === 0 ? 'OK' : ('err: ' + GetLastError(ctx)));

if (fs.existsSync(outPath)) {
  console.log('wrote', outPath, fs.statSync(outPath).size, 'bytes');
} else {
  console.log('NO FILE WRITTEN');
}

DestroyContext(ctx);
process.exit(crc === 0 ? 0 : 1);
