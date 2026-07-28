'use strict';

const { createBinding, prepareAsync, clean, state, ThirdeyeMode } = require('@lofcz/thirdeye');

(async () => {
  const b = createBinding();
  console.log('version locked?', b.GetVersion());
  console.log('state before', state(), 'expect NotReady', ThirdeyeMode.NotReady);
  const t0 = performance.now();
  const out = [null];
  b.CreateContext(out);
  console.log('locked CreateContext ms', (performance.now() - t0).toFixed(1), 'err', b.GetLastError(out[0]));
  b.DestroyContext(out[0]);

  console.log('bad prepare', b.Prepare('wrong', { size: 16, elevate: 1, reserved0: 0, reserved1: 0 }));
  console.log('state after bad', state());

  console.log('good prepare', await prepareAsync({ elevate: true }));
  console.log('state after good', state(), 'expect Master', ThirdeyeMode.Master);
  console.log('version unlocked?', b.GetVersion());
  console.log('clean', clean());
  console.log('state after clean', state(), 'expect NotReady', ThirdeyeMode.NotReady);
})();
