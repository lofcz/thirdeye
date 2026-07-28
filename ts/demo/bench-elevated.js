'use strict';

const path = require('path');
const fs = require('fs');
const { ThirdEyeSession, ThirdeyeFormat } = require('@lofcz/thirdeye');

const outDir = path.join(__dirname, 'bench_out');
fs.mkdirSync(outDir, { recursive: true });

const s = new ThirdEyeSession();
const tBoot = performance.now();
const bootOk = s.ensureElevatedWorker();
console.log(`bootstrap: ${bootOk ? 'ok' : 'FAIL'} ${(performance.now() - tBoot).toFixed(1)}ms`);

const opts = { format: ThirdeyeFormat.Jpeg, quality: 90, bypassProtection: true };
const times = [];
for (let i = 0; i < 5; i++) {
  const file = path.join(outDir, `cap_${i}.jpg`);
  const t0 = performance.now();
  s.captureToFile(file, opts);
  const ms = performance.now() - t0;
  times.push(ms);
  const sz = fs.statSync(file).size;
  console.log(`capture ${i}: ${ms.toFixed(1)}ms (${sz} bytes)`);
}

const avg = times.reduce((a, b) => a + b, 0) / times.length;
const hot = times.slice(1);
const hotAvg = hot.length ? hot.reduce((a, b) => a + b, 0) / hot.length : avg;
console.log(`avg=${avg.toFixed(1)}ms  hotAvg(excl first)=${hotAvg.toFixed(1)}ms`);
s.close();
