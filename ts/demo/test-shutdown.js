'use strict';

const { execSync } = require('child_process');
const { prepareAsync, clean, state } = require('@lofcz/thirdeye');

function rundllCount() {
  try {
    const out = execSync('tasklist /FI "IMAGENAME eq rundll32.exe"', { encoding: 'utf8' });
    if (/No tasks/i.test(out)) return 0;
    return out.split('\n').filter((l) => /rundll32\.exe/i.test(l)).length;
  } catch {
    return 0;
  }
}

(async () => {
  console.log('before', rundllCount(), state());
  console.log('prepare', await prepareAsync());
  console.log('after prepare', rundllCount(), state());
  console.log('clean', clean());
  await new Promise((r) => setTimeout(r, 500));
  console.log('after clean', rundllCount(), state());
})();
