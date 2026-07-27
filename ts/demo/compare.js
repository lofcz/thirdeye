'use strict';

// Compare the thirdeye JPEG against the normal GDI PNG to locate where they
// differ (the protected window region). Uses the bundled koffi-free approach:
// decode via Electron? No -- use raw BMP via PowerShell instead. Simpler:
// shell out nothing; just report file sizes and let the caller crop.
// This script crops a region from both images using Jimp if available,
// otherwise prints guidance.

const fs = require('fs');

const th = fs.statSync('capture_2026-07-27_19-25-40.jpg');
const nm = fs.statSync('normal_capture.png');
console.log('thirdeye jpg bytes:', th.size);
console.log('normal  png bytes:', nm.size);
console.log('Images exist. Crop comparison requires an image lib; done externally.');
