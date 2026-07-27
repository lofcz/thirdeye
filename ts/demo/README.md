# ThirdEye Electron Demo

Minimal Electron app demonstrating `@lofcz/thirdeye` screen capture with a
`WDA_EXCLUDEFROMCAPTURE`-protected companion window.

## What it does

- **Main app** (`main.js`): an Electron window with two buttons.
  - **Launch invisible app** spawns a second Electron instance
    (`invisible.js`) whose window is flagged with
    `WDA_EXCLUDEFROMCAPTURE` via `win.setContentProtection(true)`. Normal
    screenshots (PrintScreen, Snipping Tool, `BitBlt`) will not show it.
  - **Capture screenshot** captures the full screen using
    `ThirdEyeSession.captureToFile` with `bypassProtection: true` and saves a
    timestamped JPEG (`capture_<timestamp>.jpg`) into this `demo` directory.
    The "invisible" window is visible in the saved image.

## Run

```sh
npm install
npm start
```

Requires Windows x64.
