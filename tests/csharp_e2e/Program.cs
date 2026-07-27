using System;
using System.Drawing;
using System.Drawing.Imaging;
using System.IO;
using System.Runtime.InteropServices;
using System.Threading;

namespace Thirdeye.E2E
{
    internal static class Native
    {
        public enum ThirdeyeResult
        {
            OK = 0,
            ERROR_NOT_INITIALIZED = -1,
            ERROR_SYSCALL_INIT_FAILED = -2,
            ERROR_GDIPLUS_INIT_FAILED = -3,
            ERROR_ENCODER_NOT_FOUND = -4,
            ERROR_SAVE_FAILED = -5,
            ERROR_ALLOCATION_FAILED = -6,
            ERROR_INVALID_PARAM = -7,
            ERROR_NO_REMOTE_SECTION = -8,
        }

        public enum ThirdeyeFormat
        {
            JPEG = 0,
            PNG = 1,
            BMP = 2,
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct ThirdeyeOptions
        {
            public ThirdeyeFormat format;
            public int quality;
            public int bypassProtection;
        }

        [DllImport("thirdeye.dll", CallingConvention = CallingConvention.StdCall)]
        public static extern ThirdeyeResult Thirdeye_CreateContext(out IntPtr ppContext);

        [DllImport("thirdeye.dll", CallingConvention = CallingConvention.StdCall)]
        public static extern void Thirdeye_DestroyContext(IntPtr context);

        [DllImport("thirdeye.dll", CallingConvention = CallingConvention.StdCall)]
        public static extern void Thirdeye_GetDefaultOptions(out ThirdeyeOptions options);

        [DllImport("thirdeye.dll", CallingConvention = CallingConvention.StdCall, CharSet = CharSet.Unicode)]
        public static extern ThirdeyeResult Thirdeye_CaptureToBuffer(
            IntPtr context, out IntPtr buffer, out uint size, ref ThirdeyeOptions options);

        [DllImport("thirdeye.dll", CallingConvention = CallingConvention.StdCall)]
        public static extern void Thirdeye_FreeBuffer(IntPtr buffer);

        [DllImport("thirdeye.dll", CallingConvention = CallingConvention.StdCall)]
        public static extern IntPtr Thirdeye_GetLastError(IntPtr context);

        [DllImport("thirdeye.dll", CallingConvention = CallingConvention.StdCall)]
        public static extern IntPtr Thirdeye_GetVersion();

        [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern IntPtr FindWindowW(string lpClassName, string lpWindowName);

        [DllImport("user32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool GetWindowRect(IntPtr hWnd, out RECT lpRect);

        [DllImport("user32.dll")]
        public static extern int GetSystemMetrics(int nIndex);

        [StructLayout(LayoutKind.Sequential)]
        public struct RECT { public int Left, Top, Right, Bottom; }

        public const int SM_XVIRTUALSCREEN = 76;
        public const int SM_YVIRTUALSCREEN = 77;
        public const int SM_CXVIRTUALSCREEN = 78;
        public const int SM_CYVIRTUALSCREEN = 79;
    }

    internal static class Program
    {
        private const string TargetTitle = "thirdeye_capture_target";
        private static int _failures;

        private static readonly Color[] Markers =
        {
            Color.FromArgb(0xFF, 0x00, 0x00),
            Color.FromArgb(0x00, 0xFF, 0x00),
            Color.FromArgb(0x00, 0x00, 0xFF),
            Color.FromArgb(0xFF, 0xFF, 0x00),
        };
        private static readonly string[] MarkerNames = { "red", "green", "blue", "yellow" };

        private static void Check(bool cond, string msg)
        {
            Console.WriteLine(cond ? "  [ok] " + msg : "  [FAIL] " + msg);
            if (!cond) _failures++;
        }

        private static string PtrToAnsi(IntPtr p)
        {
            return p == IntPtr.Zero ? "" : Marshal.PtrToStringAnsi(p);
        }

        private static Bitmap CaptureRawScreen()
        {
            int x = Native.GetSystemMetrics(Native.SM_XVIRTUALSCREEN);
            int y = Native.GetSystemMetrics(Native.SM_YVIRTUALSCREEN);
            int w = Native.GetSystemMetrics(Native.SM_CXVIRTUALSCREEN);
            int h = Native.GetSystemMetrics(Native.SM_CYVIRTUALSCREEN);
            var bmp = new Bitmap(w, h, PixelFormat.Format32bppArgb);
            using (var g = Graphics.FromImage(bmp))
            {
                g.CopyFromScreen(x, y, 0, 0, new Size(w, h), CopyPixelOperation.SourceCopy);
            }
            return bmp;
        }

        private static int CountMarkers(Bitmap bmp, Rectangle region, int tolerance, bool[] foundOut)
        {
            bool[] found = new bool[4];
            Rectangle r = Rectangle.Intersect(region, new Rectangle(0, 0, bmp.Width, bmp.Height));
            if (r.Width <= 0 || r.Height <= 0) return 0;

            BitmapData data = bmp.LockBits(r, ImageLockMode.ReadOnly, PixelFormat.Format32bppArgb);
            try
            {
                int stride = Math.Abs(data.Stride);
                unsafe
                {
                    byte* basePtr = (byte*)data.Scan0;
                    for (int yy = 0; yy < r.Height; yy++)
                    {
                        byte* row = basePtr + yy * stride;
                        for (int xx = 0; xx < r.Width; xx++)
                        {
                            byte b = row[xx * 4 + 0];
                            byte g = row[xx * 4 + 1];
                            byte rr = row[xx * 4 + 2];
                            for (int i = 0; i < 4; i++)
                            {
                                if (found[i]) continue;
                                Color m = Markers[i];
                                if (Math.Abs(rr - m.R) <= tolerance &&
                                    Math.Abs(g - m.G) <= tolerance &&
                                    Math.Abs(b - m.B) <= tolerance)
                                {
                                    found[i] = true;
                                }
                            }
                        }
                    }
                }
            }
            finally
            {
                bmp.UnlockBits(data);
            }

            int hits = 0;
            for (int i = 0; i < 4; i++)
            {
                if (found[i]) hits++;
                if (foundOut != null) foundOut[i] = found[i];
            }
            return hits;
        }

        private static int Main()
        {
            Console.WriteLine("[*] thirdeye C# E2E: WDA_EXCLUDEFROMCAPTURE bypass via P/Invoke");
            Console.WriteLine("[*] thirdeye version: " + PtrToAnsi(Native.Thirdeye_GetVersion()));

            string exeDir = AppContext.BaseDirectory;
            string targetPath = Path.Combine(exeDir, "capture_target.exe");
            if (!File.Exists(targetPath))
            {
                Console.WriteLine("[!] capture_target.exe not found next to host: " + targetPath);
                return 2;
            }

            var psi = new System.Diagnostics.ProcessStartInfo
            {
                FileName = targetPath,
                UseShellExecute = false,
            };
            var proc = System.Diagnostics.Process.Start(psi);
            if (proc == null)
            {
                Console.WriteLine("[!] failed to launch capture_target.exe");
                return 2;
            }
            Console.WriteLine("[*] target launched (pid=" + proc.Id + ")");
            Thread.Sleep(2000);

            IntPtr hwnd = Native.FindWindowW(null, TargetTitle);
            Check(hwnd != IntPtr.Zero, "target window located");

            Native.RECT wrect = new Native.RECT();
            bool haveRect = hwnd != IntPtr.Zero && Native.GetWindowRect(hwnd, out wrect);
            int vx = Native.GetSystemMetrics(Native.SM_XVIRTUALSCREEN);
            int vy = Native.GetSystemMetrics(Native.SM_YVIRTUALSCREEN);
            Rectangle region = haveRect
                ? new Rectangle(wrect.Left - vx, wrect.Top - vy, wrect.Right - wrect.Left, wrect.Bottom - wrect.Top)
                : new Rectangle(0, 0, Native.GetSystemMetrics(Native.SM_CXVIRTUALSCREEN), Native.GetSystemMetrics(Native.SM_CYVIRTUALSCREEN));

            Console.WriteLine("[*] phase 1: baseline raw capture (expect marker absent)");
            using (Bitmap baseline = CaptureRawScreen())
            {
                bool[] baselineFound = new bool[4];
                int baselineHits = CountMarkers(baseline, region, 4, baselineFound);
                Check(baselineHits == 0, "baseline: marker absent from raw capture (exclusion active)");
                if (baselineHits > 0)
                {
                    Console.WriteLine("      -> " + baselineHits + "/4 leaked; exclusion not active, test vacuous");
                    for (int i = 0; i < 4; i++)
                        if (baselineFound[i]) Console.WriteLine("         leaked: " + MarkerNames[i]);
                }
            }

            Thread.Sleep(3000);

            Console.WriteLine("[*] phase 2: thirdeye bypass capture from C# (expect marker present)");
            IntPtr ctx;
            Native.ThirdeyeResult cr = Native.Thirdeye_CreateContext(out ctx);
            Check(cr == Native.ThirdeyeResult.OK && ctx != IntPtr.Zero, "Thirdeye_CreateContext");

            if (cr == Native.ThirdeyeResult.OK && ctx != IntPtr.Zero)
            {
                Native.ThirdeyeOptions opts;
                Native.Thirdeye_GetDefaultOptions(out opts);
                opts.format = Native.ThirdeyeFormat.JPEG;
                opts.quality = 95;
                opts.bypassProtection = 1;

                IntPtr buf;
                uint size;
                Native.ThirdeyeResult capRes = Native.Thirdeye_CaptureToBuffer(ctx, out buf, out size, ref opts);
                Check(capRes == Native.ThirdeyeResult.OK && buf != IntPtr.Zero && size > 0,
                    "Thirdeye_CaptureToBuffer(bypass=1) -> " + capRes);
                if (capRes != Native.ThirdeyeResult.OK)
                    Console.WriteLine("      -> capture error: " + PtrToAnsi(Native.Thirdeye_GetLastError(ctx)));

                if (buf != IntPtr.Zero && size > 0)
                {
                    byte[] managed = new byte[size];
                    Marshal.Copy(buf, managed, 0, (int)size);
                    using (var ms = new MemoryStream(managed))
                    using (Bitmap bypass = new Bitmap(ms))
                    {
                        bool[] bypassFound = new bool[4];
                        int bypassHits = CountMarkers(bypass, region, 24, bypassFound);
                        Check(bypassHits == 4, "bypass: all 4 marker colors visible (exclusion bypassed)");
                        if (bypassHits != 4)
                        {
                            Console.WriteLine("      -> only " + bypassHits + "/4 found in bypass capture");
                            for (int i = 0; i < 4; i++)
                                if (!bypassFound[i]) Console.WriteLine("         missing: " + MarkerNames[i]);
                        }
                    }
                    Native.Thirdeye_FreeBuffer(buf);
                }
                Native.Thirdeye_DestroyContext(ctx);
            }

            try { proc.Kill(); } catch { }
            proc.Dispose();

            Console.WriteLine("==========================================");
            if (_failures == 0)
            {
                Console.WriteLine("[PASS] C# host: thirdeye.dll bypassed WDA_EXCLUDEFROMCAPTURE");
                return 0;
            }
            Console.WriteLine("[FAIL] " + _failures + " check(s) failed");
            return 1;
        }
    }
}
