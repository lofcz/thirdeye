using System;
using System.IO;
using ThirdEye;

namespace ThirdEye.Demo;

class Program
{
    static int Main(string[] args)
    {
        Console.WriteLine("╔══════════════════════════════════════════╗");
        Console.WriteLine("║         ThirdEye Demo Application        ║");
        Console.WriteLine("╚══════════════════════════════════════════╝");
        Console.WriteLine();

        try
        {
            Console.WriteLine($"ThirdEye version: {ThirdEye.GetVersion()}");
            Console.WriteLine();

            // Parse command line arguments
            var outputPath = args.Length > 0 ? args[0] : "screenshot.jpg";
            var format = GetFormatFromExtension(outputPath);

            // Show current settings
            var defaultOptions = ThirdEye.GetDefaultOptions();
            Console.WriteLine("Default Options:");
            Console.WriteLine($"  Format:     {defaultOptions.Format}");
            Console.WriteLine($"  Quality:    {defaultOptions.Quality}");
            Console.WriteLine($"  Bypass:     {(defaultOptions.IsBypassEnabled ? "Enabled" : "Disabled")}");
            Console.WriteLine();

            // Demo 1: Capture to file with default options
            Console.WriteLine("═══ Demo 1: Capture to File (Default) ═══");
            var defaultOutput = Path.Combine(Path.GetDirectoryName(outputPath) ?? ".", 
                $"demo1_default{Path.GetExtension(outputPath)}");
            ThirdEye.CaptureToFile(defaultOutput);
            Console.WriteLine($"  Saved: {Path.GetFullPath(defaultOutput)}");
            Console.WriteLine($"  Size:  {new FileInfo(defaultOutput).Length:N0} bytes");
            Console.WriteLine();

            // Demo 2: Capture with custom options (PNG, no bypass)
            Console.WriteLine("═══ Demo 2: Capture with Custom Options ═══");
            var customOptions = new ThirdEyeOptions(ThirdeyeFormat.Png, quality: 100, bypassProtection: false);
            var pngOutput = Path.Combine(Path.GetDirectoryName(outputPath) ?? ".", "demo2_custom.png");
            ThirdEye.CaptureToFile(pngOutput, customOptions);
            Console.WriteLine($"  Format: PNG, Bypass: Disabled");
            Console.WriteLine($"  Saved:  {Path.GetFullPath(pngOutput)}");
            Console.WriteLine($"  Size:   {new FileInfo(pngOutput).Length:N0} bytes");
            Console.WriteLine();

            // Demo 3: Capture with bypass enabled
            Console.WriteLine("═══ Demo 3: Capture with Bypass Enabled ═══");
            var bypassOptions = new ThirdEyeOptions(format, quality: 90, bypassProtection: true);
            ThirdEye.CaptureToFile(outputPath, bypassOptions);
            Console.WriteLine($"  Format: {format}, Bypass: Enabled");
            Console.WriteLine($"  Saved:  {Path.GetFullPath(outputPath)}");
            Console.WriteLine($"  Size:   {new FileInfo(outputPath).Length:N0} bytes");
            Console.WriteLine();

            // Demo 4: Capture to memory buffer
            Console.WriteLine("═══ Demo 4: Capture to Memory Buffer ═══");
            var bufferData = ThirdEye.CaptureToBuffer();
            Console.WriteLine($"  Captured {bufferData.Length:N0} bytes to memory");
            
            // Save buffer to file
            var bufferOutput = Path.Combine(Path.GetDirectoryName(outputPath) ?? ".", "demo4_buffer.jpg");
            File.WriteAllBytes(bufferOutput, bufferData);
            Console.WriteLine($"  Saved buffer to: {Path.GetFullPath(bufferOutput)}");
            Console.WriteLine();

            // Summary
            Console.WriteLine("════════════════════════════════════════════");
            Console.WriteLine("All demos completed successfully!");
            Console.WriteLine();

            return 0;
        }
        catch (ThirdEyeException ex)
        {
            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"ThirdEye Error: {ex.Message}");
            Console.WriteLine($"Result Code: {ex.ResultCode}");
            Console.ResetColor();
            return (int)ex.ResultCode;
        }
        catch (Exception ex)
        {
            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"Unexpected Error: {ex.Message}");
            Console.ResetColor();
            return -100;
        }
        finally
        {
            // Optional: ThirdEye shuts down on process exit automatically.
        }
    }

    static ThirdeyeFormat GetFormatFromExtension(string path)
    {
        var ext = Path.GetExtension(path).ToLowerInvariant();
        return ext switch
        {
            ".png" => ThirdeyeFormat.Png,
            ".bmp" => ThirdeyeFormat.Bmp,
            _ => ThirdeyeFormat.Jpeg
        };
    }
}

